package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
)

var ErrQueueFull = errors.New("cola llena")

// opTimeout limita cada escritura en el store: si la BD se cuelga, el worker
// no se queda bloqueado para siempre y sigue con el siguiente evento.
const opTimeout = 5 * time.Second

type Store interface {
	Add(ctx context.Context, e event.Event) (event.Event, error)
}

type Detector interface {
	Check(e event.Event) *detector.Alert
}

type AlertSink interface {
	Add(ctx context.Context, a detector.Alert) (detector.Alert, error)
}

// Notifier recibe las alertas ya guardadas. Enqueue no debe bloquear: el worker
// no puede quedarse esperando a un servicio externo.
type Notifier interface {
	Enqueue(a detector.Alert)
}

type Pipeline struct {
	queue     chan event.Event
	store     Store
	detectors []Detector
	alerts    AlertSink
	notifier  Notifier // puede ser nil: sin notificaciones externas
	logger    *slog.Logger
	wg        sync.WaitGroup
}

func New(store Store, detectors []Detector, alerts AlertSink, notifier Notifier, logger *slog.Logger, queueSize int) *Pipeline {
	return &Pipeline{
		queue:     make(chan event.Event, queueSize),
		store:     store,
		detectors: detectors,
		alerts:    alerts,
		notifier:  notifier,
		logger:    logger,
	}
}

func (p *Pipeline) Start(workers int) {
	for i := 1; i <= workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

func (p *Pipeline) worker(id int) {
	defer p.wg.Done()
	for e := range p.queue {
		p.process(id, e)
	}
}

// process guarda el evento y lo pasa por cada detector. Usa context.Background (con
// timeout) y no el contexto de la petición HTTP: cuando el worker toma el evento,
// la petición ya respondió 202 y su contexto está cancelado.
func (p *Pipeline) process(worker int, e event.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	saved, err := p.store.Add(ctx, e)
	cancel()
	if err != nil {
		// El cliente ya recibió 202: el evento se pierde. Se registra para poder rastrearlo.
		p.logger.Error("no se pudo guardar el evento",
			"worker", worker, "type", e.Type, "ip", e.IP, "error", err)
		return
	}
	p.logger.Info("evento procesado",
		"worker", worker, "id", saved.ID, "type", saved.Type, "ip", saved.IP)

	// Un mismo evento puede disparar varias reglas: el login exitoso que cierra una
	// racha de fallos alerta como possible_compromise aunque brute_force ya haya alertado.
	for _, det := range p.detectors {
		if a := det.Check(saved); a != nil {
			p.raise(worker, *a)
		}
	}
}

// raise guarda la alerta y la pasa al notificador. Solo se notifican las alertas
// guardadas, así el ID del mensaje existe en GET /alerts.
func (p *Pipeline) raise(worker int, a detector.Alert) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	saved, err := p.alerts.Add(ctx, a)
	cancel()
	if err != nil {
		p.logger.Error("no se pudo guardar la alerta",
			"worker", worker, "rule", a.Rule, "ip", a.IP, "error", err)
		return
	}
	p.logger.Warn("ALERTA",
		"id", saved.ID, "rule", saved.Rule, "ip", saved.IP, "count", saved.Count, "worker", worker)

	if p.notifier != nil {
		p.notifier.Enqueue(saved)
	}
}

func (p *Pipeline) Submit(e event.Event) error {
	select {
	case p.queue <- e:
		return nil
	default:
		return ErrQueueFull
	}
}

// Stop cierra la cola y espera a que los workers terminen lo que queda en ella.
// Debe llamarse antes de cerrar el pool de la base de datos.
func (p *Pipeline) Stop() {
	close(p.queue)
	p.wg.Wait()
}
