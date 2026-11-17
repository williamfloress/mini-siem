// Package notify envía las alertas a canales externos (Telegram) sin frenar a los workers.
package notify

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
)

// Notifier envía una alerta por algún canal. Cada llamada es un solo intento:
// los reintentos los maneja el Dispatcher.
type Notifier interface {
	Notify(ctx context.Context, a detector.Alert) error
}

// PermanentError marca un error que no se arregla reintentando (por ejemplo, un token inválido).
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Dispatcher desacopla el envío de los workers: Enqueue nunca bloquea, y una sola
// goroutine envía las alertas con timeout por intento y reintentos con backoff.
// Si el canal externo está caído, las alertas se acumulan en la cola (y se descartan
// si se llena) en lugar de frenar el procesamiento de eventos.
type Dispatcher struct {
	notifier    Notifier
	logger      *slog.Logger
	queue       chan detector.Alert
	maxAttempts int
	backoff     time.Duration // espera antes del 2.º intento; se duplica en cada reintento
	timeout     time.Duration // límite de cada intento

	ctx    context.Context // se cancela si Stop agota su plazo
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewDispatcher(n Notifier, logger *slog.Logger, queueSize int) *Dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		notifier:    n,
		logger:      logger,
		queue:       make(chan detector.Alert, queueSize),
		maxAttempts: 4,
		backoff:     time.Second,
		timeout:     10 * time.Second,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (d *Dispatcher) Start() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for a := range d.queue {
			d.send(a)
		}
	}()
}

// Enqueue agenda la alerta para enviarla. No bloquea nunca.
func (d *Dispatcher) Enqueue(a detector.Alert) {
	select {
	case d.queue <- a:
	default:
		d.logger.Error("cola de notificaciones llena, alerta no enviada", "alert_id", a.ID, "rule", a.Rule, "ip", a.IP)
	}
}

func (d *Dispatcher) send(a detector.Alert) {
	wait := d.backoff
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
		err := d.notifier.Notify(ctx, a)
		cancel()
		if err == nil {
			d.logger.Info("alerta notificada", "alert_id", a.ID, "rule", a.Rule, "attempt", attempt)
			return
		}

		var perm *PermanentError
		if errors.As(err, &perm) || attempt == d.maxAttempts {
			d.logger.Error("no se pudo notificar la alerta",
				"alert_id", a.ID, "rule", a.Rule, "attempt", attempt, "error", err)
			return
		}
		d.logger.Warn("fallo al notificar, se reintentará",
			"alert_id", a.ID, "attempt", attempt, "retry_in", wait.String(), "error", err)

		select {
		case <-time.After(wait):
			wait *= 2
		case <-d.ctx.Done():
			d.logger.Error("apagado: alerta no notificada", "alert_id", a.ID, "rule", a.Rule)
			return
		}
	}
}

// Stop deja de aceptar alertas y espera hasta timeout a que se envíen las pendientes.
// Si el plazo se agota, cancela los envíos en curso. Debe llamarse después de
// detener el pipeline, que es quien encola.
func (d *Dispatcher) Stop(timeout time.Duration) {
	close(d.queue)
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		d.cancel()
		<-done
	}
	d.cancel()
}
