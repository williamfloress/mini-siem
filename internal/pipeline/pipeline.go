package pipeline

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/williamfloress/mini-siem/internal/event"
)

var ErrQueueFull = errors.New("cola llena")

type Store interface {
	Add(e event.Event) event.Event
}

type Pipeline struct {
	queue  chan event.Event
	store  Store
	logger *slog.Logger
	wg     sync.WaitGroup
}

func New(store Store, logger *slog.Logger, queueSize int) *Pipeline {
	return &Pipeline{
		queue:  make(chan event.Event, queueSize),
		store:  store,
		logger: logger,
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
		saved := p.store.Add(e)
		p.logger.Info("evento procesado",
			"worker", id, "id", saved.ID, "type", saved.Type, "ip", saved.IP)
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

func (p *Pipeline) Stop() {
	close(p.queue)
	p.wg.Wait()
}
