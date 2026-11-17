package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
	"github.com/williamfloress/mini-siem/internal/store"
)

type countingObserver struct {
	mu                    sync.Mutex
	stored, failed, alert int
}

func (o *countingObserver) EventStored()      { o.mu.Lock(); o.stored++; o.mu.Unlock() }
func (o *countingObserver) EventStoreFailed() { o.mu.Lock(); o.failed++; o.mu.Unlock() }
func (o *countingObserver) AlertRaised(string) {
	o.mu.Lock()
	o.alert++
	o.mu.Unlock()
}

// alertOnFailed alerta con cada login_failed, para no depender de los umbrales reales.
type alertOnFailed struct{}

func (alertOnFailed) Check(e event.Event) *detector.Alert {
	if e.Type != "login_failed" {
		return nil
	}
	return &detector.Alert{Rule: "test", IP: e.IP, Count: 1, TriggeredAt: e.Timestamp}
}

type failingStore struct{}

func (failingStore) Add(context.Context, event.Event) (event.Event, error) {
	return event.Event{}, errors.New("base caída")
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func ev(typ string) event.Event {
	return event.Event{Timestamp: time.Now(), Source: "ssh", Type: typ, IP: "203.0.113.7"}
}

func TestPipelineProcessesAndObserves(t *testing.T) {
	events := store.NewMemoryEventStore()
	alerts := store.NewMemoryAlertStore()
	obs := &countingObserver{}

	p := New(events, []Detector{alertOnFailed{}}, alerts, nil, quietLogger(), 10)
	p.SetObserver(obs)
	p.Start(2)
	for _, typ := range []string{"login_failed", "login_success", "login_failed"} {
		if err := p.Submit(ev(typ)); err != nil {
			t.Fatal(err)
		}
	}
	p.Stop() // espera a que se procese toda la cola

	if obs.stored != 3 || obs.alert != 2 || obs.failed != 0 {
		t.Fatalf("observador: %+v", obs)
	}
	saved, _ := alerts.List(context.Background(), 10)
	if len(saved) != 2 {
		t.Fatalf("se guardaron %d alertas, se esperaban 2", len(saved))
	}
}

func TestPipelineStoreFailure(t *testing.T) {
	obs := &countingObserver{}
	p := New(failingStore{}, []Detector{alertOnFailed{}}, store.NewMemoryAlertStore(), nil, quietLogger(), 10)
	p.SetObserver(obs)
	p.Start(1)
	_ = p.Submit(ev("login_failed"))
	p.Stop()

	// Si el evento no se guardó, tampoco se evalúa: no hay alerta.
	if obs.failed != 1 || obs.stored != 0 || obs.alert != 0 {
		t.Fatalf("observador: %+v", obs)
	}
}

func TestPipelineQueueFull(t *testing.T) {
	// Sin Start: nadie consume la cola.
	p := New(store.NewMemoryEventStore(), nil, store.NewMemoryAlertStore(), nil, quietLogger(), 2)
	_ = p.Submit(ev("x"))
	_ = p.Submit(ev("x"))
	if p.QueueLen() != 2 || p.QueueCap() != 2 {
		t.Fatalf("QueueLen=%d QueueCap=%d", p.QueueLen(), p.QueueCap())
	}
	if err := p.Submit(ev("x")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("se esperaba ErrQueueFull, llegó %v", err)
	}
}
