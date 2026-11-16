package store

import (
	"context"
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
)

// MemoryEventStore guarda eventos en memoria. Se pierde todo al reiniciar;
// sirve para desarrollo y tests. Nunca devuelve error, pero cumple la misma
// interfaz que PostgresEventStore.
type MemoryEventStore struct {
	mu     sync.RWMutex
	events []event.Event
	nextID int64
}

func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{nextID: 1}
}

func (s *MemoryEventStore) Add(_ context.Context, e event.Event) (event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.ID = s.nextID
	s.nextID++
	e.ReceivedAt = time.Now().UTC()
	s.events = append(s.events, e)
	return e, nil
}

func (s *MemoryEventStore) List(_ context.Context, limit int) ([]event.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastN(s.events, limit), nil
}

type MemoryAlertStore struct {
	mu     sync.RWMutex
	alerts []detector.Alert
	nextID int64
}

func NewMemoryAlertStore() *MemoryAlertStore {
	return &MemoryAlertStore{nextID: 1}
}

func (s *MemoryAlertStore) Add(_ context.Context, a detector.Alert) (detector.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a.ID = s.nextID
	s.nextID++
	s.alerts = append(s.alerts, a)
	return a, nil
}

func (s *MemoryAlertStore) List(_ context.Context, limit int) ([]detector.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastN(s.alerts, limit), nil
}

// lastN devuelve una copia de los últimos limit elementos, en orden de llegada.
func lastN[T any](items []T, limit int) []T {
	n := len(items)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]T, limit)
	copy(out, items[n-limit:])
	return out
}
