package store

import (
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

type MemoryStore struct {
	mu     sync.RWMutex
	events []event.Event
	nextID int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{nextID: 1}
}

func (s *MemoryStore) Add(e event.Event) event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	e.ID = s.nextID
	s.nextID++
	e.ReceivedAt = time.Now().UTC()
	s.events = append(s.events, e)
	return e
}

func (s *MemoryStore) List(limit int) []event.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.events)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]event.Event, limit)
	copy(out, s.events[n-limit:])
	return out
}
