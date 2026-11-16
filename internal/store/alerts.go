package store

import (
	"sync"

	"github.com/williamfloress/mini-siem/internal/detector"
)

type AlertStore struct {
	mu     sync.RWMutex
	alerts []detector.Alert
}

func NewAlertStore() *AlertStore {
	return &AlertStore{}
}

func (s *AlertStore) Add(a detector.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
}

func (s *AlertStore) List(limit int) []detector.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.alerts)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]detector.Alert, limit)
	copy(out, s.alerts[n-limit:])
	return out
}
