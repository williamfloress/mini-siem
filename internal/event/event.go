package event

import (
	"errors"
	"net/netip"
	"strings"
	"time"
)

type Event struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Source     string    `json:"source"`
	Type       string    `json:"type"`
	IP         string    `json:"ip"`
	User       string    `json:"user,omitempty"`
	Message    string    `json:"message,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
}

var validSources = map[string]bool{"ssh": true, "nginx": true, "app": true}

func (e *Event) Validate() error {
	if e.Timestamp.IsZero() {
		return errors.New("timestamp es requerido")
	}
	if !validSources[e.Source] {
		return errors.New("source inválido: use ssh, nginx o app")
	}
	if strings.TrimSpace(e.Type) == "" {
		return errors.New("type es requerido")
	}
	if _, err := netip.ParseAddr(e.IP); err != nil {
		return errors.New("ip inválida")
	}
	return nil
}
