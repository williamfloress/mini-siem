package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

type Alert struct {
	Rule        string    `json:"rule"`
	IP          string    `json:"ip"`
	Count       int       `json:"count"`
	TriggeredAt time.Time `json:"triggered_at"`
	Message     string    `json:"message"`
}

type BruteForce struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	cooldown  time.Duration
	attempts  map[string][]time.Time
	lastAlert map[string]time.Time
}

func NewBruteForce(threshold int, window, cooldown time.Duration) *BruteForce {
	return &BruteForce{
		threshold: threshold,
		window:    window,
		cooldown:  cooldown,
		attempts:  make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
	}
}

func (d *BruteForce) Check(e event.Event) *Alert {
	if e.Type != "login_failed" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := e.Timestamp.Add(-d.window)
	kept := d.attempts[e.IP][:0]
	for _, t := range d.attempts[e.IP] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, e.Timestamp)
	d.attempts[e.IP] = kept

	if len(kept) < d.threshold {
		return nil
	}
	if last, ok := d.lastAlert[e.IP]; ok && e.Timestamp.Sub(last) < d.cooldown {
		return nil
	}
	d.lastAlert[e.IP] = e.Timestamp

	return &Alert{
		Rule:        "brute_force",
		IP:          e.IP,
		Count:       len(kept),
		TriggeredAt: e.Timestamp,
		Message: fmt.Sprintf("%d logins fallidos desde %s en %s",
			len(kept), e.IP, d.window),
	}
}
