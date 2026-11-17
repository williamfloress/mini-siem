package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

type Alert struct {
	ID          int64     `json:"id"`
	Rule        string    `json:"rule"`
	IP          string    `json:"ip"`
	Count       int       `json:"count"`
	TriggeredAt time.Time `json:"triggered_at"`
	Message     string    `json:"message"`
}

// Threshold es una regla genérica: alerta cuando una IP acumula threshold eventos
// que cumplen match dentro de window, y luego calla durante cooldown.
// La fuerza bruta y el escaneo de 404 son dos configuraciones de esta misma regla.
type Threshold struct {
	mu        sync.Mutex
	rule      string
	match     func(event.Event) bool
	describe  func(count int, ip string, window time.Duration) string
	threshold int
	window    *slidingWindow
	cooldown  *cooldown
}

func (d *Threshold) Check(e event.Event) *Alert {
	if !d.match(e) {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	n := d.window.add(e.IP, e.Timestamp)
	if n < d.threshold || !d.cooldown.allow(e.IP, e.Timestamp) {
		return nil
	}
	return &Alert{
		Rule:        d.rule,
		IP:          e.IP,
		Count:       n,
		TriggeredAt: e.Timestamp,
		Message:     d.describe(n, e.IP, d.window.size),
	}
}

// NewBruteForce alerta con threshold logins fallidos desde una IP dentro de window.
func NewBruteForce(threshold int, window, cooldownPeriod time.Duration) *Threshold {
	return &Threshold{
		rule:  "brute_force",
		match: func(e event.Event) bool { return e.Type == "login_failed" },
		describe: func(n int, ip string, w time.Duration) string {
			return fmt.Sprintf("%d logins fallidos desde %s en %s", n, ip, w)
		},
		threshold: threshold,
		window:    newSlidingWindow(window),
		cooldown:  newCooldown(cooldownPeriod),
	}
}

// NewNotFoundScan alerta con threshold respuestas 404 de nginx a una IP dentro de window:
// alguien está probando rutas a ciegas (/wp-admin, /.env, /phpmyadmin...).
func NewNotFoundScan(threshold int, window, cooldownPeriod time.Duration) *Threshold {
	return &Threshold{
		rule:  "http_404_scan",
		match: func(e event.Event) bool { return e.Source == "nginx" && e.Type == "http_404" },
		describe: func(n int, ip string, w time.Duration) string {
			return fmt.Sprintf("%d respuestas 404 a %s en %s (posible escaneo)", n, ip, w)
		},
		threshold: threshold,
		window:    newSlidingWindow(window),
		cooldown:  newCooldown(cooldownPeriod),
	}
}
