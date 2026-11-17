package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

// Compromise detecta un login exitoso desde una IP que acaba de fallar muchas veces:
// la fuerza bruta probablemente funcionó. Es más grave que brute_force, porque el
// atacante ya podría estar dentro.
type Compromise struct {
	mu        sync.Mutex
	threshold int
	failures  *slidingWindow
}

// NewCompromise alerta si un login_success llega después de al menos threshold
// login_failed desde la misma IP dentro de window.
func NewCompromise(threshold int, window time.Duration) *Compromise {
	return &Compromise{threshold: threshold, failures: newSlidingWindow(window)}
}

func (d *Compromise) Check(e event.Event) *Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch e.Type {
	case "login_failed":
		d.failures.add(e.IP, e.Timestamp)
		return nil

	case "login_success":
		n := d.failures.count(e.IP, e.Timestamp)
		// Tras un login exitoso, la racha de fallos se cierra: un segundo login exitoso
		// no vuelve a alertar por los mismos fallos.
		d.failures.reset(e.IP)
		if n < d.threshold {
			return nil
		}

		who := ""
		if e.User != "" {
			who = fmt.Sprintf(" como %q", e.User)
		}
		return &Alert{
			Rule:        "possible_compromise",
			IP:          e.IP,
			Count:       n,
			TriggeredAt: e.Timestamp,
			Message: fmt.Sprintf("login exitoso%s desde %s tras %d intentos fallidos en %s",
				who, e.IP, n, d.failures.size),
		}
	}
	return nil
}
