package detector

import (
	"testing"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

var base = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

func failedLogin(ip string, at time.Time) event.Event {
	return event.Event{Timestamp: at, Source: "ssh", Type: "login_failed", IP: ip}
}

func TestBruteForce_AlertsAtThreshold(t *testing.T) {
	d := NewBruteForce(5, time.Minute, 5*time.Minute)

	for i := 0; i < 4; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		if a := d.Check(failedLogin("203.0.113.7", at)); a != nil {
			t.Fatalf("no debía alertar en el intento %d", i+1)
		}
	}

	a := d.Check(failedLogin("203.0.113.7", base.Add(4*time.Second)))
	if a == nil {
		t.Fatal("debía alertar en el 5.º intento")
	}
	if a.Count != 5 {
		t.Errorf("Count = %d, quería 5", a.Count)
	}
}

func TestBruteForce_DifferentIPsAreIndependent(t *testing.T) {
	d := NewBruteForce(3, time.Minute, 5*time.Minute)

	alertsByIP := map[string]int{}
	ips := []string{"203.0.113.7", "198.51.100.9"}

	for i := 0; i < 6; i++ {
		ip := ips[i%2]
		at := base.Add(time.Duration(i) * time.Second)
		if a := d.Check(failedLogin(ip, at)); a != nil {
			alertsByIP[a.IP]++
		}
	}

	// TODO: verifica que alertsByIP tenga exactamente 2 entradas
	// y que cada IP tenga exactamente 1 alerta.
	if len(alertsByIP) != 2 {
		t.Fatalf("alertaron %d IPs, quería 2", len(alertsByIP))
	}
	for ip, n := range alertsByIP {
		if n != 1 {
			t.Errorf("la IP %s tuvo %d alertas, quería 1", ip, n)
		}
	}
}
func TestBruteForce_OldAttemptsExpire(t *testing.T) {
	d := NewBruteForce(3, time.Minute, 5*time.Minute)

	d.Check(failedLogin("203.0.113.7", base))
	d.Check(failedLogin("203.0.113.7", base.Add(10*time.Second)))

	if a := d.Check(failedLogin("203.0.113.7", base.Add(2*time.Minute))); a != nil {
		t.Fatal("los intentos viejos no deberían contar")
	}
}

func TestBruteForce_CooldownAvoidsAlertSpam(t *testing.T) {
	d := NewBruteForce(3, time.Minute, 5*time.Minute)

	alerts := 0
	for i := 0; i < 20; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		if d.Check(failedLogin("203.0.113.7", at)) != nil {
			alerts++
		}
	}
	if alerts != 1 {
		t.Errorf("alertas = %d, quería 1", alerts)
	}
}
