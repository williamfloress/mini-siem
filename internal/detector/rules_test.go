package detector

import (
	"testing"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

func successLogin(ip, user string, at time.Time) event.Event {
	return event.Event{Timestamp: at, Source: "ssh", Type: "login_success", IP: ip, User: user}
}

func notFound(ip string, at time.Time) event.Event {
	return event.Event{Timestamp: at, Source: "nginx", Type: "http_404", IP: ip}
}

func sec(n int) time.Time { return base.Add(time.Duration(n) * time.Second) }

func TestCompromise_SuccessAfterManyFailures(t *testing.T) {
	d := NewCompromise(3, 10*time.Minute)
	for i := 0; i < 3; i++ {
		if a := d.Check(failedLogin("203.0.113.7", sec(i))); a != nil {
			t.Fatal("un login fallido no debería alertar")
		}
	}

	a := d.Check(successLogin("203.0.113.7", "root", sec(10)))
	if a == nil {
		t.Fatal("debía alertar: login exitoso tras 3 fallos")
	}
	if a.Rule != "possible_compromise" || a.Count != 3 || a.IP != "203.0.113.7" {
		t.Errorf("alerta incorrecta: %+v", a)
	}

	// La racha se cerró: otro login exitoso no repite la alerta.
	if d.Check(successLogin("203.0.113.7", "root", sec(20))) != nil {
		t.Error("no debía alertar dos veces por los mismos fallos")
	}
}

func TestCompromise_IgnoresNormalLogins(t *testing.T) {
	d := NewCompromise(3, 10*time.Minute)

	// Un usuario que se equivoca dos veces y entra: normal.
	d.Check(failedLogin("198.51.100.9", sec(0)))
	d.Check(failedLogin("198.51.100.9", sec(5)))
	if d.Check(successLogin("198.51.100.9", "ana", sec(10))) != nil {
		t.Error("2 fallos por debajo del umbral no deberían alertar")
	}

	// Fallos desde otra IP no cuentan.
	for i := 0; i < 5; i++ {
		d.Check(failedLogin("203.0.113.7", sec(i)))
	}
	if d.Check(successLogin("192.0.2.1", "ana", sec(10))) != nil {
		t.Error("los fallos de otra IP no deberían contar")
	}
}

func TestCompromise_OldFailuresExpire(t *testing.T) {
	d := NewCompromise(3, 10*time.Minute)
	for i := 0; i < 5; i++ {
		d.Check(failedLogin("203.0.113.7", sec(i)))
	}
	if d.Check(successLogin("203.0.113.7", "root", base.Add(time.Hour))) != nil {
		t.Error("los fallos de hace una hora no deberían contar")
	}
}

func TestNotFoundScan_AlertsOnBurst(t *testing.T) {
	d := NewNotFoundScan(10, time.Minute, 10*time.Minute)

	alerts := 0
	for i := 0; i < 30; i++ {
		if a := d.Check(notFound("203.0.113.7", sec(i))); a != nil {
			alerts++
			if a.Rule != "http_404_scan" || a.Count != 10 {
				t.Errorf("alerta incorrecta: %+v", a)
			}
		}
	}
	if alerts != 1 {
		t.Errorf("alertas = %d, quería 1 (el enfriamiento evita repetir)", alerts)
	}
}

func TestNotFoundScan_OnlyNginx404(t *testing.T) {
	d := NewNotFoundScan(2, time.Minute, time.Minute)

	other := []event.Event{
		{Timestamp: sec(0), Source: "app", Type: "http_404", IP: "203.0.113.7"},
		{Timestamp: sec(1), Source: "nginx", Type: "http_200", IP: "203.0.113.7"},
		failedLogin("203.0.113.7", sec(2)),
	}
	for _, e := range other {
		if d.Check(e) != nil {
			t.Fatalf("no debía alertar con %+v", e)
		}
	}
	d.Check(notFound("203.0.113.7", sec(3)))
	if d.Check(notFound("203.0.113.7", sec(4))) == nil {
		t.Error("debía alertar con 2 respuestas 404 de nginx")
	}
}
