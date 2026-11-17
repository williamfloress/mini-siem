package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// clock es un reloj manual para que los tests no dependan del tiempo real.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(rps float64, burst int, trustProxy bool) (*RateLimiter, *clock) {
	c := &clock{t: time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)}
	l := NewRateLimiter(rps, burst, trustProxy)
	l.now = c.now
	return l, c
}

func TestRateLimiterBurstAndRefill(t *testing.T) {
	l, c := newTestLimiter(1, 3, false)

	for i := range 3 {
		if ok, _ := l.allow("198.51.100.1"); !ok {
			t.Fatalf("la petición %d de la ráfaga debería pasar", i+1)
		}
	}
	ok, wait := l.allow("198.51.100.1")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("la cuarta debería rechazarse con espera de hasta 1s: ok=%v wait=%s", ok, wait)
	}
	// Otra IP tiene su propio balde.
	if ok, _ := l.allow("198.51.100.2"); !ok {
		t.Fatal("otra IP no debería verse afectada")
	}

	c.advance(time.Second)
	if ok, _ := l.allow("198.51.100.1"); !ok {
		t.Fatal("tras 1s debería haber una ficha nueva")
	}
}

// Una petición rechazada no debe gastar ficha: si no, un cliente que reintenta
// seguido nunca saldría del bloqueo.
func TestRateLimiterRejectedRequestsDoNotConsume(t *testing.T) {
	l, c := newTestLimiter(1, 1, false)
	l.allow("198.51.100.1")
	for range 10 {
		l.allow("198.51.100.1")
	}
	c.advance(time.Second)
	if ok, _ := l.allow("198.51.100.1"); !ok {
		t.Fatal("los rechazos no deberían haber acumulado deuda")
	}
}

func TestRateLimiterForgetsIdleClients(t *testing.T) {
	l, c := newTestLimiter(1, 1, false)
	l.allow("198.51.100.1")
	l.allow("198.51.100.2")
	c.advance(11 * time.Minute)
	l.allow("198.51.100.3")
	if n := l.size(); n != 1 {
		t.Fatalf("quedan %d IPs en el mapa, se esperaba 1", n)
	}
}

func TestRateLimiterClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")

	direct, _ := newTestLimiter(1, 1, false)
	if ip := direct.clientIP(req); ip != "10.0.0.1" {
		t.Errorf("sin proxy de confianza debe usar RemoteAddr: %s", ip)
	}
	proxied, _ := newTestLimiter(1, 1, true)
	if ip := proxied.clientIP(req); ip != "203.0.113.9" {
		t.Errorf("detrás de un proxy debe usar el último valor de X-Forwarded-For: %s", ip)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	l, _ := newTestLimiter(1, 2, false)
	h, _ := newTestRouter(t, Deps{RateLimiter: l})

	for i := range 2 {
		if rec := do(h, "GET", "/alerts", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("petición %d: status %d", i+1, rec.Code)
		}
	}
	rec := do(h, "GET", "/alerts", "", nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("se esperaba 429 con Retry-After: 1, llegó %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := do(h, "GET", "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("/healthz no debe tener rate limit: %d", rec.Code)
	}
}
