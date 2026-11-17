package api

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter limita las peticiones por IP con un token bucket: cada IP tiene un balde
// de burst fichas que se rellena a rps fichas por segundo, y cada petición gasta una.
//
// Las IPs que no envían nada durante idleTTL se borran del mapa. Sin eso, un atacante
// que rota IPs (o simplemente el paso del tiempo) haría crecer el mapa sin límite.
type RateLimiter struct {
	rps        rate.Limit
	burst      int
	trustProxy bool
	idleTTL    time.Duration
	now        func() time.Time // reemplazable en los tests

	mu        sync.Mutex
	clients   map[string]*client
	lastSweep time.Time
}

type client struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter crea el limitador. Con trustProxy, la IP del cliente se toma de
// X-Forwarded-For: actívalo solo detrás de un proxy propio (Caddy, nginx), porque
// cualquiera puede escribir esa cabecera.
func NewRateLimiter(rps float64, burst int, trustProxy bool) *RateLimiter {
	return &RateLimiter{
		rps:        rate.Limit(rps),
		burst:      burst,
		trustProxy: trustProxy,
		idleTTL:    10 * time.Minute,
		now:        time.Now,
		clients:    make(map[string]*client),
	}
}

// allow descuenta una ficha a la IP. Si no hay, devuelve cuánto esperar.
func (l *RateLimiter) allow(ip string) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Limpieza perezosa: como mucho una vez por idleTTL, dentro de una petición normal.
	// Así no hace falta una goroutine aparte que haya que parar al apagar.
	if now.Sub(l.lastSweep) > l.idleTTL {
		for k, c := range l.clients {
			if now.Sub(c.lastSeen) > l.idleTTL {
				delete(l.clients, k)
			}
		}
		l.lastSweep = now
	}

	c, ok := l.clients[ip]
	if !ok {
		c = &client{lim: rate.NewLimiter(l.rps, l.burst)}
		l.clients[ip] = c
	}
	c.lastSeen = now

	r := c.lim.ReserveN(now, 1)
	if delay := r.DelayFrom(now); delay > 0 {
		// No se va a esperar: se devuelve la ficha para no castigar al cliente dos veces.
		r.CancelAt(now)
		return false, delay
	}
	return true, 0
}

func (l *RateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}

// Middleware responde 429 con Retry-After a las IPs que superan el límite.
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := l.allow(l.clientIP(r))
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			writeError(w, http.StatusTooManyRequests, "demasiadas peticiones, reintente más tarde")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *RateLimiter) clientIP(r *http.Request) string {
	if l.trustProxy {
		// El proxy agrega la IP que ve al final de la lista; lo anterior lo puede
		// haber escrito el cliente, así que se toma el último valor.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
