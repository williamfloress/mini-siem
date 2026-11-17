package detector

import "time"

// slidingWindow guarda, por clave (normalmente una IP), los instantes de los eventos
// que siguen dentro de la ventana. No es seguro para uso concurrente: cada regla lo
// protege con su propio mutex.
type slidingWindow struct {
	size time.Duration
	hits map[string][]time.Time
}

func newSlidingWindow(size time.Duration) *slidingWindow {
	return &slidingWindow{size: size, hits: make(map[string][]time.Time)}
}

// add registra un evento en at y devuelve cuántos hay dentro de la ventana que termina en at.
func (w *slidingWindow) add(key string, at time.Time) int {
	kept := w.prune(key, at)
	kept = append(kept, at)
	w.hits[key] = kept
	return len(kept)
}

// count devuelve cuántos eventos hay dentro de la ventana que termina en at, sin registrar uno nuevo.
func (w *slidingWindow) count(key string, at time.Time) int {
	kept := w.prune(key, at)
	if len(kept) == 0 {
		delete(w.hits, key)
		return 0
	}
	w.hits[key] = kept
	return len(kept)
}

func (w *slidingWindow) reset(key string) {
	delete(w.hits, key)
}

// prune descarta los instantes anteriores al inicio de la ventana. Reutiliza el arreglo
// subyacente para no reservar memoria en cada evento.
func (w *slidingWindow) prune(key string, at time.Time) []time.Time {
	cutoff := at.Add(-w.size)
	kept := w.hits[key][:0]
	for _, t := range w.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

// cooldown evita repetir la misma alerta para una clave durante un tiempo.
type cooldown struct {
	period time.Duration
	last   map[string]time.Time
}

func newCooldown(period time.Duration) *cooldown {
	return &cooldown{period: period, last: make(map[string]time.Time)}
}

// allow dice si se puede alertar en at y, si se puede, lo registra.
func (c *cooldown) allow(key string, at time.Time) bool {
	if last, ok := c.last[key]; ok && at.Sub(last) < c.period {
		return false
	}
	c.last[key] = at
	return true
}
