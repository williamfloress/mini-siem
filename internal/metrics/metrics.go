// Package metrics expone las métricas del servidor en formato Prometheus.
//
// Usa un registro propio en vez del global de client_golang: así el contenido de
// /metrics es explícito y los tests pueden crear instancias independientes.
//
// Todos los métodos aceptan un *Metrics nil y no hacen nada, para que el resto del
// código no tenga que preguntar si las métricas están activas.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry *prometheus.Registry

	eventsAccepted    prometheus.Counter
	eventsRejected    *prometheus.CounterVec
	eventsStored      prometheus.Counter
	eventsStoreFailed prometheus.Counter
	alerts            *prometheus.CounterVec
	httpRequests      *prometheus.CounterVec
	httpDuration      *prometheus.HistogramVec
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	f := promauto.With(reg)

	m := &Metrics{
		registry: reg,
		eventsAccepted: f.NewCounter(prometheus.CounterOpts{
			Name: "siem_events_received_total",
			Help: "Eventos aceptados por POST /events y encolados (respuesta 202).",
		}),
		eventsRejected: f.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_events_rejected_total",
			Help: "Eventos rechazados por POST /events, por motivo (invalid, queue_full).",
		}, []string{"reason"}),
		eventsStored: f.NewCounter(prometheus.CounterOpts{
			Name: "siem_events_stored_total",
			Help: "Eventos guardados por los workers.",
		}),
		eventsStoreFailed: f.NewCounter(prometheus.CounterOpts{
			Name: "siem_events_store_failed_total",
			Help: "Eventos que no se pudieron guardar después de responder 202 (se pierden).",
		}),
		alerts: f.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_alerts_total",
			Help: "Alertas generadas y guardadas, por regla.",
		}, []string{"rule"}),
		httpRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "siem_http_requests_total",
			Help: "Peticiones HTTP atendidas, por ruta y código de respuesta.",
		}, []string{"route", "code"}),
		httpDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "siem_http_request_duration_seconds",
			Help:    "Duración de las peticiones HTTP, por ruta.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		}, []string{"route"}),
	}

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// RegisterQueue publica el estado de la cola del pipeline. Se lee en cada scrape,
// así que no hay que actualizar nada al encolar o desencolar.
func (m *Metrics) RegisterQueue(length func() int, capacity int) {
	if m == nil {
		return
	}
	m.registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "siem_queue_length",
			Help: "Eventos esperando en la cola de procesamiento.",
		}, func() float64 { return float64(length()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "siem_queue_capacity",
			Help: "Capacidad de la cola: si siem_queue_length llega aquí, la API responde 503.",
		}, func() float64 { return float64(capacity) }),
	)
}

func (m *Metrics) EventAccepted() {
	if m != nil {
		m.eventsAccepted.Inc()
	}
}

func (m *Metrics) EventRejected(reason string) {
	if m != nil {
		m.eventsRejected.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) EventStored() {
	if m != nil {
		m.eventsStored.Inc()
	}
}

func (m *Metrics) EventStoreFailed() {
	if m != nil {
		m.eventsStoreFailed.Inc()
	}
}

func (m *Metrics) AlertRaised(rule string) {
	if m != nil {
		m.alerts.WithLabelValues(rule).Inc()
	}
}

// Handler sirve /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Middleware mide cada petición. La etiqueta route es el patrón del ServeMux
// ("GET /events"), no la URL: con la URL, cada ?limit=N distinto crearía una serie
// nueva y la memoria de Prometheus crecería sin límite.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// El ServeMux escribe r.Pattern en la misma petición al elegir el handler.
		route := r.Pattern
		if route == "" || route == "/" {
			route = "other" // 404, o rechazada (429) antes de llegar a una ruta concreta
		}
		m.httpRequests.WithLabelValues(route, strconv.Itoa(rec.status)).Inc()
		m.httpDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap deja que http.ResponseController llegue al ResponseWriter original.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}
