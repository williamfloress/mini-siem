package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
	"github.com/williamfloress/mini-siem/internal/web"
)

type EventReader interface {
	List(ctx context.Context, limit int) ([]event.Event, error)
	TopIPs(ctx context.Context, since time.Time, limit int) ([]event.IPCount, error)
}

type AlertLister interface {
	List(ctx context.Context, limit int) ([]detector.Alert, error)
}

type EventSubmitter interface {
	Submit(e event.Event) error
}

// Deps son las dependencias del router. Logger, Events, Alerts y Submitter son obligatorias.
type Deps struct {
	Events    EventReader
	Alerts    AlertLister
	Submitter EventSubmitter
	Logger    *slog.Logger

	// APIKey protege POST /events. Vacía = ingesta abierta (modo desarrollo).
	APIKey string
}

type Handler struct {
	events    EventReader
	alerts    AlertLister
	submitter EventSubmitter
	logger    *slog.Logger
}

func NewRouter(d Deps) http.Handler {
	h := &Handler{events: d.Events, alerts: d.Alerts, submitter: d.Submitter, logger: d.Logger}

	var ingest http.Handler = http.HandlerFunc(h.createEvent)
	if d.APIKey != "" {
		ingest = requireAPIKey(d.APIKey, ingest)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.Handle("POST /events", ingest)
	mux.HandleFunc("GET /events", h.listEvents)
	mux.HandleFunc("GET /alerts", h.listAlerts)
	mux.HandleFunc("GET /stats/top-ips", h.topIPs)
	// {$} = solo la raíz exacta; cualquier otra ruta desconocida sigue dando 404.
	mux.HandleFunc("GET /{$}", web.Dashboard)
	return mux
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) createEvent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var e event.Event
	if err := dec.Decode(&e); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return
	}
	if err := e.Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := h.submitter.Submit(e); err != nil {
		h.logger.Warn("cola llena, evento rechazado", "ip", e.IP)
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "servidor ocupado, reintente")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func parseLimit(r *http.Request) (int, error) {
	return parseLimitRange(r, 50, 500)
}

func parseLimitRange(r *http.Request, def, max int) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("limit debe estar entre 1 y %d", max)
	}
	return n, nil
}

const maxStatsWindow = 30 * 24 * time.Hour

type topIPsResponse struct {
	Window string          `json:"window"`
	Since  time.Time       `json:"since"`
	IPs    []event.IPCount `json:"ips"`
}

// topIPs devuelve las IPs con más eventos en el periodo window (por defecto 24h).
func (h *Handler) topIPs(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimitRange(r, 10, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	window := 24 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		window, err = time.ParseDuration(v)
		if err != nil || window <= 0 || window > maxStatsWindow {
			writeError(w, http.StatusBadRequest, "window debe ser una duración entre 1s y 720h (por ejemplo 1h o 24h)")
			return
		}
	}

	since := time.Now().UTC().Add(-window)
	ips, err := h.events.TopIPs(r.Context(), since, limit)
	if err != nil {
		h.internalError(w, "top IPs", err)
		return
	}
	writeJSON(w, http.StatusOK, topIPsResponse{Window: window.String(), Since: since, IPs: ips})
}

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	events, err := h.events.List(r.Context(), limit)
	if err != nil {
		h.internalError(w, "listar eventos", err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (h *Handler) listAlerts(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	alerts, err := h.alerts.List(r.Context(), limit)
	if err != nil {
		h.internalError(w, "listar alertas", err)
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// internalError registra el detalle y responde un mensaje genérico: el error de la BD
// puede revelar nombres de tablas o de host que el cliente no necesita ver.
func (h *Handler) internalError(w http.ResponseWriter, op string, err error) {
	h.logger.Error("error interno", "op", op, "error", err)
	writeError(w, http.StatusInternalServerError, "error interno")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
