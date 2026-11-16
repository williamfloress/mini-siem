package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
)

type EventLister interface {
	List(ctx context.Context, limit int) ([]event.Event, error)
}

type AlertLister interface {
	List(ctx context.Context, limit int) ([]detector.Alert, error)
}

type EventSubmitter interface {
	Submit(e event.Event) error
}

type Handler struct {
	events    EventLister
	alerts    AlertLister
	submitter EventSubmitter
	logger    *slog.Logger
}

func NewRouter(events EventLister, alerts AlertLister, submitter EventSubmitter, logger *slog.Logger) http.Handler {
	h := &Handler{events: events, alerts: alerts, submitter: submitter, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("POST /events", h.createEvent)
	mux.HandleFunc("GET /events", h.listEvents)
	mux.HandleFunc("GET /alerts", h.listAlerts)
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
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 500 {
		return 0, errors.New("limit debe estar entre 1 y 500")
	}
	return n, nil
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
