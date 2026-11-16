package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
)

type EventLister interface {
	List(limit int) []event.Event
}

type AlertLister interface {
	List(limit int) []detector.Alert
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
	writeJSON(w, http.StatusOK, h.events.List(limit))
}

func (h *Handler) listAlerts(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h.alerts.List(limit))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
