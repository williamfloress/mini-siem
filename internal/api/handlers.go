package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/williamfloress/mini-siem/internal/event"
)

type EventLister interface {
	List(limit int) []event.Event
}

type EventSubmitter interface {
	Submit(e event.Event) error
}

type Handler struct {
	lister    EventLister
	submitter EventSubmitter
	logger    *slog.Logger
}

func NewRouter(lister EventLister, submitter EventSubmitter, logger *slog.Logger) http.Handler {
	h := &Handler{lister: lister, submitter: submitter, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("POST /events", h.createEvent)
	mux.HandleFunc("GET /events", h.listEvents)
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

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "limit debe estar entre 1 y 500")
			return
		}
		limit = n
	}
	writeJSON(w, http.StatusOK, h.lister.List(limit))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
