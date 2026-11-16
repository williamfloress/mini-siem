package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/williamfloress/mini-siem/internal/event"
)

type EventStore interface {
	Add(e event.Event) event.Event
	List(limit int) []event.Event
}

type Handler struct {
	store  EventStore
	logger *slog.Logger
}

func NewRouter(store EventStore, logger *slog.Logger) http.Handler {
	h := &Handler{store: store, logger: logger}

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

	saved := h.store.Add(e)
	h.logger.Info("evento recibido",
		"id", saved.ID, "source", saved.Source, "type", saved.Type, "ip", saved.IP)
	writeJSON(w, http.StatusCreated, saved)
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
	writeJSON(w, http.StatusOK, h.store.List(limit))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
