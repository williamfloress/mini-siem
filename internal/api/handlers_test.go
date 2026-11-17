package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/williamfloress/mini-siem/internal/event"
	"github.com/williamfloress/mini-siem/internal/pipeline"
	"github.com/williamfloress/mini-siem/internal/store"
)

const testKey = "clave-de-prueba-de-32-caracteres!"

const validEvent = `{"timestamp":"2026-11-16T10:00:00Z","source":"ssh","type":"login_failed","ip":"203.0.113.7"}`

// fakeSubmitter guarda los eventos en vez de encolarlos; full simula la cola llena.
type fakeSubmitter struct {
	mu     sync.Mutex
	events []event.Event
	full   bool
}

func (f *fakeSubmitter) Submit(e event.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.full {
		return pipeline.ErrQueueFull
	}
	f.events = append(f.events, e)
	return nil
}

func newTestRouter(t *testing.T, d Deps) (http.Handler, *fakeSubmitter) {
	t.Helper()
	sub := &fakeSubmitter{}
	if d.Events == nil {
		d.Events = store.NewMemoryEventStore()
	}
	if d.Alerts == nil {
		d.Alerts = store.NewMemoryAlertStore()
	}
	if d.Submitter == nil {
		d.Submitter = sub
	}
	d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRouter(d), sub
}

func do(h http.Handler, method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCreateEventAPIKey(t *testing.T) {
	h, sub := newTestRouter(t, Deps{APIKey: testKey})

	cases := []struct {
		name   string
		auth   string
		status int
	}{
		{"sin cabecera", "", http.StatusUnauthorized},
		{"clave incorrecta", "Bearer otra-clave", http.StatusUnauthorized},
		{"esquema incorrecto", "Basic " + testKey, http.StatusUnauthorized},
		{"token vacío", "Bearer ", http.StatusUnauthorized},
		{"clave correcta", "Bearer " + testKey, http.StatusAccepted},
		{"esquema en minúsculas", "bearer " + testKey, http.StatusAccepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(h, "POST", "/events", validEvent, map[string]string{"Authorization": c.auth})
			if rec.Code != c.status {
				t.Fatalf("status = %d, se esperaba %d (body: %s)", rec.Code, c.status, rec.Body)
			}
			if c.status == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("falta WWW-Authenticate en el 401")
			}
		})
	}
	if len(sub.events) != 2 {
		t.Errorf("se encolaron %d eventos, se esperaban 2", len(sub.events))
	}
}

func TestCreateEventWithoutKeyConfigured(t *testing.T) {
	h, _ := newTestRouter(t, Deps{})
	if rec := do(h, "POST", "/events", validEvent, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("sin APIKey configurada la ingesta debería estar abierta: status %d", rec.Code)
	}
}

func TestReadEndpointsDoNotNeedKey(t *testing.T) {
	h, _ := newTestRouter(t, Deps{APIKey: testKey})
	for _, path := range []string{"/healthz", "/events", "/alerts", "/stats/top-ips", "/"} {
		if rec := do(h, "GET", path, "", nil); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", path, rec.Code)
		}
	}
}

func TestCreateEventValidation(t *testing.T) {
	h, sub := newTestRouter(t, Deps{})
	cases := []struct {
		name   string
		body   string
		status int
	}{
		{"JSON roto", `{"source":`, http.StatusBadRequest},
		{"campo desconocido", `{"timestamp":"2026-11-16T10:00:00Z","source":"ssh","type":"x","ip":"1.2.3.4","extra":1}`, http.StatusBadRequest},
		{"IP inválida", `{"timestamp":"2026-11-16T10:00:00Z","source":"ssh","type":"x","ip":"999.1.1.1"}`, http.StatusUnprocessableEntity},
		{"cuerpo de más de 1 MB", `{"message":"` + strings.Repeat("a", 1<<20) + `"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rec := do(h, "POST", "/events", c.body, nil); rec.Code != c.status {
				t.Fatalf("status = %d, se esperaba %d", rec.Code, c.status)
			}
		})
	}

	sub.full = true
	rec := do(h, "POST", "/events", validEvent, nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("con la cola llena: status %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestLimitValidation(t *testing.T) {
	h, _ := newTestRouter(t, Deps{})
	for _, path := range []string{"/events?limit=0", "/alerts?limit=501", "/stats/top-ips?window=-1h"} {
		if rec := do(h, "GET", path, "", nil); rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, se esperaba 400", path, rec.Code)
		}
	}
}
