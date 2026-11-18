package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

var sampleEvent = event.Event{
	ID:        99, // no debe enviarse
	Timestamp: time.Date(2026, 11, 17, 10, 0, 1, 0, time.UTC),
	Source:    "ssh", Type: "login_failed", IP: "203.0.113.7", User: "root",
	Message: "Failed password for root",
}

func fastClient(url string) *Client {
	c := NewClient(url, "clave-de-prueba", quiet)
	c.backoff = time.Millisecond
	c.maxBackoff = 5 * time.Millisecond
	return c
}

func TestClient_SendsEvent(t *testing.T) {
	var got map[string]any
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if err := fastClient(srv.URL+"/").Send(context.Background(), sampleEvent); err != nil {
		t.Fatal(err)
	}
	if path != "/events" || auth != "Bearer clave-de-prueba" {
		t.Errorf("path = %q, auth = %q", path, auth)
	}
	if got["ip"] != "203.0.113.7" || got["type"] != "login_failed" || got["timestamp"] != "2026-11-17T10:00:01Z" {
		t.Errorf("cuerpo = %v", got)
	}
	for _, field := range []string{"id", "received_at"} {
		if _, ok := got[field]; ok {
			t.Errorf("el agente no debe enviar %q: lo asigna el SIEM", field)
		}
	}
}

func TestClient_RetriesTransientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable) // cola llena
		case 2:
			w.WriteHeader(http.StatusTooManyRequests)
		case 3:
			w.WriteHeader(http.StatusBadGateway) // Caddy sin backend durante un despliegue
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	if err := fastClient(srv.URL).Send(context.Background(), sampleEvent); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Errorf("intentos = %d, quiero 4", calls.Load())
	}
}

func TestClient_DoesNotRetryRejections(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusUnprocessableEntity} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"no"}`))
		}))

		err := fastClient(srv.URL).Send(context.Background(), sampleEvent)
		var rej *RejectedError
		if !errors.As(err, &rej) || rej.Status != status {
			t.Errorf("%d: error = %v, quiero *RejectedError", status, err)
		}
		if calls.Load() != 1 {
			t.Errorf("%d: intentos = %d, quiero 1", status, calls.Load())
		}
		srv.Close()
	}
}

func TestClient_StopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := fastClient(srv.URL).Send(ctx, sampleEvent); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, quiero context.DeadlineExceeded", err)
	}
}

func TestRetryAfter(t *testing.T) {
	tests := map[string]time.Duration{"": 0, "x": 0, "-1": 0, "2": 2 * time.Second, "9999": 30 * time.Second}
	for h, want := range tests {
		if got := retryAfter(h, 30*time.Second); got != want {
			t.Errorf("retryAfter(%q) = %s, quiero %s", h, got, want)
		}
	}
}
