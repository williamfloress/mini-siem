package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/williamfloress/mini-siem/internal/metrics"
)

func TestReadyz(t *testing.T) {
	h, _ := newTestRouter(t, Deps{})
	if rec := do(h, "GET", "/readyz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("sin comprobación (modo memoria) debería estar listo: %d", rec.Code)
	}

	var dbErr error
	h, _ = newTestRouter(t, Deps{Ready: func(context.Context) error { return dbErr }})
	if rec := do(h, "GET", "/readyz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("con la base respondiendo: %d", rec.Code)
	}

	dbErr = errors.New("dial tcp 10.0.0.5:5432: connection refused")
	rec := do(h, "GET", "/readyz", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("con la base caída: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Error("la respuesta no debe revelar el detalle del error")
	}
	if rec := do(h, "GET", "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("/healthz no depende de la base: %d", rec.Code)
	}
}

func TestMetrics(t *testing.T) {
	m := metrics.New()
	m.RegisterQueue(func() int { return 3 }, 1000)
	m.AlertRaised("brute_force")
	l, _ := newTestLimiter(1, 1, false)
	h, _ := newTestRouter(t, Deps{Metrics: m, RateLimiter: l})

	do(h, "POST", "/events", validEvent, nil) // 202
	do(h, "POST", "/events", validEvent, nil) // 429: el límite es 1

	body := do(h, "GET", "/metrics", "", nil).Body.String()
	for _, want := range []string{
		"siem_events_received_total 1",
		`siem_alerts_total{rule="brute_force"} 1`,
		"siem_queue_length 3",
		"siem_queue_capacity 1000",
		`siem_http_requests_total{code="202",route="POST /events"} 1`,
		`siem_http_requests_total{code="429",route="other"} 1`,
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics no contiene %q", want)
		}
	}
}

func TestMetricsCountsRejections(t *testing.T) {
	m := metrics.New()
	h, sub := newTestRouter(t, Deps{Metrics: m})
	do(h, "POST", "/events", `{roto`, nil)
	sub.full = true
	do(h, "POST", "/events", validEvent, nil)

	body := do(h, "GET", "/metrics", "", nil).Body.String()
	for _, want := range []string{
		`siem_events_rejected_total{reason="invalid"} 1`,
		`siem_events_rejected_total{reason="queue_full"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics no contiene %q", want)
		}
	}
}
