package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

var sample = detector.Alert{
	ID: 7, Rule: "brute_force", IP: "203.0.113.7", Count: 5,
	TriggeredAt: time.Date(2026, 11, 16, 10, 0, 5, 0, time.UTC),
	Message:     "5 logins fallidos desde 203.0.113.7 en 1m0s",
}

func TestTelegram_SendsMessage(t *testing.T) {
	var got struct{ ChatID, Text, Path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		got.ChatID, got.Text, got.Path = body["chat_id"], body["text"], r.URL.Path
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tg := NewTelegram("123:ABC", "42")
	tg.baseURL = srv.URL
	if err := tg.Notify(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	if got.Path != "/bot123:ABC/sendMessage" || got.ChatID != "42" {
		t.Errorf("petición incorrecta: %+v", got)
	}
	for _, want := range []string{"Fuerza bruta", "203.0.113.7", "alerta #7"} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("el mensaje no contiene %q:\n%s", want, got.Text)
		}
	}
}

func TestTelegram_ClassifiesErrors(t *testing.T) {
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer srv.Close()

	tg := NewTelegram("secreto", "42")
	tg.baseURL = srv.URL

	var perm *PermanentError
	if err := tg.Notify(context.Background(), sample); !errors.As(err, &perm) {
		t.Errorf("401 debería ser permanente, fue %v", err)
	}
	status = http.StatusTooManyRequests
	if err := tg.Notify(context.Background(), sample); err == nil || errors.As(err, &perm) {
		t.Errorf("429 debería ser reintentable, fue %v", err)
	}
}

func TestTelegram_ErrorDoesNotLeakToken(t *testing.T) {
	tg := NewTelegram("TOKEN-SECRETO", "42")
	tg.baseURL = "http://127.0.0.1:1" // nada escucha aquí
	err := tg.Notify(context.Background(), sample)
	if err == nil {
		t.Fatal("se esperaba error de conexión")
	}
	if strings.Contains(err.Error(), "TOKEN-SECRETO") {
		t.Errorf("el error filtra el token: %v", err)
	}
}

// fakeNotifier falla las primeras failures llamadas.
type fakeNotifier struct {
	failures int32
	calls    atomic.Int32
	err      error
}

func (f *fakeNotifier) Notify(ctx context.Context, a detector.Alert) error {
	if f.calls.Add(1) <= f.failures {
		return f.err
	}
	return nil
}

func newTestDispatcher(n Notifier) *Dispatcher {
	d := NewDispatcher(n, quiet, 10)
	d.backoff = time.Millisecond
	d.Start()
	return d
}

func TestDispatcher_RetriesTransientErrors(t *testing.T) {
	f := &fakeNotifier{failures: 2, err: errors.New("timeout")}
	d := newTestDispatcher(f)
	d.Enqueue(sample)
	d.Stop(time.Second)

	if f.calls.Load() != 3 {
		t.Errorf("llamadas = %d, quería 3 (2 fallos + 1 éxito)", f.calls.Load())
	}
}

func TestDispatcher_GivesUpAfterMaxAttempts(t *testing.T) {
	f := &fakeNotifier{failures: 100, err: errors.New("caído")}
	d := newTestDispatcher(f)
	d.Enqueue(sample)
	d.Stop(time.Second)

	if f.calls.Load() != int32(d.maxAttempts) {
		t.Errorf("llamadas = %d, quería %d", f.calls.Load(), d.maxAttempts)
	}
}

func TestDispatcher_DoesNotRetryPermanentErrors(t *testing.T) {
	f := &fakeNotifier{failures: 100, err: &PermanentError{errors.New("token inválido")}}
	d := newTestDispatcher(f)
	d.Enqueue(sample)
	d.Stop(time.Second)

	if f.calls.Load() != 1 {
		t.Errorf("llamadas = %d, quería 1", f.calls.Load())
	}
}

func TestDispatcher_EnqueueNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	n := notifierFunc(func(ctx context.Context, a detector.Alert) error {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil
	})
	d := NewDispatcher(n, quiet, 2)
	d.Start()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ { // muchas más que el tamaño de la cola
			d.Enqueue(sample)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Enqueue bloqueó con la cola llena")
	}
	close(block)
	d.Stop(time.Second)
}

type notifierFunc func(context.Context, detector.Alert) error

func (f notifierFunc) Notify(ctx context.Context, a detector.Alert) error { return f(ctx, a) }
