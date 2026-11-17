package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/williamfloress/mini-siem/internal/db"
	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
)

// Tests de integración: necesitan un Postgres real y se saltan si no hay uno.
//
//	docker compose up -d
//	TEST_DATABASE_URL=postgres://siem:siem@localhost:5433/siem_test?sslmode=disable go test ./internal/store/
//
// OJO: vacían las tablas events y alerts. Usa siem_test (la crea docker/postgres/init.sql),
// nunca la base de desarrollo.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL no definida: se omite el test de integración")
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	if err := db.Migrate(ctx, pool, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE events, alerts RESTART IDENTITY"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPostgresEventStore(t *testing.T) {
	ctx := context.Background()
	s := NewPostgresEventStore(testPool(t))

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "2001:db8::1"} {
		e := event.Event{Timestamp: base.Add(time.Duration(i) * time.Second), Source: "ssh", Type: "login_failed", IP: ip}
		if i == 0 {
			e.User, e.Message = "root", "Failed password"
		}
		saved, err := s.Add(ctx, e)
		if err != nil {
			t.Fatal(err)
		}
		if saved.ID == 0 || saved.ReceivedAt.IsZero() {
			t.Fatalf("Add no devolvió ID/received_at: %+v", saved)
		}
	}

	all, err := s.List(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("se esperaban 3 eventos, hay %d", len(all))
	}
	first := all[0]
	if first.IP != "10.0.0.1" || first.User != "root" || first.Message != "Failed password" || !first.Timestamp.Equal(base) {
		t.Fatalf("primer evento incorrecto: %+v", first)
	}
	if all[2].IP != "2001:db8::1" || all[2].User != "" {
		t.Fatalf("IPv6 o campos vacíos mal leídos: %+v", all[2])
	}

	// limit devuelve los más recientes, en orden cronológico.
	last2, err := s.List(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(last2) != 2 || last2[0].IP != "10.0.0.2" || last2[1].IP != "2001:db8::1" {
		t.Fatalf("List(2) incorrecto: %+v", last2)
	}
}

func TestPostgresAlertStore(t *testing.T) {
	ctx := context.Background()
	s := NewPostgresAlertStore(testPool(t))

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	saved, err := s.Add(ctx, detector.Alert{
		Rule: "brute_force", IP: "10.0.0.1", Count: 5, TriggeredAt: now, Message: "5 logins fallidos",
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID == 0 {
		t.Fatal("Add no devolvió ID")
	}

	got, err := s.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != saved {
		t.Fatalf("List = %+v, se esperaba [%+v]", got, saved)
	}
}

func TestPostgresTopIPs(t *testing.T) {
	ctx := context.Background()
	s := NewPostgresEventStore(testPool(t))

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	add := func(ip, typ string, at time.Time) {
		t.Helper()
		if _, err := s.Add(ctx, event.Event{Timestamp: at, Source: "ssh", Type: typ, IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	add("10.0.0.1", "login_failed", base.Add(-48*time.Hour)) // fuera del periodo
	for i := range 3 {
		add("10.0.0.1", "login_failed", base.Add(time.Duration(i)*time.Minute))
	}
	add("10.0.0.2", "login_success", base)
	add("10.0.0.3", "login_failed", base)
	add("10.0.0.3", "login_success", base.Add(time.Minute))

	got, err := s.TopIPs(ctx, base.Add(-time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []event.IPCount{
		{IP: "10.0.0.1", Events: 3, FailedLogins: 3, LastSeen: base.Add(2 * time.Minute)},
		{IP: "10.0.0.3", Events: 2, FailedLogins: 1, LastSeen: base.Add(time.Minute)},
	}
	if len(got) != len(want) {
		t.Fatalf("TopIPs = %+v, quería %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("TopIPs[%d] = %+v, quería %+v", i, got[i], want[i])
		}
	}
}
