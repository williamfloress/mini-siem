package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/event"
)

// PostgresEventStore persiste eventos en la tabla events.
type PostgresEventStore struct {
	pool *pgxpool.Pool
}

func NewPostgresEventStore(pool *pgxpool.Pool) *PostgresEventStore {
	return &PostgresEventStore{pool: pool}
}

// Add inserta el evento y devuelve la copia con el ID y received_at que asignó la base.
// User y Message vacíos se guardan como NULL.
func (s *PostgresEventStore) Add(ctx context.Context, e event.Event) (event.Event, error) {
	const q = `
		INSERT INTO events (occurred_at, source, type, ip, username, message)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''))
		RETURNING id, received_at`

	err := s.pool.QueryRow(ctx, q, e.Timestamp, e.Source, e.Type, e.IP, e.User, e.Message).
		Scan(&e.ID, &e.ReceivedAt)
	if err != nil {
		return event.Event{}, fmt.Errorf("insertar evento: %w", err)
	}
	e.ReceivedAt = e.ReceivedAt.UTC()
	return e, nil
}

// List devuelve los últimos limit eventos por fecha de ocurrencia, del más antiguo al
// más nuevo (el mismo orden que el store en memoria). La subconsulta usa el índice
// events_occurred_at_idx para no ordenar la tabla entera.
func (s *PostgresEventStore) List(ctx context.Context, limit int) ([]event.Event, error) {
	const q = `
		SELECT id, occurred_at, source, type, host(ip), coalesce(username, ''), coalesce(message, ''), received_at
		FROM (
			SELECT * FROM events
			ORDER BY occurred_at DESC, id DESC
			LIMIT $1
		) recent
		ORDER BY occurred_at, id`

	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("listar eventos: %w", err)
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (event.Event, error) {
		var e event.Event
		err := row.Scan(&e.ID, &e.Timestamp, &e.Source, &e.Type, &e.IP, &e.User, &e.Message, &e.ReceivedAt)
		// pgx devuelve timestamptz en la zona local; la API responde en UTC.
		e.Timestamp, e.ReceivedAt = e.Timestamp.UTC(), e.ReceivedAt.UTC()
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("leer eventos: %w", err)
	}
	return events, nil
}

// PostgresAlertStore persiste alertas en la tabla alerts.
type PostgresAlertStore struct {
	pool *pgxpool.Pool
}

func NewPostgresAlertStore(pool *pgxpool.Pool) *PostgresAlertStore {
	return &PostgresAlertStore{pool: pool}
}

func (s *PostgresAlertStore) Add(ctx context.Context, a detector.Alert) (detector.Alert, error) {
	const q = `
		INSERT INTO alerts (rule, ip, event_count, triggered_at, message)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`

	if err := s.pool.QueryRow(ctx, q, a.Rule, a.IP, a.Count, a.TriggeredAt, a.Message).Scan(&a.ID); err != nil {
		return detector.Alert{}, fmt.Errorf("insertar alerta: %w", err)
	}
	return a, nil
}

func (s *PostgresAlertStore) List(ctx context.Context, limit int) ([]detector.Alert, error) {
	const q = `
		SELECT id, rule, host(ip), event_count, triggered_at, message
		FROM (
			SELECT * FROM alerts
			ORDER BY triggered_at DESC, id DESC
			LIMIT $1
		) recent
		ORDER BY triggered_at, id`

	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("listar alertas: %w", err)
	}
	alerts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (detector.Alert, error) {
		var a detector.Alert
		err := row.Scan(&a.ID, &a.Rule, &a.IP, &a.Count, &a.TriggeredAt, &a.Message)
		a.TriggeredAt = a.TriggeredAt.UTC()
		return a, err
	})
	if err != nil {
		return nil, fmt.Errorf("leer alertas: %w", err)
	}
	return alerts, nil
}
