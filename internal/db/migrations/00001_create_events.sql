-- +goose Up
CREATE TABLE events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    source      TEXT        NOT NULL CHECK (source IN ('ssh', 'nginx', 'app')),
    type        TEXT        NOT NULL,
    ip          INET        NOT NULL,
    username    TEXT,
    message     TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- GET /events: los eventos más recientes.
CREATE INDEX events_occurred_at_idx ON events (occurred_at);
-- Consultas por IP en un rango de tiempo (reglas, estadísticas, reconstruir el detector).
CREATE INDEX events_ip_occurred_at_idx ON events (ip, occurred_at);

-- +goose Down
DROP TABLE events;
