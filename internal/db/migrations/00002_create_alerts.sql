-- +goose Up
CREATE TABLE alerts (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule         TEXT        NOT NULL,
    ip           INET        NOT NULL,
    event_count  INTEGER     NOT NULL CHECK (event_count > 0),
    triggered_at TIMESTAMPTZ NOT NULL,
    message      TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- GET /alerts: las alertas más recientes.
CREATE INDEX alerts_triggered_at_idx ON alerts (triggered_at);

-- +goose Down
DROP TABLE alerts;
