// Package db abre el pool de conexiones a PostgreSQL y aplica las migraciones.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Las migraciones viajan dentro del binario: no hace falta copiar archivos al desplegar.
// También se pueden correr a mano: goose -dir internal/db/migrations postgres "$DATABASE_URL" up
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// Connect crea el pool y verifica que la base responda.
// El tamaño del pool se ajusta desde la URL, por ejemplo ?pool_max_conns=10.
func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL inválida: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("crear pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("conectar a postgres: %w", err)
	}
	return pool, nil
}

// Migrate aplica las migraciones pendientes. Es idempotente: si no hay nada nuevo, no hace nada.
func Migrate(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	fsys, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}

	// goose trabaja con database/sql; este *sql.DB reutiliza el pool de pgx.
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys)
	if err != nil {
		return fmt.Errorf("preparar migraciones: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("aplicar migraciones: %w", err)
	}
	for _, r := range results {
		logger.Info("migración aplicada", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration.String())
	}
	return nil
}
