package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/williamfloress/mini-siem/internal/api"
	"github.com/williamfloress/mini-siem/internal/config"
	"github.com/williamfloress/mini-siem/internal/db"
	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/pipeline"
	"github.com/williamfloress/mini-siem/internal/store"
)

// Interfaces que cumplen tanto los stores en memoria como los de Postgres.
type eventStore interface {
	pipeline.Store
	api.EventLister
}

type alertStore interface {
	pipeline.AlertSink
	api.AlertLister
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("el servidor terminó con error", "error", err)
		os.Exit(1)
	}
	logger.Info("apagado completo")
}

func run(logger *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var events eventStore
	var alerts alertStore
	if cfg.DatabaseURL == "" {
		logger.Warn("DATABASE_URL vacía: modo memoria, los datos se pierden al reiniciar")
		events = store.NewMemoryEventStore()
		alerts = store.NewMemoryAlertStore()
	} else {
		pool, err := db.Connect(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		// Se cierra al final de run, después de pipe.Stop: los workers todavía escriben
		// mientras vacían la cola.
		defer pool.Close()

		if err := db.Migrate(ctx, pool, logger); err != nil {
			return err
		}
		logger.Info("conectado a postgres")
		events = store.NewPostgresEventStore(pool)
		alerts = store.NewPostgresAlertStore(pool)
	}

	det := detector.NewBruteForce(cfg.BruteForceThreshold, cfg.BruteForceWindow, cfg.BruteForceCooldown)
	logger.Info("detector configurado", "threshold", cfg.BruteForceThreshold,
		"window", cfg.BruteForceWindow.String(), "cooldown", cfg.BruteForceCooldown.String())

	pipe := pipeline.New(events, det, alerts, logger, 1000)
	pipe.Start(4)
	defer pipe.Stop()

	router := api.NewRouter(events, alerts, pipe, logger)
	srv := &http.Server{Addr: cfg.Addr(), Handler: router}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("servidor iniciado", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("apagando")
	case err := <-serverErr:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("error al apagar el servidor", "error", err)
	}
	// Los defer corren en orden inverso: pipe.Stop() (vacía la cola) y luego pool.Close().
	return nil
}
