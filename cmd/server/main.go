package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/williamfloress/mini-siem/internal/api"
	"github.com/williamfloress/mini-siem/internal/config"
	"github.com/williamfloress/mini-siem/internal/db"
	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/notify"
	"github.com/williamfloress/mini-siem/internal/pipeline"
	"github.com/williamfloress/mini-siem/internal/store"
)

// Interfaces que cumplen tanto los stores en memoria como los de Postgres.
type eventStore interface {
	pipeline.Store
	api.EventReader
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
	// .env es opcional y solo rellena variables que no estén definidas:
	// en Docker o en el servidor mandan las variables del entorno.
	if err := godotenv.Load(); err == nil {
		logger.Info("variables cargadas desde .env")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("leer .env: %w", err)
	}

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

	detectors := []pipeline.Detector{
		detector.NewBruteForce(cfg.BruteForceThreshold, cfg.BruteForceWindow, cfg.BruteForceCooldown),
		detector.NewCompromise(cfg.CompromiseThreshold, cfg.CompromiseWindow),
		detector.NewNotFoundScan(cfg.ScanThreshold, cfg.ScanWindow, cfg.ScanCooldown),
	}
	logger.Info("reglas configuradas",
		"brute_force", fmt.Sprintf("%d en %s, enfriamiento %s", cfg.BruteForceThreshold, cfg.BruteForceWindow, cfg.BruteForceCooldown),
		"possible_compromise", fmt.Sprintf("éxito tras %d fallos en %s", cfg.CompromiseThreshold, cfg.CompromiseWindow),
		"http_404_scan", fmt.Sprintf("%d en %s, enfriamiento %s", cfg.ScanThreshold, cfg.ScanWindow, cfg.ScanCooldown))

	// Se declara como interfaz y solo se asigna si hay Telegram: un *Dispatcher nil
	// guardado en la interfaz no sería == nil y el pipeline lo llamaría igual.
	var notifier pipeline.Notifier
	if cfg.TelegramEnabled() {
		dispatcher := notify.NewDispatcher(notify.NewTelegram(cfg.TelegramToken, cfg.TelegramChatID), logger, 100)
		dispatcher.Start()
		// Los defer corren en orden inverso: este se ejecuta después de pipe.Stop(),
		// cuando ya no se pueden generar alertas nuevas.
		defer dispatcher.Stop(10 * time.Second)
		notifier = dispatcher
		logger.Info("notificaciones por Telegram activadas")
	} else {
		logger.Info("sin TELEGRAM_BOT_TOKEN: las alertas no se notifican fuera del panel")
	}

	pipe := pipeline.New(events, detectors, alerts, notifier, logger, 1000)
	pipe.Start(4)
	defer pipe.Stop()

	router := api.NewRouter(events, alerts, pipe, logger)
	srv := &http.Server{Addr: cfg.Addr(), Handler: router}
	logger.Info("panel disponible", "url", fmt.Sprintf("http://localhost:%d/", cfg.Port))

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
	// Los defer corren en orden inverso: pipe.Stop() (vacía la cola), dispatcher.Stop()
	// (envía las alertas pendientes) y por último pool.Close().
	return nil
}
