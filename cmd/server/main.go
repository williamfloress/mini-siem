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
	"github.com/williamfloress/mini-siem/internal/detector"
	"github.com/williamfloress/mini-siem/internal/pipeline"
	"github.com/williamfloress/mini-siem/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	memStore := store.NewMemoryStore()
	alertStore := store.NewAlertStore()
	det := detector.NewBruteForce(5, time.Minute, 5*time.Minute)

	pipe := pipeline.New(memStore, det, alertStore, logger, 1000)
	pipe.Start(4)

	router := api.NewRouter(memStore, alertStore, pipe, logger)
	srv := &http.Server{Addr: ":8080", Handler: router}

	go func() {
		logger.Info("servidor iniciado", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("el servidor falló", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	logger.Info("apagando")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("error al apagar el servidor", "error", err)
	}
	pipe.Stop()
	logger.Info("apagado completo")
}
