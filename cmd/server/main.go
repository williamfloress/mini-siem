package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/williamfloress/mini-siem/internal/api"
	"github.com/williamfloress/mini-siem/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	memStore := store.NewMemoryStore()
	router := api.NewRouter(memStore, logger)

	addr := ":8080"
	logger.Info("servidor iniciado", "addr", addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		logger.Error("el servidor se detuvo", "error", err)
		os.Exit(1)
	}
}
