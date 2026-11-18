// Command agent lee /var/log/auth.log en tiempo real y envía al SIEM los intentos de
// login por SSH.
//
//	SIEM_URL=https://siem.example.com INGEST_API_KEY=... mini-siem-agent
//	mini-siem-agent -dry-run -from-start -once -log ./auth.log   # probar el parser con un log
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/williamfloress/mini-siem/internal/agent"
	"github.com/williamfloress/mini-siem/internal/event"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("el agente terminó con error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	logPath := flag.String("log", envOr("AUTH_LOG", "/var/log/auth.log"), "log de autenticación a seguir (env AUTH_LOG)")
	fromStart := flag.Bool("from-start", false, "leer el log desde el principio, no solo las líneas nuevas")
	once := flag.Bool("once", false, "terminar al llegar al final del log en vez de seguir esperando líneas")
	dryRun := flag.Bool("dry-run", false, "imprimir los eventos en JSON en vez de enviarlos")
	flag.Parse()

	siemURL := os.Getenv("SIEM_URL")
	var client *agent.Client
	if !*dryRun {
		if err := checkURL(siemURL, logger); err != nil {
			return err
		}
		apiKey := os.Getenv("INGEST_API_KEY")
		if apiKey == "" {
			logger.Warn("INGEST_API_KEY vacía: solo funciona si el SIEM tiene la ingesta abierta")
		}
		client = agent.NewClient(siemURL, apiKey, logger)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	parser := agent.NewSSHParser(time.Local)
	tailer := &agent.Tailer{
		Path:      *logPath,
		FromStart: *fromStart,
		Follow:    !*once,
		Poll:      500 * time.Millisecond,
		Logger:    logger,
	}
	// Los logs van a stderr: en -dry-run, stdout queda solo con los eventos.
	out := json.NewEncoder(os.Stdout)

	var sent, rejected int
	logger.Info("agente iniciado", "log", *logPath, "siem", siemURL, "dry_run", *dryRun)
	err := tailer.Run(ctx, func(line string) error {
		ev, ok := parser.Parse(line)
		if !ok {
			return nil
		}
		if *dryRun {
			return out.Encode(agent.NewPayload(ev))
		}
		return send(ctx, client, ev, logger, &sent, &rejected)
	})
	logger.Info("agente detenido", "sent", sent, "rejected", rejected)
	return err
}

func send(ctx context.Context, c *agent.Client, ev event.Event, logger *slog.Logger, sent, rejected *int) error {
	err := c.Send(ctx, ev)
	var rej *agent.RejectedError
	switch {
	case err == nil:
		*sent++
		logger.Debug("evento enviado", "type", ev.Type, "ip", ev.IP)
		return nil
	case errors.As(err, &rej):
		// Un evento que el SIEM no acepta no debe frenar a los demás.
		*rejected++
		logger.Error("evento descartado", "type", ev.Type, "ip", ev.IP, "status", rej.Status, "error", rej.Body)
		return nil
	default:
		return err
	}
}

// checkURL exige una URL absoluta y avisa si la API key viajaría sin cifrar.
func checkURL(raw string, logger *slog.Logger) error {
	if raw == "" {
		return errors.New("falta SIEM_URL (por ejemplo https://siem.example.com); con -dry-run no hace falta")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("SIEM_URL inválida: %q", raw)
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		logger.Warn("SIEM_URL usa http: la API key viaja sin cifrar", "url", raw)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
