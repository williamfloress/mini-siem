package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

// RejectedError es una respuesta 4xx (salvo 429): el SIEM no acepta el evento y
// reenviarlo no cambiaría nada.
type RejectedError struct {
	Status int
	Body   string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("el SIEM rechazó el evento (%d): %s", e.Status, e.Body)
}

// Client envía eventos a POST /events del SIEM.
type Client struct {
	url        string
	apiKey     string
	http       *http.Client
	logger     *slog.Logger
	backoff    time.Duration // primera espera entre reintentos; se duplica en cada uno
	maxBackoff time.Duration
}

func NewClient(baseURL, apiKey string, logger *slog.Logger) *Client {
	return &Client{
		url:        strings.TrimSuffix(baseURL, "/") + "/events",
		apiKey:     apiKey,
		http:       &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
		backoff:    time.Second,
		maxBackoff: 30 * time.Second,
	}
}

// Payload es lo que se envía a POST /events: solo los campos que escribe el cliente,
// porque id y received_at los asigna el SIEM.
type Payload struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Type      string    `json:"type"`
	IP        string    `json:"ip"`
	User      string    `json:"user,omitempty"`
	Message   string    `json:"message,omitempty"`
}

func NewPayload(ev event.Event) Payload {
	return Payload{
		Timestamp: ev.Timestamp, Source: ev.Source, Type: ev.Type,
		IP: ev.IP, User: ev.User, Message: ev.Message,
	}
}

// Send entrega el evento y reintenta sin límite mientras el fallo sea pasajero (red,
// 5xx, 429, 503), con espera exponencial hasta maxBackoff. Solo vuelve sin entregarlo
// si el SIEM lo rechaza (*RejectedError) o si se cancela ctx.
//
// Reintentar para siempre es a propósito: mientras tanto el agente no lee más líneas, y
// las que faltan siguen en el log. Un SIEM caído retrasa los eventos, no los pierde.
func (c *Client) Send(ctx context.Context, ev event.Event) error {
	body, err := json.Marshal(NewPayload(ev))
	if err != nil {
		return err
	}

	wait := c.backoff
	for attempt := 1; ; attempt++ {
		retryAfter, err := c.post(ctx, body)
		if err == nil {
			return nil
		}
		if rej := (*RejectedError)(nil); errors.As(err, &rej) || ctx.Err() != nil {
			return err
		}

		delay := max(wait, retryAfter)
		c.logger.Warn("no se pudo enviar el evento, se reintentará",
			"attempt", attempt, "retry_in", delay.String(), "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		wait = min(wait*2, c.maxBackoff)
	}
}

// post hace un intento. Si el SIEM pide esperar (Retry-After), devuelve cuánto.
func (c *Client) post(ctx context.Context, body []byte) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	// G704 (SSRF): la URL es la del SIEM que configura el administrador del agente.
	resp, err := c.http.Do(req) //nolint:gosec
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	switch {
	case resp.StatusCode == http.StatusAccepted:
		return 0, nil
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return retryAfter(resp.Header.Get("Retry-After"), c.maxBackoff),
			fmt.Errorf("el SIEM respondió %d", resp.StatusCode)
	default:
		return 0, &RejectedError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
}

// retryAfter interpreta Retry-After en segundos (el formato que usa el SIEM), acotado
// para que un valor enorme no deje al agente parado.
func retryAfter(h string, limit time.Duration) time.Duration {
	secs, err := strconv.Atoi(h)
	if err != nil || secs <= 0 {
		return 0
	}
	return min(time.Duration(secs)*time.Second, limit)
}
