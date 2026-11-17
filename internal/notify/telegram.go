package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/williamfloress/mini-siem/internal/detector"
)

// Telegram envía alertas con un bot a un chat, usando sendMessage de la Bot API.
type Telegram struct {
	token   string
	chatID  string
	baseURL string
	client  *http.Client
}

func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{
		token:   token,
		chatID:  chatID,
		baseURL: "https://api.telegram.org",
		client:  &http.Client{},
	}
}

func (t *Telegram) Notify(ctx context.Context, a detector.Alert) error {
	body, err := json.Marshal(map[string]string{
		"chat_id": t.chatID,
		"text":    FormatAlert(a),
	})
	if err != nil {
		return &PermanentError{err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.baseURL+"/bot"+t.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return &PermanentError{errors.New("no se pudo armar la petición a Telegram")}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		// El error de net/http incluye la URL, y la URL incluye el token del bot:
		// se descarta la URL para que el token nunca llegue a los logs.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	var apiErr struct {
		Description string `json:"description"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&apiErr)
	err = fmt.Errorf("telegram respondió %d: %s", resp.StatusCode, apiErr.Description)

	// 429 (límite de mensajes) y 5xx son pasajeros; cualquier otro 4xx (token o chat
	// incorrectos) no se arregla reintentando.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return err
	}
	return &PermanentError{err}
}

var ruleTitles = map[string]string{
	"brute_force":         "Fuerza bruta",
	"possible_compromise": "Posible cuenta comprometida",
	"http_404_scan":       "Escaneo de rutas (404)",
}

// FormatAlert arma el texto plano del mensaje. Sin parse_mode, Telegram no interpreta
// nada como Markdown/HTML, así que no hace falta escapar el contenido de la alerta.
func FormatAlert(a detector.Alert) string {
	title := ruleTitles[a.Rule]
	if title == "" {
		title = a.Rule
	}
	return fmt.Sprintf("🚨 %s\n\n%s\n\nIP: %s\nEventos: %d\nCuándo: %s UTC\nRegla: %s · alerta #%d",
		title, a.Message, a.IP, a.Count, a.TriggeredAt.UTC().Format(time.DateTime), a.Rule, a.ID)
}
