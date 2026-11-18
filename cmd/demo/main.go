// Command demo llena un mini-siem con un escenario realista: tres horas de tráfico
// normal y cinco ataques que disparan las tres reglas de detección. Sirve para ver el
// panel con datos sin tener un servidor Linux enviando eventos reales.
//
//	go run ./cmd/server          # en una terminal
//	go run ./cmd/demo            # en otra; luego abre http://localhost:8080/
//
// Las marcas de tiempo son relativas al momento en que se ejecuta, y todas las IPs son
// de los rangos reservados para documentación (RFC 5737 y RFC 3849) o privadas.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/williamfloress/mini-siem/internal/agent"
	"github.com/williamfloress/mini-siem/internal/event"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run() error {
	// Misma configuración que el servidor: si su .env tiene INGEST_API_KEY, la demo la usa.
	_ = godotenv.Load()

	baseURL := flag.String("url", envOr("SIEM_URL", "http://localhost:8080"), "URL base del SIEM (env SIEM_URL)")
	flag.Parse()
	base := strings.TrimSuffix(*baseURL, "/")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := checkHealth(ctx, base); err != nil {
		return fmt.Errorf("el SIEM no responde en %s (¿arrancaste `go run ./cmd/server`?): %w", base, err)
	}

	// Solo se registran los reintentos (429 por el rate limit, por ejemplo).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	client := agent.NewClient(base, os.Getenv("INGEST_API_KEY"), logger)

	events := scenario(time.Now().UTC().Truncate(time.Second))
	for i, ev := range events {
		// Los workers procesan en paralelo: una pausa antes de cada login exitoso asegura
		// que los fallos previos de esa IP ya pasaron por los detectores.
		if ev.Type == "login_success" {
			time.Sleep(300 * time.Millisecond)
		}
		if err := client.Send(ctx, ev); err != nil {
			if rej, ok := errors.AsType[*agent.RejectedError](err); ok && rej.Status == http.StatusUnauthorized {
				return errors.New("API key rechazada: define INGEST_API_KEY con la misma clave que el servidor")
			}
			return fmt.Errorf("evento %d de %d: %w", i+1, len(events), err)
		}
	}

	fmt.Printf("%d eventos enviados. Panel: %s/\n", len(events), base)
	return nil
}

func checkHealth(ctx context.Context, base string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/healthz respondió %d", resp.StatusCode)
	}
	return nil
}

// scenario devuelve los eventos ordenados por timestamp, terminando poco antes de now.
func scenario(now time.Time) []event.Event {
	var evs []event.Event
	at := func(ago time.Duration) time.Time { return now.Add(-ago) }
	port := 40000 // puertos de origen distintos, como en un auth.log real

	sshFail := func(t time.Time, ip, user string) {
		port += 37
		line := fmt.Sprintf("Failed password for %s from %s port %d ssh2", user, ip, port)
		if user != "root" && user != "deploy" && user != "ana" {
			line = fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2", user, ip, port)
		}
		evs = append(evs, event.Event{Timestamp: t, Source: "ssh", Type: "login_failed", IP: ip, User: user, Message: line})
	}
	sshOK := func(t time.Time, ip, user, method string) {
		port += 37
		evs = append(evs, event.Event{Timestamp: t, Source: "ssh", Type: "login_success", IP: ip, User: user,
			Message: fmt.Sprintf("Accepted %s for %s from %s port %d ssh2", method, user, ip, port)})
	}
	web := func(t time.Time, ip, path string, status int) {
		evs = append(evs, event.Event{Timestamp: t, Source: "nginx", Type: fmt.Sprintf("http_%d", status), IP: ip,
			Message: fmt.Sprintf(`"GET %s HTTP/1.1" %d`, path, status)})
	}
	app := func(t time.Time, ip, typ, user, msg string) {
		evs = append(evs, event.Event{Timestamp: t, Source: "app", Type: typ, IP: ip, User: user, Message: msg})
	}

	// --- Tráfico normal ---------------------------------------------------------------

	// Dos administradores que entran con su clave, y uno que se equivoca una vez.
	for _, ago := range []time.Duration{170 * time.Minute, 80 * time.Minute, 14 * time.Minute} {
		sshOK(at(ago), "192.168.1.10", "deploy", "publickey")
	}
	sshOK(at(130*time.Minute), "192.168.1.24", "ana", "publickey")
	sshFail(at(41*time.Minute), "192.168.1.24", "ana")
	sshOK(at(40*time.Minute), "192.168.1.24", "ana", "password")

	// Visitas a la web, incluido algún 404 suelto que no llega a ser un escaneo.
	pages := []string{"/", "/blog", "/blog/hola-mundo", "/contacto", "/static/app.css"}
	visitors := []string{"198.51.100.140", "198.51.100.61", "203.0.113.200"}
	for i := range 18 {
		web(at(time.Duration(175-i*9)*time.Minute), visitors[i%len(visitors)], pages[i%len(pages)], 200)
	}
	web(at(95*time.Minute), "198.51.100.61", "/favicon.png", 404)
	web(at(33*time.Minute), "203.0.113.200", "/blog/borrador", 404)

	// Eventos de la propia aplicación.
	app(at(150*time.Minute), "198.51.100.140", "signup", "lucia", "cuenta creada")
	app(at(66*time.Minute), "198.51.100.61", "password_reset", "marco", "enlace de recuperación enviado")
	app(at(52*time.Minute), "198.51.100.61", "login_failed", "marco", "contraseña incorrecta")
	app(at(51*time.Minute), "198.51.100.61", "login_success", "marco", "sesión iniciada")

	// --- Ataques ----------------------------------------------------------------------

	// 1. Fuerza bruta desde IPv6, hace dos horas.
	for i, u := range []string{"root", "root", "admin", "admin", "ubuntu", "pi", "root", "test"} {
		sshFail(at(125*time.Minute).Add(time.Duration(i*4)*time.Second), "2001:db8:4f2a::17", u)
	}

	// 2. Diccionario de usuarios: un solo brute_force, el resto cae en el enfriamiento.
	dict := []string{"root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "user",
		"ftp", "guest", "mysql", "support", "root", "admin", "jenkins"}
	for i, u := range dict {
		sshFail(at(58*time.Minute).Add(time.Duration(i*2)*time.Second), "203.0.113.45", u)
	}

	// 3. Escaneo de rutas sensibles en nginx.
	scan := []string{"/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/admin",
		"/config.php", "/backup.zip", "/.aws/credentials", "/server-status", "/xmlrpc.php", "/vendor/phpunit",
		"/actuator/env", "/.DS_Store", "/db.sql", "/api/.env", "/cgi-bin/luci", "/boaform/admin",
		"/HNAP1", "/solr/admin", "/owa", "/manager/html", "/.htpasswd", "/shell.php"}
	for i, p := range scan {
		web(at(27*time.Minute).Add(time.Duration(i)*time.Second), "192.0.2.77", p, 404)
	}

	// 4. La fuerza bruta funciona: brute_force y, con el login exitoso, possible_compromise.
	for i := range 7 {
		sshFail(at(9*time.Minute).Add(time.Duration(i*4)*time.Second), "198.51.100.23", "deploy")
	}
	sshOK(at(9*time.Minute).Add(40*time.Second), "198.51.100.23", "deploy", "password")

	// 5. Intentos sueltos que no cruzan el umbral: quedan en el panel, sin alerta.
	for i, u := range []string{"admin", "root", "admin"} {
		sshFail(at(3*time.Minute).Add(time.Duration(i*20)*time.Second), "203.0.113.99", u)
	}

	slices.SortStableFunc(evs, func(a, b event.Event) int { return a.Timestamp.Compare(b.Timestamp) })
	return evs
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
