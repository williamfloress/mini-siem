// Package config lee la configuración desde variables de entorno (12-factor).
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port        int
	DatabaseURL string // vacío = modo memoria

	BruteForceThreshold int
	BruteForceWindow    time.Duration
	BruteForceCooldown  time.Duration

	CompromiseThreshold int
	CompromiseWindow    time.Duration

	ScanThreshold int
	ScanWindow    time.Duration
	ScanCooldown  time.Duration

	// Vacíos = sin notificaciones externas (las alertas igual se guardan y se ven en el panel).
	TelegramToken  string
	TelegramChatID string

	// Clave que deben enviar los clientes de POST /events. Vacía = ingesta abierta (solo para desarrollo).
	IngestAPIKey string

	// Rate limit por IP: RateLimitRPS peticiones por segundo con ráfagas de RateLimitBurst.
	// RateLimitRPS = 0 lo desactiva.
	RateLimitRPS   float64
	RateLimitBurst int
	// TrustProxy toma la IP del cliente de X-Forwarded-For. Solo detrás de un proxy propio.
	TrustProxy bool
}

func (c Config) RateLimitEnabled() bool {
	return c.RateLimitRPS > 0
}

// minAPIKeyLen evita claves triviales: con 32 caracteres aleatorios no se puede adivinar.
const minAPIKeyLen = 32

func (c Config) TelegramEnabled() bool {
	return c.TelegramToken != ""
}

// Load lee la configuración de getenv (os.Getenv en producción, un mapa en los tests).
// Junta todos los errores en vez de cortar en el primero, para arreglarlos de una vez.
func Load(getenv func(string) string) (Config, error) {
	var errs []error

	cfg := Config{
		DatabaseURL:         getenv("DATABASE_URL"),
		Port:                intVar(getenv, "PORT", 8080, &errs),
		BruteForceThreshold: intVar(getenv, "BRUTEFORCE_THRESHOLD", 5, &errs),
		BruteForceWindow:    durationVar(getenv, "BRUTEFORCE_WINDOW", time.Minute, &errs),
		BruteForceCooldown:  durationVar(getenv, "BRUTEFORCE_COOLDOWN", 5*time.Minute, &errs),
		CompromiseThreshold: intVar(getenv, "COMPROMISE_THRESHOLD", 5, &errs),
		CompromiseWindow:    durationVar(getenv, "COMPROMISE_WINDOW", 10*time.Minute, &errs),
		ScanThreshold:       intVar(getenv, "SCAN_THRESHOLD", 20, &errs),
		ScanWindow:          durationVar(getenv, "SCAN_WINDOW", time.Minute, &errs),
		ScanCooldown:        durationVar(getenv, "SCAN_COOLDOWN", 10*time.Minute, &errs),
		TelegramToken:       getenv("TELEGRAM_BOT_TOKEN"),
		TelegramChatID:      getenv("TELEGRAM_CHAT_ID"),
		IngestAPIKey:        getenv("INGEST_API_KEY"),
		RateLimitRPS:        floatVar(getenv, "RATE_LIMIT_RPS", 20, &errs),
		RateLimitBurst:      intVar(getenv, "RATE_LIMIT_BURST", 50, &errs),
		TrustProxy:          boolVar(getenv, "TRUST_PROXY", false, &errs),
	}

	if cfg.Port < 1 || cfg.Port > 65535 {
		errs = append(errs, fmt.Errorf("PORT debe estar entre 1 y 65535 (es %d)", cfg.Port))
	}
	checkRule(&errs, "BRUTEFORCE", cfg.BruteForceThreshold, cfg.BruteForceWindow, cfg.BruteForceCooldown)
	checkRule(&errs, "COMPROMISE", cfg.CompromiseThreshold, cfg.CompromiseWindow, 0)
	checkRule(&errs, "SCAN", cfg.ScanThreshold, cfg.ScanWindow, cfg.ScanCooldown)

	if (cfg.TelegramToken == "") != (cfg.TelegramChatID == "") {
		errs = append(errs, errors.New("TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID van juntos: define las dos o ninguna"))
	}

	if cfg.IngestAPIKey != "" && len(cfg.IngestAPIKey) < minAPIKeyLen {
		errs = append(errs, fmt.Errorf("INGEST_API_KEY debe tener al menos %d caracteres (tiene %d)", minAPIKeyLen, len(cfg.IngestAPIKey)))
	}

	if cfg.RateLimitRPS < 0 {
		errs = append(errs, fmt.Errorf("RATE_LIMIT_RPS no puede ser negativo (es %g)", cfg.RateLimitRPS))
	}
	if cfg.RateLimitEnabled() && cfg.RateLimitBurst < 1 {
		errs = append(errs, fmt.Errorf("RATE_LIMIT_BURST debe ser al menos 1 (es %d)", cfg.RateLimitBurst))
	}

	return cfg, errors.Join(errs...)
}

// FromEnv es el atajo para producción.
func FromEnv() (Config, error) {
	return Load(os.Getenv)
}

func checkRule(errs *[]error, prefix string, threshold int, window, cooldown time.Duration) {
	if threshold < 1 {
		*errs = append(*errs, fmt.Errorf("%s_THRESHOLD debe ser al menos 1 (es %d)", prefix, threshold))
	}
	if window <= 0 {
		*errs = append(*errs, fmt.Errorf("%s_WINDOW debe ser positiva (es %s)", prefix, window))
	}
	if cooldown < 0 {
		*errs = append(*errs, fmt.Errorf("%s_COOLDOWN no puede ser negativo (es %s)", prefix, cooldown))
	}
}

func (c Config) Addr() string {
	return fmt.Sprintf(":%d", c.Port)
}

func intVar(getenv func(string) string, key string, def int, errs *[]error) int {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s debe ser un entero (es %q)", key, v))
		return def
	}
	return n
}

func durationVar(getenv func(string) string, key string, def time.Duration, errs *[]error) time.Duration {
	v := getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s debe ser una duración como 30s, 1m o 2h (es %q)", key, v))
		return def
	}
	return d
}

func floatVar(getenv func(string) string, key string, def float64, errs *[]error) float64 {
	v := getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s debe ser un número (es %q)", key, v))
		return def
	}
	return f
}

func boolVar(getenv func(string) string, key string, def bool, errs *[]error) bool {
	v := getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s debe ser true o false (es %q)", key, v))
		return def
	}
	return b
}
