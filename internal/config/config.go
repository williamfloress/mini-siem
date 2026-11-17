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
}

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
