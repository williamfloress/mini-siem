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
	}

	if cfg.Port < 1 || cfg.Port > 65535 {
		errs = append(errs, fmt.Errorf("PORT debe estar entre 1 y 65535 (es %d)", cfg.Port))
	}
	if cfg.BruteForceThreshold < 1 {
		errs = append(errs, fmt.Errorf("BRUTEFORCE_THRESHOLD debe ser al menos 1 (es %d)", cfg.BruteForceThreshold))
	}
	if cfg.BruteForceWindow <= 0 {
		errs = append(errs, fmt.Errorf("BRUTEFORCE_WINDOW debe ser positiva (es %s)", cfg.BruteForceWindow))
	}
	if cfg.BruteForceCooldown < 0 {
		errs = append(errs, fmt.Errorf("BRUTEFORCE_COOLDOWN no puede ser negativo (es %s)", cfg.BruteForceCooldown))
	}

	return cfg, errors.Join(errs...)
}

// FromEnv es el atajo para producción.
func FromEnv() (Config, error) {
	return Load(os.Getenv)
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
