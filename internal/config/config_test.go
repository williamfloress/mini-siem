package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Port != 8080 || cfg.DatabaseURL != "" ||
		cfg.BruteForceThreshold != 5 || cfg.BruteForceWindow != time.Minute || cfg.BruteForceCooldown != 5*time.Minute {
		t.Fatalf("valores por defecto incorrectos: %+v", cfg)
	}
	if cfg.Addr() != ":8080" {
		t.Fatalf("Addr = %q", cfg.Addr())
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"PORT":                 "9000",
		"DATABASE_URL":         "postgres://x",
		"BRUTEFORCE_THRESHOLD": "3",
		"BRUTEFORCE_WINDOW":    "30s",
		"BRUTEFORCE_COOLDOWN":  "0s",
	}))
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cfg.Port != 9000 || cfg.DatabaseURL != "postgres://x" ||
		cfg.BruteForceThreshold != 3 || cfg.BruteForceWindow != 30*time.Second || cfg.BruteForceCooldown != 0 {
		t.Fatalf("valores incorrectos: %+v", cfg)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{
		"PORT":                 "abc",
		"BRUTEFORCE_THRESHOLD": "0",
		"BRUTEFORCE_WINDOW":    "un minuto",
		"BRUTEFORCE_COOLDOWN":  "-1m",
	}))
	if err == nil {
		t.Fatal("se esperaba error")
	}
	for _, key := range []string{"PORT", "BRUTEFORCE_THRESHOLD", "BRUTEFORCE_WINDOW", "BRUTEFORCE_COOLDOWN"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("el error no menciona %s: %v", key, err)
		}
	}
}
