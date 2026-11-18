package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// collector junta las líneas que entrega el Tailer desde otra goroutine.
type collector struct {
	mu    sync.Mutex
	lines []string
}

func (c *collector) add(l string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, l)
	return nil
}

func (c *collector) waitFor(t *testing.T, want ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := slices.Clone(c.lines)
		c.mu.Unlock()
		if slices.Equal(got, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("líneas = %q, quiero %q", c.lines, want)
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// startTail arranca el Tailer en segundo plano y lo detiene al terminar el test.
func startTail(t *testing.T, tl *Tailer) *collector {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &collector{}
	done := make(chan error, 1)
	go func() { done <- tl.Run(ctx, c.add) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return c
}

func newTailer(path string) *Tailer {
	return &Tailer{Path: path, Follow: true, Poll: 5 * time.Millisecond, Logger: quiet}
}

func TestTailer_OnlyNewLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "vieja\n")

	c := startTail(t, newTailer(path))
	time.Sleep(50 * time.Millisecond) // que el Tailer llegue al final antes de escribir
	appendTo(t, path, "nueva 1\nnueva 2\n")
	c.waitFor(t, "nueva 1", "nueva 2")
}

func TestTailer_FromStartAndPartialLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "uno\r\ndo")

	tl := newTailer(path)
	tl.FromStart = true
	c := startTail(t, tl)
	c.waitFor(t, "uno")
	appendTo(t, path, "s\n") // la segunda línea se completa después
	c.waitFor(t, "uno", "dos")
}

func TestTailer_WaitsForFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	c := startTail(t, newTailer(path))
	time.Sleep(30 * time.Millisecond)
	appendTo(t, path, "hola\n")
	c.waitFor(t, "hola")
}

func TestTailer_CopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "")
	c := startTail(t, newTailer(path))
	time.Sleep(30 * time.Millisecond)

	appendTo(t, path, "antes de vaciar\n")
	c.waitFor(t, "antes de vaciar")
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	appendTo(t, path, "después\n")
	c.waitFor(t, "antes de vaciar", "después")
}

func TestTailer_RenameRotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows no deja renombrar un archivo abierto; la rotación por renombre es de Linux")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendTo(t, path, "")
	c := startTail(t, newTailer(path))
	time.Sleep(30 * time.Millisecond)

	// logrotate renombra el archivo; rsyslog sigue escribiendo en el viejo hasta que
	// recibe la señal, y después crea uno nuevo.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path+".1", "tarde en el viejo\n")
	appendTo(t, path, "primera del nuevo\n")
	c.waitFor(t, "tarde en el viejo", "primera del nuevo")
}

func TestTailer_NoFollowStopsAtEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "a\nb\nsin salto")

	c := &collector{}
	tl := &Tailer{Path: path, FromStart: true, Logger: quiet}
	if err := tl.Run(context.Background(), c.add); err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "b", "sin salto"}; !slices.Equal(c.lines, want) {
		t.Errorf("líneas = %q, quiero %q", c.lines, want)
	}
}

func TestTailer_NoFollowMissingFile(t *testing.T) {
	tl := &Tailer{Path: filepath.Join(t.TempDir(), "no-existe"), Logger: quiet}
	if err := tl.Run(context.Background(), func(string) error { return nil }); err == nil {
		t.Error("quiero un error si el archivo no existe")
	}
}
