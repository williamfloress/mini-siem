package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Tailer sigue un archivo de log como "tail -F": entrega cada línea nueva y sobrevive
// a la rotación de logrotate, tanto si renombra el archivo y crea otro (lo normal con
// rsyslog) como si lo vacía en el sitio (copytruncate).
//
// Usa sondeo en lugar de inotify: un log de autenticación crece unas pocas líneas por
// segundo, así que mirar cada medio segundo es suficiente, funciona en cualquier sistema
// y no necesita dependencias.
type Tailer struct {
	Path      string
	FromStart bool          // leer el archivo desde el principio en lugar de solo lo nuevo
	Follow    bool          // false = terminar al llegar al final (para procesar un log viejo)
	Poll      time.Duration // cada cuánto mirar si hay líneas nuevas
	Logger    *slog.Logger
}

// Run llama a fn con cada línea completa, sin el salto de línea. Termina cuando se
// cancela ctx, cuando fn devuelve un error o, sin Follow, al llegar al final.
//
// Mientras fn no vuelve, no se lee más: si el SIEM está caído, el agente espera en
// lugar de acumular eventos en memoria. Como el archivo abierto se conserva aunque
// logrotate lo renombre, las líneas pendientes no se pierden.
func (t *Tailer) Run(ctx context.Context, fn func(line string) error) error {
	f, waited, err := t.open(ctx)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()

	// Si hubo que esperar a que el archivo existiera, todo lo que tiene es nuevo.
	if !t.FromStart && !waited {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return fmt.Errorf("ir al final de %s: %w", t.Path, err)
		}
	}

	r := bufio.NewReader(f)
	var partial string // línea a medio escribir: todavía no llegó su salto de línea
	for {
		chunk, err := r.ReadString('\n')
		if err == nil {
			if err := fn(trimEOL(partial + chunk)); err != nil {
				return err
			}
			partial = ""
			continue
		}
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("leer %s: %w", t.Path, err)
		}
		partial += chunk

		if !t.Follow {
			if partial != "" {
				return fn(trimEOL(partial))
			}
			return nil
		}

		switch t.check(f) {
		case truncated:
			t.Logger.Info("el log se vació, se lee desde el principio", "path", t.Path)
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("volver al principio de %s: %w", t.Path, err)
			}
			r.Reset(f)
			partial = ""
			continue
		case rotated:
			// Lo que se escribió en el archivo viejo entre la última lectura y la rotación
			// todavía hay que procesarlo antes de cambiar al nuevo.
			if err := drain(r, partial, fn); err != nil {
				return err
			}
			partial = ""
			f.Close()
			if f, _, err = t.open(ctx); err != nil {
				return err
			}
			r.Reset(f)
			t.Logger.Info("el log rotó, se sigue con el archivo nuevo", "path", t.Path)
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t.Poll):
		}
	}
}

type fileState int

const (
	unchanged fileState = iota
	truncated
	rotated
)

// check compara el archivo abierto con el que hay ahora en Path.
func (t *Tailer) check(f *os.File) fileState {
	onDisk, err := os.Stat(t.Path)
	if err != nil {
		// Entre que logrotate renombra el archivo y rsyslog crea el nuevo, Path no existe.
		// Se sigue esperando con el viejo.
		return unchanged
	}
	open, err := f.Stat()
	if err != nil {
		return unchanged
	}
	if !os.SameFile(onDisk, open) {
		return rotated
	}
	// Al llegar al final del buffer, la posición del archivo es lo que ya se leyó.
	pos, err := f.Seek(0, io.SeekCurrent)
	if err == nil && onDisk.Size() < pos {
		return truncated
	}
	return unchanged
}

// open abre Path, esperando a que exista si todavía no está (por ejemplo, si rsyslog
// aún no lo creó tras la rotación o al arrancar el sistema). waited indica si tuvo
// que esperar.
func (t *Tailer) open(ctx context.Context) (f *os.File, waited bool, err error) {
	for {
		// G304: la ruta la elige quien configura el agente, no un usuario remoto.
		f, err := os.Open(t.Path) //nolint:gosec
		if err == nil {
			return f, waited, nil
		}
		if !errors.Is(err, fs.ErrNotExist) || !t.Follow {
			return nil, false, fmt.Errorf("abrir %s: %w", t.Path, err)
		}
		if !waited {
			t.Logger.Warn("el log no existe todavía, esperando", "path", t.Path)
			waited = true
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-time.After(t.Poll):
		}
	}
}

func drain(r *bufio.Reader, partial string, fn func(string) error) error {
	rest, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	text := partial + string(rest)
	for line := range strings.Lines(text) {
		if err := fn(trimEOL(line)); err != nil {
			return err
		}
	}
	return nil
}

func trimEOL(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}
