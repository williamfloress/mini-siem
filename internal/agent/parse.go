// Package agent lee los logs de un servidor Linux, interpreta los eventos de SSH y
// los envía al SIEM.
package agent

import (
	"net/netip"
	"regexp"
	"time"

	"github.com/williamfloress/mini-siem/internal/event"
)

// Cabecera de syslog seguida de un mensaje de sshd. Acepta los dos formatos de fecha
// de rsyslog:
//
//	Nov 17 10:00:01 vps sshd[1234]: ...                          (RFC 3164, clásico)
//	2026-11-17T10:00:01.123456+00:00 vps sshd[1234]: ...         (RFC 3339, Debian 12+ / Ubuntu 24.04+)
//
// Desde OpenSSH 9.8 cada conexión la atiende un proceso "sshd-session" (o "sshd-auth"),
// así que el programa puede llamarse de las tres formas.
var syslogRe = regexp.MustCompile(
	`^(?:([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}T\S+)) \S+ sshd(?:-session|-auth)?\[(\d+)\]: (.*)$`)

var (
	// Un intento de contraseña fallido, para un usuario que existe o no.
	// "Failed publickey" no se cuenta: lo produce un cliente legítimo que prueba varias claves.
	failedRe = regexp.MustCompile(`^Failed (?:password|keyboard-interactive/pam) for (?:invalid user )?(.*?) from (\S+) port \d+`)
	// Un login correcto, con cualquier método.
	acceptedRe = regexp.MustCompile(`^Accepted \S+ for (.*?) from (\S+) port \d+`)
	// Una conexión que se cerró antes de autenticarse, después de elegir usuario.
	preauthCloseRe = regexp.MustCompile(`^(?:Connection closed by|Disconnected from) (?:invalid|authenticating) user (.*?) (\S+) port \d+ \[preauth\]$`)
)

// maxTrackedSessions acota el mapa de conexiones abiertas: si sshd muere sin registrar
// los cierres, las entradas huérfanas no se acumulan para siempre.
const maxTrackedSessions = 10000

// SSHParser convierte líneas de /var/log/auth.log en eventos.
//
// Cuenta un login_failed por cada contraseña rechazada. En un servidor que solo acepta
// claves (lo recomendable) no hay contraseñas que rechazar: los bots se conectan, piden
// un usuario y se van. Para no perder esos intentos, una conexión que se cierra antes
// de autenticarse sin ningún fallo previo también cuenta como un login_failed. Así cada
// intento se cuenta una sola vez, acepte o no contraseñas el servidor.
//
// Para saber qué líneas son de la misma conexión usa el PID de sshd, que es uno por
// conexión. No es seguro para uso concurrente.
type SSHParser struct {
	loc      *time.Location   // zona horaria de las fechas RFC 3164, que no la incluyen
	now      func() time.Time // para deducir el año de las fechas RFC 3164
	failures map[string]int   // PID -> contraseñas fallidas en esa conexión
}

func NewSSHParser(loc *time.Location) *SSHParser {
	return &SSHParser{loc: loc, now: time.Now, failures: make(map[string]int)}
}

// Parse devuelve el evento de la línea, o false si la línea no interesa.
func (p *SSHParser) Parse(line string) (event.Event, bool) {
	m := syslogRe.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}
	ts, ok := p.timestamp(m[1], m[2])
	if !ok {
		return event.Event{}, false
	}
	pid, msg := m[3], m[4]

	var typ, user, ip string
	switch {
	case matchInto(failedRe, msg, &user, &ip):
		typ = "login_failed"
		p.trackFailure(pid)
	case matchInto(acceptedRe, msg, &user, &ip):
		typ = "login_success"
		delete(p.failures, pid)
	case matchInto(preauthCloseRe, msg, &user, &ip):
		n := p.failures[pid]
		delete(p.failures, pid)
		if n > 0 {
			return event.Event{}, false // ya se contó cada contraseña fallida
		}
		typ = "login_failed"
	default:
		return event.Event{}, false
	}

	// Con UseDNS, sshd puede registrar un nombre de host en lugar de la IP.
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return event.Event{}, false
	}
	return event.Event{
		Timestamp: ts,
		Source:    "ssh",
		Type:      typ,
		IP:        addr.Unmap().String(),
		User:      user,
		Message:   line,
	}, true
}

func (p *SSHParser) trackFailure(pid string) {
	if _, ok := p.failures[pid]; !ok && len(p.failures) >= maxTrackedSessions {
		clear(p.failures)
	}
	p.failures[pid]++
}

func matchInto(re *regexp.Regexp, s string, user, ip *string) bool {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	*user, *ip = m[1], m[2]
	return true
}

func (p *SSHParser) timestamp(rfc3164, rfc3339 string) (time.Time, bool) {
	if rfc3339 != "" {
		t, err := time.Parse(time.RFC3339Nano, rfc3339)
		return t.UTC(), err == nil
	}
	// RFC 3164 no trae año ni zona: se usa la zona del servidor y el año actual. Si la
	// fecha queda en el futuro (leer en enero una línea de diciembre), es del año anterior.
	t, err := time.ParseInLocation(time.Stamp, rfc3164, p.loc)
	if err != nil {
		return time.Time{}, false
	}
	now := p.now().In(p.loc)
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t.UTC(), true
}
