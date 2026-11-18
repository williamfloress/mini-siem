package agent

import (
	"testing"
	"time"
)

func newTestParser() *SSHParser {
	p := NewSSHParser(time.UTC)
	p.now = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	return p
}

func TestParse_Lines(t *testing.T) {
	tests := []struct {
		name, line         string
		wantType, user, ip string
		wantTime           time.Time
	}{
		{
			name:     "contraseña fallida",
			line:     "Nov 17 10:00:01 vps sshd[1234]: Failed password for root from 203.0.113.7 port 51234 ssh2",
			wantType: "login_failed", user: "root", ip: "203.0.113.7",
			wantTime: time.Date(2026, 11, 17, 10, 0, 1, 0, time.UTC),
		},
		{
			name:     "usuario inexistente",
			line:     "Nov  7 09:05:00 vps sshd[99]: Failed password for invalid user admin from 198.51.100.4 port 40000 ssh2",
			wantType: "login_failed", user: "admin", ip: "198.51.100.4",
			wantTime: time.Date(2026, 11, 7, 9, 5, 0, 0, time.UTC),
		},
		{
			name:     "PAM keyboard-interactive",
			line:     "Nov 17 10:00:01 vps sshd[7]: Failed keyboard-interactive/pam for oracle from 192.0.2.1 port 22 ssh2",
			wantType: "login_failed", user: "oracle", ip: "192.0.2.1",
			wantTime: time.Date(2026, 11, 17, 10, 0, 1, 0, time.UTC),
		},
		{
			name:     "login correcto, fecha RFC 3339 y sshd-session",
			line:     "2026-11-17T10:00:02.123456-03:00 vps sshd-session[4321]: Accepted publickey for william from 2001:db8::1 port 50000 ssh2: ED25519 SHA256:abc",
			wantType: "login_success", user: "william", ip: "2001:db8::1",
			wantTime: time.Date(2026, 11, 17, 13, 0, 2, 123456000, time.UTC),
		},
		{
			name:     "cierre antes de autenticarse (servidor solo con claves)",
			line:     "Nov 17 10:00:03 vps sshd[555]: Connection closed by invalid user test 203.0.113.9 port 6000 [preauth]",
			wantType: "login_failed", user: "test", ip: "203.0.113.9",
			wantTime: time.Date(2026, 11, 17, 10, 0, 3, 0, time.UTC),
		},
		{
			name:     "desconexión de un usuario existente",
			line:     "Nov 17 10:00:04 vps sshd[556]: Disconnected from authenticating user root 203.0.113.9 port 6001 [preauth]",
			wantType: "login_failed", user: "root", ip: "203.0.113.9",
			wantTime: time.Date(2026, 11, 17, 10, 0, 4, 0, time.UTC),
		},
		{
			name:     "IPv4 mapeada en IPv6",
			line:     "Nov 17 10:00:05 vps sshd[557]: Failed password for root from ::ffff:203.0.113.7 port 1 ssh2",
			wantType: "login_failed", user: "root", ip: "203.0.113.7",
			wantTime: time.Date(2026, 11, 17, 10, 0, 5, 0, time.UTC),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := newTestParser().Parse(tt.line)
			if !ok {
				t.Fatal("la línea no se reconoció")
			}
			if ev.Type != tt.wantType || ev.User != tt.user || ev.IP != tt.ip || ev.Source != "ssh" {
				t.Errorf("evento = %+v", ev)
			}
			if !ev.Timestamp.Equal(tt.wantTime) {
				t.Errorf("timestamp = %s, quiero %s", ev.Timestamp, tt.wantTime)
			}
			if ev.Message != tt.line {
				t.Errorf("message = %q", ev.Message)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("el evento no pasaría la validación del servidor: %v", err)
			}
		})
	}
}

func TestParse_IgnoresOtherLines(t *testing.T) {
	lines := []string{
		"",
		"Nov 17 10:00:01 vps CRON[1]: pam_unix(cron:session): session opened for user root",
		"Nov 17 10:00:01 vps sshd[1]: Server listening on 0.0.0.0 port 22.",
		"Nov 17 10:00:01 vps sshd[1]: Invalid user admin from 203.0.113.7 port 1",
		"Nov 17 10:00:01 vps sshd[1]: Connection closed by 203.0.113.7 port 1 [preauth]",
		"Nov 17 10:00:01 vps sshd[1]: Failed publickey for root from 203.0.113.7 port 1 ssh2",
		"Nov 17 10:00:01 vps sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.7",
		"Nov 17 10:00:01 vps sshd[1]: Failed password for root from host.example.com port 1 ssh2", // UseDNS
		"Nov 17 10:00:01 vps sudo[1]: Failed password for root from 203.0.113.7 port 1 ssh2",      // no es sshd
	}
	p := newTestParser()
	for _, l := range lines {
		if ev, ok := p.Parse(l); ok {
			t.Errorf("no debería generar evento: %q -> %+v", l, ev)
		}
	}
}

// Con contraseñas activadas, una conexión produce "Failed password" y después el cierre:
// el cierre no debe volver a contar el intento.
func TestParse_CountsEachAttemptOnce(t *testing.T) {
	p := newTestParser()
	session := []string{
		"Nov 17 10:00:01 vps sshd[42]: Invalid user admin from 203.0.113.7 port 1",
		"Nov 17 10:00:02 vps sshd[42]: Failed password for invalid user admin from 203.0.113.7 port 1 ssh2",
		"Nov 17 10:00:03 vps sshd[42]: Failed password for invalid user admin from 203.0.113.7 port 1 ssh2",
		"Nov 17 10:00:04 vps sshd[42]: Connection closed by invalid user admin 203.0.113.7 port 1 [preauth]",
		// Otra conexión (otro PID) que se cierra sin contraseña sí cuenta.
		"Nov 17 10:00:05 vps sshd[43]: Connection closed by invalid user admin 203.0.113.7 port 2 [preauth]",
		// El PID 42 se reutiliza más tarde: empieza de cero.
		"Nov 17 10:00:06 vps sshd[42]: Disconnected from invalid user admin 203.0.113.7 port 3 [preauth]",
	}
	var got int
	for _, l := range session {
		if _, ok := p.Parse(l); ok {
			got++
		}
	}
	if got != 4 {
		t.Errorf("eventos = %d, quiero 4 (2 contraseñas + 2 conexiones sin contraseña)", got)
	}
	if len(p.failures) != 0 {
		t.Errorf("quedaron conexiones abiertas en el mapa: %v", p.failures)
	}
}

func TestParse_YearRollover(t *testing.T) {
	p := NewSSHParser(time.UTC)
	p.now = func() time.Time { return time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC) }
	ev, ok := p.Parse("Dec 31 23:59:58 vps sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2")
	if !ok {
		t.Fatal("la línea no se reconoció")
	}
	if want := time.Date(2026, 12, 31, 23, 59, 58, 0, time.UTC); !ev.Timestamp.Equal(want) {
		t.Errorf("timestamp = %s, quiero %s", ev.Timestamp, want)
	}
}

func TestParse_LocalTimezone(t *testing.T) {
	loc := time.FixedZone("UTC-3", -3*60*60)
	p := NewSSHParser(loc)
	p.now = func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }
	ev, _ := p.Parse("Nov 17 07:00:00 vps sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2")
	if want := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC); !ev.Timestamp.Equal(want) {
		t.Errorf("timestamp = %s, quiero %s (hora local del servidor pasada a UTC)", ev.Timestamp, want)
	}
}

func TestParse_BoundedSessions(t *testing.T) {
	p := newTestParser()
	for i := range maxTrackedSessions + 10 {
		p.trackFailure(time.Duration(i).String())
	}
	if len(p.failures) > maxTrackedSessions {
		t.Errorf("el mapa creció a %d entradas", len(p.failures))
	}
}
