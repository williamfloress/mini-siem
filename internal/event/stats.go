package event

import "time"

// IPCount resume la actividad de una IP en un periodo (GET /stats/top-ips).
type IPCount struct {
	IP           string    `json:"ip"`
	Events       int64     `json:"events"`
	FailedLogins int64     `json:"failed_logins"`
	LastSeen     time.Time `json:"last_seen"`
}
