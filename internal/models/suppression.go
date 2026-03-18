package models

import (
	"time"

	"github.com/google/uuid"
)

// Suppression is a manual rule that prevents alert delivery.
// Rules are evaluated in order; the first match wins.
//
// Scope hierarchy (most specific first):
//   1. CatalogServiceID + ClientID + VulnID  — suppress for one client, one service, one CVE
//   2. CatalogServiceID + VulnID             — suppress for all clients, one service, one CVE
//   3. CatalogServiceID + MaxCVSS            — suppress all CVEs below threshold for a service
//   4. VulnID only                           — suppress a CVE globally
type Suppression struct {
	ID               uuid.UUID  `db:"id"`
	CatalogServiceID *uuid.UUID `db:"catalog_service_id"` // nil = applies to all services
	ClientID         *uuid.UUID `db:"client_id"`           // nil = applies to all clients
	VulnID           string     `db:"vuln_id"`             // empty = matches any CVE
	MaxCVSS          *float64   `db:"max_cvss"`            // suppress if cvss <= this

	Reason    string     `db:"reason"`
	CreatedBy string     `db:"created_by"`
	ExpiresAt *time.Time `db:"expires_at"` // nil = permanent
	Active    bool       `db:"active"`
	CreatedAt time.Time  `db:"created_at"`
}

// IsExpired returns true if the suppression has passed its expiry time.
func (s *Suppression) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}
