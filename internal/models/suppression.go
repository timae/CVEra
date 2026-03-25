package models

import (
	"time"

	"github.com/google/uuid"
)

// Suppression is a manual rule that prevents alert delivery.
// Rules are evaluated in order; the first match wins.
//
// Scope hierarchy (most specific first):
//  1. CatalogServiceID + VulnID — suppress one CVE for one service
//  2. VulnID only              — suppress one CVE globally
//  3. CatalogServiceID only    — suppress all CVEs for one service
type Suppression struct {
	ID               uuid.UUID  `db:"id"`
	CatalogServiceID *uuid.UUID `db:"catalog_service_id"` // nil = applies to all services
	VulnID           string     `db:"vuln_id"`            // empty = matches any CVE

	Reason    string     `db:"reason"`
	CreatedBy string     `db:"created_by"`
	ExpiresAt *time.Time `db:"expires_at"` // nil = permanent
	CreatedAt time.Time  `db:"created_at"`
}

// IsExpired returns true if the suppression has passed its expiry time.
func (s *Suppression) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}
