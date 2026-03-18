package models

import (
	"time"

	"github.com/google/uuid"
)

// CatalogService represents one managed service offering.
// Version lives here — not on client records.
// When you upgrade HAProxy 2.8.3 → 2.8.5, you update this record
// and the system re-evaluates all matches automatically.
type CatalogService struct {
	ID               uuid.UUID `db:"id"`
	Slug             string    `db:"slug"`
	Name             string    `db:"name"`
	ProductName      string    `db:"product_name"`
	Vendor           string    `db:"vendor"`
	Version          string    `db:"version"`
	VersionNormalized string   `db:"version_normalized"`

	// Package coordinates — used for OSV ecosystem matching.
	// Particularly important for Go-based services (Loki, ArgoCD, Prometheus)
	// where NVD CPE coverage is thinner than OSV.
	PackageName      string `db:"package_name"`
	PackageEcosystem string `db:"package_ecosystem"`

	// CPE 2.3 URI — most precise matching anchor.
	// e.g. cpe:2.3:a:haproxy:haproxy:2.8.3:*:*:*:*:*:*:*
	CPE23 string `db:"cpe23"`

	ContainerImage string `db:"container_image"`
	PURL           string `db:"purl"`

	// Default risk context; overridable per enrollment.
	Criticality    string `db:"criticality"`    // critical, high, medium, low
	Exposure       string `db:"exposure"`       // public, internal, private
	DeploymentType string `db:"deployment_type"` // kubernetes, vm, baremetal

	OwningTeam string `db:"owning_team"`
	Contact    string `db:"contact"`
	Tags       map[string]string `db:"tags"`
	Notes      string            `db:"notes"`
	Active     bool              `db:"active"`
	CreatedAt  time.Time         `db:"created_at"`
	UpdatedAt  time.Time         `db:"updated_at"`
}

// ClientEnrollment records that a client runs a specific catalog service.
// It optionally overrides the catalog's default criticality and exposure.
type ClientEnrollment struct {
	ID               uuid.UUID  `db:"id"`
	ClientID         uuid.UUID  `db:"client_id"`
	CatalogServiceID uuid.UUID  `db:"catalog_service_id"`

	// Overrides — if empty string, catalog defaults apply.
	CriticalityOverride string     `db:"criticality_override"`
	ExposureOverride    string     `db:"exposure_override"`
	Environment         string     `db:"environment"`

	// SuppressUntil temporarily excludes this client from alert client lists.
	// Useful for maintenance windows or compliance freezes.
	SuppressUntil *time.Time `db:"suppress_until"`

	Active     bool      `db:"active"`
	EnrolledAt time.Time `db:"enrolled_at"`
	Notes      string    `db:"notes"`

	// Populated by JOIN when needed — not stored in enrollments table.
	ClientName string `db:"-"`
	ClientSlug string `db:"-"`
	Contact    string `db:"-"`
}

// EffectiveCriticality returns the enrollment override if set, else the catalog default.
func (e *ClientEnrollment) EffectiveCriticality(catalogDefault string) string {
	if e.CriticalityOverride != "" {
		return e.CriticalityOverride
	}
	return catalogDefault
}

// EffectiveExposure returns the enrollment override if set, else the catalog default.
func (e *ClientEnrollment) EffectiveExposure(catalogDefault string) string {
	if e.ExposureOverride != "" {
		return e.ExposureOverride
	}
	return catalogDefault
}

// IsSuppressed returns true if suppress_until is set and is in the future.
func (e *ClientEnrollment) IsSuppressed() bool {
	if e.SuppressUntil == nil {
		return false
	}
	return time.Now().Before(*e.SuppressUntil)
}

// CatalogVersionHistory records every version change to a catalog entry.
type CatalogVersionHistory struct {
	ID               int64     `db:"id"`
	CatalogServiceID uuid.UUID `db:"catalog_service_id"`
	PreviousVersion  string    `db:"previous_version"`
	NewVersion       string    `db:"new_version"`
	ChangedBy        string    `db:"changed_by"`
	ChangedAt        time.Time `db:"changed_at"`
	Notes            string    `db:"notes"`
}
