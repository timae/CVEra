package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/yourorg/vulnmon/internal/models"
)

// CatalogRepository manages the managed service catalog.
// Version is a first-class concern here: UpdateVersion records history
// and returns the previous version so callers can invalidate stale matches.
type CatalogRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.CatalogService, error)
	GetBySlug(ctx context.Context, slug string) (*models.CatalogService, error)
	List(ctx context.Context) ([]*models.CatalogService, error)
	ListActive(ctx context.Context) ([]*models.CatalogService, error)
	Upsert(ctx context.Context, s *models.CatalogService) error

	// UpdateVersion updates the version field, records history,
	// and returns the previous version string.
	UpdateVersion(ctx context.Context, id uuid.UUID, newVersion, changedBy, notes string) (string, error)

	// Lookup helpers for the matching engine.
	ListByCPEComponent(ctx context.Context, vendor, product string) ([]*models.CatalogService, error)
	ListByPackage(ctx context.Context, ecosystem, name string) ([]*models.CatalogService, error)
}

// EnrollmentRepository manages which clients run which catalog services.
type EnrollmentRepository interface {
	ListByService(ctx context.Context, catalogServiceID uuid.UUID) ([]*models.ClientEnrollment, error)
	ListByClient(ctx context.Context, clientID uuid.UUID) ([]*models.ClientEnrollment, error)
	Enroll(ctx context.Context, e *models.ClientEnrollment) error
	Unenroll(ctx context.Context, clientID, catalogServiceID uuid.UUID) error
	CountByService(ctx context.Context, catalogServiceID uuid.UUID) (int, error)
}

// ClientRepository is intentionally thin — clients carry no version state.
type ClientRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Client, error)
	GetBySlug(ctx context.Context, slug string) (*models.Client, error)
	List(ctx context.Context) ([]*models.Client, error)
	Upsert(ctx context.Context, c *models.Client) error
}

// VulnerabilityRepository manages normalized vulnerability records.
type VulnerabilityRepository interface {
	GetByVulnID(ctx context.Context, vulnID string) (*models.Vulnerability, error)
	Upsert(ctx context.Context, v *models.Vulnerability) error
	UpsertSourceRecord(ctx context.Context, r *models.VulnerabilitySourceRecord) error
	ListModifiedSince(ctx context.Context, since time.Time, limit, offset int) ([]*models.Vulnerability, error)
	UpdateEPSS(ctx context.Context, vulnID string, score, percentile float64) error
	MarkKEV(ctx context.Context, vulnID string, dateAdded time.Time) error
}

// MatchRepository manages match records between catalog services and vulnerabilities.
// One match record per (catalog_service, vulnerability, method) — not per client.
type MatchRepository interface {
	GetByCatalogAndVuln(ctx context.Context, catalogServiceID, vulnID uuid.UUID) (*models.Match, error)
	Upsert(ctx context.Context, m *models.Match) error
	ListActiveForVuln(ctx context.Context, vulnID uuid.UUID) ([]*models.Match, error)
	ListActiveForCatalogService(ctx context.Context, catalogServiceID uuid.UUID) ([]*models.Match, error)
	// InvalidateForCatalogService is called when UpdateVersion runs.
	InvalidateForCatalogService(ctx context.Context, catalogServiceID uuid.UUID, reason string) error
	InvalidateForVuln(ctx context.Context, vulnID uuid.UUID, reason string) error
}

// AlertRepository manages alert state. Dedup key: "{catalog_slug}:{vuln_id}".
type AlertRepository interface {
	GetByDedupKey(ctx context.Context, key string) (*models.Alert, error)
	Create(ctx context.Context, a *models.Alert) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.AlertStatus, detail map[string]any) error
	Acknowledge(ctx context.Context, id uuid.UUID, by, note string) error
	ListPending(ctx context.Context) ([]*models.Alert, error)
	List(ctx context.Context, filter AlertFilter) ([]*models.Alert, error)
}

// AlertFilter scopes the List query.
type AlertFilter struct {
	Status           *models.AlertStatus
	CatalogServiceID *uuid.UUID
	Limit            int
	Offset           int
}

// SuppressionRepository evaluates whether an alert should be suppressed.
type SuppressionRepository interface {
	// Match returns the first active suppression applying to the given
	// (catalogServiceID, clientID, vuln) triple, or nil if none applies.
	Match(ctx context.Context, catalogServiceID uuid.UUID, clientID *uuid.UUID, v *models.Vulnerability) (*models.Suppression, error)
	Create(ctx context.Context, s *models.Suppression) error
	Expire(ctx context.Context, id uuid.UUID) error
	ListActive(ctx context.Context) ([]*models.Suppression, error)
}

// CheckpointRepository manages ingestion source cursors.
type CheckpointRepository interface {
	Get(ctx context.Context, source string) (*models.IngestionCheckpoint, error)
	Save(ctx context.Context, cp *models.IngestionCheckpoint) error
}
