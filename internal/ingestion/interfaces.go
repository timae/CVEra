package ingestion

import (
	"context"
	"time"

	"github.com/yourorg/vulnmon/internal/models"
)

// VulnerabilitySource fetches raw vulnerability data from one upstream feed.
// It is responsible only for fetching and normalizing — it does not write to the DB.
// Each source implementation lives in its own sub-package (nvd/, osv/, kev/, epss/).
type VulnerabilitySource interface {
	// Name returns a stable identifier, e.g. "nvd", "osv", "cisa_kev", "epss".
	Name() string

	// Fetch retrieves vulnerabilities modified since `since`.
	// Results are streamed via a channel to support large result sets without
	// holding everything in memory. The source closes the channel when done.
	// The caller must drain the channel even on error.
	Fetch(ctx context.Context, since time.Time) (<-chan FetchResult, error)

	// HealthCheck verifies the source is reachable.
	HealthCheck(ctx context.Context) error
}

// FetchResult wraps a single normalized vulnerability or an error from Fetch.
type FetchResult struct {
	Vulnerability *models.Vulnerability
	RawPayload    []byte // original JSON for VulnerabilitySourceRecord storage
	Err           error
}

// IngestionJob orchestrates one complete ingestion cycle for one source.
// It loads the checkpoint, calls the source, stores raw records,
// upserts normalized vulnerabilities, and saves the updated checkpoint.
// All operations must be idempotent.
type IngestionJob interface {
	// Run executes one ingestion cycle. Must be safe to call concurrently
	// (the scheduler uses a PostgreSQL advisory lock to prevent overlap,
	// but the implementation should be idempotent regardless).
	Run(ctx context.Context) error

	// Source returns the underlying VulnerabilitySource for health checking.
	Source() VulnerabilitySource
}
