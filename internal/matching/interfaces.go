package matching

import (
	"context"

	"github.com/yourorg/cvera/internal/models"
)

// Matcher evaluates a single (CatalogService, Vulnerability) pair.
// Each implementation uses a distinct strategy. Matchers must be safe for
// concurrent use and must not write to the database directly.
type Matcher interface {
	// Name returns the stable match method identifier, e.g. "cpe_exact".
	Name() string

	// Match evaluates the pair.
	// Returns nil if this matcher cannot evaluate the pair
	// (e.g. no CPE data on either side — not an error, just not applicable).
	// Returns a MatchResult with Confidence=unknown if there is soft evidence
	// but the match cannot be confirmed (e.g. version is "latest").
	Match(ctx context.Context, svc *models.CatalogService, vuln *models.Vulnerability) (*MatchResult, error)
}

// MatchResult is the output of a successful Matcher evaluation.
type MatchResult struct {
	Confidence      models.Confidence
	Method          models.MatchMethod
	MatchedOn       string         // the CPE, package spec, or product name that matched
	VersionAffected bool           // true if the catalog version is in the affected range
	Detail          map[string]any // full evidence for audit; stored as JSONB in matches table
}

// MatchEngine orchestrates all matchers against the catalog.
// It is the entry point called by the ingestion layer after upserting a vulnerability.
type MatchEngine interface {
	// RunForVulnerability evaluates all active catalog entries against a new/updated vulnerability.
	// Called automatically after each successful ingestion of a modified CVE.
	RunForVulnerability(ctx context.Context, vulnID string) error

	// RunForCatalogService evaluates all recent vulnerabilities against an updated catalog entry.
	// Called automatically after CatalogRepository.UpdateVersion().
	RunForCatalogService(ctx context.Context, catalogServiceID string) error
}
