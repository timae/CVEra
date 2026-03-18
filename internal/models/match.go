package models

import (
	"time"

	"github.com/google/uuid"
)

// Confidence represents how certain a match is.
// Use an enum — a float gives false precision.
type Confidence string

const (
	// ConfidenceExact: service CPE is listed verbatim in the NVD CPE configuration.
	ConfidenceExact Confidence = "exact"
	// ConfidenceStrong: version range match via CPE applicability or OSV range.
	ConfidenceStrong Confidence = "strong"
	// ConfidenceWeak: product name fuzzy match only; no version data. Do not auto-alert.
	ConfidenceWeak Confidence = "weak"
	// ConfidenceUnknown: product/CPE matches but version is unparseable or "latest".
	ConfidenceUnknown Confidence = "unknown"
)

// MatchMethod identifies which strategy produced the match.
type MatchMethod string

const (
	MatchMethodCPEExact      MatchMethod = "cpe_exact"
	MatchMethodCPERange      MatchMethod = "cpe_range"
	MatchMethodPackageRange  MatchMethod = "package_range"
	MatchMethodProductFuzzy  MatchMethod = "product_fuzzy"
)

// Match records that a CatalogService is potentially affected by a Vulnerability.
// One match covers ALL clients enrolled in that catalog service.
// Matches are immutable once created; a new record is written if conditions change.
type Match struct {
	ID               uuid.UUID   `db:"id"`
	CatalogServiceID uuid.UUID   `db:"catalog_service_id"`
	VulnerabilityID  uuid.UUID   `db:"vulnerability_id"`

	Confidence   Confidence  `db:"confidence"`
	MatchMethod  MatchMethod `db:"match_method"`
	MatchedCPE   string      `db:"matched_cpe"`     // which CPE or package spec triggered this
	MatchedVersion string    `db:"matched_version"` // catalog version at match time

	// MatchDetail holds full match evidence for audit and debugging.
	// Stored as JSONB — content varies by match method.
	MatchDetail []byte `db:"match_detail"`

	IsValid            bool       `db:"is_valid"`
	InvalidatedReason  string     `db:"invalidated_reason"`
	InvalidatedAt      *time.Time `db:"invalidated_at"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}
