package repository

import (
	"context"

	"github.com/google/uuid"
	"database/sql"

	"github.com/yourorg/cvera/internal/models"
)

type pgSuppressionRepository struct {
	db *sql.DB
}

// NewSuppressionRepository returns a SuppressionRepository backed by PostgreSQL.
func NewSuppressionRepository(db *sql.DB) SuppressionRepository {
	return &pgSuppressionRepository{db: db}
}

// Match returns the first active suppression that applies to
// (catalogServiceID, clientID, vuln), or nil if none matches.
//
// Scope resolution (most-specific first):
//
//	vuln_id + catalog_service_id  → exact scope
//	vuln_id only                  → CVE-wide suppression
//	catalog_service_id only       → service-wide suppression
func (r *pgSuppressionRepository) Match(
	ctx context.Context,
	catalogServiceID uuid.UUID,
	clientID *uuid.UUID,
	v *models.Vulnerability,
) (*models.Suppression, error) {
	// TODO: implement
	// SELECT * FROM suppressions
	// WHERE (expires_at IS NULL OR expires_at > NOW())
	//   AND (
	//     (vuln_id = $1 AND catalog_service_id = $2)
	//  OR (vuln_id = $1 AND catalog_service_id IS NULL)
	//  OR (vuln_id IS NULL AND catalog_service_id = $2)
	//   )
	// ORDER BY
	//   (CASE WHEN vuln_id IS NOT NULL AND catalog_service_id IS NOT NULL THEN 0
	//         WHEN vuln_id IS NOT NULL THEN 1
	//         ELSE 2 END)
	// LIMIT 1
	panic("not implemented")
}

// Create inserts a new suppression rule.
func (r *pgSuppressionRepository) Create(ctx context.Context, s *models.Suppression) error {
	// TODO: implement
	// INSERT INTO suppressions (id, vuln_id, catalog_service_id, reason, created_by, expires_at)
	// VALUES ($1, $2, $3, $4, $5, $6)
	panic("not implemented")
}

// Expire sets expires_at = NOW() on a suppression, effectively deactivating it.
func (r *pgSuppressionRepository) Expire(ctx context.Context, id uuid.UUID) error {
	// TODO: implement
	// UPDATE suppressions SET expires_at = NOW() WHERE id = $1
	panic("not implemented")
}

// ListActive returns all non-expired suppression rules, ordered newest-first.
func (r *pgSuppressionRepository) ListActive(ctx context.Context) ([]*models.Suppression, error) {
	// TODO: implement
	// SELECT * FROM suppressions
	// WHERE expires_at IS NULL OR expires_at > NOW()
	// ORDER BY created_at DESC
	panic("not implemented")
}
