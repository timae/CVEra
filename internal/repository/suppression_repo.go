package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/models"
)

type pgSuppressionRepository struct {
	db *sql.DB
}

func NewSuppressionRepository(db *sql.DB) SuppressionRepository {
	return &pgSuppressionRepository{db: db}
}

func (r *pgSuppressionRepository) Match(
	ctx context.Context,
	catalogServiceID uuid.UUID,
	clientID *uuid.UUID,
	v *models.Vulnerability,
) (*models.Suppression, error) {
	_ = clientID
	query := rebindPlaceholders(r.db, `
		SELECT id, vuln_id, catalog_service_id, reason, created_by, expires_at, created_at
		FROM suppressions
		WHERE (expires_at IS NULL OR expires_at > ?)
		  AND (
		    (vuln_id = ? AND catalog_service_id = ?)
		 OR (vuln_id = ? AND catalog_service_id IS NULL)
		 OR (vuln_id IS NULL AND catalog_service_id = ?)
		  )
		ORDER BY
		  CASE
		    WHEN vuln_id IS NOT NULL AND catalog_service_id IS NOT NULL THEN 0
		    WHEN vuln_id IS NOT NULL THEN 1
		    ELSE 2
		  END,
		  created_at DESC
		LIMIT 1
	`)
	rows, err := r.db.QueryContext(ctx, query,
		formatDBTime(time.Now().UTC()),
		v.VulnID, catalogServiceID.String(),
		v.VulnID,
		catalogServiceID.String(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanSuppressionRows(rows)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	return items[0], nil
}

func (r *pgSuppressionRepository) Create(ctx context.Context, s *models.Suppression) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	query := rebindPlaceholders(r.db, `
		INSERT INTO suppressions (id, vuln_id, catalog_service_id, reason, created_by, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	var catalogServiceID any
	if s.CatalogServiceID != nil {
		catalogServiceID = s.CatalogServiceID.String()
	}
	_, err := r.db.ExecContext(ctx, query, s.ID.String(), nullableString(s.VulnID), catalogServiceID, s.Reason, s.CreatedBy, nullableTime(s.ExpiresAt))
	return err
}

func (r *pgSuppressionRepository) Expire(ctx context.Context, id uuid.UUID) error {
	query := rebindPlaceholders(r.db, "UPDATE suppressions SET expires_at = ? WHERE id = ?")
	_, err := r.db.ExecContext(ctx, query, formatDBTime(time.Now().UTC()), id.String())
	return err
}

func (r *pgSuppressionRepository) ListActive(ctx context.Context) ([]*models.Suppression, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, vuln_id, catalog_service_id, reason, created_by, expires_at, created_at
		FROM suppressions
		WHERE expires_at IS NULL OR expires_at > ?
		ORDER BY created_at DESC
	`)
	rows, err := r.db.QueryContext(ctx, query, formatDBTime(time.Now().UTC()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSuppressionRows(rows)
}

func scanSuppressionRows(rows *sql.Rows) ([]*models.Suppression, error) {
	var suppressions []*models.Suppression
	for rows.Next() {
		var (
			s                models.Suppression
			vulnID           sql.NullString
			catalogServiceID sql.NullString
			expiresAt        any
			createdAt        any
		)
		if err := rows.Scan(&s.ID, &vulnID, &catalogServiceID, &s.Reason, &s.CreatedBy, &expiresAt, &createdAt); err != nil {
			return nil, err
		}
		s.VulnID = vulnID.String
		if catalogServiceID.Valid {
			id, err := uuid.Parse(catalogServiceID.String)
			if err != nil {
				return nil, err
			}
			s.CatalogServiceID = &id
		}
		if !isNullishTime(expiresAt) {
			if ts, err := parseDBTime(expiresAt); err == nil {
				s.ExpiresAt = &ts
			}
		}
		if ts, err := parseDBTime(createdAt); err == nil {
			s.CreatedAt = ts
		}
		suppressions = append(suppressions, &s)
	}
	return suppressions, rows.Err()
}
