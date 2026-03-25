package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/models"
)

type pgMatchRepository struct {
	db *sql.DB
}

func NewMatchRepository(db *sql.DB) MatchRepository {
	return &pgMatchRepository{db: db}
}

func (r *pgMatchRepository) GetByCatalogAndVuln(ctx context.Context, catalogServiceID uuid.UUID, vulnID string) (*models.Match, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, catalog_service_id, vuln_id, confidence, match_method, matched_version,
		       matched_cpe, notes, is_valid, invalidated_at, matched_at
		FROM matches
		WHERE catalog_service_id = ? AND vuln_id = ?
		LIMIT 1
	`)
	rows, err := r.db.QueryContext(ctx, query, catalogServiceID.String(), vulnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	matches, err := scanMatchRows(rows)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return matches[0], nil
}

func (r *pgMatchRepository) Upsert(ctx context.Context, m *models.Match) error {
	if m == nil {
		return errors.New("nil match")
	}
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if len(m.Notes) == 0 {
		m.Notes = []byte("{}")
	}

	if isPostgres(r.db) {
		query := `
			INSERT INTO matches (
				id, catalog_service_id, vuln_id, confidence, match_method,
				matched_version, matched_cpe, notes, is_valid, invalidated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (catalog_service_id, vuln_id) DO UPDATE SET
				confidence = EXCLUDED.confidence,
				match_method = EXCLUDED.match_method,
				matched_version = EXCLUDED.matched_version,
				matched_cpe = EXCLUDED.matched_cpe,
				notes = EXCLUDED.notes,
				is_valid = EXCLUDED.is_valid,
				invalidated_at = EXCLUDED.invalidated_at
		`
		_, err := r.db.ExecContext(ctx, query,
			m.ID.String(), m.CatalogServiceID.String(), m.VulnID, string(m.Confidence), string(m.MatchMethod),
			m.MatchedVersion, nullableString(m.MatchedCPE), string(m.Notes), m.IsValid, nullableTime(m.InvalidatedAt),
		)
		return err
	}

	query := `
		INSERT INTO matches (
			id, catalog_service_id, vuln_id, confidence, match_method,
			matched_version, matched_cpe, notes, is_valid, invalidated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(catalog_service_id, vuln_id) DO UPDATE SET
			confidence = excluded.confidence,
			match_method = excluded.match_method,
			matched_version = excluded.matched_version,
			matched_cpe = excluded.matched_cpe,
			notes = excluded.notes,
			is_valid = excluded.is_valid,
			invalidated_at = excluded.invalidated_at
	`
	_, err := r.db.ExecContext(ctx, query,
		m.ID.String(), m.CatalogServiceID.String(), m.VulnID, string(m.Confidence), string(m.MatchMethod),
		m.MatchedVersion, nullableString(m.MatchedCPE), string(m.Notes), m.IsValid, nullableTime(m.InvalidatedAt),
	)
	return err
}

func (r *pgMatchRepository) ListActiveForVuln(ctx context.Context, vulnID string) ([]*models.Match, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, catalog_service_id, vuln_id, confidence, match_method, matched_version,
		       matched_cpe, notes, is_valid, invalidated_at, matched_at
		FROM matches
		WHERE vuln_id = ? AND is_valid = ?
		ORDER BY matched_at DESC
	`)
	rows, err := r.db.QueryContext(ctx, query, vulnID, true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMatchRows(rows)
}

func (r *pgMatchRepository) ListActiveForCatalogService(ctx context.Context, catalogServiceID uuid.UUID) ([]*models.Match, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, catalog_service_id, vuln_id, confidence, match_method, matched_version,
		       matched_cpe, notes, is_valid, invalidated_at, matched_at
		FROM matches
		WHERE catalog_service_id = ? AND is_valid = ?
		ORDER BY matched_at DESC
	`)
	rows, err := r.db.QueryContext(ctx, query, catalogServiceID.String(), true)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMatchRows(rows)
}

func (r *pgMatchRepository) InvalidateForCatalogService(ctx context.Context, catalogServiceID uuid.UUID, reason string) error {
	return r.invalidate(ctx, "catalog_service_id = ?", catalogServiceID.String())
}

func (r *pgMatchRepository) InvalidateForVuln(ctx context.Context, vulnID string, reason string) error {
	_ = reason
	return r.invalidate(ctx, "vuln_id = ?", vulnID)
}

func (r *pgMatchRepository) invalidate(ctx context.Context, predicate string, arg any) error {
	query := "UPDATE matches SET is_valid = ?, invalidated_at = ? WHERE " + predicate + " AND is_valid = ?"
	query = rebindPlaceholders(r.db, query)
	_, err := r.db.ExecContext(ctx, query, false, formatDBTime(time.Now().UTC()), arg, true)
	return err
}

func scanMatchRows(rows *sql.Rows) ([]*models.Match, error) {
	var matches []*models.Match
	for rows.Next() {
		var (
			m             models.Match
			matchedCPE    sql.NullString
			notes         sql.NullString
			invalidatedAt any
			createdAt     any
		)
		if err := rows.Scan(
			&m.ID, &m.CatalogServiceID, &m.VulnID, &m.Confidence, &m.MatchMethod, &m.MatchedVersion,
			&matchedCPE, &notes, &m.IsValid, &invalidatedAt, &createdAt,
		); err != nil {
			return nil, err
		}
		if matchedCPE.Valid {
			m.MatchedCPE = matchedCPE.String
		}
		if notes.Valid {
			m.Notes = []byte(notes.String)
		}
		if !isNullishTime(invalidatedAt) {
			if ts, err := parseDBTime(invalidatedAt); err == nil {
				m.InvalidatedAt = &ts
			}
		}
		if ts, err := parseDBTime(createdAt); err == nil {
			m.CreatedAt = ts
			m.UpdatedAt = ts
		}
		matches = append(matches, &m)
	}
	return matches, rows.Err()
}
