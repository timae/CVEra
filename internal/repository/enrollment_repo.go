package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/models"
)

type pgEnrollmentRepository struct {
	db *sql.DB
}

func NewEnrollmentRepository(db *sql.DB) EnrollmentRepository {
	return &pgEnrollmentRepository{db: db}
}

func (r *pgEnrollmentRepository) ListByService(ctx context.Context, catalogServiceID uuid.UUID) ([]*models.ClientEnrollment, error) {
	query := rebindPlaceholders(r.db, `
		SELECT e.id, e.client_id, e.catalog_service_id, e.criticality_override, e.exposure_override,
		       e.suppression_end_date, e.enrolled_at, e.suppression_reason,
		       c.name, c.slug, c.contact_email
		FROM client_enrollments e
		JOIN clients c ON c.id = e.client_id
		WHERE e.catalog_service_id = ?
		ORDER BY c.name
	`)
	rows, err := r.db.QueryContext(ctx, query, catalogServiceID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEnrollmentRows(rows)
}

func (r *pgEnrollmentRepository) ListByClient(ctx context.Context, clientID uuid.UUID) ([]*models.ClientEnrollment, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, client_id, catalog_service_id, criticality_override, exposure_override,
		       suppression_end_date, enrolled_at, suppression_reason, '', '', ''
		FROM client_enrollments
		WHERE client_id = ?
		ORDER BY enrolled_at
	`)
	rows, err := r.db.QueryContext(ctx, query, clientID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEnrollmentRows(rows)
}

func (r *pgEnrollmentRepository) Enroll(ctx context.Context, e *models.ClientEnrollment) error {
	if e == nil {
		return errors.New("nil enrollment")
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.EnrolledAt.IsZero() {
		e.EnrolledAt = time.Now().UTC()
	}

	if isPostgres(r.db) {
		query := `
			INSERT INTO client_enrollments (
				id, client_id, catalog_service_id, criticality_override, exposure_override,
				suppressed, suppression_reason, suppression_end_date
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (client_id, catalog_service_id) DO UPDATE SET
				criticality_override = EXCLUDED.criticality_override,
				exposure_override = EXCLUDED.exposure_override,
				suppressed = EXCLUDED.suppressed,
				suppression_reason = EXCLUDED.suppression_reason,
				suppression_end_date = EXCLUDED.suppression_end_date,
				updated_at = NOW()
		`
		_, err := r.db.ExecContext(ctx, query,
			e.ID.String(), e.ClientID.String(), e.CatalogServiceID.String(),
			nullableString(e.CriticalityOverride), nullableString(e.ExposureOverride),
			e.SuppressUntil != nil, nullableString(e.Notes), e.SuppressUntil,
		)
		return err
	}

	query := `
		INSERT INTO client_enrollments (
			id, client_id, catalog_service_id, criticality_override, exposure_override,
			suppressed, suppression_reason, suppression_end_date
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(client_id, catalog_service_id) DO UPDATE SET
			criticality_override = excluded.criticality_override,
			exposure_override = excluded.exposure_override,
			suppressed = excluded.suppressed,
			suppression_reason = excluded.suppression_reason,
			suppression_end_date = excluded.suppression_end_date,
			updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
	`
	var suppressionEnd any
	if e.SuppressUntil != nil {
		suppressionEnd = formatDBTime(*e.SuppressUntil)
	}
	_, err := r.db.ExecContext(ctx, query,
		e.ID.String(), e.ClientID.String(), e.CatalogServiceID.String(),
		nullableString(e.CriticalityOverride), nullableString(e.ExposureOverride),
		e.SuppressUntil != nil, nullableString(e.Notes), suppressionEnd,
	)
	return err
}

func (r *pgEnrollmentRepository) Unenroll(ctx context.Context, clientID, catalogServiceID uuid.UUID) error {
	query := rebindPlaceholders(r.db, "DELETE FROM client_enrollments WHERE client_id = ? AND catalog_service_id = ?")
	_, err := r.db.ExecContext(ctx, query, clientID.String(), catalogServiceID.String())
	return err
}

func (r *pgEnrollmentRepository) CountByService(ctx context.Context, catalogServiceID uuid.UUID) (int, error) {
	query := rebindPlaceholders(r.db, "SELECT COUNT(*) FROM client_enrollments WHERE catalog_service_id = ?")
	var count int
	err := r.db.QueryRowContext(ctx, query, catalogServiceID.String()).Scan(&count)
	return count, err
}

func scanEnrollmentRows(rows *sql.Rows) ([]*models.ClientEnrollment, error) {
	var enrollments []*models.ClientEnrollment
	for rows.Next() {
		var (
			e              models.ClientEnrollment
			criticality    sql.NullString
			exposure       sql.NullString
			suppressionEnd sql.NullString
			enrolledAt     any
			notes          sql.NullString
			clientName     string
			clientSlug     string
			contact        string
		)
		if err := rows.Scan(
			&e.ID, &e.ClientID, &e.CatalogServiceID, &criticality, &exposure,
			&suppressionEnd, &enrolledAt, &notes, &clientName, &clientSlug, &contact,
		); err != nil {
			return nil, err
		}
		e.CriticalityOverride = criticality.String
		e.ExposureOverride = exposure.String
		if suppressionEnd.Valid {
			ts, err := parseDBTime(suppressionEnd.String)
			if err != nil {
				return nil, err
			}
			e.SuppressUntil = &ts
		}
		if ts, err := parseDBTime(enrolledAt); err == nil {
			e.EnrolledAt = ts
		}
		e.Notes = notes.String
		e.ClientName = clientName
		e.ClientSlug = clientSlug
		e.Contact = contact
		e.Active = true
		enrollments = append(enrollments, &e)
	}
	return enrollments, rows.Err()
}
