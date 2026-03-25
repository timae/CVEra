package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/models"
)

type pgAlertRepository struct {
	db *sql.DB
}

func NewAlertRepository(db *sql.DB) AlertRepository {
	return &pgAlertRepository{db: db}
}

func (r *pgAlertRepository) GetByDedupKey(ctx context.Context, key string) (*models.Alert, error) {
	query := rebindPlaceholders(r.db, baseAlertSelect()+" WHERE dedup_key = ? LIMIT 1")
	rows, err := r.db.QueryContext(ctx, query, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	alerts, err := scanAlertRows(rows)
	if err != nil {
		return nil, err
	}
	if len(alerts) == 0 {
		return nil, nil
	}
	return alerts[0], nil
}

func (r *pgAlertRepository) Create(ctx context.Context, a *models.Alert) error {
	if a == nil {
		return errors.New("nil alert")
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if len(a.AffectedClients) == 0 {
		a.AffectedClients = []byte("[]")
	}

	query := rebindPlaceholders(r.db, `
		INSERT INTO alerts (
			id, dedup_key, catalog_service_id, vuln_id, status, affected_clients,
			acknowledged_at, acknowledged_by, ack_note, resolved_at, suppressed_at,
			suppression_reason, last_sent_at, send_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	_, err := r.db.ExecContext(ctx, query,
		a.ID.String(), a.DedupKey, a.CatalogServiceID.String(), a.VulnID, string(a.Status), string(a.AffectedClients),
		nullableTime(a.AcknowledgedAt), nullableString(a.AcknowledgedBy), nullableString(a.AckNote),
		nullableTime(a.ResolvedAt), nullableTime(a.SuppressedAt), nullableString(a.SuppressionReason),
		nullableTime(a.LastSentAt), a.SendCount,
	)
	return err
}

func (r *pgAlertRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.AlertStatus, detail map[string]any) error {
	query := rebindPlaceholders(r.db, "UPDATE alerts SET status = ? WHERE id = ?")
	_, err := r.db.ExecContext(ctx, query, string(status), id.String())
	_ = detail
	return err
}

func (r *pgAlertRepository) Acknowledge(ctx context.Context, id uuid.UUID, by, note string) error {
	query := rebindPlaceholders(r.db, `
		UPDATE alerts
		SET status = ?, acknowledged_by = ?, acknowledged_at = ?, ack_note = ?
		WHERE id = ?
	`)
	_, err := r.db.ExecContext(ctx, query, string(models.AlertStatusAcknowledged), by, formatDBTime(time.Now().UTC()), note, id.String())
	return err
}

func (r *pgAlertRepository) ListPending(ctx context.Context) ([]*models.Alert, error) {
	return r.List(ctx, AlertFilter{Status: statusPtr(models.AlertStatusPending)})
}

func (r *pgAlertRepository) List(ctx context.Context, filter AlertFilter) ([]*models.Alert, error) {
	query := baseAlertSelect()
	var (
		clauses []string
		args    []any
	)
	if filter.Status != nil {
		clauses = append(clauses, "status = ?")
		args = append(args, string(*filter.Status))
	}
	if filter.CatalogServiceID != nil {
		clauses = append(clauses, "catalog_service_id = ?")
		args = append(args, filter.CatalogServiceID.String())
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}
	query = rebindPlaceholders(r.db, query)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertRows(rows)
}

func baseAlertSelect() string {
	return `
		SELECT id, dedup_key, catalog_service_id, vuln_id, status, affected_clients,
		       acknowledged_at, acknowledged_by, ack_note, resolved_at, suppressed_at,
		       suppression_reason, last_sent_at, send_count, created_at, updated_at
		FROM alerts
	`
}

func scanAlertRows(rows *sql.Rows) ([]*models.Alert, error) {
	var alerts []*models.Alert
	for rows.Next() {
		var (
			a                 models.Alert
			affectedClients   string
			ackAt             any
			ackBy             sql.NullString
			ackNote           sql.NullString
			resolvedAt        any
			suppressedAt      any
			suppressionReason sql.NullString
			lastSentAt        any
			createdAt         any
			updatedAt         any
		)
		if err := rows.Scan(
			&a.ID, &a.DedupKey, &a.CatalogServiceID, &a.VulnID, &a.Status, &affectedClients,
			&ackAt, &ackBy, &ackNote, &resolvedAt, &suppressedAt,
			&suppressionReason, &lastSentAt, &a.SendCount, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		a.AffectedClients = []byte(affectedClients)
		a.AcknowledgedBy = ackBy.String
		a.AckNote = ackNote.String
		a.SuppressionReason = suppressionReason.String
		if !isNullishTime(ackAt) {
			if ts, err := parseDBTime(ackAt); err == nil {
				a.AcknowledgedAt = &ts
			}
		}
		if !isNullishTime(resolvedAt) {
			if ts, err := parseDBTime(resolvedAt); err == nil {
				a.ResolvedAt = &ts
			}
		}
		if !isNullishTime(suppressedAt) {
			if ts, err := parseDBTime(suppressedAt); err == nil {
				a.SuppressedAt = &ts
			}
		}
		if !isNullishTime(lastSentAt) {
			if ts, err := parseDBTime(lastSentAt); err == nil {
				a.LastSentAt = &ts
			}
		}
		if ts, err := parseDBTime(createdAt); err == nil {
			a.CreatedAt = ts
		}
		if ts, err := parseDBTime(updatedAt); err == nil {
			a.UpdatedAt = ts
		}
		alerts = append(alerts, &a)
	}
	return alerts, rows.Err()
}

func statusPtr(status models.AlertStatus) *models.AlertStatus { return &status }
