package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourorg/vulnmon/internal/models"
)

type pgAlertRepository struct {
	pool *pgxpool.Pool
}

func NewAlertRepository(pool *pgxpool.Pool) AlertRepository {
	return &pgAlertRepository{pool: pool}
}

func (r *pgAlertRepository) GetByDedupKey(ctx context.Context, key string) (*models.Alert, error) {
	// TODO: implement — SELECT * FROM alerts WHERE dedup_key = $1
	return nil, errors.New("not implemented")
}

func (r *pgAlertRepository) Create(ctx context.Context, a *models.Alert) error {
	// TODO: implement — INSERT INTO alerts (...) VALUES (...)
	// dedup_key has UNIQUE constraint; this should fail if called twice for same key.
	return errors.New("not implemented")
}

func (r *pgAlertRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.AlertStatus, detail map[string]any) error {
	// TODO: implement — UPDATE alerts SET status = $2, updated_at = NOW()
	// detail is written to audit_log, not alerts table
	return errors.New("not implemented")
}

func (r *pgAlertRepository) Acknowledge(ctx context.Context, id uuid.UUID, by, note string) error {
	// TODO: implement
	// UPDATE alerts SET status = 'acknowledged', acknowledged_by = $2,
	//   acknowledged_at = NOW(), ack_note = $3, updated_at = NOW()
	return errors.New("not implemented")
}

func (r *pgAlertRepository) ListPending(ctx context.Context) ([]*models.Alert, error) {
	// TODO: implement — WHERE status = 'pending' ORDER BY created_at ASC
	return nil, errors.New("not implemented")
}

func (r *pgAlertRepository) List(ctx context.Context, filter AlertFilter) ([]*models.Alert, error) {
	// TODO: implement — dynamic WHERE clause from filter fields
	return nil, errors.New("not implemented")
}
