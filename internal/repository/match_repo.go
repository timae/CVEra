package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourorg/cvera/internal/models"
)

type pgMatchRepository struct {
	pool *pgxpool.Pool
}

func NewMatchRepository(pool *pgxpool.Pool) MatchRepository {
	return &pgMatchRepository{pool: pool}
}

func (r *pgMatchRepository) GetByCatalogAndVuln(ctx context.Context, catalogServiceID, vulnID uuid.UUID) (*models.Match, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (r *pgMatchRepository) Upsert(ctx context.Context, m *models.Match) error {
	// TODO: implement
	// ON CONFLICT (catalog_service_id, vulnerability_id, match_method) DO UPDATE
	// Update: confidence, matched_cpe, matched_version, match_detail, is_valid, updated_at
	return errors.New("not implemented")
}

func (r *pgMatchRepository) ListActiveForVuln(ctx context.Context, vulnID uuid.UUID) ([]*models.Match, error) {
	// TODO: implement — WHERE vulnerability_id = $1 AND is_valid = true
	return nil, errors.New("not implemented")
}

func (r *pgMatchRepository) ListActiveForCatalogService(ctx context.Context, catalogServiceID uuid.UUID) ([]*models.Match, error) {
	// TODO: implement — WHERE catalog_service_id = $1 AND is_valid = true
	return nil, errors.New("not implemented")
}

func (r *pgMatchRepository) InvalidateForCatalogService(ctx context.Context, catalogServiceID uuid.UUID, reason string) error {
	// TODO: implement
	// UPDATE matches SET is_valid = false, invalidated_reason = $2, invalidated_at = NOW()
	// WHERE catalog_service_id = $1 AND is_valid = true
	return errors.New("not implemented")
}

func (r *pgMatchRepository) InvalidateForVuln(ctx context.Context, vulnID uuid.UUID, reason string) error {
	// TODO: implement
	// UPDATE matches SET is_valid = false, invalidated_reason = $2, invalidated_at = NOW()
	// WHERE vulnerability_id = $1 AND is_valid = true
	return errors.New("not implemented")
}
