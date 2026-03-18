package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourorg/vulnmon/internal/models"
)

type pgCatalogRepository struct {
	pool *pgxpool.Pool
}

func NewCatalogRepository(pool *pgxpool.Pool) CatalogRepository {
	return &pgCatalogRepository{pool: pool}
}

func (r *pgCatalogRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CatalogService, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (r *pgCatalogRepository) GetBySlug(ctx context.Context, slug string) (*models.CatalogService, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (r *pgCatalogRepository) List(ctx context.Context) ([]*models.CatalogService, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (r *pgCatalogRepository) ListActive(ctx context.Context) ([]*models.CatalogService, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (r *pgCatalogRepository) Upsert(ctx context.Context, s *models.CatalogService) error {
	// TODO: implement — ON CONFLICT (slug) DO UPDATE
	return errors.New("not implemented")
}

func (r *pgCatalogRepository) UpdateVersion(
	ctx context.Context, id uuid.UUID, newVersion, changedBy, notes string,
) (string, error) {
	// TODO: implement
	// 1. SELECT current version
	// 2. UPDATE catalog_services SET version = $1, updated_at = NOW()
	// 3. INSERT catalog_version_history (previous_version, new_version, changed_by, notes)
	// Returns the previous version string.
	_ = time.Now() // suppress unused import
	return "", errors.New("not implemented")
}

func (r *pgCatalogRepository) ListByCPEComponent(ctx context.Context, vendor, product string) ([]*models.CatalogService, error) {
	// TODO: implement — parse cpe23 and filter by vendor:product component
	return nil, errors.New("not implemented")
}

func (r *pgCatalogRepository) ListByPackage(ctx context.Context, ecosystem, name string) ([]*models.CatalogService, error) {
	// TODO: implement — WHERE package_ecosystem = $1 AND package_name = $2
	return nil, errors.New("not implemented")
}
