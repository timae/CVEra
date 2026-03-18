package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourorg/vulnmon/internal/models"
)

type pgClientRepository struct {
	pool *pgxpool.Pool
}

// NewClientRepository returns a ClientRepository backed by PostgreSQL.
func NewClientRepository(pool *pgxpool.Pool) ClientRepository {
	return &pgClientRepository{pool: pool}
}

// GetByID retrieves a client by its primary key UUID.
func (r *pgClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Client, error) {
	// TODO: implement
	// SELECT id, slug, name, contact_email, metadata, created_at, updated_at
	// FROM clients WHERE id = $1
	panic("not implemented")
}

// GetBySlug retrieves a client by its unique slug.
func (r *pgClientRepository) GetBySlug(ctx context.Context, slug string) (*models.Client, error) {
	// TODO: implement
	// SELECT ... FROM clients WHERE slug = $1
	panic("not implemented")
}

// List returns all clients ordered by name.
func (r *pgClientRepository) List(ctx context.Context) ([]*models.Client, error) {
	// TODO: implement
	// SELECT ... FROM clients ORDER BY name
	panic("not implemented")
}

// Upsert inserts or updates a client record.
// Conflict target: slug.  Updated fields: name, contact_email, metadata, updated_at.
func (r *pgClientRepository) Upsert(ctx context.Context, c *models.Client) error {
	// TODO: implement
	// INSERT INTO clients (id, slug, name, contact_email, metadata)
	// VALUES ($1,$2,$3,$4,$5)
	// ON CONFLICT (slug) DO UPDATE SET
	//     name = EXCLUDED.name,
	//     contact_email = EXCLUDED.contact_email,
	//     metadata = EXCLUDED.metadata,
	//     updated_at = NOW()
	panic("not implemented")
}
