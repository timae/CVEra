package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/models"
)

type pgClientRepository struct {
	db *sql.DB
}

func NewClientRepository(db *sql.DB) ClientRepository {
	return &pgClientRepository{db: db}
}

func (r *pgClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Client, error) {
	return r.getOne(ctx, "WHERE id = ?", id.String())
}

func (r *pgClientRepository) GetBySlug(ctx context.Context, slug string) (*models.Client, error) {
	return r.getOne(ctx, "WHERE slug = ?", slug)
}

func (r *pgClientRepository) List(ctx context.Context) ([]*models.Client, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, slug, name, contact_email, metadata, created_at, updated_at
		FROM clients
		ORDER BY name
	`)
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClientRows(rows)
}

func (r *pgClientRepository) Upsert(ctx context.Context, c *models.Client) error {
	if c == nil {
		return errors.New("nil client")
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	c.UpdatedAt = time.Now().UTC()
	if !c.Active {
		c.Active = true
	}
	tags, err := json.Marshal(c.Tags)
	if err != nil {
		return err
	}

	if isPostgres(r.db) {
		query := `
			INSERT INTO clients (id, slug, name, contact_email, metadata)
			VALUES ($1,$2,$3,$4,$5::jsonb)
			ON CONFLICT (slug) DO UPDATE SET
				name = EXCLUDED.name,
				contact_email = EXCLUDED.contact_email,
				metadata = EXCLUDED.metadata,
				updated_at = NOW()
		`
		_, err = r.db.ExecContext(ctx, query, c.ID.String(), c.Slug, c.Name, c.Contact, string(tags))
		return err
	}

	query := `
		INSERT INTO clients (id, slug, name, contact_email, metadata)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(slug) DO UPDATE SET
			name = excluded.name,
			contact_email = excluded.contact_email,
			metadata = excluded.metadata,
			updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
	`
	_, err = r.db.ExecContext(ctx, query, c.ID.String(), c.Slug, c.Name, c.Contact, string(tags))
	return err
}

func (r *pgClientRepository) getOne(ctx context.Context, where string, arg any) (*models.Client, error) {
	query := rebindPlaceholders(r.db, `
		SELECT id, slug, name, contact_email, metadata, created_at, updated_at
		FROM clients
		`+where+` LIMIT 1`)
	rows, err := r.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients, err := scanClientRows(rows)
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, nil
	}
	return clients[0], nil
}

func scanClientRows(rows *sql.Rows) ([]*models.Client, error) {
	var clients []*models.Client
	for rows.Next() {
		var (
			c         models.Client
			metaRaw   string
			createdAt any
			updatedAt any
		)
		if err := rows.Scan(&c.ID, &c.Slug, &c.Name, &c.Contact, &metaRaw, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if metaRaw != "" {
			_ = json.Unmarshal([]byte(metaRaw), &c.Tags)
		}
		c.Active = true
		if ts, err := parseDBTime(createdAt); err == nil {
			c.CreatedAt = ts
		}
		if ts, err := parseDBTime(updatedAt); err == nil {
			c.UpdatedAt = ts
		}
		clients = append(clients, &c)
	}
	return clients, rows.Err()
}
