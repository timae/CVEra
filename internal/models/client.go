package models

import (
	"time"

	"github.com/google/uuid"
)

// Client is a tenant. It is intentionally thin — no version state lives here.
// Version is a property of the catalog, not of each client.
type Client struct {
	ID        uuid.UUID         `db:"id"`
	Slug      string            `db:"slug"`
	Name      string            `db:"name"`
	Contact   string            `db:"contact"`
	Tags      map[string]string `db:"tags"`
	Active    bool              `db:"active"`
	CreatedAt time.Time         `db:"created_at"`
	UpdatedAt time.Time         `db:"updated_at"`
}
