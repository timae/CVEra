package repository

import (
	"context"
	"errors"

	"database/sql"
	"github.com/yourorg/cvera/internal/models"
)

type pgCheckpointRepository struct {
	db *sql.DB
}

func NewCheckpointRepository(db *sql.DB) CheckpointRepository {
	return &pgCheckpointRepository{db: db}
}

func (r *pgCheckpointRepository) Get(ctx context.Context, source string) (*models.IngestionCheckpoint, error) {
	// TODO: implement — SELECT * FROM ingestion_checkpoints WHERE source_type = $1
	// Returns a zero-value checkpoint (not an error) if no row exists yet.
	return nil, errors.New("not implemented")
}

func (r *pgCheckpointRepository) Save(ctx context.Context, cp *models.IngestionCheckpoint) error {
	// TODO: implement
	// INSERT INTO ingestion_checkpoints (...) VALUES (...)
	// ON CONFLICT (source_type) DO UPDATE SET
	//   last_run_at, last_success_at, checkpoint_data, error_count, last_error, updated_at
	return errors.New("not implemented")
}
