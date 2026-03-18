package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourorg/vulnmon/internal/models"
)

type pgCheckpointRepository struct {
	pool *pgxpool.Pool
}

func NewCheckpointRepository(pool *pgxpool.Pool) CheckpointRepository {
	return &pgCheckpointRepository{pool: pool}
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
