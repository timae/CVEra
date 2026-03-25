package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/yourorg/cvera/internal/models"
)

type pgCheckpointRepository struct {
	db *sql.DB
}

func NewCheckpointRepository(db *sql.DB) CheckpointRepository {
	return &pgCheckpointRepository{db: db}
}

func (r *pgCheckpointRepository) Get(ctx context.Context, source string) (*models.IngestionCheckpoint, error) {
	query := `
		SELECT source_type, last_success_at, last_cursor, metadata
		FROM ingestion_checkpoints
		WHERE source_type = ?
	`
	query = rebindPlaceholders(r.db, query)

	var (
		cp         models.IngestionCheckpoint
		lastCursor sql.NullString
		metadata   string
		lastOK     any
	)
	err := r.db.QueryRowContext(ctx, query, source).Scan(&cp.SourceType, &lastOK, &lastCursor, &metadata)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	ts, err := parseDBTime(lastOK)
	if err != nil {
		return nil, err
	}
	cp.LastSuccessAt = &ts

	if lastCursor.Valid {
		cp.CheckpointData = []byte(lastCursor.String)
	}
	if metadata != "" {
		cp.Metadata = []byte(metadata)
	}
	return &cp, nil
}

func (r *pgCheckpointRepository) Save(ctx context.Context, cp *models.IngestionCheckpoint) error {
	if cp == nil {
		return errors.New("nil checkpoint")
	}
	lastSuccessAt := time.Now().UTC()
	if cp.LastSuccessAt != nil {
		lastSuccessAt = cp.LastSuccessAt.UTC()
	}
	lastCursor := ""
	if len(cp.CheckpointData) > 0 {
		lastCursor = string(cp.CheckpointData)
	}
	metadata := "{}"
	if len(cp.Metadata) > 0 {
		if !json.Valid(cp.Metadata) {
			return errors.New("checkpoint metadata must be valid JSON")
		}
		metadata = string(cp.Metadata)
	}

	query := `
		INSERT INTO ingestion_checkpoints (source_type, last_success_at, last_cursor, metadata)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(source_type) DO UPDATE SET
			last_success_at = excluded.last_success_at,
			last_cursor = excluded.last_cursor,
			metadata = excluded.metadata
	`
	query = rebindPlaceholders(r.db, query)

	_, err := r.db.ExecContext(ctx, query, cp.SourceType, formatDBTime(lastSuccessAt), nullableString(lastCursor), metadata)
	return err
}
