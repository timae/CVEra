package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

// Migrate runs all pending goose migrations for the given backend.
func Migrate(ctx context.Context, sqlDB *sql.DB, backend Backend) error {
	if err := goose.SetDialect(backend.GooseDialect()); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}
	goose.SetBaseFS(nil)
	if err := goose.UpContext(ctx, sqlDB, backend.MigrationsDir()); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// MigrateStatus prints the current migration state to stdout.
func MigrateStatus(ctx context.Context, sqlDB *sql.DB, backend Backend) error {
	if err := goose.SetDialect(backend.GooseDialect()); err != nil {
		return err
	}
	goose.SetBaseFS(nil)
	return goose.StatusContext(ctx, sqlDB, backend.MigrationsDir())
}

// MigrateDown rolls back the last applied migration.
func MigrateDown(ctx context.Context, sqlDB *sql.DB, backend Backend) error {
	if err := goose.SetDialect(backend.GooseDialect()); err != nil {
		return err
	}
	goose.SetBaseFS(nil)
	return goose.DownContext(ctx, sqlDB, backend.MigrationsDir())
}
