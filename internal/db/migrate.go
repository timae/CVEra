package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx stdlib driver for goose
	"github.com/pressly/goose/v3"
)

// Migrate runs all pending goose migrations in the given directory.
func Migrate(ctx context.Context, dsn, migrationsDir string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("opening db for migration: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(nil) // use OS filesystem
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	return nil
}

// MigrateStatus prints the current migration status to stdout.
func MigrateStatus(ctx context.Context, dsn, migrationsDir string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("opening db: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	return goose.StatusContext(ctx, db, migrationsDir)
}

// MigrateDown rolls back the last applied migration.
func MigrateDown(ctx context.Context, dsn, migrationsDir string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("opening db: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	return goose.DownContext(ctx, db, migrationsDir)
}
