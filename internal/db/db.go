package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver for database/sql
	_ "modernc.org/sqlite"             // registers "sqlite" driver for database/sql

	"github.com/yourorg/cvera/internal/config"
)

// Backend identifies which database engine is in use.
type Backend string

const (
	BackendPostgres Backend = "postgres"
	BackendSQLite   Backend = "sqlite"
)

// GooseDialect returns the goose dialect string for this backend.
func (b Backend) GooseDialect() string {
	switch b {
	case BackendSQLite:
		return "sqlite3"
	default:
		return "postgres"
	}
}

// MigrationsDir returns the migration directory for this backend.
func (b Backend) MigrationsDir() string {
	candidates := []string{}
	switch b {
	case BackendSQLite:
		candidates = []string{"migrations/sqlite", "/migrations/sqlite"}
	default:
		candidates = []string{"migrations/postgres", "/migrations/postgres"}
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return filepath.Clean(candidates[0])
}

// Open creates a *sql.DB connected to the configured backend and verifies
// connectivity. The caller is responsible for calling db.Close().
//
// Backends:
//
//	"sqlite"   — single-file database, zero infrastructure, ideal for
//	             single-instance deployments and local development.
//	"postgres" — full PostgreSQL; supports multiple replicas with advisory
//	             locking. Requires a running PostgreSQL server.
func Open(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, Backend, error) {
	backend := Backend(cfg.Backend)
	if backend == "" {
		backend = BackendSQLite
	}

	var (
		sqlDB *sql.DB
		err   error
	)

	switch backend {
	case BackendSQLite:
		path := cfg.SQLitePath
		if path == "" {
			path = "cvera.db"
		}
		dsn := fmt.Sprintf(
			"file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on",
			path,
		)
		sqlDB, err = sql.Open("sqlite", dsn)
		if err != nil {
			return nil, "", fmt.Errorf("open sqlite %q: %w", path, err)
		}
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)

	case BackendPostgres:
		sqlDB, err = sql.Open("pgx", cfg.DSN())
		if err != nil {
			return nil, "", fmt.Errorf("open postgres: %w", err)
		}
		if cfg.MaxOpenConns > 0 {
			sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
		}
		if cfg.MaxIdleConns > 0 {
			sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
		}

	default:
		return nil, "", fmt.Errorf(
			"unknown database backend %q — use \"sqlite\" or \"postgres\"",
			backend,
		)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		return nil, "", fmt.Errorf("ping %s: %w", backend, err)
	}

	return sqlDB, backend, nil
}
