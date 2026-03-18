package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/db"
)

// Job is a function that can be registered with the Scheduler.
type Job func(ctx context.Context) error

// Scheduler wraps robfig/cron with per-job distributed locking.
//
// PostgreSQL backend: uses pg_try_advisory_lock — safe across multiple replicas.
// SQLite backend:     uses an in-process sync.Mutex — single instance only.
type Scheduler struct {
	cron    *cron.Cron
	sqlDB   *sql.DB
	backend db.Backend
	logger  *zap.Logger
	ctx     context.Context
	cancel  context.CancelFunc

	// inMemoryLocks is used only for the SQLite backend.
	mu             sync.Mutex
	inMemoryLocks  map[uint32]bool
}

// New creates a Scheduler. Call Start() to begin executing jobs.
func New(sqlDB *sql.DB, backend db.Backend, logger *zap.Logger) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		cron:          cron.New(),
		sqlDB:         sqlDB,
		backend:       backend,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		inMemoryLocks: make(map[uint32]bool),
	}
}

// Register adds a named job with a cron expression.
func (s *Scheduler) Register(name, cronExpr string, job Job) {
	lockKey := lockKey(name)
	logger := s.logger.With(zap.String("job", name))

	_, err := s.cron.AddFunc(cronExpr, func() {
		ctx := s.ctx
		if ctx.Err() != nil {
			return
		}

		acquired, release, err := s.acquireLock(ctx, lockKey)
		if err != nil {
			logger.Error("failed to acquire lock", zap.Error(err))
			return
		}
		if !acquired {
			logger.Debug("job already running, skipping")
			return
		}
		defer release()

		logger.Info("job starting")
		if err := job(ctx); err != nil {
			logger.Error("job failed", zap.Error(err))
			return
		}
		logger.Info("job complete")
	})
	if err != nil {
		panic(fmt.Sprintf("scheduler: invalid cron expression %q for job %q: %v", cronExpr, name, err))
	}
}

// Start begins executing registered jobs.
func (s *Scheduler) Start() { s.cron.Start() }

// Stop gracefully shuts down the scheduler and waits for running jobs to finish.
func (s *Scheduler) Stop() {
	s.cancel()
	<-s.cron.Stop().Done()
}

// acquireLock dispatches to the backend-appropriate locking strategy.
func (s *Scheduler) acquireLock(ctx context.Context, key uint32) (bool, func(), error) {
	switch s.backend {
	case db.BackendSQLite:
		return s.acquireInMemoryLock(key)
	default:
		return s.acquireAdvisoryLock(ctx, int64(key))
	}
}

// acquireInMemoryLock uses a sync.Mutex for single-process SQLite deployments.
func (s *Scheduler) acquireInMemoryLock(key uint32) (bool, func(), error) {
	s.mu.Lock()
	if s.inMemoryLocks[key] {
		s.mu.Unlock()
		return false, nil, nil
	}
	s.inMemoryLocks[key] = true
	s.mu.Unlock()

	release := func() {
		s.mu.Lock()
		delete(s.inMemoryLocks, key)
		s.mu.Unlock()
	}
	return true, release, nil
}

// acquireAdvisoryLock uses PostgreSQL session-level advisory locks.
// Safe across multiple replicas — only one instance runs a given job at a time.
func (s *Scheduler) acquireAdvisoryLock(ctx context.Context, key int64) (bool, func(), error) {
	conn, err := s.sqlDB.Conn(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("acquiring connection for advisory lock: %w", err)
	}

	var acquired bool
	err = conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired)
	if err != nil {
		_ = conn.Close()
		return false, nil, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		return false, nil, nil
	}

	release := func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key)
		_ = conn.Close()
	}
	return true, release, nil
}

// lockKey derives a stable uint32 key from a job name using FNV-1a.
func lockKey(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte("cvera:" + name))
	return h.Sum32()
}
