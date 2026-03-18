package scheduler

import (
	"context"
	"fmt"
	"hash/fnv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// Job is a function that can be registered with the Scheduler.
type Job func(ctx context.Context) error

// Scheduler wraps robfig/cron with per-job PostgreSQL advisory locks.
// If two replicas of the binary are running, only one will execute each job
// at a time — the second acquires the lock after the first releases it.
type Scheduler struct {
	cron   *cron.Cron
	pool   *pgxpool.Pool
	logger *zap.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a Scheduler. Call Start() to begin executing jobs.
func New(pool *pgxpool.Pool, logger *zap.Logger) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		cron:   cron.New(),
		pool:   pool,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Register adds a named job with a cron expression.
// The job name is used to derive the PostgreSQL advisory lock key.
// Example: Register("nvd_ingestion", "0 * * * *", myJobFn)
func (s *Scheduler) Register(name, cronExpr string, job Job) {
	lockKey := advisoryLockKey(name)
	logger := s.logger.With(zap.String("job", name))

	_, err := s.cron.AddFunc(cronExpr, func() {
		ctx := s.ctx
		if ctx.Err() != nil {
			return
		}

		acquired, release, err := acquireAdvisoryLock(ctx, s.pool, lockKey)
		if err != nil {
			logger.Error("failed to acquire advisory lock", zap.Error(err))
			return
		}
		if !acquired {
			logger.Debug("job already running on another instance, skipping")
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
		// cron expression syntax errors are programming mistakes, not runtime errors.
		panic(fmt.Sprintf("scheduler: invalid cron expression %q for job %q: %v", cronExpr, name, err))
	}
}

// Start begins executing registered jobs. Blocks until Stop() is called.
func (s *Scheduler) Start() {
	s.cron.Start()
}

// Stop gracefully shuts down the scheduler and waits for running jobs to complete.
func (s *Scheduler) Stop() {
	s.cancel()
	<-s.cron.Stop().Done()
}

// acquireAdvisoryLock attempts to acquire a PostgreSQL session-level advisory lock.
// Returns (true, releaseFn, nil) if acquired, (false, nil, nil) if already held.
func acquireAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, key int64) (bool, func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("acquiring connection for advisory lock: %w", err)
	}

	var acquired bool
	err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired)
	if err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}

	if !acquired {
		conn.Release()
		return false, nil, nil
	}

	release := func() {
		// Release the lock and return the connection to the pool.
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", key)
		conn.Release()
	}

	return true, release, nil
}

// advisoryLockKey derives a stable int64 lock key from a job name using FNV-1a.
// The same name always produces the same key across restarts and replicas.
func advisoryLockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("cvera:" + name))
	// Convert to int64 — PostgreSQL advisory locks use int8 (signed 64-bit).
	return int64(h.Sum64())
}
