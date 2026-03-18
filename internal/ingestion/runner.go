package ingestion

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Runner coordinates multiple IngestionJobs.
// Each job runs independently; a failure in one does not block others.
type Runner struct {
	jobs   []IngestionJob
	logger *zap.Logger
}

// NewRunner creates a Runner with the given jobs.
func NewRunner(logger *zap.Logger, jobs ...IngestionJob) *Runner {
	return &Runner{
		jobs:   jobs,
		logger: logger,
	}
}

// RunAll executes all registered jobs sequentially.
// Returns the first error encountered, but always attempts all jobs.
func (r *Runner) RunAll(ctx context.Context) error {
	var firstErr error
	for _, job := range r.jobs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := job.Source().Name()
		r.logger.Info("starting ingestion job", zap.String("source", name))
		if err := job.Run(ctx); err != nil {
			r.logger.Error("ingestion job failed",
				zap.String("source", name),
				zap.Error(err),
			)
			if firstErr == nil {
				firstErr = fmt.Errorf("job %s: %w", name, err)
			}
			continue
		}
		r.logger.Info("ingestion job complete", zap.String("source", name))
	}
	return firstErr
}

// RunSource executes the job for a specific source name.
func (r *Runner) RunSource(ctx context.Context, sourceName string) error {
	for _, job := range r.jobs {
		if job.Source().Name() == sourceName {
			return job.Run(ctx)
		}
	}
	return fmt.Errorf("unknown source: %s", sourceName)
}
