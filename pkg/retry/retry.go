package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"
)

// permanentError wraps an error that should not be retried.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent wraps err to signal that retry.Do should not retry this error.
func Permanent(err error) error { return &permanentError{err: err} }

// IsPermanent returns true if the error was wrapped with Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Do calls fn up to maxAttempts times, applying exponential backoff with jitter
// between attempts. Returns the last error if all attempts fail.
//
// Return retry.Permanent(err) from fn to stop retrying immediately.
// Context cancellation also stops retrying.
func Do(ctx context.Context, maxAttempts int, baseDelay, maxDelay time.Duration, fn func() error) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err = fn()
		if err == nil {
			return nil
		}
		if IsPermanent(err) {
			return errors.Unwrap(err)
		}

		if attempt == maxAttempts-1 {
			break
		}

		delay := backoff(attempt, baseDelay, maxDelay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}

// backoff calculates the delay for attempt n with full jitter.
// Formula: min(maxDelay, baseDelay * 2^n) * random(0, 1)
func backoff(attempt int, base, max time.Duration) time.Duration {
	exp := math.Pow(2, float64(attempt))
	delay := time.Duration(float64(base) * exp)
	if delay > max {
		delay = max
	}
	// Full jitter: random between 0 and delay
	jitter := time.Duration(rand.Int63n(int64(delay) + 1))
	return jitter
}
