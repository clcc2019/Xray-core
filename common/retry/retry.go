package retry // import "github.com/xtls/xray-core/common/retry"

import (
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var ErrRetryFailed = errors.New("all retry attempts failed")

// Strategy is a way to retry on a specific function.
type Strategy interface {
	// On performs a retry on a specific function, until it doesn't return any error.
	On(func() error) error
}

// errorSlicePool pools error slices to reduce allocations during retries
var errorSlicePool = sync.Pool{
	New: func() interface{} {
		s := make([]error, 0, 8) // Most retry scenarios have < 8 unique errors
		return &s
	},
}

type retryer struct {
	totalAttempt int
	nextDelay    func() uint32
}

// On implements Strategy.On.
func (r *retryer) On(method func() error) error {
	attempt := 0

	// Get error slice from pool
	errSlicePtr := errorSlicePool.Get().(*[]error)
	accumulatedError := (*errSlicePtr)[:0]
	defer func() {
		// Clear references before returning to pool
		for i := range accumulatedError {
			accumulatedError[i] = nil
		}
		*errSlicePtr = accumulatedError[:0]
		errorSlicePool.Put(errSlicePtr)
	}()

	for attempt < r.totalAttempt {
		err := method()
		if err == nil {
			return nil
		}
		numErrors := len(accumulatedError)
		if numErrors == 0 || err.Error() != accumulatedError[numErrors-1].Error() {
			accumulatedError = append(accumulatedError, err)
		}
		delay := r.nextDelay()
		time.Sleep(time.Duration(delay) * time.Millisecond)
		attempt++
	}

	// Make a copy of errors for the final error message
	// since we're returning the slice to the pool
	finalErrors := make([]error, len(accumulatedError))
	copy(finalErrors, accumulatedError)
	return errors.New(finalErrors).Base(ErrRetryFailed)
}

// Timed returns a retry strategy with fixed interval.
func Timed(attempts int, delay uint32) Strategy {
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			return delay
		},
	}
}

func ExponentialBackoff(attempts int, delay uint32) Strategy {
	nextDelay := uint32(0)
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			r := nextDelay
			nextDelay += delay
			return r
		},
	}
}
