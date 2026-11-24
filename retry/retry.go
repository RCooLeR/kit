// Package retry holds the small pieces every retry loop is built from: the next backoff delay, a
// random spread on top of it, a wait that ends with the context, and the Retry-After header.
//
// It is deliberately not a retry framework. Which errors are worth another attempt, how many
// attempts there are and what a provider's rejection means stay in the caller, where the
// protocol is known. A write whose outcome is unknown must not be repeated blindly; nothing here
// decides that for the caller.
package retry

import (
	"context"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Next returns the delay to wait after one more failure: twice the previous delay, never below
// floor and never above ceiling. A ceiling below the floor is ignored, so the floor always
// holds; it is the configured interval the caller would wait anyway.
func Next(previous, floor, ceiling time.Duration) time.Duration {
	ceiling = max(ceiling, floor)
	previous = max(previous, 0)
	doubled := ceiling
	if previous < ceiling/2+1 {
		// Doubling stays below the ceiling, so it cannot overflow either.
		doubled = previous * 2
	}
	return max(floor, min(doubled, ceiling))
}

// Jitter returns delay plus a random share of spread, so that clients which failed together do
// not come back together. It only ever lengthens: a backoff floor or a provider's Retry-After
// stays respected. A spread of zero or less returns delay unchanged.
func Jitter(delay, spread time.Duration) time.Duration {
	if spread <= 0 {
		return delay
	}
	var extra time.Duration
	if spread == math.MaxInt64 {
		// spread+1 would overflow the bound of Int64N.
		extra = time.Duration(rand.Int64()) //nolint:gosec // G404: a retry spread is not a secret
	} else {
		extra = time.Duration(rand.Int64N(int64(spread) + 1)) //nolint:gosec // G404: a retry spread is not a secret
	}
	if delay > math.MaxInt64-extra {
		return math.MaxInt64
	}
	return delay + extra
}

// Sleep waits for delay, or until ctx ends and then returns its error. A delay of zero or less
// returns at once with nil, even when ctx has already ended.
func Sleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ParseRetryAfter reads the value of a Retry-After header: whole seconds, or an HTTP date that
// is measured from now. It returns zero for an empty, malformed, non-positive or past value; the
// caller bounds a large one, since the sender chooses it.
func ParseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
