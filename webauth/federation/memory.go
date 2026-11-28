package federation

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrTooManyAttempts reports that a MemoryAttempts is full of attempts still waiting.
var ErrTooManyAttempts = errors.New("federation: too many attempts waiting")

// MemoryAttempts keeps attempts in memory, for an application that runs as one process: a restart
// drops the waiting attempts and their people start again.
type MemoryAttempts struct {
	mu      sync.Mutex
	limit   int
	expires map[[32]byte]time.Time
}

// NewMemoryAttempts holds at most limit waiting attempts; zero or less means 10,000.
func NewMemoryAttempts(limit int) *MemoryAttempts {
	if limit <= 0 {
		limit = 10_000
	}
	return &MemoryAttempts{limit: limit, expires: map[[32]byte]time.Time{}}
}

// Begin records an attempt, dropping expired ones first.
func (m *MemoryAttempts) Begin(_ context.Context, digest [32]byte, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.expires) >= m.limit {
		now := time.Now()
		for key, at := range m.expires {
			if !now.Before(at) {
				delete(m.expires, key)
			}
		}
		if len(m.expires) >= m.limit {
			return ErrTooManyAttempts
		}
	}
	m.expires[digest] = expires
	return nil
}

// Consume removes the attempt and reports whether it was waiting and not expired at now.
func (m *MemoryAttempts) Consume(_ context.Context, digest [32]byte, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	expires, ok := m.expires[digest]
	delete(m.expires, digest)
	return ok && now.Before(expires), nil
}
