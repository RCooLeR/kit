package webauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const tokenBytes = 32

// NewToken returns a random secret for a session cookie or an API key, and the digest to store.
// Only the digest is kept, so a leaked database does not hand out working sessions or keys.
func NewToken() (plain string, hash []byte, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("read random token: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(raw)
	return plain, HashToken(plain), nil
}

// HashToken is the lookup key of a token: its SHA-256. Tokens are 256 random bits, so a plain
// digest is enough; a slow hash would only add load to every request.
func HashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

// EqualHash compares two token digests in constant time.
func EqualHash(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Limiter allows a fixed number of attempts per key in a time window. It guards the endpoints
// that accept guessable secrets (passwords, codes). State is in memory, which fits a
// single-instance service; a restart forgets the attempts.
//
// It holds at most maxBuckets keys. When fresh keys fill it, the key with attempts left and the
// fewest attempts made makes room; a key that has used its allowance is never forgotten before its
// window ends. When no key has attempts left, a new key is refused until a window ends.
type Limiter struct {
	maxAttempts int
	window      time.Duration
	now         func() time.Time

	mu      sync.Mutex // guards buckets; nothing slow happens under it
	buckets map[string]*bucket
}

type bucket struct {
	startedAt time.Time
	count     int
}

// maxBuckets bounds the memory an attacker can make the limiter hold by rotating keys.
const maxBuckets = 10_000

// NewLimiter allows maxAttempts per key in every window. now is the clock, time.Now outside tests.
func NewLimiter(maxAttempts int, window time.Duration, now func() time.Time) *Limiter {
	return &Limiter{maxAttempts: maxAttempts, window: window, now: now, buckets: make(map[string]*bucket)}
}

// Allow counts one attempt for key and reports whether it is within the limit.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil || now.Sub(b.startedAt) >= l.window {
		if b == nil && len(l.buckets) >= maxBuckets && !l.makeRoom(now) {
			return false
		}
		b = &bucket{startedAt: now}
		l.buckets[key] = b
	}
	b.count++
	return b.count <= l.maxAttempts
}

// Reset forgets the attempts of key, after a success. Reset only the key the success proves (the
// login that signed in): resetting a shared key such as the client's address would let anyone with
// one account clear the count of everyone guessing from that address.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// makeRoom frees one place for a new key: expired keys go first, then the key with attempts left
// and the fewest attempts made, the oldest of those. Forgetting a key with many attempts would hand
// them back, so a flood of fresh keys pushes out only its own kind. It reports false when no key has
// attempts left, which is the attempt to refuse.
func (l *Limiter) makeRoom(now time.Time) bool {
	var victim *bucket
	var victimKey string
	for key, b := range l.buckets {
		switch {
		case now.Sub(b.startedAt) >= l.window:
			delete(l.buckets, key)
		case b.count >= l.maxAttempts: // no attempts left: as good as blocked
		case victim == nil || b.count < victim.count || (b.count == victim.count && b.startedAt.Before(victim.startedAt)):
			victim, victimKey = b, key
		}
	}
	if len(l.buckets) < maxBuckets {
		return true
	}
	if victim == nil {
		return false
	}
	delete(l.buckets, victimKey)
	return true
}
