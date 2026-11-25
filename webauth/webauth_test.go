package webauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash %q is not in the PHC format with the current parameters", hash)
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("the hash contains the password")
	}

	if ok, err := VerifyPassword("correct horse battery staple", hash); err != nil || !ok {
		t.Fatalf("VerifyPassword with the right password = %t, %v", ok, err)
	}
	if ok, err := VerifyPassword("correct horse battery stapl", hash); err != nil || ok {
		t.Fatalf("VerifyPassword with a wrong password = %t, %v; want false without an error", ok, err)
	}

	again, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if again == hash {
		t.Fatal("two hashes of one password are equal: the salt is not random")
	}
}

func TestHashPasswordRefusesABlankPassword(t *testing.T) {
	for _, password := range []string{"", "   ", "\t\n"} {
		if _, err := HashPassword(password); err == nil {
			t.Fatalf("HashPassword(%q) succeeded", password)
		}
	}
}

// A hash made with other parameters, as an older release or another service wrote it, verifies.
func TestVerifyPasswordReadsTheParametersOfTheHash(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	key := argon2.IDKey([]byte("secret"), salt, 1, 8, 1, 16)
	stored := "$argon2id$v=19$m=8,t=1,p=1$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)

	if ok, err := VerifyPassword("secret", stored); err != nil || !ok {
		t.Fatalf("VerifyPassword of a hash with other parameters = %t, %v", ok, err)
	}
	if ok, err := VerifyPassword("other", stored); err != nil || ok {
		t.Fatalf("VerifyPassword with a wrong password = %t, %v", ok, err)
	}
}

func TestVerifyPasswordRejectsWhatIsNotAHash(t *testing.T) {
	tests := map[string]string{
		"empty":               "",
		"plain text":          "password",
		"bcrypt":              "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"argon2i":             "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$a2V5",
		"other version":       "$argon2id$v=16$m=65536,t=3,p=4$c2FsdA$a2V5",
		"unknown parameter":   "$argon2id$v=19$m=65536,t=3,x=4$c2FsdA$a2V5",
		"zero memory":         "$argon2id$v=19$m=0,t=3,p=4$c2FsdA$a2V5",
		"memory beyond bound": "$argon2id$v=19$m=4294967295,t=3,p=4$c2FsdA$a2V5",
		"time beyond bound":   "$argon2id$v=19$m=65536,t=1000,p=4$c2FsdA$a2V5",
		"threads over a byte": "$argon2id$v=19$m=65536,t=3,p=256$c2FsdA$a2V5",
		"salt is not base64":  "$argon2id$v=19$m=65536,t=3,p=4$!!!$a2V5",
		"key is not base64":   "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!",
		"empty key":           "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$",
		"text before the tag": "x$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$a2V5",
	}
	for name, hash := range tests {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword("secret", hash)
			if ok || !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("VerifyPassword = %t, %v; want false with ErrInvalidHash", ok, err)
			}
		})
	}
}

func TestNewToken(t *testing.T) {
	plain, hash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if len(plain) != 43 {
		t.Fatalf("token %q has %d characters, want 43 (256 bits in URL-safe base64)", plain, len(plain))
	}
	if len(hash) != 32 || !bytes.Equal(hash, HashToken(plain)) {
		t.Fatal("the returned digest is not the SHA-256 of the token")
	}
	other, otherHash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if other == plain || EqualHash(hash, otherHash) {
		t.Fatal("two tokens are equal")
	}
	if !EqualHash(hash, HashToken(plain)) {
		t.Fatal("EqualHash does not recognise the same digest")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(3, 10*time.Minute, func() time.Time { return now })

	for attempt := 1; attempt <= 3; attempt++ {
		if !limiter.Allow("owner") {
			t.Fatalf("attempt %d of 3 was refused", attempt)
		}
	}
	if limiter.Allow("owner") {
		t.Fatal("a fourth attempt inside the window was allowed")
	}
	if !limiter.Allow("someone else") {
		t.Fatal("another key was refused because of the first one")
	}

	now = now.Add(9 * time.Minute)
	if limiter.Allow("owner") {
		t.Fatal("an attempt was allowed before the window ended")
	}
	now = now.Add(2 * time.Minute)
	if !limiter.Allow("owner") {
		t.Fatal("an attempt after the window was refused")
	}

	for range 5 {
		limiter.Allow("reset me")
	}
	limiter.Reset("reset me")
	if !limiter.Allow("reset me") {
		t.Fatal("an attempt after Reset was refused")
	}
}

func TestLimiterBoundsItsMemory(t *testing.T) {
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(1, time.Minute, func() time.Time { return now })
	for i := range maxBuckets + 500 {
		limiter.Allow(string(rune('a'+i%26)) + time.Duration(i).String())
	}
	if got := len(limiter.buckets); got > maxBuckets {
		t.Fatalf("the limiter holds %d keys, more than its bound of %d", got, maxBuckets)
	}
}

// Filling the limiter with fresh keys must not set a blocked key free: the bound on memory would
// otherwise be a way around the limit.
func TestABlockedKeyStaysBlockedWhenTheLimiterFills(t *testing.T) {
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(3, 15*time.Minute, func() time.Time { return now })
	for range 4 {
		limiter.Allow("login:owner")
	}
	// One guess short of the limit, so the key is not blocked yet.
	for range 3 {
		limiter.Allow("login:admin")
	}
	for i := range maxBuckets + 10 {
		now = now.Add(time.Millisecond)
		limiter.Allow("login:guess-" + strconv.Itoa(i))
	}
	if limiter.Allow("login:owner") {
		t.Fatal("a blocked key was allowed again after fresh keys filled the limiter")
	}
	if limiter.Allow("login:admin") {
		t.Fatal("a key at its limit got fresh attempts after fresh keys filled the limiter")
	}
	if got := len(limiter.buckets); got > maxBuckets {
		t.Fatalf("the limiter holds %d keys, more than its bound of %d", got, maxBuckets)
	}
}

// With every bucket over its limit there is nothing to forget, so a new key waits until a window
// ends rather than the limiter growing or forgetting a blocked key.
func TestAFullLimiterOfBlockedKeysRefusesNewKeys(t *testing.T) {
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(1, time.Minute, func() time.Time { return now })
	for i := range maxBuckets {
		key := "address:" + strconv.Itoa(i)
		limiter.Allow(key)
		limiter.Allow(key)
	}
	if limiter.Allow("address:new") {
		t.Fatal("a new key was allowed although that meant forgetting a blocked one")
	}
	if limiter.Allow("address:0") {
		t.Fatal("a blocked key was allowed")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("address:new") {
		t.Fatal("a new key was refused after every window ended")
	}
}

func TestALimitOfNoAttemptsAllowsNone(t *testing.T) {
	limiter := NewLimiter(0, time.Minute, time.Now)
	if limiter.Allow("login:owner") {
		t.Fatal("a limiter of zero attempts allowed the first one")
	}
}
