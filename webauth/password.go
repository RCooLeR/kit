// Package webauth holds what a web service needs to let people and programs prove who they are:
// password hashes (argon2id), random tokens of which only a digest is stored, and a limiter for
// the endpoints that accept guessable secrets, and authenticator app TOTP.
//
// Storage, cookies and routes stay with the service: this package never reads a request and
// names no cookie, header or table.
package webauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters of new hashes. A stored hash carries its own, so they can be raised later without
// invalidating existing passwords.
const (
	argonMemoryKiB   uint32 = 64 * 1024
	argonIterations  uint32 = 3
	argonParallelism uint8  = 4
	argonSaltLength         = 16
	argonKeyLength          = 32
)

// Upper bounds for the parameters of a stored hash. Verifying costs what the hash says, so a
// corrupted or planted row must not be able to ask for gigabytes or minutes.
const (
	maxArgonMemoryKiB  = 1024 * 1024
	maxArgonIterations = 16
	maxArgonKeyLength  = 128
)

// ErrInvalidHash means the stored value is not an argon2id hash this package can verify.
var ErrInvalidHash = errors.New("invalid password hash")

// HashPassword returns the argon2id hash of password in the PHC string format
// ($argon2id$v=19$m=...,t=...,p=...$salt$key). An empty or blank password is refused.
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password is required")
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read random salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemoryKiB, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemoryKiB, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches encodedHash. A wrong password is (false, nil);
// an error means the stored hash itself is unusable (ErrInvalidHash).
//
// Each call holds the hash's memory (64 MiB with the defaults) for its duration, and the Limiter
// lets every new key try. A service on a small host should bound how many verifications run at
// once, for example with a buffered channel used as a semaphore around this call.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, ErrInvalidHash
	}
	params, err := parseParams(parts[3])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false, ErrInvalidHash
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 || len(expected) > maxArgonKeyLength {
		return false, ErrInvalidHash
	}
	keyLength := uint32(len(expected)) // bounded by maxArgonKeyLength above
	key := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, keyLength)
	return subtle.ConstantTimeCompare(key, expected) == 1, nil
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parseParams(value string) (argonParams, error) {
	var out argonParams
	for part := range strings.SplitSeq(value, ",") {
		name, number, found := strings.Cut(part, "=")
		if !found {
			return out, ErrInvalidHash
		}
		parsed, err := strconv.ParseUint(number, 10, 32)
		if err != nil {
			return out, ErrInvalidHash
		}
		switch name {
		case "m":
			out.memory = uint32(parsed)
		case "t":
			out.time = uint32(parsed)
		case "p":
			if parsed > 255 {
				return out, ErrInvalidHash
			}
			out.threads = uint8(parsed)
		default:
			return out, ErrInvalidHash
		}
	}
	if out.memory == 0 || out.time == 0 || out.threads == 0 ||
		out.memory > maxArgonMemoryKiB || out.time > maxArgonIterations {
		return out, ErrInvalidHash
	}
	return out, nil
}
