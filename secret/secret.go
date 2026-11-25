// Package secret resolves a secret that is configured either as a value or as a file holding it,
// the `X` and `X_FILE` pair every service repeats.
//
// Two modes exist because the existing services disagree and must not change behaviour when they
// adopt this package. New projects use Strict. The package reads no environment variable itself and
// knows no variable name: the caller passes both settings and the names to use in error messages.
// Whether a secret is required is also the caller's decision: with neither setting configured
// Resolve returns an empty string and no error.
package secret

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Mode selects how a value and a file are combined.
type Mode int

const (
	// Strict refuses a value together with a file, reads the file only when it is a regular file
	// reached without a symlink and within the size limit, and treats an empty secret as an error.
	Strict Mode = iota
	// Legacy keeps the precedence many existing services use: a non-blank value wins over the
	// file, the file is read without checks, and an empty file gives an empty secret.
	Legacy
)

// DefaultMaxBytes bounds a secret file in Strict mode when Input.MaxBytes is zero. It is far above
// any password, token or key file and far below anything that could exhaust memory.
const DefaultMaxBytes int64 = 64 << 10

// Errors a caller can test with errors.Is. They never carry the secret.
var (
	// ErrBothSet means the value and the file were configured together in Strict mode.
	ErrBothSet = errors.New("value and file are both configured")
	// ErrEmpty means the configured value or file holds nothing but white space.
	ErrEmpty = errors.New("secret is empty")
	// ErrNotRegularFile means the path is a symlink, a directory or a device, or changed while read.
	ErrNotRegularFile = errors.New("secret file is not a regular file")
	// ErrTooLarge means the file exceeds the size limit.
	ErrTooLarge = errors.New("secret file is too large")
)

// Input is one secret's configuration.
type Input struct {
	// Name and FileName are what the two settings are called in error messages, for example
	// "HERALD_DB_PASSWORD" and "HERALD_DB_PASSWORD_FILE".
	Name     string
	FileName string
	// Value is the secret itself when it was configured directly.
	Value string
	// Path is the file holding the secret; surrounding white space is ignored.
	Path string
	// MaxBytes limits the file in Strict mode; zero means DefaultMaxBytes.
	MaxBytes int64
}

// Resolve returns the secret, or an empty string when neither a value nor a file is configured.
// A value is returned unchanged. A file's content loses its trailing line break and nothing else, so
// a secret may contain spaces. Errors name the setting and, for a file that cannot be read, the
// path and the cause; they never contain the secret.
func Resolve(in Input, mode Mode) (string, error) {
	if mode == Legacy {
		return resolveLegacy(in)
	}
	path := strings.TrimSpace(in.Path)
	switch {
	case in.Value != "" && path != "":
		return "", fmt.Errorf("%s and %s: %w", in.Name, in.FileName, ErrBothSet)
	case in.Value != "":
		if strings.TrimSpace(in.Value) == "" {
			return "", fmt.Errorf("%s: %w", in.Name, ErrEmpty)
		}
		return in.Value, nil
	case path == "":
		return "", nil
	}
	value, err := readRegularFile(path, in.MaxBytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", in.FileName, err)
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s: %w", in.FileName, ErrEmpty)
	}
	return value, nil
}

// resolveLegacy is the reader of services that predate Strict: the value wins so an operator can
// override a mounted secret without touching the file.
func resolveLegacy(in Input) (string, error) {
	if strings.TrimSpace(in.Value) != "" {
		return in.Value, nil
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", in.FileName, err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// readRegularFile reads a bounded regular file without following a symlink. The file is checked
// before and after opening, so swapping it for a link in between is noticed.
func readRegularFile(path string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", ErrNotRegularFile
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }() // read-only: a close error loses nothing
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", ErrNotRegularFile
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > maxBytes {
		return "", fmt.Errorf("%w: more than %d bytes", ErrTooLarge, maxBytes)
	}
	// Windows editors and PowerShell 5.1 save UTF-8 with a byte order mark; it is no part of a
	// secret, and a password with it silently fails.
	return strings.TrimRight(strings.TrimPrefix(string(raw), "\ufeff"), "\r\n"), nil
}
