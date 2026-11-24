// Package logx builds the one root logger of a service.
//
// The logger is a value the caller injects into its packages. This package never touches
// zerolog's global logger, global level or other package-level settings, so two loggers in one
// process (a server and its tests) cannot disturb each other. Field names and messages stay with
// the service.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Options configure the root logger.
type Options struct {
	// Level is a zerolog level name: trace, debug, info, warn or error. Empty means info.
	Level string
	// Console writes one readable line per event instead of JSON; for command line tools and local
	// runs. Services log JSON.
	Console bool
	// Writer receives the output; nil means os.Stderr, which leaves stdout for command output.
	Writer io.Writer
}

// New returns a logger that stamps every event with the time. An unknown level is an error, so a
// typing mistake in the configuration stops the start instead of silently logging at info.
func New(opts Options) (zerolog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return zerolog.Nop(), err
	}
	var writer io.Writer = os.Stderr
	if opts.Writer != nil {
		writer = opts.Writer
	}
	if opts.Console {
		writer = zerolog.ConsoleWriter{Out: writer, TimeFormat: time.RFC3339}
	}
	return zerolog.New(writer).Level(level).With().Timestamp().Logger(), nil
}

func parseLevel(name string) (zerolog.Level, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return zerolog.InfoLevel, nil
	}
	level, err := zerolog.ParseLevel(name)
	if err != nil {
		return zerolog.NoLevel, fmt.Errorf("unknown log level %q", name)
	}
	return level, nil
}

// Slog returns a log/slog logger that writes through logger, for libraries that log with slog.
// Their records come out in the service's format and obey its level.
func Slog(logger zerolog.Logger) *slog.Logger {
	return slog.New(zerolog.NewSlogHandler(logger))
}
