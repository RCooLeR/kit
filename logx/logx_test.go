package logx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func decodeLine(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		t.Fatalf("log line %q is not JSON: %v", line, err)
	}
	return event
}

func TestNewWritesJSONAtTheConfiguredLevel(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(Options{Level: "WARN", Writer: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info().Msg("below the level")
	if out.Len() != 0 {
		t.Fatalf("an info event passed a warn logger: %s", out.String())
	}

	logger.Warn().Str("component", "mqtt").Msg("poll failed")
	event := decodeLine(t, out.Bytes())
	if event["level"] != "warn" || event["message"] != "poll failed" || event["component"] != "mqtt" {
		t.Fatalf("unexpected event %v", event)
	}
	if _, ok := event["time"]; !ok {
		t.Fatalf("event %v has no timestamp", event)
	}
}

func TestNewDefaultsToInfo(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(Options{Writer: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Debug().Msg("hidden")
	logger.Info().Msg("shown")
	if lines := strings.Count(out.String(), "\n"); lines != 1 {
		t.Fatalf("got %d lines, want only the info event: %s", lines, out.String())
	}
}

func TestNewRejectsAnUnknownLevel(t *testing.T) {
	if _, err := New(Options{Level: "verbose"}); err == nil {
		t.Fatal("New accepted the level \"verbose\"")
	}
}

func TestNewLeavesTheGlobalLevelAlone(t *testing.T) {
	before := zerolog.GlobalLevel()
	if _, err := New(Options{Level: "error"}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if after := zerolog.GlobalLevel(); after != before {
		t.Fatalf("New changed zerolog's global level from %v to %v", before, after)
	}
}

func TestConsoleOutputIsNotJSON(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var out bytes.Buffer
	logger, err := New(Options{Console: true, Writer: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info().Str("addr", ":8080").Msg("listening")
	line := out.String()
	if strings.HasPrefix(line, "{") || !strings.Contains(line, "listening") || !strings.Contains(line, "addr=:8080") {
		t.Fatalf("console line %q is not the readable form", line)
	}
}

func TestSlogWritesThroughTheLogger(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(Options{Level: "info", Writer: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bridged := Slog(logger.With().Str("component", "library").Logger())

	bridged.Debug("hidden by the service level")
	if out.Len() != 0 {
		t.Fatalf("a debug record passed an info logger: %s", out.String())
	}
	bridged.Warn("retrying", "attempt", 2)
	event := decodeLine(t, out.Bytes())
	if event["level"] != "warn" || event["message"] != "retrying" || event["component"] != "library" || event["attempt"] != float64(2) {
		t.Fatalf("unexpected event %v", event)
	}
}
