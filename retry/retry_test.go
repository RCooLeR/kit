package retry

import (
	"context"
	"errors"
	"math"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

func TestNext(t *testing.T) {
	const floor, ceiling = 30 * time.Second, 5 * time.Minute
	tests := []struct {
		name     string
		previous time.Duration
		floor    time.Duration
		ceiling  time.Duration
		want     time.Duration
	}{
		{"first failure starts at the floor", 0, floor, ceiling, floor},
		{"doubles", time.Minute, floor, ceiling, 2 * time.Minute},
		{"doubling below the floor still gives the floor", 10 * time.Second, floor, ceiling, floor},
		{"stops at the ceiling", 4 * time.Minute, floor, ceiling, ceiling},
		{"stays at the ceiling", ceiling, floor, ceiling, ceiling},
		{"a ceiling below the floor is ignored", time.Hour, 10 * time.Minute, ceiling, 10 * time.Minute},
		{"a negative previous delay counts as none", -time.Hour, floor, ceiling, floor},
		{"the largest duration does not overflow", math.MaxInt64, floor, math.MaxInt64, math.MaxInt64},
		{"half the largest duration does not overflow", math.MaxInt64/2 + 1, floor, math.MaxInt64, math.MaxInt64},
		{"the lowest duration does not overflow", math.MinInt64, floor, ceiling, floor},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Next(tc.previous, tc.floor, tc.ceiling); got != tc.want {
				t.Fatalf("Next(%v, %v, %v) = %v, want %v", tc.previous, tc.floor, tc.ceiling, got, tc.want)
			}
		})
	}
}

func TestNextReachesTheCeilingAndStays(t *testing.T) {
	delay := time.Duration(0)
	var steps []time.Duration
	for range 6 {
		delay = Next(delay, time.Second, 10*time.Second)
		steps = append(steps, delay)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i := range want {
		if steps[i] != want[i] {
			t.Fatalf("backoff steps = %v, want %v", steps, want)
		}
	}
}

func TestJitterOnlyLengthensWithinTheSpread(t *testing.T) {
	const delay, spread = time.Minute, 10 * time.Second
	var sawLonger bool
	for range 1000 {
		got := Jitter(delay, spread)
		if got < delay || got > delay+spread {
			t.Fatalf("Jitter = %v, want a value in [%v, %v]", got, delay, delay+spread)
		}
		sawLonger = sawLonger || got > delay
	}
	if !sawLonger {
		t.Fatal("1000 draws never added anything: the spread is not applied")
	}
}

func TestJitterEdges(t *testing.T) {
	if got := Jitter(time.Minute, 0); got != time.Minute {
		t.Fatalf("no spread: Jitter = %v, want the delay unchanged", got)
	}
	if got := Jitter(time.Minute, -time.Second); got != time.Minute {
		t.Fatalf("negative spread: Jitter = %v, want the delay unchanged", got)
	}
	if got := Jitter(time.Minute, math.MaxInt64); got < time.Minute {
		t.Fatalf("largest spread: Jitter = %v overflowed below the delay", got)
	}
	if got := Jitter(math.MaxInt64, time.Hour); got != math.MaxInt64 {
		t.Fatalf("largest delay: Jitter = %v, want it capped", got)
	}
}

func TestSleepWaitsForTheDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		if err := Sleep(t.Context(), 90*time.Second); err != nil {
			t.Fatalf("Sleep: %v", err)
		}
		if waited := time.Since(start); waited != 90*time.Second {
			t.Fatalf("Sleep returned after %v, want 90s", waited)
		}
	})
}

func TestSleepEndsWithTheContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		start := time.Now()
		err := Sleep(ctx, time.Hour)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Sleep = %v, want the context's error", err)
		}
		if waited := time.Since(start); waited != 5*time.Second {
			t.Fatalf("Sleep returned after %v, want the context's 5s", waited)
		}
	})
}

func TestSleepWithoutDelayReturnsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Sleep(ctx, 0); err != nil {
		t.Fatalf("Sleep(0) on an ended context = %v, want nil: there is nothing to wait for", err)
	}
	if err := Sleep(ctx, -time.Second); err != nil {
		t.Fatalf("Sleep(-1s) = %v, want nil", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"seconds", "120", 2 * time.Minute},
		{"HTTP date in the future", now.Add(20 * time.Minute).Format(http.TimeFormat), 20 * time.Minute},
		{"HTTP date in the past", now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"HTTP date equal to now", now.Format(http.TimeFormat), 0},
		{"empty", "", 0},
		{"zero seconds", "0", 0},
		{"negative seconds", "-5", 0},
		{"fraction", "1.5", 0},
		{"words", "soon", 0},
		{"number beyond 32 bits", "99999999999", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseRetryAfter(tc.value, now); got != tc.want {
				t.Fatalf("ParseRetryAfter(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
