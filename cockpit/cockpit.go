// Package cockpit serves an application's tile for a cockpit page that shows every application at
// a glance: GET /api/v1/cockpit with a bearer key, answering a small summary in Ukrainian and
// English.
//
// The key is the application's own, read from a file it names in its configuration. Without a key
// the path does not exist (404), so an application that was never connected to a cockpit shows
// nothing there. The key is compared in constant time. The summary is the application's: two
// numbers, an optional note and at most five items to look at, each with a path inside the
// application's own interface. It must not name people, addresses or secrets.
//
// The package depends on the standard library and the kit's jsonhttp only.
package cockpit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/RCooLeR/kit/jsonhttp"
)

// Path is where the summary is served.
const Path = "/api/v1/cockpit"

// MaxItems is how many items a summary holds at most, most important first.
const MaxItems = 5

// State says how the application is doing as a whole.
type State string

// States of a summary.
const (
	StateOK        State = "ok"
	StateAttention State = "attention"
	StateProblem   State = "problem"
)

// Tone colours a number or an item; empty is neutral.
type Tone string

// Tones of a number or an item.
const (
	ToneNone Tone = ""
	ToneOK   Tone = "ok"
	ToneWarn Tone = "warn"
	ToneBad  Tone = "bad"
)

// Text is one text in both languages of the cockpit.
type Text struct {
	UK string `json:"uk"`
	EN string `json:"en"`
}

// Number is one of the two figures on the tile, such as "9" open or "7/12" readings.
type Number struct {
	Value string `json:"value"`
	Label Text   `json:"label"`
	Tone  Tone   `json:"tone,omitempty"`
}

// Item is one thing worth a look, linking into the application.
type Item struct {
	// ID is stable for the same kind of item, so the cockpit can keep it in place between loads.
	ID     string `json:"id"`
	Tone   Tone   `json:"tone,omitempty"`
	Title  Text   `json:"title"`
	Detail *Text  `json:"detail,omitempty"`
	// Path is a path inside the application's own interface, such as "#/checklist".
	Path string `json:"path"`
}

// Summary is the answer of the cockpit path.
type Summary struct {
	// App is the application's token, such as "homeledger".
	App     string    `json:"app"`
	State   State     `json:"state"`
	Numbers [2]Number `json:"numbers"`
	Note    *Text     `json:"note,omitempty"`
	Items   []Item    `json:"items"`
	// GeneratedAt is when the summary was made; the handler sets it when it is zero.
	GeneratedAt time.Time `json:"generated_at"`
}

// Validate reports the first way the summary breaks the contract.
func (s Summary) Validate() error {
	if strings.TrimSpace(s.App) == "" {
		return errors.New("cockpit: app is required")
	}
	switch s.State {
	case StateOK, StateAttention, StateProblem:
	default:
		return fmt.Errorf("cockpit: unknown state %q", s.State)
	}
	for index, number := range s.Numbers {
		if strings.TrimSpace(number.Value) == "" {
			return fmt.Errorf("cockpit: number %d has no value", index+1)
		}
		if !validTone(number.Tone) {
			return fmt.Errorf("cockpit: number %d has an unknown tone %q", index+1, number.Tone)
		}
	}
	if len(s.Items) > MaxItems {
		return fmt.Errorf("cockpit: %d items, at most %d", len(s.Items), MaxItems)
	}
	for index, item := range s.Items {
		switch {
		case strings.TrimSpace(item.ID) == "":
			return fmt.Errorf("cockpit: item %d has no id", index+1)
		case !validTone(item.Tone):
			return fmt.Errorf("cockpit: item %d has an unknown tone %q", index+1, item.Tone)
		case !insideApp(item.Path):
			return fmt.Errorf("cockpit: item %d path must be a path inside the application", index+1)
		}
	}
	return nil
}

// insideApp reports whether path stays in the application: a hash route or a path on its own host.
func insideApp(path string) bool {
	if strings.HasPrefix(path, "#/") {
		return true
	}
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//")
}

func validTone(tone Tone) bool {
	switch tone {
	case ToneNone, ToneOK, ToneWarn, ToneBad:
		return true
	default:
		return false
	}
}

// Options configure the handler.
type Options struct {
	// Key is the bearer key, read from the application's key file. Empty makes the path answer 404.
	Key string
	// Summarize makes the summary; it must honour ctx.
	Summarize func(ctx context.Context) (Summary, error)
	// OnError receives a failed or invalid summary, for a log line; nil drops it. The caller sees
	// only a status.
	OnError func(err error)
	// Now is the clock for GeneratedAt; nil means time.Now.
	Now func() time.Time
}

// Handler serves Path. Mount it for GET on the application's mux.
func Handler(opts Options) http.Handler {
	keyDigest := sha256.Sum256([]byte(opts.Key))
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	report := opts.OnError
	if report == nil {
		report = func(error) {}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if opts.Key == "" {
			_ = jsonhttp.WriteError(w, http.StatusNotFound, "not_found", "not found") // nothing more to tell
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			_ = jsonhttp.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		if !authorized(r, keyDigest) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			_ = jsonhttp.WriteError(w, http.StatusUnauthorized, "unauthorized", "send the cockpit key")
			return
		}
		summary, err := opts.Summarize(r.Context())
		if err != nil {
			report(fmt.Errorf("cockpit summary: %w", err))
			_ = jsonhttp.WriteError(w, http.StatusServiceUnavailable, "unavailable", "the summary cannot be made now")
			return
		}
		if err := summary.Validate(); err != nil {
			report(err)
			_ = jsonhttp.WriteError(w, http.StatusInternalServerError, "internal", "the summary is not valid")
			return
		}
		if summary.Items == nil {
			summary.Items = []Item{}
		}
		if summary.GeneratedAt.IsZero() {
			summary.GeneratedAt = now().UTC()
		}
		_ = jsonhttp.WriteJSON(w, http.StatusOK, summary) // the status is sent; a broken connection is the client's
	})
}

// authorized compares the bearer key with the expected one in constant time. Both sides are
// hashed first, so neither the comparison nor its length gives the key away.
func authorized(r *http.Request, keyDigest [sha256.Size]byte) bool {
	value := r.Header.Get("Authorization")
	scheme, key, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || key == "" {
		return false
	}
	given := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(given[:], keyDigest[:]) == 1
}
