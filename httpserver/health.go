package httpserver

import (
	"context"
	"fmt"
	"net/http"
)

// Response is one fixed answer of a health endpoint. There is no default: every existing service
// answers differently (204, "ok", a JSON object) and probes and dashboards depend on it, so the
// caller writes the answer out.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// ContentType is sent when Body is not empty.
	ContentType string
	// Body is sent as is; empty for a 204.
	Body string
}

func (r Response) validate(role string) {
	if r.Status < 100 || r.Status > 599 {
		panic(fmt.Sprintf("httpserver: %s response has no valid HTTP status (%d)", role, r.Status))
	}
}

func (r Response) write(w http.ResponseWriter) {
	if r.Body != "" && r.ContentType != "" {
		w.Header().Set("Content-Type", r.ContentType)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(r.Status)
	if r.Body != "" {
		// The status is sent; a client that hung up cannot be told anything more.
		_, _ = w.Write([]byte(r.Body))
	}
}

// Live returns the liveness handler: it always sends alive, because a process that can answer at
// all is alive. It panics when alive carries no HTTP status; that is a mistake in the wiring and
// shows at the first start.
func Live(alive Response) http.Handler {
	alive.validate("liveness")
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { alive.write(w) })
}

// Check reports whether the service can do its work right now, for example by pinging its
// database. It must respect ctx, which ends when the prober gives up.
type Check func(ctx context.Context) error

// Ready returns the readiness handler: ready when check returns nil, notReady otherwise. The
// error goes to onFailure (nil: dropped) and never into the response, so a probe from outside
// learns nothing about the inside. It panics on a nil check or a response without an HTTP status,
// as Live does.
func Ready(check Check, ready, notReady Response, onFailure func(error)) http.Handler {
	if check == nil {
		panic("httpserver: readiness handler needs a check")
	}
	ready.validate("ready")
	notReady.validate("not ready")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := check(r.Context()); err != nil {
			if onFailure != nil {
				onFailure(err)
			}
			notReady.write(w)
			return
		}
		ready.write(w)
	})
}
