// Package mcpx serves an application's tools to MCP clients over the Model Context Protocol: one
// endpoint at /mcp, Streamable HTTP without sessions, behind a bearer key.
//
// It wraps the official Go SDK (github.com/modelcontextprotocol/go-sdk) with what every
// application would otherwise repeat:
//   - the key check of the cockpit summary: the key is the application's own, read from a file it
//     names; without a key the path answers 404, a wrong key 401, and the comparison takes
//     constant time. A key in the query string is never read;
//   - limits: the request body size and a deadline for each tool call;
//   - recovery: a panicking tool answers an error and the process keeps running;
//   - one report per tool call (tool, target, result, duration) for the application's log, which
//     never carries the call's arguments;
//   - errors a model can act on: only an [Error] reaches the client in its own words; any other
//     error, which may quote a database or a file, is replaced by a general message and handed to
//     the report instead;
//   - an in-memory client session for tests ([Server.Connect]; package mcpxtest builds on it).
//
// The tools are the application's: what they read and change, and that they go through the same
// checks as its web API. The package composes no tool names and no environment variable.
package mcpx

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RCooLeR/kit/jsonhttp"
)

// Path is where the endpoint is served.
const Path = "/mcp"

// Defaults of the limits in [Options].
const (
	DefaultMaxBodyBytes = 1 << 20
	DefaultTimeout      = 30 * time.Second
)

// Options configure a [Server].
type Options struct {
	// Name and Version identify the application to clients, such as its token and build version.
	Name    string
	Version string
	// Title is a display name; Instructions tell a model how the tools fit together. Both optional.
	Title        string
	Instructions string
	// Key is the bearer key, read from the application's key file. Empty makes the path answer 404.
	Key string
	// MaxBodyBytes limits a request body (413 above it); zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// Timeout is the deadline of one tool call; zero means DefaultTimeout.
	Timeout time.Duration
	// OnCall receives one report per tool call, for a log line; nil drops them.
	OnCall func(Call)
	// OnError receives a panic outside a tool call, for a log line; nil drops it.
	OnError func(error)
}

// Result is how a tool call ended.
type Result string

// Results of a tool call.
const (
	// ResultOK: the tool did what it was asked.
	ResultOK Result = "ok"
	// ResultRefused: the call was answered with an error the client sees in full: arguments that
	// do not fit the tool, an unknown tool, or an [Error] such as "not found".
	ResultRefused Result = "refused"
	// ResultFailed: the tool failed or panicked; the client sees a general message and Err holds
	// the cause.
	ResultFailed Result = "failed"
)

// Call reports one tool call. It never holds the call's arguments.
type Call struct {
	Tool string
	// ReadOnly is the tool's read-only annotation, so the log can tell reads from writes.
	ReadOnly bool
	// Target is what the tool named with [Target], such as the ID of the object it changed.
	Target   string
	Result   Result
	Duration time.Duration
	// Err is the cause of a refused or failed call.
	Err error
}

// Server is an application's MCP server: add its tools with [AddTool], then mount [Server.Handler]
// at [Path].
type Server struct {
	sdk      *mcp.Server
	opts     Options
	readOnly map[string]bool
}

// New makes a server without tools.
func New(opts Options) *Server {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.OnCall == nil {
		opts.OnCall = func(Call) {}
	}
	if opts.OnError == nil {
		opts.OnError = func(error) {}
	}
	s := &Server{opts: opts, readOnly: map[string]bool{}}
	s.sdk = mcp.NewServer(
		&mcp.Implementation{Name: opts.Name, Title: opts.Title, Version: opts.Version},
		// A non-nil Capabilities drops the logging capability the SDK would otherwise announce;
		// the tools capability is still inferred from the tools added.
		&mcp.ServerOptions{Instructions: opts.Instructions, Capabilities: &mcp.ServerCapabilities{}},
	)
	s.sdk.AddReceivingMiddleware(s.middleware)
	return s
}

// Read describes a tool that only reads the application's data.
func Read(name, description string) *mcp.Tool {
	return &mcp.Tool{
		Name: name, Description: description,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
	}
}

// Effect says what a write tool does beyond changing the application's own data.
type Effect struct {
	// Idempotent: calling the tool again with the same arguments changes nothing more.
	Idempotent bool
	// OpenWorld: the tool reaches outside the application, such as sending a message or starting
	// a download.
	OpenWorld bool
}

// Write describes a tool that changes data without deleting any.
func Write(name, description string, effect Effect) *mcp.Tool {
	return &mcp.Tool{
		Name: name, Description: description,
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: new(false), IdempotentHint: effect.Idempotent, OpenWorldHint: new(effect.OpenWorld),
		},
	}
}

// AddTool adds a tool with a typed handler, as the SDK's mcp.AddTool does, and wraps the handler:
// a panic or an error other than [Error] reaches the client as a general message, and the report
// of the call gets the cause.
func AddTool[In, Out any](s *Server, tool *mcp.Tool, handler mcp.ToolHandlerFor[In, Out]) {
	s.readOnly[tool.Name] = tool.Annotations != nil && tool.Annotations.ReadOnlyHint
	mcp.AddTool(s.sdk, tool, func(ctx context.Context, req *mcp.CallToolRequest, in In) (
		result *mcp.CallToolResult, out Out, err error,
	) {
		defer func() {
			if recovered := recover(); recovered != nil {
				recordOf(ctx).fail(fmt.Errorf("mcpx: tool %s panicked: %v\n%s", tool.Name, recovered, debug.Stack()))
				var zero Out
				result, out, err = nil, zero, errInternal
			}
		}()
		result, out, err = handler(ctx, req, in)
		if err == nil {
			return result, out, nil
		}
		var zero Out
		var public *Error
		switch {
		case errors.As(err, &public):
			recordOf(ctx).refuse(err)
			return nil, zero, public
		case ctx.Err() != nil && errors.Is(err, ctx.Err()):
			recordOf(ctx).fail(err)
			return nil, zero, &Error{Code: "timeout", Message: "the call did not finish in time"}
		default:
			recordOf(ctx).fail(err)
			return nil, zero, errInternal
		}
	})
}

// Target names the object a tool call acts on, such as the ID of a delivery it retries, for the
// report of the call. The last name given wins.
func Target(ctx context.Context, id string) {
	recordOf(ctx).target = id
}

// Error is an error the client sees in full: what went wrong in words a model can act on, never a
// secret. Return it from a tool for wrong arguments, a missing object or a refused change.
type Error struct {
	// Code is a short word for the kind, such as "not_found", or the web API's code for the case.
	Code    string
	Message string
}

// Error returns the code and the message.
func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

// Errorf makes an [Error] with the given code.
func Errorf(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Invalid reports arguments the application refuses, as its web API would with 400 or 422.
func Invalid(format string, args ...any) error {
	return Errorf("invalid", format, args...)
}

// NotFound reports an object that does not exist.
func NotFound(format string, args ...any) error {
	return Errorf("not_found", format, args...)
}

// Conflict reports a change the object's current state does not allow.
func Conflict(format string, args ...any) error {
	return Errorf("conflict", format, args...)
}

var errInternal = &Error{Code: "internal", Message: "the application could not complete the call; its log has the cause"}

// callRecord collects what a tool tells about its call while it runs.
type callRecord struct {
	target string
	result Result
	err    error
}

func (r *callRecord) refuse(err error) { r.result, r.err = ResultRefused, err }
func (r *callRecord) fail(err error)   { r.result, r.err = ResultFailed, err }

type recordKey struct{}

func recordOf(ctx context.Context) *callRecord {
	if record, ok := ctx.Value(recordKey{}).(*callRecord); ok {
		return record
	}
	return &callRecord{} // a handler called outside a server call: nothing reads this
}

// middleware gives every tool call its deadline, its record and its report, and turns a panic in
// any method into an error.
func (s *Server) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (result mcp.Result, err error) {
		if method != "tools/call" {
			defer func() {
				if recovered := recover(); recovered != nil {
					s.opts.OnError(fmt.Errorf("mcpx: %s panicked: %v\n%s", method, recovered, debug.Stack()))
					result, err = nil, errors.New("internal error")
				}
			}()
			return next(ctx, method, req)
		}
		record := &callRecord{}
		call := Call{Result: ResultOK}
		if params, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
			call.Tool, call.ReadOnly = params.Name, s.readOnly[params.Name]
		}
		ctx, cancel := context.WithTimeout(context.WithValue(ctx, recordKey{}, record), s.opts.Timeout)
		defer cancel()
		started := time.Now()
		defer func() {
			if recovered := recover(); recovered != nil {
				record.fail(fmt.Errorf("mcpx: tools/call panicked: %v\n%s", recovered, debug.Stack()))
				result, err = nil, errors.New("internal error")
			}
			call.Target, call.Duration = record.target, time.Since(started)
			switch toolResult, _ := result.(*mcp.CallToolResult); {
			case record.err != nil:
				call.Result, call.Err = record.result, record.err
			case err != nil:
				call.Result, call.Err = ResultRefused, err
			case toolResult != nil && toolResult.IsError:
				call.Result, call.Err = ResultRefused, toolResult.GetError()
			}
			s.opts.OnCall(call)
		}()
		return next(ctx, method, req)
	}
}

// Handler serves [Path]: the key check, then the SDK's Streamable HTTP transport without
// sessions, answering JSON. Mount it for every method; GET and DELETE answer 405.
//
// The SDK refuses a request that reaches the server on a loopback address with a Host header that
// is not loopback (DNS rebinding protection). A reverse proxy on the same machine must therefore
// forward the original loopback Host, or clients use the application's own address.
func (s *Server) Handler() http.Handler {
	keyDigest := sha256.Sum256([]byte(s.opts.Key))
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.sdk }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: s.opts.MaxBodyBytes,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler { //nolint:errorlint // the sentinel is re-panicked as net/http expects
					panic(recovered)
				}
				s.opts.OnError(fmt.Errorf("mcpx: request panicked: %v\n%s", recovered, debug.Stack()))
				_ = jsonhttp.WriteError(w, http.StatusInternalServerError, "internal", "internal error") // headers may be gone already
			}
		}()
		if s.opts.Key == "" {
			_ = jsonhttp.WriteError(w, http.StatusNotFound, "not_found", "not found") // nothing more to tell
			return
		}
		if !authorized(r, keyDigest) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			_ = jsonhttp.WriteError(w, http.StatusUnauthorized, "unauthorized", "send the MCP key")
			return
		}
		streamable.ServeHTTP(w, r)
	})
}

// authorized compares the bearer key with the expected one in constant time. Both sides are
// hashed first, so neither the comparison nor its length gives the key away.
func authorized(r *http.Request, keyDigest [sha256.Size]byte) bool {
	scheme, key, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || key == "" {
		return false
	}
	given := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(given[:], keyDigest[:]) == 1
}

// Connect opens a client session on the server in memory, for tests. Calls go through the same
// deadline, recovery and reports as over HTTP; there is no key check. Close the session when done.
func (s *Server) Connect(ctx context.Context) (*mcp.ClientSession, error) {
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := s.sdk.Connect(ctx, serverTransport, nil); err != nil {
		return nil, fmt.Errorf("mcpx: connect the server: %w", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpx-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		return nil, fmt.Errorf("mcpx: connect the client: %w", err)
	}
	return session, nil
}
