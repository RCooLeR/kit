package mcpx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RCooLeR/kit/mcpx"
	"github.com/RCooLeR/kit/mcpx/mcpxtest"
)

const testKey = "a-test-key-for-mcp"

type itemArgs struct {
	ID string `json:"id" jsonschema:"the item's ID"`
}

type item struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// calls collects the reports of a server's tool calls.
type calls struct {
	mu   sync.Mutex
	list []mcpx.Call
}

func (c *calls) add(call mcpx.Call) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, call)
}

func (c *calls) last(t *testing.T) mcpx.Call {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.list) == 0 {
		t.Fatal("no call was reported")
	}
	return c.list[len(c.list)-1]
}

// newServer is a server with one tool of each kind the tests need.
func newServer(t *testing.T, opts mcpx.Options) (*mcpx.Server, *calls) {
	t.Helper()
	reports := &calls{}
	opts.Name, opts.Version, opts.OnCall = "example", "test", reports.add
	server := mcpx.New(opts)
	mcpx.AddTool(server, mcpx.Read("get_item", "Reads one item by its ID."),
		func(_ context.Context, _ *mcp.CallToolRequest, args itemArgs) (*mcp.CallToolResult, item, error) {
			if args.ID != "1" {
				return nil, item{}, mcpx.NotFound("item %s does not exist", args.ID)
			}
			return nil, item{ID: "1", Title: "first"}, nil
		})
	mcpx.AddTool(server, mcpx.Write("rename_item", "Renames an item.", mcpx.Effect{Idempotent: true}),
		func(ctx context.Context, _ *mcp.CallToolRequest, args itemArgs) (*mcp.CallToolResult, item, error) {
			mcpx.Target(ctx, args.ID)
			return nil, item{ID: args.ID, Title: "renamed"}, nil
		})
	mcpx.AddTool(server, mcpx.Write("send_item", "Sends an item away.", mcpx.Effect{OpenWorld: true}),
		func(_ context.Context, _ *mcp.CallToolRequest, _ itemArgs) (*mcp.CallToolResult, item, error) {
			return nil, item{}, errors.New("dial postgres://app:hunter2-secret@db.example.test/app: refused")
		})
	mcpx.AddTool(server, mcpx.Write("break_item", "Panics.", mcpx.Effect{}),
		func(_ context.Context, _ *mcp.CallToolRequest, _ itemArgs) (*mcp.CallToolResult, item, error) {
			panic("hunter2-secret in a panic")
		})
	mcpx.AddTool(server, mcpx.Read("wait_item", "Waits until the call's deadline."),
		func(ctx context.Context, _ *mcp.CallToolRequest, _ itemArgs) (*mcp.CallToolResult, item, error) {
			<-ctx.Done()
			return nil, item{}, ctx.Err()
		})
	return server, reports
}

// bearer adds the key to every request of the SDK's HTTP client.
type bearer struct{ key string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.key)
	return http.DefaultTransport.RoundTrip(r)
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28",` +
	`"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`

// post sends a request and returns its status and headers; the body is closed here.
func post(t *testing.T, url, authorization, body string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header
}

func TestHandlerChecksTheKey(t *testing.T) {
	server, _ := newServer(t, mcpx.Options{})
	closed := httptest.NewServer(server.Handler())
	defer closed.Close()
	if status, _ := post(t, closed.URL+mcpx.Path, "Bearer "+testKey, initialize); status != http.StatusNotFound {
		t.Fatalf("without a key the status is %d, want 404", status)
	}

	server, _ = newServer(t, mcpx.Options{Key: testKey, MaxBodyBytes: 4096})
	open := httptest.NewServer(server.Handler())
	defer open.Close()
	for name, authorization := range map[string]string{
		"no header": "", "wrong key": "Bearer not-the-key", "other scheme": "Basic " + testKey, "empty key": "Bearer ",
	} {
		status, header := post(t, open.URL+mcpx.Path, authorization, initialize)
		if status != http.StatusUnauthorized || header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: status %d, WWW-Authenticate %q, want 401 Bearer", name, status, header.Get("WWW-Authenticate"))
		}
	}
	if status, _ := post(t, open.URL+mcpx.Path+"?key="+testKey, "", initialize); status != http.StatusUnauthorized {
		t.Errorf("a key in the query string got %d, want 401", status)
	}
	if status, _ := post(t, open.URL+mcpx.Path, "Bearer "+testKey, strings.Repeat(" ", 8192)+initialize); status !=
		http.StatusRequestEntityTooLarge {
		t.Errorf("a body over the limit got %d, want 413", status)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, open.URL+mcpx.Path, nil)
	req.Header.Set("Authorization", "bearer "+testKey) // the scheme is case-insensitive
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET got %d, want 405 (no sessions, no event stream)", resp.StatusCode)
	}
}

func TestHandlerServesToolsWithTheRightKey(t *testing.T) {
	server, reports := newServer(t, mcpx.Options{Key: testKey})
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL + mcpx.Path, HTTPClient: &http.Client{Transport: bearer{testKey}},
		MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect over HTTP: %v", err)
	}
	defer func() { _ = session.Close() }()
	if tools := mcpxtest.Tools(t, session); len(tools) != 5 {
		t.Fatalf("%d tools listed, want 5", len(tools))
	}
	result := mcpxtest.Call(t, session, "get_item", map[string]any{"id": "1"})
	var got item
	result.Decode(t, &got)
	if result.IsError || got.Title != "first" {
		t.Fatalf("get_item = %+v, want the first item", result)
	}
	if call := reports.last(t); call.Tool != "get_item" || !call.ReadOnly || call.Result != mcpx.ResultOK {
		t.Fatalf("report = %+v", call)
	}
}

func TestToolsCarryTheirAnnotations(t *testing.T) {
	server, _ := newServer(t, mcpx.Options{})
	tools := map[string]*mcp.ToolAnnotations{}
	for _, tool := range mcpxtest.Tools(t, mcpxtest.Connect(t, server)) {
		tools[tool.Name] = tool.Annotations
	}
	read, rename, send := tools["get_item"], tools["rename_item"], tools["send_item"]
	if !read.ReadOnlyHint || read.OpenWorldHint == nil || *read.OpenWorldHint {
		t.Errorf("get_item annotations = %+v, want read-only and closed", read)
	}
	if rename.ReadOnlyHint || !rename.IdempotentHint || rename.DestructiveHint == nil || *rename.DestructiveHint ||
		*rename.OpenWorldHint {
		t.Errorf("rename_item annotations = %+v, want an idempotent, non-destructive, closed write", rename)
	}
	if send.IdempotentHint || !*send.OpenWorldHint || *send.DestructiveHint {
		t.Errorf("send_item annotations = %+v, want an open-world, non-destructive write", send)
	}
}

func TestErrorsReachTheClientOnlyWhenPublic(t *testing.T) {
	server, reports := newServer(t, mcpx.Options{})
	session := mcpxtest.Connect(t, server)
	tests := []struct {
		tool   string
		args   any
		want   string
		result mcpx.Result
	}{
		{tool: "get_item", args: map[string]any{"id": "2"}, want: "not_found: item 2 does not exist", result: mcpx.ResultRefused},
		{tool: "send_item", args: map[string]any{"id": "1"}, want: "internal: ", result: mcpx.ResultFailed},
		{tool: "break_item", args: map[string]any{"id": "1"}, want: "internal: ", result: mcpx.ResultFailed},
		{tool: "get_item", args: map[string]any{"id": 7}, want: "id", result: mcpx.ResultRefused},
	}
	for _, tc := range tests {
		answer := mcpxtest.Call(t, session, tc.tool, tc.args)
		if !answer.IsError || !strings.Contains(answer.Text, tc.want) {
			t.Errorf("%s(%v) = %+v, want an error containing %q", tc.tool, tc.args, answer, tc.want)
		}
		mcpxtest.NoSecret(t, tc.tool, answer.All(), "hunter2-secret")
		call := reports.last(t)
		if call.Tool != tc.tool || call.Result != tc.result || call.Err == nil {
			t.Errorf("%s report = %+v, want %s with its cause", tc.tool, call, tc.result)
		}
	}
	reports.mu.Lock()
	failed, panicked := reports.list[1].Err, reports.list[2].Err
	reports.mu.Unlock()
	if !strings.Contains(failed.Error(), "hunter2-secret") {
		t.Error("the report of a failed call lost its cause")
	}
	if !strings.Contains(panicked.Error(), "panicked") {
		t.Errorf("the panic's report = %v, want its cause", panicked)
	}
	// The SDK answers an unknown tool with a protocol error or an error result; either is refused.
	if answer, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "no_such_tool"}); err == nil && !answer.IsError {
		t.Error("an unknown tool was answered without an error")
	}
	if call := reports.last(t); call.Tool != "no_such_tool" || call.Result != mcpx.ResultRefused {
		t.Errorf("unknown tool report = %+v, want refused", call)
	}
}

func TestACallHasADeadline(t *testing.T) {
	server, reports := newServer(t, mcpx.Options{Timeout: 50 * time.Millisecond})
	answer := mcpxtest.Call(t, mcpxtest.Connect(t, server), "wait_item", map[string]any{"id": "1"})
	if !answer.IsError || !strings.Contains(answer.Text, "timeout: ") {
		t.Fatalf("a call past its deadline = %+v, want a timeout error", answer)
	}
	if call := reports.last(t); call.Result != mcpx.ResultFailed || !errors.Is(call.Err, context.DeadlineExceeded) {
		t.Fatalf("report = %+v, want failed with the deadline", call)
	}
}

func TestAWriteReportsItsTarget(t *testing.T) {
	server, reports := newServer(t, mcpx.Options{})
	answer := mcpxtest.Call(t, mcpxtest.Connect(t, server), "rename_item", map[string]any{"id": "42"})
	if answer.IsError {
		t.Fatalf("rename_item = %+v", answer)
	}
	call := reports.last(t)
	if call.Tool != "rename_item" || call.ReadOnly || call.Target != "42" || call.Result != mcpx.ResultOK || call.Err != nil {
		t.Fatalf("report = %+v, want an ok write on 42", call)
	}
	if call.Duration <= 0 {
		t.Errorf("duration = %v", call.Duration)
	}
}
