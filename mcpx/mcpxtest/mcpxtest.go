// Package mcpxtest helps an application test its MCP tools: an in-memory client session, tool
// calls read as text, and a check that no output carries a secret.
package mcpxtest

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RCooLeR/kit/mcpx"
)

// Connect opens an in-memory client session on server and closes it when the test ends.
func Connect(t testing.TB, server *mcpx.Server) *mcp.ClientSession {
	t.Helper()
	session, err := server.Connect(t.Context())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// Tools lists every tool the server offers.
func Tools(t testing.TB, session *mcp.ClientSession) []*mcp.Tool {
	t.Helper()
	var tools []*mcp.Tool
	for tool, err := range session.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		tools = append(tools, tool)
	}
	return tools
}

// Result is a tool call's answer as a test reads it.
type Result struct {
	// Text joins the text contents, which hold the error message of a failed call.
	Text string
	// Structured is the structured output as JSON, empty when the tool gave none.
	Structured string
	IsError    bool
}

// All is everything the client received, for checks that look at the whole answer.
func (r Result) All() string {
	return r.Text + "\n" + r.Structured
}

// Decode reads the structured output into v.
func (r Result) Decode(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.Structured), v); err != nil {
		t.Fatalf("decode %s: %v", r.Structured, err)
	}
}

// Call calls a tool and fails the test on a protocol error; a tool error comes back as IsError.
func Call(t testing.TB, session *mcp.ClientSession, name string, args any) Result {
	t.Helper()
	answer, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	var result Result
	result.IsError = answer.IsError
	var texts []string
	for _, content := range answer.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			texts = append(texts, text.Text)
		}
	}
	result.Text = strings.Join(texts, "\n")
	if answer.StructuredContent != nil {
		structured, err := json.Marshal(answer.StructuredContent)
		if err != nil {
			t.Fatalf("encode the structured output of %s: %v", name, err)
		}
		result.Structured = string(structured)
	}
	return result
}

// secretPatterns are shapes a secret usually has. They complement the known values a test plants
// in its fixtures, which FindSecret looks for exactly.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	// A JSON Web Token: three base64url parts, the first starting with {"
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+`),
	// Credentials in a URL, such as a database DSN.
	regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@"]+:[^/\s@"]+@`),
	// A password in a key=value connection string.
	regexp.MustCompile(`(?i)\bpassword=[^\s&"]+`),
	// A bearer header value.
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`),
	// A JSON field named like a secret with a value.
	regexp.MustCompile(`(?i)"(password|passwd|secret|secret_key|token|access_token|refresh_token|api_key|apikey|` +
		`private_key|client_secret|callback_key|dsn)"\s*:\s*"[^"]+"`),
}

// FindSecret returns the first part of text that equals one of the known secret values or looks
// like a secret, or "" when there is none. Known values shorter than 6 characters are ignored, as
// they would match ordinary words.
func FindSecret(text string, known ...string) string {
	for _, value := range known {
		if len(value) >= 6 && strings.Contains(text, value) {
			return value
		}
	}
	for _, pattern := range secretPatterns {
		if match := pattern.FindString(text); match != "" {
			return match
		}
	}
	return ""
}

// NoSecret fails the test when text holds one of the known secret values or something that looks
// like a secret. The message names where the text came from and only the start of the match.
func NoSecret(t testing.TB, where, text string, known ...string) {
	t.Helper()
	if match := FindSecret(text, known...); match != "" {
		t.Errorf("%s shows something secret: %q…", where, prefix(match, 12))
	}
}

func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
