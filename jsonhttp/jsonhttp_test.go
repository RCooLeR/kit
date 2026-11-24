package jsonhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	value := map[string]any{"version": "1.4.0", "ready": true}
	if err := WriteJSON(recorder, http.StatusCreated, value); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if want := `{"ready":true,"version":"1.4.0"}` + "\n"; recorder.Body.String() != want {
		t.Fatalf("body = %q, want %q", recorder.Body.String(), want)
	}
}

// The envelope is a wire contract with @rcooler/http: this test pins it byte for byte.
func TestWriteErrorEnvelope(t *testing.T) {
	recorder := httptest.NewRecorder()
	if err := WriteError(recorder, http.StatusNotFound, "not_found", "not found"); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if want := `{"error":{"code":"not_found","message":"not found"}}` + "\n"; recorder.Body.String() != want {
		t.Fatalf("body = %q, want %q", recorder.Body.String(), want)
	}
}

func TestWriteJSONEscapesMarkup(t *testing.T) {
	recorder := httptest.NewRecorder()
	if err := WriteError(recorder, http.StatusBadRequest, "invalid_input", "<script>"); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	// encoding/json writes angle brackets as escapes, so the body is safe inside an HTML page too.
	if body := recorder.Body.String(); strings.ContainsAny(body, "<>") {
		t.Fatalf("body %q contains a raw angle bracket", body)
	}
	var decoded ErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if decoded.Error.Message != "<script>" {
		t.Fatalf("message decodes to %q, want the original text", decoded.Error.Message)
	}
}

func TestWriteJSONReportsAValueItCannotEncode(t *testing.T) {
	recorder := httptest.NewRecorder()
	if err := WriteJSON(recorder, http.StatusOK, map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("WriteJSON encoded a channel")
	}
}

type brokenWriter struct{ header http.Header }

func (w *brokenWriter) Header() http.Header       { return w.header }
func (w *brokenWriter) WriteHeader(int)           {}
func (w *brokenWriter) Write([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestWriteJSONReportsAConnectionFailure(t *testing.T) {
	if err := WriteJSON(&brokenWriter{header: http.Header{}}, http.StatusOK, "ok"); err == nil {
		t.Fatal("WriteJSON hid a failed write")
	}
}
