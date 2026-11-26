package cockpit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var generated = time.Date(2026, time.November, 26, 13, 0, 0, 0, time.UTC)

func summary() Summary {
	return Summary{
		App:   "example",
		State: StateAttention,
		Numbers: [2]Number{
			{Value: "9", Label: Text{UK: "відкрито", EN: "open"}, Tone: ToneBad},
			{Value: "7/12", Label: Text{UK: "показників", EN: "readings"}},
		},
		Note: &Text{UK: "8 прострочено", EN: "8 overdue"},
		Items: []Item{{
			ID: "checklist-overdue", Tone: ToneBad, Path: "#/checklist",
			Title:  Text{UK: "8 прострочених рахунків", EN: "8 overdue bills"},
			Detail: &Text{UK: "три місця", EN: "three places"},
		}},
	}
}

func call(t *testing.T, handler http.Handler, method, auth string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, Path, nil)
	if auth != "" {
		request.Header.Set("Authorization", auth)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func fixed(s Summary) func(context.Context) (Summary, error) {
	return func(context.Context) (Summary, error) { return s, nil }
}

func TestTheSummaryNeedsTheKey(t *testing.T) {
	handler := Handler(Options{Key: "the-cockpit-key", Summarize: fixed(summary()), Now: func() time.Time { return generated }})
	for name, auth := range map[string]string{
		"no header":      "",
		"another scheme": "Basic dGhlLWNvY2twaXQta2V5",
		"wrong key":      "Bearer not-the-key",
		"key as prefix":  "Bearer the-cockpit-key-and-more",
		"empty bearer":   "Bearer ",
	} {
		recorder := call(t, handler, http.MethodGet, auth)
		if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: %d %q, want 401 with a Bearer challenge", name, recorder.Code, recorder.Header().Get("WWW-Authenticate"))
		}
		if strings.Contains(recorder.Body.String(), "the-cockpit-key") {
			t.Errorf("%s: the answer quotes the key", name)
		}
	}
}

func TestTheSummaryAnswersWithItsContract(t *testing.T) {
	handler := Handler(Options{Key: "the-cockpit-key", Summarize: fixed(summary()), Now: func() time.Time { return generated }})
	recorder := call(t, handler, http.MethodGet, "Bearer the-cockpit-key")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET = %d, Cache-Control %q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
	const want = `{"app":"example","state":"attention",` +
		`"numbers":[{"value":"9","label":{"uk":"відкрито","en":"open"},"tone":"bad"},{"value":"7/12","label":{"uk":"показників","en":"readings"}}],` +
		`"note":{"uk":"8 прострочено","en":"8 overdue"},` +
		`"items":[{"id":"checklist-overdue","tone":"bad","title":{"uk":"8 прострочених рахунків","en":"8 overdue bills"},` +
		`"detail":{"uk":"три місця","en":"three places"},"path":"#/checklist"}],"generated_at":"2026-11-26T13:00:00Z"}`
	if got := strings.TrimSpace(recorder.Body.String()); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestAnEmptySummaryHasEmptyItemsAndNoNote(t *testing.T) {
	s := summary()
	s.State, s.Note, s.Items = StateOK, nil, nil
	recorder := call(t, Handler(Options{Key: "k", Summarize: fixed(s)}), http.MethodGet, "Bearer k")
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if items, ok := body["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("items = %v, want an empty list", body["items"])
	}
	if _, hasNote := body["note"]; hasNote {
		t.Fatal("an absent note was sent")
	}
	if body["generated_at"] == "" || body["generated_at"] == "0001-01-01T00:00:00Z" {
		t.Fatalf("generated_at = %v, want the time of the answer", body["generated_at"])
	}
}

func TestWithoutAKeyTheSummaryDoesNotExist(t *testing.T) {
	handler := Handler(Options{Summarize: fixed(summary())})
	for _, auth := range []string{"", "Bearer ", "Bearer anything"} {
		if recorder := call(t, handler, http.MethodGet, auth); recorder.Code != http.StatusNotFound {
			t.Errorf("auth %q without a key file = %d, want 404", auth, recorder.Code)
		}
	}
}

func TestOnlyGetIsAnswered(t *testing.T) {
	handler := Handler(Options{Key: "k", Summarize: fixed(summary())})
	if recorder := call(t, handler, http.MethodPost, "Bearer k"); recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", recorder.Code)
	}
}

func TestAFailedSummaryIsAServerErrorWithoutItsText(t *testing.T) {
	var reported error
	handler := Handler(Options{
		Key: "k",
		Summarize: func(context.Context) (Summary, error) {
			return Summary{}, errors.New("database at db.internal refused")
		},
		OnError: func(err error) { reported = err },
	})
	recorder := call(t, handler, http.MethodGet, "Bearer k")
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "db.internal") {
		t.Fatalf("GET = %d %s, want 503 without the cause", recorder.Code, recorder.Body.String())
	}
	if reported == nil {
		t.Fatal("the failure was not reported to OnError")
	}
}

func TestASummaryOutsideTheContractIsRefused(t *testing.T) {
	for name, change := range map[string]func(*Summary){
		"no app":           func(s *Summary) { s.App = "" },
		"unknown state":    func(s *Summary) { s.State = "fine" },
		"unknown tone":     func(s *Summary) { s.Numbers[0].Tone = "red" },
		"number no value":  func(s *Summary) { s.Numbers[1].Value = "" },
		"item tone":        func(s *Summary) { s.Items[0].Tone = "loud" },
		"item without id":  func(s *Summary) { s.Items[0].ID = "" },
		"path outside app": func(s *Summary) { s.Items[0].Path = "https://elsewhere.example/" },
		"six items": func(s *Summary) {
			for len(s.Items) < 6 {
				s.Items = append(s.Items, s.Items[0])
			}
		},
	} {
		s := summary()
		change(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
		var reported error
		handler := Handler(Options{Key: "k", Summarize: fixed(s), OnError: func(err error) { reported = err }})
		if recorder := call(t, handler, http.MethodGet, "Bearer k"); recorder.Code != http.StatusInternalServerError || reported == nil {
			t.Errorf("%s: GET = %d, reported %v; want 500 and a report", name, recorder.Code, reported)
		}
	}
	if err := summary().Validate(); err != nil {
		t.Fatalf("Validate of a good summary: %v", err)
	}
}
