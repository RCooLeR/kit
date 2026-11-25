package herald

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHerald records what the client sends and answers with a status the test switches.
type fakeHerald struct {
	server *httptest.Server

	mu       sync.Mutex // guards the fields below
	status   int
	body     string
	requests []recorded
}

type recorded struct {
	method string
	path   string
	auth   string
	event  Event
	raw    string
}

func newFakeHerald(t *testing.T) *fakeHerald {
	t.Helper()
	fake := &fakeHerald{status: http.StatusAccepted}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		request := recorded{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), raw: string(raw)}
		_ = json.Unmarshal(raw, &request.event)
		fake.mu.Lock()
		fake.requests = append(fake.requests, request)
		status, body := fake.status, fake.body
		fake.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeHerald) answer(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeHerald) seen() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func newClient(t *testing.T, fake *fakeHerald, spoolDir string) *Client {
	t.Helper()
	client, err := New(Options{BaseURL: fake.server.URL + "/", APIKey: "test-key", SpoolDir: spoolDir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func spooled(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func reading() Event {
	return Event{Type: "reading.submitted", Severity: SeverityInfo, Audience: []string{AudienceOwner}, Title: "Meter reading"}
}

func TestNewChecksItsOptions(t *testing.T) {
	for name, opts := range map[string]Options{
		"no URL":           {APIKey: "k"},
		"URL without host": {BaseURL: "herald:8080", APIKey: "k"},
		"other scheme":     {BaseURL: "ftp://herald", APIKey: "k"},
		"no key":           {BaseURL: "http://herald:8080"},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("New with %s succeeded", name)
		}
	}
}

func TestSendDeliversTheEventWithAnIDAndTheKey(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	client := newClient(t, fake, dir)

	if err := client.Send(t.Context(), reading()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	requests := fake.seen()
	if len(requests) != 1 {
		t.Fatalf("Herald saw %d requests, want 1", len(requests))
	}
	got := requests[0]
	if got.method != http.MethodPost || got.path != "/v1/events" || got.auth != "Bearer test-key" {
		t.Fatalf("request = %s %s with %q", got.method, got.path, got.auth)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(got.event.ID) {
		t.Fatalf("event id %q is not a version 4 UUID", got.event.ID)
	}
	if got.event.OccurredAt.IsZero() || time.Since(got.event.OccurredAt) > time.Minute {
		t.Fatalf("occurred_at = %v, want about now", got.event.OccurredAt)
	}
	if got.event.Type != "reading.submitted" || got.event.Audience[0] != "owner" {
		t.Fatalf("event = %+v", got.event)
	}
	if left := spooled(t, dir); len(left) != 0 {
		t.Fatalf("a delivered event was spooled: %v", left)
	}
}

func TestSendKeepsTheCallersIDAndTime(t *testing.T) {
	fake := newFakeHerald(t)
	client := newClient(t, fake, "")
	event := reading()
	event.ID = "0193562a-0000-7000-8000-000000000001"
	event.OccurredAt = time.Date(2026, time.November, 24, 10, 0, 0, 0, time.UTC)

	if err := client.Send(t.Context(), event); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := fake.seen()[0].event
	if got.ID != event.ID || !got.OccurredAt.Equal(event.OccurredAt) {
		t.Fatalf("Send changed the id or the time: %+v", got)
	}
}

func TestSendSpoolsWhenHeraldIsAwayAndFlushReplaysInOrder(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	client := newClient(t, fake, dir)
	// A clock that moves, so the two spool files sort in the order of the sends.
	tick := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { tick = tick.Add(time.Second); return tick }

	fake.answer(http.StatusServiceUnavailable, "")
	first, second := reading(), reading()
	first.Title, second.Title = "first", "second"
	for _, event := range []Event{first, second} {
		err := client.Send(t.Context(), event)
		if !errors.Is(err, ErrSpooled) {
			t.Fatalf("Send while Herald answers 503 = %v, want ErrSpooled", err)
		}
	}
	if left := spooled(t, dir); len(left) != 2 {
		t.Fatalf("spool holds %v, want two events", left)
	}

	// Still away: nothing is lost and nothing is sent twice.
	if sent, err := client.Flush(t.Context()); sent != 0 || err == nil {
		t.Fatalf("Flush while Herald is away = %d, %v", sent, err)
	}
	if left := spooled(t, dir); len(left) != 2 {
		t.Fatalf("a failed flush changed the spool: %v", left)
	}

	fake.answer(http.StatusAccepted, "")
	before := len(fake.seen())
	sent, err := client.Flush(t.Context())
	if err != nil || sent != 2 {
		t.Fatalf("Flush = %d, %v; want 2 events", sent, err)
	}
	replayed := fake.seen()[before:]
	if len(replayed) != 2 || replayed[0].event.Title != "first" || replayed[1].event.Title != "second" {
		t.Fatalf("replayed %+v, want first then second", replayed)
	}
	if left := spooled(t, dir); len(left) != 0 {
		t.Fatalf("spool after a full flush: %v", left)
	}
}

func TestAReplayCarriesTheSameIDAsTheFirstAttempt(t *testing.T) {
	fake := newFakeHerald(t)
	client := newClient(t, fake, t.TempDir())

	fake.answer(http.StatusBadGateway, "")
	if err := client.Send(t.Context(), reading()); !errors.Is(err, ErrSpooled) {
		t.Fatalf("Send = %v, want ErrSpooled", err)
	}
	fake.answer(http.StatusAccepted, "")
	if _, err := client.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	requests := fake.seen()
	if len(requests) != 2 || requests[0].event.ID == "" || requests[0].raw != requests[1].raw {
		t.Fatalf("the replay differs from the first attempt:\n%s\n%s", requests[0].raw, requests[1].raw)
	}
}

func TestSendSpoolsWhenNothingListens(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	client := newClient(t, fake, dir)
	fake.server.Close()

	if err := client.Send(t.Context(), reading()); !errors.Is(err, ErrSpooled) {
		t.Fatalf("Send to a closed port = %v, want ErrSpooled", err)
	}
	if left := spooled(t, dir); len(left) != 1 {
		t.Fatalf("spool holds %v, want one event", left)
	}
}

func TestSendReturnsARejectionAndDoesNotSpoolIt(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	client := newClient(t, fake, dir)
	fake.answer(http.StatusUnprocessableEntity, `{"error":{"code":"invalid_event","message":"type is not allowed"}}`)

	err := client.Send(t.Context(), reading())
	rejected, ok := errors.AsType[*RejectedError](err)
	if !ok || rejected.Status != http.StatusUnprocessableEntity || rejected.Code != "invalid_event" {
		t.Fatalf("Send = %v, want a RejectedError with the status and Herald's code", err)
	}
	if errors.Is(err, ErrSpooled) {
		t.Fatal("a rejected event was reported as spooled")
	}
	if left := spooled(t, dir); len(left) != 0 {
		t.Fatalf("a rejected event was spooled: %v", left)
	}
}

func TestWithoutASpoolSendReturnsTheFailure(t *testing.T) {
	fake := newFakeHerald(t)
	client := newClient(t, fake, "")
	fake.answer(http.StatusServiceUnavailable, "")

	err := client.Send(t.Context(), reading())
	if err == nil || errors.Is(err, ErrSpooled) {
		t.Fatalf("Send without a spool = %v, want the failure itself", err)
	}
	if sent, err := client.Flush(t.Context()); sent != 0 || err != nil {
		t.Fatalf("Flush without a spool = %d, %v", sent, err)
	}
}

func TestFlushDropsWhatHeraldRejectsAndGoesOn(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	var dropped []string
	client, err := New(Options{
		BaseURL: fake.server.URL, APIKey: "test-key", SpoolDir: dir,
		OnDrop: func(eventID string, _ error) { dropped = append(dropped, eventID) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fake.answer(http.StatusServiceUnavailable, "")
	event := reading()
	event.ID = "0193562a-0000-7000-8000-00000000000a"
	if err := client.Send(t.Context(), event); !errors.Is(err, ErrSpooled) {
		t.Fatalf("Send = %v", err)
	}
	// A file that is not an event at all, as a full disk could leave it.
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000001-broken.json"), nil, 0o600); err != nil {
		t.Fatalf("write broken file: %v", err)
	}

	fake.answer(http.StatusBadRequest, `{"error":{"code":"invalid_input","message":"no"}}`)
	sent, err := client.Flush(t.Context())
	if err != nil || sent != 0 {
		t.Fatalf("Flush = %d, %v", sent, err)
	}
	if len(dropped) != 2 || !strings.Contains(strings.Join(dropped, " "), event.ID) {
		t.Fatalf("dropped %v, want both the broken file and the rejected event", dropped)
	}
	if left := spooled(t, dir); len(left) != 0 {
		t.Fatalf("spool still holds %v", left)
	}
}

// Herald, or a proxy in front of it, refusing the producer says nothing about the events: a
// rotated key, a disabled producer, a type the key may no longer send, a route that is gone while
// Herald restarts. The spool keeps them for the replay once that is fixed.
func TestARefusedProducerKeepsItsSpool(t *testing.T) {
	for _, refusal := range []struct {
		status int
		body   string
	}{
		{http.StatusUnauthorized, `{"error":{"code":"unauthorized","message":"no"}}`},
		{http.StatusForbidden, `{"error":{"code":"type_not_allowed","message":"no"}}`},
		{http.StatusNotFound, "404 page not found"},
		{http.StatusFound, ""},
	} {
		t.Run(http.StatusText(refusal.status), func(t *testing.T) {
			fake := newFakeHerald(t)
			dir := t.TempDir()
			var dropped []string
			client, err := New(Options{
				BaseURL: fake.server.URL, APIKey: "test-key", SpoolDir: dir,
				OnDrop: func(eventID string, _ error) { dropped = append(dropped, eventID) },
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			fake.answer(http.StatusServiceUnavailable, "")
			if err := client.Send(t.Context(), reading()); !errors.Is(err, ErrSpooled) {
				t.Fatalf("Send = %v", err)
			}

			fake.answer(refusal.status, refusal.body)
			err = client.Send(t.Context(), reading())
			if _, isAccess := errors.AsType[*AccessError](err); !isAccess || !errors.Is(err, ErrSpooled) {
				t.Fatalf("Send while the producer is refused = %v, want ErrSpooled and the AccessError", err)
			}
			before := len(fake.seen())
			sent, err := client.Flush(t.Context())
			if _, isAccess := errors.AsType[*AccessError](err); sent != 0 || !isAccess {
				t.Fatalf("Flush while the producer is refused = %d, %v, want the AccessError", sent, err)
			}
			if after := len(fake.seen()); after != before+1 {
				t.Fatalf("Flush made %d calls after the refusal, want it to stop at the first", after-before-1)
			}
			if len(dropped) != 0 || len(spooled(t, dir)) != 2 {
				t.Fatalf("dropped %v, spool holds %v; want both events kept", dropped, spooled(t, dir))
			}

			fake.answer(http.StatusAccepted, "")
			if sent, err := client.Flush(t.Context()); sent != 2 || err != nil {
				t.Fatalf("Flush once the producer is let in = %d, %v, want both events", sent, err)
			}
		})
	}
}

// Run tells the producer once that its spool is stuck behind a refusal, not at every tick, and
// tells it again only after a replay got through in between.
func TestRunReportsARefusalOnce(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	var reports atomic.Int32
	client, err := New(Options{
		BaseURL: fake.server.URL, APIKey: "test-key", SpoolDir: dir,
		OnAccessError: func(error) { reports.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fake.answer(http.StatusServiceUnavailable, "")
	if err := client.Send(t.Context(), reading()); !errors.Is(err, ErrSpooled) {
		t.Fatalf("Send = %v", err)
	}
	fake.answer(http.StatusUnauthorized, `{"error":{"code":"unauthorized","message":"no"}}`)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		client.Run(ctx, time.Millisecond)
		close(done)
	}()
	waitFor(t, "several refused replays", func() bool { return len(fake.seen()) >= 6 })
	if got := reports.Load(); got != 1 {
		t.Fatalf("OnAccessError was called %d times, want once", got)
	}
	if left := spooled(t, dir); len(left) != 1 {
		t.Fatalf("spool holds %v, want the event kept", left)
	}
	fake.answer(http.StatusAccepted, "")
	waitFor(t, "the replay", func() bool { return len(spooled(t, dir)) == 0 })
	cancel()
	<-done
}

// Two replays at once (Run, and a Flush at shutdown) list the same files; the one that comes
// second must not report an event the first delivered as dropped.
func TestAnEventAnotherReplayDeliveredIsNotDropped(t *testing.T) {
	dir := t.TempDir()
	var spooling atomic.Bool
	spooling.Store(true)
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if spooling.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// While this event is delivered, the other replay delivers and removes the rest.
		once.Do(func() {
			entries, _ := os.ReadDir(dir)
			for _, entry := range entries[1:] {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
			}
		})
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	var dropped []string
	client, err := New(Options{
		BaseURL: server.URL, APIKey: "test-key", SpoolDir: dir,
		OnDrop: func(eventID string, _ error) { dropped = append(dropped, eventID) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for range 3 {
		if err := client.Send(t.Context(), reading()); !errors.Is(err, ErrSpooled) {
			t.Fatalf("Send = %v", err)
		}
	}
	spooling.Store(false)
	if sent, err := client.Flush(t.Context()); sent != 1 || err != nil {
		t.Fatalf("Flush = %d, %v, want the one event left to it", sent, err)
	}
	if len(dropped) != 0 {
		t.Fatalf("events another replay delivered were reported as dropped: %v", dropped)
	}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSpoolFilesArePrivateAndComplete(t *testing.T) {
	fake := newFakeHerald(t)
	dir := filepath.Join(t.TempDir(), "spool")
	client := newClient(t, fake, dir)
	fake.answer(http.StatusServiceUnavailable, "")

	event := reading()
	event.PrivatePayload = map[string]any{"note": "for the app only"}
	if err := client.Send(t.Context(), event); !errors.Is(err, ErrSpooled) {
		t.Fatalf("Send = %v", err)
	}
	names := spooled(t, dir)
	if len(names) != 1 || !strings.HasSuffix(names[0], ".json") {
		t.Fatalf("spool holds %v, want one .json file and no temporary one", names)
	}
	raw, err := os.ReadFile(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatalf("read spooled event: %v", err)
	}
	var stored Event
	if err := json.Unmarshal(raw, &stored); err != nil || stored.PrivatePayload["note"] != "for the app only" {
		t.Fatalf("spooled event is incomplete: %s (%v)", raw, err)
	}
	if strings.Contains(string(raw), "test-key") {
		t.Fatal("the API key was written to the spool")
	}
}

func TestRunFlushesUntilItsContextEnds(t *testing.T) {
	fake := newFakeHerald(t)
	dir := t.TempDir()
	client := newClient(t, fake, dir)
	fake.answer(http.StatusServiceUnavailable, "")
	if err := client.Send(t.Context(), reading()); !errors.Is(err, ErrSpooled) {
		t.Fatalf("Send = %v", err)
	}
	fake.answer(http.StatusAccepted, "")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		client.Run(ctx, time.Hour)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(spooled(t, dir)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run did not replay the spool")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestEndpointCalls(t *testing.T) {
	fake := newFakeHerald(t)
	client := newClient(t, fake, "")
	endpoint := Endpoint{
		App: "shop-web", Subject: "shop/user:42", Address: "https://push.example.test/abc",
		Keys: map[string]string{"p256dh": "p", "auth": "a"}, Locale: "en",
	}

	if err := client.PutEndpoint(t.Context(), endpoint); err != nil {
		t.Fatalf("PutEndpoint: %v", err)
	}
	if err := client.DeleteEndpoint(t.Context(), "shop-web", endpoint.Address); err != nil {
		t.Fatalf("DeleteEndpoint: %v", err)
	}
	requests := fake.seen()
	if requests[0].method != http.MethodPut || requests[0].path != "/v1/endpoints" ||
		!strings.Contains(requests[0].raw, `"subject":"shop/user:42"`) {
		t.Fatalf("PutEndpoint sent %s %s %s", requests[0].method, requests[0].path, requests[0].raw)
	}
	if requests[1].method != http.MethodDelete || requests[1].raw != `{"address":"https://push.example.test/abc","app":"shop-web"}` {
		t.Fatalf("DeleteEndpoint sent %s %s", requests[1].method, requests[1].raw)
	}

	fake.answer(http.StatusNotFound, `{"error":{"code":"unknown_app","message":"no such app"}}`)
	err := client.PutEndpoint(t.Context(), endpoint)
	if rejected, ok := errors.AsType[*RejectedError](err); !ok || rejected.Code != "unknown_app" {
		t.Fatalf("PutEndpoint with an unknown app = %v", err)
	}
}

func TestTheKeyIsNotSentToARedirectTarget(t *testing.T) {
	var elsewhere []string
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		elsewhere = append(elsewhere, r.Header.Get("Authorization"))
	}))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/events", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	client, err := New(Options{BaseURL: redirecting.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Send(t.Context(), reading()); err == nil {
		t.Fatal("Send through a redirect succeeded")
	}
	if len(elsewhere) != 0 {
		t.Fatalf("the client followed the redirect and sent %v", elsewhere)
	}
}
