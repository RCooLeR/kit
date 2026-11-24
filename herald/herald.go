// Package herald is the client a producer uses to hand its notifications to Herald, the
// notification service. The producer decides that something happened; Herald decides who hears
// about it, on which channel and when.
//
// Send never loses an event because Herald is restarting or unreachable: an event that could not
// be delivered is written to a spool directory and replayed by Flush or Run. Every event carries
// an ID made here, and Herald treats a repeated ID as the same event, so a replay cannot notify
// twice. Send still reports ErrSpooled, so a producer of critical events can use its own direct
// fallback when Herald did not accept the event in time.
//
// The package depends on the standard library only.
package herald

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Severity says how bad an event is.
type Severity string

// Severities Herald accepts.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Urgency says how soon a person must see an event, apart from how bad it is.
type Urgency string

// Urgencies Herald accepts. An empty urgency means normal.
const (
	UrgencyLow    Urgency = "low"
	UrgencyNormal Urgency = "normal"
	UrgencyHigh   Urgency = "high"
)

// Audiences that are not explicit subjects. A topic is "topic:<name>".
const (
	AudienceOwner     = "owner"
	AudienceHousehold = "household"
)

// Action is a one-tap answer offered with a notification.
type Action struct {
	// ID names the action within its event: "approve", "deny".
	ID    string `json:"id"`
	Title string `json:"title"`
	// Kind is "open" (URL is the page to open), "callback" or "reply" (URL receives the answer).
	Kind string `json:"kind"`
	URL  string `json:"url"`
}

// Event is one notification request. Type, Severity and Audience are required, and either
// Template or Title.
type Event struct {
	// ID is a UUID; Send sets it when empty. Reusing an ID repeats the same event, harmlessly.
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	Urgency  Urgency  `json:"urgency,omitempty"`
	// Audience lists who should hear about it: "owner", "household", "topic:<name>", or the
	// producer's own subjects such as "shop/user:42".
	Audience []string `json:"audience"`
	// DedupeKey with DedupeWindowSeconds: the same key inside the window does not notify again.
	DedupeKey           string `json:"dedupe_key,omitempty"`
	DedupeWindowSeconds int    `json:"dedupe_window_seconds,omitempty"`
	// GroupKey makes later events replace earlier ones on the device; State "resolved" recovers.
	GroupKey string `json:"group_key,omitempty"`
	State    string `json:"state,omitempty"`
	// Template with Params is rendered by Herald in the recipient's language; Title, Body, URL and
	// Image are ready text.
	Template string         `json:"template,omitempty"`
	Params   map[string]any `json:"params,omitempty"`
	Locale   string         `json:"locale,omitempty"`
	Title    string         `json:"title,omitempty"`
	Body     string         `json:"body,omitempty"`
	URL      string         `json:"url,omitempty"`
	Image    string         `json:"image,omitempty"`
	// PublicPayload may pass through third-party push services; PrivatePayload stays in Herald
	// for the app to fetch after the tap.
	PublicPayload    map[string]any `json:"public_payload,omitempty"`
	PrivatePayload   map[string]any `json:"private_payload,omitempty"`
	Actions          []Action       `json:"actions,omitempty"`
	ExpiresAt        *time.Time     `json:"expires_at,omitempty"`
	QuietHoursBypass bool           `json:"quiet_hours_bypass,omitempty"`
	// OccurredAt is when it happened; Send sets it to now when zero.
	OccurredAt time.Time `json:"occurred_at"`
}

// Endpoint is one address of one of the producer's users, registered through the app's backend.
type Endpoint struct {
	// App is the token of the app the address belongs to, as registered in Herald.
	App string `json:"app"`
	// Subject is the producer's opaque name for the user: "shop/user:42".
	Subject string `json:"subject"`
	// Address is the push endpoint URL, the installation ID or the e-mail address.
	Address string `json:"address"`
	// Keys holds what the channel needs besides the address: Web Push "p256dh" and "auth".
	Keys   map[string]string `json:"keys,omitempty"`
	Locale string            `json:"locale,omitempty"`
	Label  string            `json:"label,omitempty"`
}

// ErrSpooled means Herald did not take the event now and it waits in the spool for a replay. It
// is wrapped together with the cause.
var ErrSpooled = errors.New("event spooled for a later attempt")

// RejectedError means Herald refused a request for good: a wrong key, an unknown event type, an
// invalid field. Trying again cannot succeed.
type RejectedError struct {
	// Status is the HTTP status; Code is Herald's stable error code, empty when it sent none.
	Status int
	Code   string
}

func (e *RejectedError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("herald rejected the request: HTTP %d", e.Status)
	}
	return fmt.Sprintf("herald rejected the request: HTTP %d (%s)", e.Status, e.Code)
}

// DefaultTimeout bounds one call when Options.Timeout is zero. It is short on purpose: a producer
// of critical events decides within seconds whether to use its fallback.
const DefaultTimeout = 5 * time.Second

// Options configure a Client.
type Options struct {
	// BaseURL is Herald's address, such as "http://herald:8080".
	BaseURL string
	// APIKey is the producer's key, issued by Herald.
	APIKey string
	// SpoolDir is where undelivered events wait. Empty disables the spool: Send then returns the
	// error itself.
	SpoolDir string
	// Timeout bounds one call; zero means DefaultTimeout.
	Timeout time.Duration
	// HTTPClient is used for the calls; nil means a client that follows no redirects, so the key
	// is never sent to another host.
	HTTPClient *http.Client
	// OnDrop is called when a spooled event is discarded because Herald rejected it for good or
	// its file was unreadable. Optional; meant for a log line.
	OnDrop func(eventID string, err error)
}

// Client sends events to one Herald. It is safe for concurrent use.
type Client struct {
	base    *url.URL
	apiKey  string
	timeout time.Duration
	http    *http.Client
	spool   *spool
	onDrop  func(eventID string, err error)
	now     func() time.Time
}

// New returns a client. The spool directory is created when it does not exist.
func New(opts Options) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(opts.BaseURL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("herald: BaseURL must be an http(s) URL")
	}
	if opts.APIKey == "" {
		return nil, errors.New("herald: APIKey is required")
	}
	client := &Client{
		base:    base,
		apiKey:  opts.APIKey,
		timeout: opts.Timeout,
		http:    opts.HTTPClient,
		onDrop:  opts.OnDrop,
		now:     time.Now,
	}
	if client.timeout <= 0 {
		client.timeout = DefaultTimeout
	}
	if client.http == nil {
		client.http = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if opts.SpoolDir != "" {
		if client.spool, err = openSpool(opts.SpoolDir); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// Send hands the event to Herald. It returns nil when Herald accepted it, a *RejectedError when
// Herald refused it for good, and an error wrapping ErrSpooled when Herald could not be reached
// or was busy and the event was written to the spool instead.
func (c *Client) Send(ctx context.Context, event Event) error {
	if event.ID == "" {
		id, err := newUUID()
		if err != nil {
			return err
		}
		event.ID = id
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = c.now().UTC()
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("herald: encode event: %w", err)
	}
	sendErr := c.post(ctx, http.MethodPost, "/v1/events", body)
	if sendErr == nil {
		return nil
	}
	if _, isRejected := errors.AsType[*RejectedError](sendErr); isRejected || c.spool == nil {
		return sendErr
	}
	if err := c.spool.put(c.now(), event.ID, body); err != nil {
		return errors.Join(sendErr, fmt.Errorf("herald: spool event: %w", err))
	}
	return fmt.Errorf("%w: %w", ErrSpooled, sendErr)
}

// Flush replays the spool, oldest first, and returns how many events Herald accepted. It stops
// at the first event Herald cannot take right now and returns that error; an event Herald
// rejects for good is dropped, reported to OnDrop, and the replay goes on.
func (c *Client) Flush(ctx context.Context) (int, error) {
	if c.spool == nil {
		return 0, nil
	}
	names, err := c.spool.list()
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range names {
		body, err := c.spool.read(name)
		if err != nil {
			c.drop(name, err)
			continue
		}
		err = c.post(ctx, http.MethodPost, "/v1/events", body)
		if _, isRejected := errors.AsType[*RejectedError](err); isRejected {
			c.drop(name, err)
			continue
		}
		if err != nil {
			return sent, err
		}
		if err := c.spool.remove(name); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (c *Client) drop(name string, cause error) {
	if c.onDrop != nil {
		c.onDrop(eventIDOf(name), cause)
	}
	// A file that cannot be removed is tried, and dropped, again at the next flush.
	_ = c.spool.remove(name)
}

// Run replays the spool every interval until ctx ends. A failed replay is tried again at the
// next tick; Run itself never fails.
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		// The error is the same "Herald is away" Send already reported; the next tick retries.
		_, _ = c.Flush(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// PutEndpoint registers or updates one address of one of the producer's users.
func (c *Client) PutEndpoint(ctx context.Context, endpoint Endpoint) error {
	body, err := json.Marshal(endpoint)
	if err != nil {
		return fmt.Errorf("herald: encode endpoint: %w", err)
	}
	return c.post(ctx, http.MethodPut, "/v1/endpoints", body)
}

// DeleteEndpoint removes an address, for example after the user signed out or switched
// notifications off. Removing an unknown address is not an error.
func (c *Client) DeleteEndpoint(ctx context.Context, app, address string) error {
	body, err := json.Marshal(map[string]string{"app": app, "address": address})
	if err != nil {
		return fmt.Errorf("herald: encode endpoint: %w", err)
	}
	return c.post(ctx, http.MethodDelete, "/v1/endpoints", body)
}

// maxErrorBody bounds what is read of an error answer.
const maxErrorBody = 4096

// post makes one call. It returns nil for a 2xx answer, *RejectedError for an answer that will
// not change on a retry, and a plain error for everything worth another attempt.
func (c *Client) post(ctx context.Context, method, path string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("herald: build request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		// The transport error quotes the URL, never the key.
		return fmt.Errorf("herald: %s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }() // the answer is read below; a close error changes nothing
	raw, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return nil
	case response.StatusCode == http.StatusTooManyRequests, response.StatusCode == http.StatusRequestTimeout,
		response.StatusCode >= 500:
		return fmt.Errorf("herald: %s %s: HTTP %d", method, path, response.StatusCode)
	default:
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &envelope) // an answer without the envelope leaves the code empty
		return &RejectedError{Status: response.StatusCode, Code: envelope.Error.Code}
	}
}

// newUUID returns a random (version 4) UUID.
func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("herald: read random event id: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
