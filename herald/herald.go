// Package herald is the client a producer uses to hand its notifications to Herald, the
// notification service. The producer decides that something happened; Herald decides who hears
// about it, on which channel and when.
//
// Send never loses an event because Herald is restarting, unreachable or refusing the producer
// (a rotated key, a route that is gone): an event that could not be delivered is written to a
// spool directory and replayed by Flush or Run. Only an event Herald refuses for its own content
// is dropped. Every event carries
// an ID made here, and Herald treats a repeated ID as the same event, so a replay cannot notify
// twice. Send still reports ErrSpooled, so a producer of critical events can use its own direct
// fallback when Herald did not accept the event in time.
//
// A tap on one of an event's actions comes back to the producer as a signed callback to the
// action's URL. CallbackHandler (or VerifyCallback) checks the signature with the producer's
// callback key and decodes it. A tap in the producer's own app (a Web Push or FCM notification)
// reaches the producer's backend first, which hands the token to Herald with ForwardAnswer.
// PutSettings keeps a user's language, time zone, quiet hours and preferences in Herald.
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
	"io/fs"
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
	// PublicPayload travels with the notification and may pass through third-party push services.
	// Herald never delivers PrivatePayload to anybody and does not keep it: it accepts the field
	// and drops it. An app shows details after a tap by fetching them from its own backend through
	// URL. Leave it empty.
	PublicPayload  map[string]any `json:"public_payload,omitempty"`
	PrivatePayload map[string]any `json:"private_payload,omitempty"`
	Actions        []Action       `json:"actions,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
	// QuietHoursBypass sends a critical event at once inside quiet hours and past an opt-out; on
	// an event of a lower severity it changes nothing.
	QuietHoursBypass bool `json:"quiet_hours_bypass,omitempty"`
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

// RejectedError means Herald refused what a request says: an invalid field, a body too large,
// an unknown app, a token that cannot be answered. Sending the same request again cannot succeed.
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

// AccessError means Herald, or a proxy in front of it, refused the producer rather than the
// request: a key Herald does not accept or a disabled producer (401), a 403, a route that is gone
// (404 without Herald's error code, as a proxy answers while Herald restarts) or a redirect. The
// request itself may be fine: once the key, the producer or the address is fixed, the same request
// succeeds, so Send spools the event and Flush keeps it. An event type the producer may not send
// is about that one event: Herald answers 422 type_not_allowed, a *RejectedError.
type AccessError struct {
	// Status is the HTTP status; Code is Herald's error code, empty when it sent none.
	Status int
	Code   string
}

func (e *AccessError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("herald refused the producer: HTTP %d", e.Status)
	}
	return fmt.Sprintf("herald refused the producer: HTTP %d (%s)", e.Status, e.Code)
}

// DefaultTimeout bounds one call when Options.Timeout is zero. It is short on purpose: a producer
// of critical events decides within seconds whether to use its fallback.
const DefaultTimeout = 5 * time.Second

// Options configure a Client.
type Options struct {
	// BaseURL is Herald's address, such as "http://herald:9099".
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
	// OnDrop is called when a spooled event is discarded because Herald rejected its content or
	// its file was unreadable. Optional; meant for a log line.
	OnDrop func(eventID string, err error)
	// OnAccessError is called by Run when the replay stops on an *AccessError: the spool keeps
	// growing until someone fixes the key, the producer or the address. It is called once when
	// that starts and again only after a replay got through. Optional; meant for a log line or an
	// alert.
	OnAccessError func(err error)
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
	// onAccessError reports a replay stopped by an *AccessError.
	onAccessError func(err error)
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

		onAccessError: opts.OnAccessError,
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
// Herald refused its content, and an error wrapping ErrSpooled when the event was written to the
// spool instead: Herald could not be reached, was busy, or refused the producer (an *AccessError,
// wrapped too).
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
// at the first event Herald cannot take right now and returns that error, an *AccessError
// included: the events stay spooled. An event Herald rejects for its content is dropped, reported
// to OnDrop, and the replay goes on.
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
		if errors.Is(err, fs.ErrNotExist) {
			continue // another Flush delivered it in the meantime
		}
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

// DefaultReplayInterval is how often Run replays the spool when it is given no interval.
const DefaultReplayInterval = 30 * time.Second

// Run replays the spool every interval until ctx ends; zero or less means DefaultReplayInterval.
// A failed replay is tried again at the next tick; Run itself never fails. A replay stopped by an
// *AccessError goes to OnAccessError.
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultReplayInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	refused := false
	for {
		// "Herald is away" is what Send already reported; the next tick retries.
		_, err := c.Flush(ctx)
		_, isAccess := errors.AsType[*AccessError](err)
		if isAccess && !refused && c.onAccessError != nil {
			c.onAccessError(err)
		}
		if isAccess || err == nil {
			refused = isAccess
		}
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
// notifications off. Nothing is sent there any more; what was sent stays in Herald's delivery log,
// and an answer to a notification still on the device still counts. Removing an unknown address
// is not an error.
func (c *Client) DeleteEndpoint(ctx context.Context, app, address string) error {
	body, err := json.Marshal(map[string]string{"app": app, "address": address})
	if err != nil {
		return fmt.Errorf("herald: encode endpoint: %w", err)
	}
	return c.post(ctx, http.MethodDelete, "/v1/endpoints", body)
}

// Preference is one choice of a user: whether events of a class reach a channel, and from which
// severity on. The most specific choice wins: an exact event type before "*", then an exact
// channel before "*".
type Preference struct {
	// EventClass is an event type, or "*" for every type.
	EventClass string `json:"event_class"`
	// Channel is "webpush", "telegram", "email", "fcm" or "ha_notify", or "*" for every channel.
	Channel string `json:"channel"`
	Enabled bool   `json:"enabled"`
	// MinSeverity, when set, holds back events below it.
	MinSeverity Severity `json:"min_severity,omitempty"`
}

// Settings are what a producer keeps in Herald for one of its users. Each call replaces all of
// them, the preferences included.
type Settings struct {
	// Subject is the producer's opaque name for the user, starting with the producer's token.
	Subject string `json:"subject"`
	// Locale is one of the languages Herald has templates in, such as "en"; empty keeps Herald's
	// default.
	Locale string `json:"locale,omitempty"`
	// TimeZone is an IANA zone name such as "America/New_York"; empty keeps Herald's default.
	TimeZone string `json:"time_zone,omitempty"`
	// QuietHoursStart and QuietHoursEnd are "HH:MM" local times, both or neither. Events that
	// arrive in between wait for the end, unless they are critical and the producer marked them as
	// bypassing quiet hours.
	QuietHoursStart string       `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd   string       `json:"quiet_hours_end,omitempty"`
	Preferences     []Preference `json:"preferences"`
}

// PutSettings stores the settings of one of the producer's users. The user needs no registered
// address yet.
func (c *Client) PutSettings(ctx context.Context, settings Settings) error {
	if settings.Preferences == nil {
		settings.Preferences = []Preference{}
	}
	body, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("herald: encode settings: %w", err)
	}
	return c.post(ctx, http.MethodPut, "/v1/preferences", body)
}

// ForwardedAnswer is what Herald recorded for an answer an app backend passed on.
type ForwardedAnswer struct {
	EventID string `json:"event_id"`
	// Action is the action's key within its event.
	Action string `json:"action"`
	// Kind is "callback" or "reply".
	Kind string `json:"kind"`
	// Channel is the channel of the notification that was answered ("webpush", "fcm").
	Channel string `json:"channel"`
}

// Codes of the RejectedError ForwardAnswer returns for a token that cannot be used.
const (
	CodeInvalidToken    = "invalid_token"
	CodeAlreadyAnswered = "already_answered"
	CodeExpired         = "expired"
)

// ForwardAnswer passes on the token of an action button a user tapped in the producer's own app
// (a Web Push or FCM notification) with the text of a reply action, empty for the other kinds.
// Herald accepts it only for a notification of one of the producer's apps, and only once: a
// repeat gets a *RejectedError with Code CodeAlreadyAnswered, a late tap CodeExpired, a token
// Herald does not know CodeInvalidToken. The producer then learns of the answer through its
// callback like for any other channel.
func (c *Client) ForwardAnswer(ctx context.Context, token, reply string) (ForwardedAnswer, error) {
	body, err := json.Marshal(map[string]string{"token": token, "reply": reply})
	if err != nil {
		return ForwardedAnswer{}, fmt.Errorf("herald: encode answer: %w", err)
	}
	var answer ForwardedAnswer
	err = c.call(ctx, http.MethodPost, "/v1/answers", body, &answer)
	return answer, err
}

// maxErrorBody bounds what is read of an answer.
const maxErrorBody = 4096

// post makes one call. It returns nil for a 2xx answer, *RejectedError for a refusal of what the
// request says, *AccessError for a refusal of the producer, and a plain error for everything
// worth another attempt.
func (c *Client) post(ctx context.Context, method, path string, body []byte) error {
	return c.call(ctx, method, path, body, nil)
}

// call makes one call like post and, for a 2xx answer with out set, decodes the answer into out.
func (c *Client) call(ctx context.Context, method, path string, body []byte, out any) error {
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
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("herald: %s %s: decode answer: %w", method, path, err)
			}
		}
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
		if refusesTheRequest(response.StatusCode, envelope.Error.Code) {
			return &RejectedError{Status: response.StatusCode, Code: envelope.Error.Code}
		}
		return &AccessError{Status: response.StatusCode, Code: envelope.Error.Code}
	}
}

// refusesTheRequest tells a refusal of what a request says from one of the producer. 400, 413 and
// 422 are about the body whoever answers; Herald answers an event type the producer may not send
// with 422 type_not_allowed, so one such event never holds up the others. 404, 409 and 410 are
// about the body only when Herald itself says why: a bare 404 is a route that is gone. Anything
// else (401, 403, 3xx) is about the producer's key or address.
func refusesTheRequest(status int, code string) bool {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return true
	case http.StatusNotFound, http.StatusConflict, http.StatusGone:
		return code != "" && code != "not_found"
	default:
		return false
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
