package herald

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the header that carries the signature of a callback:
// "t=<unix seconds>,v1=<hex HMAC-SHA256>", the MAC taken with the producer's callback key over
// "<t>.<body>".
const SignatureHeader = "X-Herald-Signature"

// DefaultCallbackTolerance is how far a callback's timestamp may be from the receiver's clock.
const DefaultCallbackTolerance = 5 * time.Minute

// maxCallbackBody bounds what CallbackHandler reads of a request.
const maxCallbackBody = 64 << 10

// ErrBadSignature means a callback's signature is missing, malformed, does not match the body,
// or is older (or newer) than the tolerance allows.
var ErrBadSignature = errors.New("herald: callback signature does not verify")

// Callback is an answer to one of the producer's actions, as Herald posts it to the action's
// URL. ID identifies the answer: Herald may send the same callback more than once, and the
// producer acts on an ID only once.
type Callback struct {
	ID        string `json:"id"`
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	// Action is the action's key within its event, such as "approve".
	Action     string    `json:"action"`
	AnsweredAt time.Time `json:"answered_at"`
	// Channel is the channel the answer came through.
	Channel string `json:"channel"`
	// Subject is the producer's own name of the user who answered; empty when the answer came
	// from someone who is not one of the producer's users.
	Subject string `json:"subject,omitempty"`
	// Reply is the text of a reply action.
	Reply string `json:"reply,omitempty"`
}

// VerifyCallback checks the signature header of a callback body with the producer's callback
// key (shown in Herald's admin app), requires its timestamp to be within tolerance of now
// (DefaultCallbackTolerance when zero), and decodes the body.
func VerifyCallback(key, header string, body []byte, now time.Time, tolerance time.Duration) (Callback, error) {
	if tolerance <= 0 {
		tolerance = DefaultCallbackTolerance
	}
	if key == "" {
		return Callback{}, ErrBadSignature
	}
	var timestamp, signature string
	for part := range strings.SplitSeq(header, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch name {
		case "t":
			timestamp = value
		case "v1":
			signature = value
		}
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return Callback{}, ErrBadSignature
	}
	given, err := hex.DecodeString(signature)
	if err != nil {
		return Callback{}, ErrBadSignature
	}
	if !hmac.Equal(given, callbackMAC(key, timestamp, body)) {
		return Callback{}, ErrBadSignature
	}
	if age := now.Sub(time.Unix(seconds, 0)); age > tolerance || age < -tolerance {
		return Callback{}, ErrBadSignature
	}
	var callback Callback
	if err := json.Unmarshal(body, &callback); err != nil {
		return Callback{}, fmt.Errorf("herald: decode callback: %w", err)
	}
	if callback.ID == "" || callback.EventID == "" || callback.Action == "" {
		return Callback{}, errors.New("herald: decode callback: id, event_id or action is missing")
	}
	return callback, nil
}

// SignCallback returns the signature header for body, made at now. Herald signs this way; the
// function is here for the producer's own tests.
func SignCallback(key string, now time.Time, body []byte) string {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	return "t=" + timestamp + ",v1=" + hex.EncodeToString(callbackMAC(key, timestamp, body))
}

func callbackMAC(key, timestamp string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = io.WriteString(mac, timestamp+".")
	_, _ = mac.Write(body)
	return mac.Sum(nil)
}

// CallbackHandler returns a handler for the callback URL. It verifies and decodes the request
// and passes the callback to handle. It answers 204 when handle returns nil, 401 for a bad
// signature, 400 for a body that cannot be read or decoded, and 500 when handle fails, so that
// Herald tries again later. handle must be idempotent by Callback.ID.
func CallbackHandler(key string, handle func(ctx context.Context, callback Callback) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCallbackBody))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		callback, err := VerifyCallback(key, r.Header.Get(SignatureHeader), body, time.Now(), 0)
		switch {
		case errors.Is(err, ErrBadSignature):
			w.WriteHeader(http.StatusUnauthorized)
			return
		case err != nil:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := handle(r.Context(), callback); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
