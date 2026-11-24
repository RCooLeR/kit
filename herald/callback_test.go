package herald

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const callbackKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

var signedAt = time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)

const callbackBody = `{"id":"0193562a-0000-7000-8000-000000000001","event_id":"0193562a-0000-7000-8000-000000000002",` +
	`"event_type":"time.requested","action":"approve","answered_at":"2026-11-24T11:59:58Z","channel":"telegram",` +
	`"subject":"shop/user:42"}`

func TestSignCallbackMatchesAKnownValue(t *testing.T) {
	// Computed independently (Python hmac): HMAC-SHA256 with the key as text over "1795521600." + body.
	got := SignCallback("key", time.Unix(1795521600, 0), []byte(`{"id":"x"}`))
	const want = "t=1795521600,v1=47ae3dd8398d15bcab823fa1b921d7801607c869d1a123ea92f17c0d3f141a09"
	if got != want {
		t.Fatalf("SignCallback = %q, want %q", got, want)
	}
	if _, err := VerifyCallback("key", got, []byte(`{"id":"x","event_id":"e","action":"a"}`), time.Unix(1795521600, 0), 0); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a signature over another body verified: %v", err)
	}
}

func TestVerifyCallback(t *testing.T) {
	header := SignCallback(callbackKey, signedAt, []byte(callbackBody))
	callback, err := VerifyCallback(callbackKey, header, []byte(callbackBody), signedAt.Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("VerifyCallback: %v", err)
	}
	if callback.Action != "approve" || callback.Subject != "shop/user:42" || callback.Channel != "telegram" ||
		!callback.AnsweredAt.Equal(time.Date(2026, time.November, 24, 11, 59, 58, 0, time.UTC)) {
		t.Fatalf("callback = %+v", callback)
	}

	bad := []struct {
		name, key, header, body string
		now                     time.Time
	}{
		{"wrong key", strings.Repeat("a", 64), header, callbackBody, signedAt},
		{"changed body", callbackKey, header, strings.Replace(callbackBody, "approve", "deny", 1), signedAt},
		{"too old", callbackKey, header, callbackBody, signedAt.Add(6 * time.Minute)},
		{"from the future", callbackKey, header, callbackBody, signedAt.Add(-6 * time.Minute)},
		{"no header", callbackKey, "", callbackBody, signedAt},
		{"no MAC", callbackKey, "t=1795521600", callbackBody, signedAt},
		{"MAC not hex", callbackKey, "t=1795521600,v1=zz", callbackBody, signedAt},
		{"empty key", "", header, callbackBody, signedAt},
	}
	for _, tc := range bad {
		if _, err := VerifyCallback(tc.key, tc.header, []byte(tc.body), tc.now, 0); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: VerifyCallback = %v, want ErrBadSignature", tc.name, err)
		}
	}

	incomplete := `{"id":"x","event_id":"y"}`
	if _, err := VerifyCallback(callbackKey, SignCallback(callbackKey, signedAt, []byte(incomplete)), []byte(incomplete), signedAt, 0); err == nil || errors.Is(err, ErrBadSignature) {
		t.Fatalf("a signed body without an action = %v, want a decode error", err)
	}
}

func TestCallbackHandler(t *testing.T) {
	var handled []Callback
	fail := false
	handler := CallbackHandler(callbackKey, func(_ context.Context, callback Callback) error {
		if fail {
			return errors.New("database down")
		}
		handled = append(handled, callback)
		return nil
	})
	send := func(method, header, body string) int {
		request := httptest.NewRequest(method, "/herald/answers", strings.NewReader(body))
		if header != "" {
			request.Header.Set(SignatureHeader, header)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	signed := SignCallback(callbackKey, time.Now(), []byte(callbackBody))

	if code := send(http.MethodPost, signed, callbackBody); code != http.StatusNoContent || len(handled) != 1 || handled[0].Action != "approve" {
		t.Fatalf("a good callback = %d, handled %+v", code, handled)
	}
	if code := send(http.MethodPost, "t=1,v1=00", callbackBody); code != http.StatusUnauthorized {
		t.Fatalf("a bad signature = %d, want 401", code)
	}
	notJSON := "not json"
	if code := send(http.MethodPost, SignCallback(callbackKey, time.Now(), []byte(notJSON)), notJSON); code != http.StatusBadRequest {
		t.Fatalf("a signed body that is not JSON = %d, want 400", code)
	}
	if code := send(http.MethodGet, "", ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", code)
	}
	fail = true
	if code := send(http.MethodPost, signed, callbackBody); code != http.StatusInternalServerError {
		t.Fatalf("a failing handler = %d, want 500 so that Herald tries again", code)
	}
	huge := strings.Repeat("x", maxCallbackBody+1)
	if code := send(http.MethodPost, signed, huge); code != http.StatusBadRequest {
		t.Fatalf("an oversized body = %d, want 400", code)
	}
}

func TestPutSettings(t *testing.T) {
	fake := newFakeHerald(t)
	client := newClient(t, fake, "")
	if err := client.PutSettings(t.Context(), Settings{Subject: "shop/user:42"}); err != nil {
		t.Fatalf("PutSettings: %v", err)
	}
	settings := Settings{
		Subject: "shop/user:42", Locale: "en", TimeZone: "Europe/Kyiv", QuietHoursStart: "22:00", QuietHoursEnd: "07:00",
		Preferences: []Preference{{EventClass: "*", Channel: "email", Enabled: false}, {EventClass: "order.shipped", Channel: "*", Enabled: true, MinSeverity: SeverityWarning}},
	}
	if err := client.PutSettings(t.Context(), settings); err != nil {
		t.Fatalf("PutSettings: %v", err)
	}
	requests := fake.seen()
	if requests[0].method != http.MethodPut || requests[0].path != "/v1/preferences" || requests[0].raw != `{"subject":"shop/user:42","preferences":[]}` {
		t.Fatalf("PutSettings without choices sent %s %s %s", requests[0].method, requests[0].path, requests[0].raw)
	}
	const want = `{"subject":"shop/user:42","locale":"en","time_zone":"Europe/Kyiv","quiet_hours_start":"22:00","quiet_hours_end":"07:00",` +
		`"preferences":[{"event_class":"*","channel":"email","enabled":false},{"event_class":"order.shipped","channel":"*","enabled":true,"min_severity":"warning"}]}`
	if requests[1].raw != want {
		t.Fatalf("PutSettings sent\n%s\nwant\n%s", requests[1].raw, want)
	}
}
