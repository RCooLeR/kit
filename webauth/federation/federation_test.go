package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/kit/webauth/oidcsso"
)

const testIssuer = "https://sso.example.test/realms/team"

var publicURL = &url.URL{Scheme: "https", Host: "app.example.test"}

// fakeProvider stands in for oidcsso: it hands out addresses and answers exchanges as told.
type fakeProvider struct {
	identity  oidcsso.Identity
	err       error
	exchanged int
}

func (p *fakeProvider) Issuer() string { return testIssuer }

func (p *fakeProvider) AuthorizationURL(_ context.Context, attempt oidcsso.Attempt) (string, error) {
	return testIssuer + "/authorize?state=" + attempt.State, nil
}

func (p *fakeProvider) PassiveAuthorizationURL(_ context.Context, attempt oidcsso.Attempt) (string, error) {
	return testIssuer + "/authorize?prompt=none&state=" + attempt.State, nil
}

func (p *fakeProvider) Exchange(_ context.Context, code string, _ oidcsso.Attempt) (oidcsso.Identity, error) {
	p.exchanged++
	if code != "good-code" {
		return oidcsso.Identity{}, oidcsso.ErrAuthentication
	}
	return p.identity, p.err
}

type fixture struct {
	flow     *Flow
	provider *fakeProvider
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		provider: &fakeProvider{identity: oidcsso.Identity{Issuer: testIssuer, Subject: "go:0b9f-subject"}},
		now:      time.Date(2026, time.November, 28, 9, 0, 0, 0, time.UTC),
	}
	flow, err := New(Options{
		Provider: f.provider, Attempts: NewMemoryAttempts(0), PublicURL: publicURL, CookieName: "app_oidc",
		SocialProviders: []string{"google"}, Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.flow = flow
	return f
}

// start begins an attempt and returns the issuer address and the cookie the browser keeps.
func (f *fixture) start(t *testing.T, req Request) (string, *http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	location, err := f.flow.Start(t.Context(), recorder, req)
	if err != nil {
		t.Fatalf("start %+v: %v", req, err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("start set %d cookies", len(cookies))
	}
	return location, cookies[0]
}

func stateOf(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("state")
}

// finish sends the browser back to the callback with the cookies and query given.
func (f *fixture) finish(t *testing.T, method, query string, cookies ...*http.Cookie) (Result, *httptest.ResponseRecorder, error) {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, publicURL.String()+CallbackPath+"?"+query, nil)
	for _, cookie := range cookies {
		request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	recorder := httptest.NewRecorder()
	result, err := f.flow.Finish(recorder, request)
	return result, recorder, err
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFileReadsTheClientAndItsSecret(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "client_secret", "the-client-secret\n")
	path := writeFile(t, dir, "oidc.json", `{"issuer":"`+testIssuer+`","client_id":"app","client_secret_file":"client_secret",`+
		`"required_acr":"2","social_providers":["google","github"]}`)
	file, err := LoadFile("APP_OIDC_CONFIG_FILE", path)
	if err != nil {
		t.Fatal(err)
	}
	if file.ClientSecret != "the-client-secret" || file.RequiredACR != "2" || len(file.SocialProviders) != 2 {
		t.Fatalf("file = %+v", file)
	}
	config := file.Config(publicURL)
	if config.RedirectURI != "https://app.example.test/api/v1/federation/callback" || config.Issuer != testIssuer || config.ClientID != "app" {
		t.Fatalf("config = %+v", config)
	}
	for name, content := range map[string]string{
		"unknown member":    `{"issuer":"` + testIssuer + `","client_id":"app","client_secret_file":"client_secret","email_links":true}`,
		"plain http issuer": `{"issuer":"http://sso.example.test","client_id":"app","client_secret_file":"client_secret"}`,
		"no client":         `{"issuer":"` + testIssuer + `","client_secret_file":"client_secret"}`,
		"no secret file":    `{"issuer":"` + testIssuer + `","client_id":"app"}`,
		"absent secret":     `{"issuer":"` + testIssuer + `","client_id":"app","client_secret_file":"absent"}`,
		"unknown provider":  `{"issuer":"` + testIssuer + `","client_id":"app","client_secret_file":"client_secret","social_providers":["myspace"]}`,
		"repeated provider": `{"issuer":"` + testIssuer + `","client_id":"app","client_secret_file":"client_secret","social_providers":["google","google"]}`,
		"two objects":       `{"issuer":"` + testIssuer + `","client_id":"app","client_secret_file":"client_secret"} {}`,
		"too large":         `{"issuer":"` + testIssuer + `","client_id":"` + strings.Repeat("a", 17<<10) + `","client_secret_file":"client_secret"}`,
	} {
		_, err := LoadFile("APP_OIDC_CONFIG_FILE", writeFile(t, dir, "bad.json", content))
		if err == nil || !strings.Contains(err.Error(), "APP_OIDC_CONFIG_FILE") || strings.Contains(err.Error(), "the-client-secret") {
			t.Errorf("%s: err = %v, want a refusal naming the setting and not the secret", name, err)
		}
	}
}

func TestStartBindsTheAttemptToACookie(t *testing.T) {
	f := newFixture(t)
	location, cookie := f.start(t, Request{Purpose: PurposeSignIn})
	if !strings.HasPrefix(location, testIssuer) || stateOf(t, location) == "" {
		t.Fatalf("location = %q", location)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/api/v1/federation" ||
		cookie.MaxAge != int(DefaultLifetime/time.Second) || cookie.Domain != "" {
		t.Fatalf("cookie = %+v, want host-only, HttpOnly, Secure, Lax, on the federation routes", cookie)
	}
}

func TestASignInRoundTripWorksOnce(t *testing.T) {
	f := newFixture(t)
	location, cookie := f.start(t, Request{Purpose: PurposeSignIn, Carry: "session-digest"})
	query := "code=good-code&iss=" + url.QueryEscape(testIssuer) + "&state=" + stateOf(t, location)
	result, recorder, err := f.finish(t, http.MethodGet, query, cookie)
	if err != nil || result.Purpose != PurposeSignIn || result.Identity.Subject != "go:0b9f-subject" || result.Carry != "session-digest" || result.Interaction {
		t.Fatalf("finish = %+v, %v", result, err)
	}
	if recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("the callback page may leak its query through the referrer")
	}
	cleared := recorder.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Errorf("the attempt cookie was not cleared: %+v", cleared)
	}
	if _, _, err := f.finish(t, http.MethodGet, query, cookie); !errors.Is(err, ErrRejected) {
		t.Fatalf("a replayed callback = %v, want rejected", err)
	}
}

func TestCallbacksThatDoNotFitAreRejected(t *testing.T) {
	tamper := func(t *testing.T, cookie *http.Cookie) *http.Cookie {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
		var attempt pending
		if err := json.Unmarshal(raw, &attempt); err != nil {
			t.Fatal(err)
		}
		attempt.Purpose, attempt.Account = PurposeLink, "someone-else"
		changed, _ := json.Marshal(attempt)
		return &http.Cookie{Name: cookie.Name, Value: base64.RawURLEncoding.EncodeToString(changed)}
	}
	tests := []struct {
		name  string
		query func(state string) string
		setup func(t *testing.T, f *fixture, cookie *http.Cookie) []*http.Cookie
		post  bool
	}{
		{name: "wrong state", query: func(string) string { return "code=good-code&state=other" }},
		{name: "no cookie", query: func(s string) string { return "code=good-code&state=" + s },
			setup: func(*testing.T, *fixture, *http.Cookie) []*http.Cookie { return nil }},
		{name: "two cookies", query: func(s string) string { return "code=good-code&state=" + s },
			setup: func(_ *testing.T, _ *fixture, c *http.Cookie) []*http.Cookie { return []*http.Cookie{c, c} }},
		{name: "repeated state", query: func(s string) string { return "code=good-code&state=" + s + "&state=" + s }},
		{name: "issuer error", query: func(s string) string { return "error=access_denied&state=" + s }},
		{name: "no code", query: func(s string) string { return "state=" + s }},
		{name: "repeated code", query: func(s string) string { return "code=good-code&code=good-code&state=" + s }},
		{name: "another issuer", query: func(s string) string { return "code=good-code&iss=https%3A%2F%2Fevil.example.test&state=" + s }},
		{name: "a code the issuer refuses", query: func(s string) string { return "code=bad-code&state=" + s }},
		{name: "POST", query: func(s string) string { return "code=good-code&state=" + s }, post: true},
		{name: "changed cookie", query: func(s string) string { return "code=good-code&state=" + s },
			setup: func(t *testing.T, _ *fixture, c *http.Cookie) []*http.Cookie { return []*http.Cookie{tamper(t, c)} }},
		{name: "expired", query: func(s string) string { return "code=good-code&state=" + s },
			setup: func(_ *testing.T, f *fixture, c *http.Cookie) []*http.Cookie {
				f.now = f.now.Add(DefaultLifetime + time.Second)
				return []*http.Cookie{c}
			}},
		{name: "identity of another issuer", query: func(s string) string { return "code=good-code&state=" + s },
			setup: func(_ *testing.T, f *fixture, c *http.Cookie) []*http.Cookie {
				f.provider.identity.Issuer = "https://other.example.test"
				return []*http.Cookie{c}
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			location, cookie := f.start(t, Request{Purpose: PurposeSignIn})
			cookies := []*http.Cookie{cookie}
			if tc.setup != nil {
				cookies = tc.setup(t, f, cookie)
			}
			method := http.MethodGet
			if tc.post {
				method = http.MethodPost
			}
			result, _, err := f.finish(t, method, tc.query(stateOf(t, location)), cookies...)
			if !errors.Is(err, ErrRejected) || result.Identity.Subject != "" {
				t.Fatalf("finish = %+v, %v; want rejected", result, err)
			}
		})
	}
}

// A rejected callback of a found attempt still says what the attempt was for, so a failed link
// lands on the link's failure page; it never carries the account or an identity.
func TestARejectedCallbackOfAFoundAttemptKeepsItsPurpose(t *testing.T) {
	for name, query := range map[string]func(state string) string{
		"issuer error":              func(s string) string { return "error=access_denied&state=" + s },
		"a code the issuer refuses": func(s string) string { return "code=bad-code&state=" + s },
		"another issuer":            func(s string) string { return "code=good-code&iss=https%3A%2F%2Fevil.example.test&state=" + s },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			location, cookie := f.start(t, Request{Purpose: PurposeLink, Account: "account-7", Carry: "session-digest"})
			result, _, err := f.finish(t, http.MethodGet, query(stateOf(t, location)), cookie)
			if !errors.Is(err, ErrRejected) || result.Purpose != PurposeLink || result.Carry != "session-digest" ||
				result.Account != "" || result.Identity.Subject != "" || result.Interaction {
				t.Fatalf("finish = %+v, %v; want rejected with the purpose and carry only", result, err)
			}
		})
	}
	f := newFixture(t)
	location, cookie := f.start(t, Request{Purpose: PurposeLink, Account: "account-7"})
	query := "code=good-code&state=" + stateOf(t, location)
	if _, _, err := f.finish(t, http.MethodGet, query, cookie); err != nil {
		t.Fatal(err)
	}
	if result, _, err := f.finish(t, http.MethodGet, query, cookie); !errors.Is(err, ErrRejected) || result.Purpose != "" {
		t.Fatalf("a replayed callback = %+v, %v; want rejected without a purpose", result, err)
	}
}

func TestAPassiveCheckWithoutAnIssuerSessionLeadsToTheLocalSignIn(t *testing.T) {
	f := newFixture(t)
	location, cookie := f.start(t, Request{Purpose: PurposeSignIn, Passive: true})
	if !strings.Contains(location, "prompt=none") {
		t.Fatalf("location = %q, want a passive request", location)
	}
	result, _, err := f.finish(t, http.MethodGet, "error=login_required&state="+stateOf(t, location), cookie)
	if err != nil || !result.Interaction || f.provider.exchanged != 0 {
		t.Fatalf("finish = %+v, %v; want the local sign-in without an exchange", result, err)
	}
	location, cookie = f.start(t, Request{Purpose: PurposeSignIn})
	if _, _, err := f.finish(t, http.MethodGet, "error=login_required&state="+stateOf(t, location), cookie); !errors.Is(err, ErrRejected) {
		t.Fatalf("login_required on an active attempt = %v, want rejected", err)
	}
}

func TestLinkingCarriesTheSignedInAccount(t *testing.T) {
	f := newFixture(t)
	location, cookie := f.start(t, Request{Purpose: PurposeLink, Account: "account-7"})
	result, _, err := f.finish(t, http.MethodGet, "code=good-code&state="+stateOf(t, location), cookie)
	if err != nil || result.Purpose != PurposeLink || result.Account != "account-7" || result.Identity.Subject == "" {
		t.Fatalf("finish = %+v, %v", result, err)
	}
	for name, req := range map[string]Request{
		"link without account": {Purpose: PurposeLink},
		"passive link":         {Purpose: PurposeLink, Account: "account-7", Passive: true},
		"sign-in with account": {Purpose: PurposeSignIn, Account: "account-7"},
		"no purpose":           {},
		"long carry":           {Purpose: PurposeSignIn, Carry: strings.Repeat("c", 2048)},
	} {
		if _, err := f.flow.Start(t.Context(), httptest.NewRecorder(), req); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: start = %v, want refused", name, err)
		}
	}
}

func TestSocialSignInGoesThroughTheIssuer(t *testing.T) {
	f := newFixture(t)
	location, _ := f.start(t, Request{Purpose: PurposeSignIn, Social: "google"})
	parsed, _ := url.Parse(location)
	if parsed.Query().Get("identity_provider") != "google" || parsed.Query().Get("state") == "" {
		t.Fatalf("location = %q", location)
	}
	for _, req := range []Request{
		{Purpose: PurposeSignIn, Social: "github"},
		{Purpose: PurposeSignIn, Social: "google", Passive: true},
	} {
		if _, err := f.flow.Start(t.Context(), httptest.NewRecorder(), req); !errors.Is(err, ErrBadRequest) {
			t.Errorf("start %+v = %v, want refused", req, err)
		}
	}
}

func TestNewNeedsItsParts(t *testing.T) {
	if _, err := New(Options{Provider: &fakeProvider{}, PublicURL: publicURL, CookieName: "x"}); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New without attempts = %v", err)
	}
}

func TestMemoryAttemptsAreConsumedOnceAndBounded(t *testing.T) {
	attempts := NewMemoryAttempts(2)
	now := time.Now()
	first, second, third := [32]byte{1}, [32]byte{2}, [32]byte{3}
	for _, digest := range [][32]byte{first, second} {
		if err := attempts.Begin(t.Context(), digest, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := attempts.Begin(t.Context(), third, now.Add(time.Minute)); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("a third attempt = %v, want too many", err)
	}
	if ok, _ := attempts.Consume(t.Context(), first, now); !ok {
		t.Fatal("a waiting attempt was not found")
	}
	if ok, _ := attempts.Consume(t.Context(), first, now); ok {
		t.Fatal("an attempt was consumed twice")
	}
	if ok, _ := attempts.Consume(t.Context(), second, now.Add(2*time.Minute)); ok {
		t.Fatal("an expired attempt was accepted")
	}
}
