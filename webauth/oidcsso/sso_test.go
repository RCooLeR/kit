package oidcsso

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

func TestProviderRequiresExactSignedACR(t *testing.T) {
	issuer := newTestIssuer(t)
	config := issuer.config("app")
	attempt, err := NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	config.RequiredACR = "urn:example:mfa"
	provider := issuer.open(t, config)
	redirect, err := provider.AuthorizationURL(attempt)
	if err != nil {
		t.Fatal(err)
	}
	address := mustParseURL(t, redirect)
	if address.Query().Get("acr_values") != config.RequiredACR {
		t.Fatal("authorization request omitted the required assurance")
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing, with amr", func(c map[string]any) { c["amr"] = []string{"mfa"} }},
		{"null", func(c map[string]any) { c["acr"] = nil }},
		{"array", func(c map[string]any) { c["acr"] = []string{config.RequiredACR} }},
		{"wrong case", func(c map[string]any) { c["acr"] = "urn:example:MFA" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := issuer.code(config, attempt, test.change)
			checkAuthenticationFailure(t, provider, code, attempt)
		})
	}
	matchingClaim := func(c map[string]any) { c["acr"] = config.RequiredACR }
	code := issuer.code(config, attempt, matchingClaim)
	got, err := provider.Exchange(t.Context(), code, attempt)
	if err != nil || !got.MFAConfirmed {
		t.Fatalf("matching signed ACR did not confirm MFA: %+v %v", got, err)
	}
	withoutPolicy := config
	withoutPolicy.RequiredACR = ""
	code = issuer.code(withoutPolicy, attempt, matchingClaim)
	got, err = issuer.open(t, withoutPolicy).Exchange(t.Context(), code, attempt)
	if err != nil || got.MFAConfirmed {
		t.Fatalf("an unconfigured ACR established MFA: %+v %v", got, err)
	}
}

func TestBrowserReusesIssuerSessionAcrossClients(t *testing.T) {
	issuer := newTestIssuer(t)
	first := issuer.config("first")
	first.RedirectURI = "https://one.example.test/sso/return"
	second := issuer.config("second")
	second.RedirectURI = "https://two.example.test/auth/callback"
	second.ClientSecret = "another-test-secret"
	clients := map[string]Config{first.ClientID: first, second.ClientID: second}
	var signIns atomic.Int64
	const subject = "Subject-Case-42"
	issuer.mu.Lock()
	issuer.authorize = func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		config, registered := clients[query.Get("client_id")]
		if !registered || query.Get("redirect_uri") != config.RedirectURI ||
			query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		callback, err := url.Parse(config.RedirectURI)
		if err != nil {
			panic(err)
		}
		result := url.Values{"state": {query.Get("state")}}
		cookie, _ := r.Cookie("issuer_session")
		switch {
		case r.URL.Path == "/sign-in":
			signIns.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "issuer_session", Value: "signed-in", Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/authorize?"+r.URL.RawQuery, http.StatusFound)
			return
		case cookie != nil && cookie.Value == "signed-in":
			code := issuer.code(config, Attempt{Nonce: query.Get("nonce")}, nil)
			issuer.mu.Lock()
			input := issuer.codes[code]
			input.challenge = query.Get("code_challenge")
			issuer.codes[code] = input
			issuer.mu.Unlock()
			result.Set("code", code)
		case query.Get("prompt") == "none":
			result.Set("error", "login_required")
		default:
			http.Redirect(w, r, "/sign-in?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		callback.RawQuery = result.Encode()
		http.Redirect(w, r, callback.String(), http.StatusFound)
	}

	issuer.mu.Unlock()
	issuerHost := mustParseURL(t, issuer.server.URL).Host
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host == issuerHost {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}
	bindings := map[string]map[Identity]string{
		first.ClientID:  {{Issuer: issuer.server.URL, Subject: subject}: "local-account-one"},
		second.ClientID: {},
	}
	for _, step := range []struct {
		config          Config
		passive         bool
		wantError       string
		isLocallyLinked bool
	}{
		{config: first, passive: true, wantError: "login_required"},
		{config: first, isLocallyLinked: true},
		{config: second, passive: true},
	} {
		provider, err := NewLazyProvider(step.config)
		if err != nil {
			t.Fatal(err)
		}
		attempt, err := NewAttempt()
		if err != nil {
			t.Fatal(err)
		}
		authorize := provider.AuthorizationURL
		if step.passive {
			authorize = provider.PassiveAuthorizationURL
		}
		redirect, err := authorize(t.Context(), attempt)
		if err != nil {
			t.Fatal(err)
		}
		query := mustParseURL(t, redirect).Query()
		if (query.Get("prompt") == "none") != step.passive ||
			query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(attempt.Verifier) ||
			query.Get("nonce") != attempt.Nonce {
			t.Fatal("wrong prompt or attempt binding")
		}

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirect, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		callback, err := response.Location()
		if err != nil {
			t.Fatal(err)
		}
		result := callback.Query()
		callback.RawQuery = ""
		if callback.String() != step.config.RedirectURI || result.Get("state") != attempt.State ||
			result.Get("error") != step.wantError {
			t.Fatal("unexpected callback or state")
		}
		if step.wantError != "" {
			if result.Get("code") != "" {
				t.Fatal("passive login without an issuer session returned a code")
			}
			continue
		}
		got, err := provider.Exchange(t.Context(), result.Get("code"), attempt)
		if err != nil || got != (Identity{Issuer: issuer.server.URL, Subject: subject}) {
			t.Fatalf("unexpected verified identity: %+v %v", got, err)
		}
		// Each relying party owns its bindings. Only the first app has this link.
		if _, linked := bindings[step.config.ClientID][got]; linked != step.isLocallyLinked {
			t.Fatal("application binding crossed client boundaries")
		}
		if len(jar.Cookies(callback)) != 0 {
			t.Fatal("an issuer or first application cookie reached this application")
		}
		if step.isLocallyLinked {
			jar.SetCookies(callback, []*http.Cookie{{Name: "app_session", Value: "local-one", Path: "/", Secure: true, HttpOnly: true}})
		}
	}
	if got := signIns.Load(); got != 1 {
		t.Fatalf("expected the issuer to sign the browser in once, got %d", got)
	}
}

func TestLazyPassiveAuthorizationRejectsInvalidAttemptBeforeDiscovery(t *testing.T) {
	issuer := newTestIssuer(t)
	provider, err := NewLazyProvider(issuer.config("app"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.PassiveAuthorizationURL(t.Context(), Attempt{}); !errors.Is(err, ErrAuthentication) ||
		issuer.discoveryCalls.Load() != 0 {
		t.Fatalf("invalid passive attempt triggered discovery or returned an unexpected error: %v", err)
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	address, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
