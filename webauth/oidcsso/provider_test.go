package oidcsso

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestProviderCodeFlowAcrossDifferentClients(t *testing.T) {
	idp := newTestIssuer(t)
	first, second := idp.config("first-app"), idp.config("second-app")
	providers := []*Provider{idp.open(t, first), idp.open(t, second)}
	for i, config := range []Config{first, second} {
		provider := providers[i]
		attempt, err := NewAttempt()
		if err != nil {
			t.Fatal(err)
		}
		redirect, err := provider.AuthorizationURL(attempt)
		if err != nil {
			t.Fatal(err)
		}
		address, err := url.Parse(redirect)
		if err != nil {
			t.Fatal(err)
		}
		query := address.Query()
		if address.Scheme+"://"+address.Host+address.Path != idp.server.URL+"/authorize" ||
			query.Get("client_id") != config.ClientID || query.Get("redirect_uri") != config.RedirectURI ||
			query.Get("scope") != "openid" || query.Get("response_type") != "code" ||
			query.Get("nonce") != attempt.Nonce || query.Get("state") != attempt.State ||
			query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(attempt.Verifier) ||
			strings.Contains(redirect, config.ClientSecret) || strings.Contains(redirect, attempt.Verifier) {
			t.Fatal("authorization request did not bind the fixed client and PKCE attempt")
		}
		code := idp.code(config, attempt, nil)
		got, err := provider.Exchange(t.Context(), code, attempt)
		if err != nil || got != (Identity{Issuer: idp.server.URL, Subject: "Subject-Case-42"}) || provider.Issuer() != idp.server.URL {
			t.Fatalf("unexpected verified identity: %+v %v", got, err)
		}
		if _, err := provider.Exchange(t.Context(), code, attempt); !errors.Is(err, ErrAuthentication) {
			t.Fatal("one-time provider code could be replayed")
		}
		other := []Config{second, first}[i]
		foreignAudience := idp.code(config, attempt, func(claims map[string]any) { claims["aud"] = other.ClientID })
		if _, err := provider.Exchange(t.Context(), foreignAudience, attempt); !errors.Is(err, ErrAuthentication) {
			t.Fatal("another site's audience authenticated at this client")
		}
	}
}

func TestProviderRejectsInvalidClaimsAndTokenRedirect(t *testing.T) {
	idp := newTestIssuer(t)
	config := idp.config("app")
	provider := idp.open(t, config)
	attempt, err := NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = idp.server.URL + "/other" }},
		{"wrong authorized party", func(c map[string]any) { c["azp"] = "other" }},
		{"null authorized party", func(c map[string]any) { c["azp"] = nil }},
		{"untrusted audience", func(c map[string]any) { c["aud"] = []string{config.ClientID, "other"} }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }},
		{"future iat", func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"missing nonce", func(c map[string]any) { delete(c, "nonce") }},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "other" }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"invalid subject", func(c map[string]any) { c["sub"] = "\n" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := idp.code(config, attempt, test.change)
			checkAuthenticationFailure(t, provider, code, attempt)
		})
	}
	checkAuthenticationFailure(t, provider, "revoked-code", attempt)
	checkAuthenticationFailure(t, provider, "redirect-token", attempt)
	if idp.redirectCalls.Load() != 0 {
		t.Fatal("token request followed a redirect with its credentials")
	}
	for _, mode := range []string{"none", "bad-signature", "no-token"} {
		t.Run(mode, func(t *testing.T) {
			code := idp.code(config, attempt, nil)
			idp.mu.Lock()
			test := idp.codes[code]
			test.mode = mode
			idp.codes[code] = test
			idp.mu.Unlock()
			checkAuthenticationFailure(t, provider, code, attempt)
		})
	}
}

func checkAuthenticationFailure(t *testing.T, provider *Provider, code string, attempt Attempt) {
	t.Helper()
	got, err := provider.Exchange(t.Context(), code, attempt)
	if !errors.Is(err, ErrAuthentication) || got != (Identity{}) ||
		strings.Contains(err.Error(), code) || strings.Contains(err.Error(), "private response") {
		t.Fatalf("rejected exchange returned an identity or unredacted error: %v", err)
	}
}

func TestProviderValidatesDiscoveryAndFixedURLs(t *testing.T) {
	idp := newTestIssuer(t)
	config := idp.config("app")
	for _, test := range []struct {
		name, key string
		value     any
	}{
		{"mismatched issuer", "issuer", idp.server.URL + "/issuer"},
		{"password in endpoint", "token_endpoint", "https://user:secret@auth.example/token"},
		{"remote HTTP", "jwks_uri", "http://auth.example/jwks"},
		{"untrusted loopback", "jwks_uri", "http://127.0.0.1:1/jwks"},
		{"PKCE downgrade", "code_challenge_methods_supported", []string{"plain"}},
		{"unsupported token authentication", "token_endpoint_auth_methods_supported", []string{"none"}},
		{"authorization query", "authorization_endpoint", idp.server.URL + "/authorize?client_secret=unexpected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			idp.mu.Lock()
			original := idp.metadata
			idp.metadata = maps.Clone(original)
			idp.metadata[test.key] = test.value
			idp.mu.Unlock()
			defer func() {
				idp.mu.Lock()
				idp.metadata = original
				idp.mu.Unlock()
			}()
			if _, err := NewProvider(t.Context(), config); !errors.Is(err, ErrDiscovery) {
				t.Fatalf("unsafe discovery accepted: %v", err)
			}
		})
	}
	bad := config
	bad.Issuer = "http://auth.example"
	if _, err := NewProvider(t.Context(), bad); !errors.Is(err, ErrConfiguration) {
		t.Fatal("remote HTTP was accepted as an issuer")
	}
	bad = config
	bad.RedirectURI += "?return=secret"
	if _, err := NewProvider(t.Context(), bad); !errors.Is(err, ErrConfiguration) {
		t.Fatal("callback with query parameters was accepted")
	}
}

type testIssuer struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	mu             sync.Mutex
	metadata       map[string]any
	codes          map[string]testCode
	redirectCalls  atomic.Int64
	discoveryCalls atomic.Int64
	discoveryDown  atomic.Bool
	authorize      http.HandlerFunc
}

type testCode struct {
	config    Config
	challenge string
	claims    map[string]any
	mode      string
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &testIssuer{key: key, codes: make(map[string]testCode)}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(fixture.server.Close)
	fixture.metadata = map[string]any{
		"issuer": fixture.server.URL, "authorization_endpoint": fixture.server.URL + "/authorize",
		"token_endpoint": fixture.server.URL + "/token", "jwks_uri": fixture.server.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"code_challenge_methods_supported": []string{"S256"},
	}
	return fixture
}

func (f *testIssuer) config(client string) Config {
	return Config{Issuer: f.server.URL, ClientID: client, ClientSecret: "test-client-secret",
		RedirectURI: "http://app.localhost/" + client + "/callback"}
}

func (f *testIssuer) open(t *testing.T, config Config) *Provider {
	t.Helper()
	provider, err := NewProvider(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func (f *testIssuer) code(config Config, attempt Attempt, change func(map[string]any)) string {
	claims := map[string]any{
		"iss": f.server.URL, "aud": config.ClientID, "azp": config.ClientID, "sub": "Subject-Case-42",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"nonce": attempt.Nonce, "email": "ignored@example.test",
	}
	if change != nil {
		change(claims)
	}
	code := oauth2.GenerateVerifier()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[code] = testCode{config: config, challenge: oauth2.S256ChallengeFromVerifier(attempt.Verifier), claims: claims}
	return code
}

func (f *testIssuer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		f.discoveryCalls.Add(1)
		if f.discoveryDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.mu.Lock()
		metadata := f.metadata
		f.mu.Unlock()
		encodeTestResponse(w, metadata)
	case "/keys":
		public := f.key.PublicKey
		encodeTestResponse(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "active", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}}})
	case "/authorize", "/sign-in":
		f.mu.Lock()
		authorize := f.authorize
		f.mu.Unlock()
		if authorize == nil {
			http.NotFound(w, r)
			return
		}
		authorize(w, r)
	case "/token":
		f.token(w, r)
	case "/redirect-sink":
		f.redirectCalls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	default:
		http.NotFound(w, r)
	}
}

func (f *testIssuer) token(w http.ResponseWriter, r *http.Request) {
	form := r.PostFormValue("code")
	if form == "redirect-token" {
		http.Redirect(w, r, "/redirect-sink", http.StatusTemporaryRedirect)
		return
	}
	f.mu.Lock()
	input, ok := f.codes[form]
	delete(f.codes, form)
	f.mu.Unlock()
	client, secret, authenticated := r.BasicAuth()
	if !ok || !authenticated || client != input.config.ClientID || secret != input.config.ClientSecret ||
		r.PostFormValue("redirect_uri") != input.config.RedirectURI || oauth2.S256ChallengeFromVerifier(r.PostFormValue("code_verifier")) != input.challenge ||
		r.PostFormValue("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		encodeTestResponse(w, map[string]string{"error": "invalid_grant", "error_description": "private response"})
		return
	}
	reply := map[string]string{"access_token": "access-token", "token_type": "Bearer"}
	if input.mode != "no-token" {
		reply["id_token"] = f.signed(input)
	}
	encodeTestResponse(w, reply)
}

func (f *testIssuer) signed(input testCode) string {
	header := `{"alg":"RS256","kid":"active"}`
	if input.mode == "none" {
		header = `{"alg":"none"}`
	}
	raw, err := json.Marshal(input.claims)
	if err != nil {
		panic(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	token := encode([]byte(header)) + "." + encode(raw)
	if input.mode == "none" {
		return token + "."
	}
	hash := sha256.Sum256([]byte(token))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, hash[:])
	if err != nil {
		panic(err)
	}
	if input.mode == "bad-signature" {
		signature[0] ^= 1
	}
	return token + "." + encode(signature)
}

func encodeTestResponse(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
