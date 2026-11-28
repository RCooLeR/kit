package federation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/RCooLeR/kit/webauth/oidcsso"
)

// mockIssuer serves discovery, keys and a token endpoint, and signs ID tokens for codes the test
// hands out, as an issuer would after the person signed in.
type mockIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]map[string]any
}

func newMockIssuer(t *testing.T) *mockIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &mockIssuer{key: key, codes: map[string]map[string]any{}}
	issuer.server = httptest.NewServer(http.HandlerFunc(issuer.serve))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (m *mockIssuer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	base := m.server.URL
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
			"jwks_uri": base + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		})
	case "/keys":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(m.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.E)).Bytes()),
		}}})
	case "/token":
		m.mu.Lock()
		claims, ok := m.codes[r.PostFormValue("code")]
		delete(m.codes, r.PostFormValue("code"))
		m.mu.Unlock()
		client, secret, basic := r.BasicAuth()
		verifier := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || !basic || client != "app" || secret != "client-secret" ||
			base64.RawURLEncoding.EncodeToString(verifier[:]) != claims["challenge"] {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		delete(claims, "challenge")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "token_type": "Bearer", "id_token": m.sign(claims)})
	default:
		http.NotFound(w, r)
	}
}

func (m *mockIssuer) sign(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	signing := header + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// authorize plays the person signing in at the issuer: it reads the authorization address and
// returns the callback query the issuer would redirect to.
func (m *mockIssuer) authorize(t *testing.T, location, subject string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("client_id") != "app" ||
		query.Get("redirect_uri") != publicURL.JoinPath(CallbackPath).String() {
		t.Fatalf("authorization request = %q", location)
	}
	code := "code-" + query.Get("state")[:12]
	m.mu.Lock()
	m.codes[code] = map[string]any{
		"iss": m.server.URL, "aud": "app", "azp": "app", "sub": subject, "nonce": query.Get("nonce"),
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"email": "same.email@example.test", "challenge": query.Get("code_challenge"),
	}
	m.mu.Unlock()
	return "code=" + code + "&iss=" + url.QueryEscape(m.server.URL) + "&state=" + query.Get("state")
}

// The flow with the real oidcsso provider against issuer endpoints: a link, then a sign-in that
// finds the same exact identity.
func TestTheFlowWithARealProviderAgainstAMockIssuer(t *testing.T) {
	issuer := newMockIssuer(t)
	provider, err := oidcsso.NewLazyProvider(File{Issuer: issuer.server.URL, ClientID: "app", ClientSecret: "client-secret"}.Config(publicURL))
	if err != nil {
		t.Fatal(err)
	}
	flow, err := New(Options{Provider: provider, Attempts: NewMemoryAttempts(0), PublicURL: publicURL, CookieName: "app_oidc"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{flow: flow}
	links := map[string]string{}
	key := func(identity oidcsso.Identity) string { return identity.Issuer + "\x00" + identity.Subject }

	location, cookie := f.start(t, Request{Purpose: PurposeLink, Account: "account-7"})
	result, _, err := f.finish(t, http.MethodGet, issuer.authorize(t, location, "go:Subject-42"), cookie)
	if err != nil || result.Purpose != PurposeLink || result.Account != "account-7" {
		t.Fatalf("link = %+v, %v", result, err)
	}
	links[key(result.Identity)] = result.Account

	location, cookie = f.start(t, Request{Purpose: PurposeSignIn})
	result, _, err = f.finish(t, http.MethodGet, issuer.authorize(t, location, "go:Subject-42"), cookie)
	if err != nil || links[key(result.Identity)] != "account-7" {
		t.Fatalf("sign-in = %+v, %v; want the linked account", result, err)
	}

	location, cookie = f.start(t, Request{Purpose: PurposeSignIn})
	result, _, err = f.finish(t, http.MethodGet, issuer.authorize(t, location, "go:subject-42"), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if _, linked := links[key(result.Identity)]; linked {
		t.Fatal("a subject differing only in case matched a link; the email must not matter either")
	}
}
