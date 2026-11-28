// Package federation runs the browser side of OpenID Connect sign-in for an application that keeps
// its own accounts: it reads the client file, starts a sign-in or the linking of a signed-in account,
// and checks the callback before handing the application a verified identity and what the attempt
// was for.
//
// It builds on oidcsso, which verifies tokens. Every attempt is bound to one browser by a host-only
// cookie and to one server-side record, consumed once; the record holds only a digest of the cookie,
// so a changed cookie finds nothing. The callback address comes from the application's configured
// public URL, never from request headers. An identity is never matched by email: the application
// looks up the exact (issuer, subject) pair it linked before, and a link is made only for the
// account that started it while signed in.
//
// What stays with the application: its accounts, the links table, sessions, rate limits and the
// pages the browser lands on.
package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/RCooLeR/kit/secret"
	"github.com/RCooLeR/kit/webauth/oidcsso"
)

// The routes every application serves: a POST that answers the issuer's address, and the callback
// registered at the issuer.
const (
	StartPath    = "/api/v1/federation/start"
	CallbackPath = "/api/v1/federation/callback"
)

// DefaultLifetime is how long an attempt waits for its callback.
const DefaultLifetime = 5 * time.Minute

const (
	maxFileBytes   = 16 << 10
	maxCookieBytes = 2048
	maxQueryBytes  = 8192
)

// SocialProviders are the upstream providers an issuer may broker, by the names it uses.
var SocialProviders = []string{"google", "apple", "facebook", "github"}

// File is an application's client file, the one its <APP>_OIDC_CONFIG_FILE setting names.
type File struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RequiredACR, when set, is the exact assurance value the issuer uses for MFA.
	RequiredACR string
	// SocialProviders are the brokered sign-in buttons to offer, in order.
	SocialProviders []string
}

// LoadFile reads the client file: a JSON object with "issuer", "client_id", "client_secret_file",
// and optionally "required_acr" and "social_providers"; unknown members are refused. A relative
// client_secret_file is read next to the file. Errors start with setting and never hold the secret.
func LoadFile(setting, path string) (File, error) {
	raw, err := readSmallFile(path)
	if err != nil {
		return File{}, fmt.Errorf("%s: %w", setting, err)
	}
	var content struct {
		Issuer          string   `json:"issuer"`
		ClientID        string   `json:"client_id"`
		SecretFile      string   `json:"client_secret_file"`
		RequiredACR     string   `json:"required_acr"`
		SocialProviders []string `json:"social_providers"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&content); err != nil || decoder.More() {
		return File{}, fmt.Errorf("%s: not a client file (issuer, client_id, client_secret_file, required_acr, social_providers)", setting)
	}
	switch {
	case !oidcsso.ValidIssuer(content.Issuer):
		return File{}, fmt.Errorf("%s: issuer must be an https address without query or fragment", setting)
	case content.ClientID == "":
		return File{}, fmt.Errorf("%s: client_id is required", setting)
	case content.SecretFile == "":
		return File{}, fmt.Errorf("%s: client_secret_file is required", setting)
	}
	for i, provider := range content.SocialProviders {
		if !slices.Contains(SocialProviders, provider) || slices.Contains(content.SocialProviders[:i], provider) {
			return File{}, fmt.Errorf("%s: social_providers holds an unknown or repeated provider %q", setting, provider)
		}
	}
	secretPath := content.SecretFile
	if !filepath.IsAbs(secretPath) {
		secretPath = filepath.Join(filepath.Dir(path), secretPath)
	}
	clientSecret, err := secret.Resolve(
		secret.Input{Name: setting, FileName: setting + " client_secret_file", Path: secretPath}, secret.Strict)
	if err != nil {
		return File{}, err
	}
	return File{
		Issuer: content.Issuer, ClientID: content.ClientID, ClientSecret: clientSecret,
		RequiredACR: content.RequiredACR, SocialProviders: content.SocialProviders,
	}, nil
}

func readSmallFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the client file: %w", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the client file: %w", err)
	}
	if len(raw) > maxFileBytes {
		return nil, errors.New("the client file is larger than 16 KiB")
	}
	return raw, nil
}

// Config is the oidcsso configuration for the file, with the callback at CallbackPath under the
// application's public URL.
func (f File) Config(publicURL *url.URL) oidcsso.Config {
	return oidcsso.Config{
		Issuer: f.Issuer, ClientID: f.ClientID, ClientSecret: f.ClientSecret,
		RedirectURI: publicURL.JoinPath(CallbackPath).String(), RequiredACR: f.RequiredACR,
	}
}

// Provider is what the flow needs from oidcsso: *oidcsso.LazyProvider is one.
type Provider interface {
	Issuer() string
	AuthorizationURL(ctx context.Context, attempt oidcsso.Attempt) (string, error)
	Exchange(ctx context.Context, code string, attempt oidcsso.Attempt) (oidcsso.Identity, error)
}

// PassiveProvider can ask for an existing issuer session only.
type PassiveProvider interface {
	PassiveAuthorizationURL(ctx context.Context, attempt oidcsso.Attempt) (string, error)
}

// Attempts keeps one record per started attempt, by the digest of its cookie.
type Attempts interface {
	// Begin records an attempt until expires.
	Begin(ctx context.Context, digest [32]byte, expires time.Time) error
	// Consume removes the attempt and reports whether it was there and not yet expired. A second
	// call for the same digest reports false.
	Consume(ctx context.Context, digest [32]byte, now time.Time) (bool, error)
}

// Purpose says what an attempt is for.
type Purpose string

// Purposes of an attempt.
const (
	// PurposeSignIn signs in the account linked to the identity, if there is one.
	PurposeSignIn Purpose = "sign_in"
	// PurposeLink links the identity to the signed-in account that started the attempt.
	PurposeLink Purpose = "link"
)

// Request starts one attempt.
type Request struct {
	Purpose Purpose
	// Account is the signed-in account that links its identity; required for PurposeLink and
	// refused for PurposeSignIn.
	Account string
	// Passive asks only for an existing issuer session (prompt=none); sign-in only.
	Passive bool
	// Social sends the person through the issuer to one of the file's social providers.
	Social string
	// Carry is any short value the application wants back from the callback, such as the digest of
	// the session to end once the new one exists.
	Carry string
}

// Result is a checked callback.
type Result struct {
	Purpose Purpose
	Account string
	Carry   string
	// Identity is the verified issuer and subject; empty when Interaction is true.
	Identity oidcsso.Identity
	// Interaction is true when a passive attempt found no issuer session: show the local sign-in.
	Interaction bool
}

// Errors of the flow. Every rejected callback wraps ErrRejected with a reason fit for a log line;
// the application answers them all alike.
var (
	ErrRejected      = errors.New("federation: callback rejected")
	ErrBadRequest    = errors.New("federation: request not allowed")
	ErrConfiguration = errors.New("federation: configuration incomplete")
)

// Options configure a Flow.
type Options struct {
	Provider Provider
	Attempts Attempts
	// PublicURL is the application's public address. Attempts are bound to it, and the cookie is
	// Secure when it is https.
	PublicURL *url.URL
	// CookieName names the attempt cookie, such as "herald_oidc".
	CookieName string
	// SocialProviders are the file's providers that Request.Social may name.
	SocialProviders []string
	// Lifetime is how long an attempt waits; zero means DefaultLifetime.
	Lifetime time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Flow starts attempts and checks their callbacks.
type Flow struct {
	opts Options
}

// New checks the options and makes a flow.
func New(opts Options) (*Flow, error) {
	if opts.Provider == nil || opts.Attempts == nil || opts.PublicURL == nil || opts.CookieName == "" {
		return nil, ErrConfiguration
	}
	if opts.Lifetime <= 0 {
		opts.Lifetime = DefaultLifetime
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Flow{opts: opts}, nil
}

// pending is what the cookie carries.
type pending struct {
	oidcsso.Attempt
	Purpose Purpose `json:"purpose"`
	Account string  `json:"account,omitempty"`
	Passive bool    `json:"passive,omitempty"`
	Carry   string  `json:"carry,omitempty"`
}

// Start records an attempt, sets its cookie on w and returns the issuer address to send the
// browser to. Call it from the handler of StartPath, after the application's own checks (rate
// limit; for linking, the signed-in session).
func (f *Flow) Start(ctx context.Context, w http.ResponseWriter, req Request) (string, error) {
	switch {
	case req.Purpose == PurposeLink && (req.Account == "" || req.Passive):
		return "", fmt.Errorf("%w: linking needs the signed-in account and cannot be passive", ErrBadRequest)
	case req.Purpose == PurposeSignIn && req.Account != "":
		return "", fmt.Errorf("%w: a sign-in names no account", ErrBadRequest)
	case req.Purpose != PurposeLink && req.Purpose != PurposeSignIn:
		return "", fmt.Errorf("%w: unknown purpose", ErrBadRequest)
	case req.Social != "" && (req.Passive || !slices.Contains(f.opts.SocialProviders, req.Social)):
		return "", fmt.Errorf("%w: that social sign-in is not offered", ErrBadRequest)
	}
	attempt, err := oidcsso.NewAttempt()
	if err != nil {
		return "", fmt.Errorf("federation: new attempt: %w", err)
	}
	location, err := f.authorizationURL(ctx, attempt, req)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(pending{Attempt: attempt, Purpose: req.Purpose, Account: req.Account, Passive: req.Passive, Carry: req.Carry})
	if err != nil {
		return "", fmt.Errorf("federation: encode the attempt: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	if len(value) > maxCookieBytes {
		return "", fmt.Errorf("%w: account or carry too long", ErrBadRequest)
	}
	if err := f.opts.Attempts.Begin(ctx, f.digest(value), f.opts.Now().Add(f.opts.Lifetime)); err != nil {
		return "", fmt.Errorf("federation: record the attempt: %w", err)
	}
	http.SetCookie(w, f.cookie(value, int(f.opts.Lifetime/time.Second)))
	return location, nil
}

func (f *Flow) authorizationURL(ctx context.Context, attempt oidcsso.Attempt, req Request) (string, error) {
	if req.Passive {
		passive, ok := f.opts.Provider.(PassiveProvider)
		if !ok {
			return "", fmt.Errorf("%w: the provider cannot check a session passively", ErrBadRequest)
		}
		return passive.PassiveAuthorizationURL(ctx, attempt)
	}
	location, err := f.opts.Provider.AuthorizationURL(ctx, attempt)
	if err != nil || req.Social == "" {
		return location, err
	}
	endpoint, err := url.Parse(location)
	if err != nil {
		return "", oidcsso.ErrDiscovery
	}
	query := endpoint.Query()
	query.Set("identity_provider", req.Social)
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

// passiveErrors are the callback errors of a passive attempt that mean "no session, ask the
// person": they lead to the local sign-in, not to a failure.
var passiveErrors = []string{"login_required", "interaction_required", "consent_required", "account_selection_required"}

// Finish checks a callback request, consumes its attempt and clears the cookie, and returns what
// was verified. Call it from the handler of CallbackPath; on any error, answer with the same
// failure page.
func (f *Flow) Finish(w http.ResponseWriter, r *http.Request) (Result, error) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet || len(r.URL.RawQuery) > maxQueryBytes {
		return Result{}, fmt.Errorf("%w: not a GET within size", ErrRejected)
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	cookies := r.CookiesNamed(f.opts.CookieName)
	if err != nil || len(cookies) != 1 || len(cookies[0].Value) > maxCookieBytes || len(query["state"]) != 1 || query.Get("state") == "" {
		return Result{}, fmt.Errorf("%w: missing or repeated cookie or state", ErrRejected)
	}
	value := cookies[0].Value
	http.SetCookie(w, f.cookie("", -1))
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	var attempt pending
	if err != nil || json.Unmarshal(raw, &attempt) != nil ||
		subtle.ConstantTimeCompare([]byte(attempt.State), []byte(query.Get("state"))) != 1 {
		return Result{}, fmt.Errorf("%w: state does not match the attempt", ErrRejected)
	}
	valid, err := f.opts.Attempts.Consume(r.Context(), f.digest(value), f.opts.Now())
	if err != nil || !valid {
		return Result{}, fmt.Errorf("%w: unknown, used or expired attempt", ErrRejected)
	}
	result := Result{Purpose: attempt.Purpose, Account: attempt.Account, Carry: attempt.Carry}
	if attempt.Passive && len(query["error"]) == 1 && slices.Contains(passiveErrors, query.Get("error")) {
		result.Interaction = true
		return result, nil
	}
	issuer := f.opts.Provider.Issuer()
	if query.Has("error") || len(query["code"]) != 1 || query.Get("code") == "" ||
		(query.Has("iss") && (len(query["iss"]) != 1 || query.Get("iss") != issuer)) {
		return Result{}, fmt.Errorf("%w: error, missing code or another issuer", ErrRejected)
	}
	identity, err := f.opts.Provider.Exchange(r.Context(), query.Get("code"), attempt.Attempt)
	if err != nil {
		return Result{}, fmt.Errorf("%w: exchange: %w", ErrRejected, err)
	}
	if identity.Issuer != issuer || !oidcsso.ValidSubject(identity.Subject) {
		return Result{}, fmt.Errorf("%w: identity from another issuer or without a valid subject", ErrRejected)
	}
	result.Identity = identity
	return result, nil
}

// digest binds a cookie value to this application and issuer.
func (f *Flow) digest(value string) [32]byte {
	return sha256.Sum256([]byte(f.opts.PublicURL.String() + "\x00" + f.opts.Provider.Issuer() + "\x00" + value))
}

// cookie is the attempt cookie: host-only, not readable by scripts, sent on the top-level return
// from the issuer (Lax) and only to the federation routes.
func (f *Flow) cookie(value string, maxAge int) *http.Cookie {
	// Secure follows the public URL: an application reached over plain http on the local network
	// could not keep a Secure cookie.
	return &http.Cookie{ //nolint:gosec // G124: Secure is set for every https public URL
		Name: f.opts.CookieName, Value: value, Path: "/api/v1/federation", MaxAge: maxAge,
		Secure: f.opts.PublicURL.Scheme == "https", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}
