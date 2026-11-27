// Package oidcsso verifies external OpenID Connect identities for local sign-in.
package oidcsso

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config contains operator-controlled settings for one confidential OIDC client.
type Config struct {
	Issuer, ClientID, ClientSecret, RedirectURI string
	// RequiredACR is an optional exact issuer-defined MFA assurance value.
	RequiredACR string
}

// Identity contains the verified issuer and its case-sensitive user identifier.
type Identity struct {
	Issuer, Subject string
	// MFAConfirmed reports that the verified token matched the configured RequiredACR.
	MFAConfirmed bool
}

// Attempt contains the values the caller must bind to one browser and consume
// once, after checking the callback's state and before exchanging its code.
type Attempt struct {
	State, Nonce, Verifier string
}

// Provider uses one fixed issuer and client registration to verify OpenID Connect identities.
type Provider struct {
	issuer      string
	requiredACR string
	client      *http.Client
	oauth       oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

var (
	// ErrConfiguration indicates that the local issuer or client settings are invalid.
	ErrConfiguration = errors.New("invalid OpenID Connect provider configuration")
	// ErrDiscovery indicates that the issuer could not be reached or its metadata was rejected.
	ErrDiscovery = errors.New("OpenID Connect discovery failed")
	// ErrAuthentication indicates that an authorization attempt or token was rejected.
	ErrAuthentication = errors.New("OpenID Connect authentication failed")
)

const providerRequestTimeout = 10 * time.Second

func validateConfig(config Config) error {
	callback, callbackOK := providerURL(config.RedirectURI)
	if !ValidIssuer(config.Issuer) || !callbackOK ||
		callback.RawQuery != "" || callback.ForceQuery || callback.Path == "" ||
		!visibleASCII(config.ClientID, 255) || config.ClientSecret == "" ||
		config.RequiredACR != "" && !visibleASCII(config.RequiredACR, 4096) {
		return ErrConfiguration
	}
	return nil
}

// NewProvider discovers a fixed issuer and prepares a verifier using its keys.
// Discovery and back-channel requests use bounded timeouts and cannot redirect.
func NewProvider(ctx context.Context, config Config) (*Provider, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	issuer, _ := providerURL(config.Issuer)
	client := &http.Client{
		Timeout: providerRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx = oidc.ClientContext(ctx, client)
	discovered, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, ErrDiscovery
	}
	var metadata struct {
		Issuer      string   `json:"issuer"`
		JWKS        string   `json:"jwks_uri"`
		PKCEMethods []string `json:"code_challenge_methods_supported"`
		TokenAuth   []string `json:"token_endpoint_auth_methods_supported"`
	}
	endpoint := discovered.Endpoint()
	authorize, _ := url.Parse(endpoint.AuthURL)
	if err := discovered.Claims(&metadata); err != nil || metadata.Issuer != config.Issuer ||
		!validEndpoint(issuer, endpoint.AuthURL) || !validEndpoint(issuer, endpoint.TokenURL) || !validEndpoint(issuer, metadata.JWKS) ||
		authorize.RawQuery != "" || authorize.ForceQuery ||
		metadata.PKCEMethods != nil && !slices.Contains(metadata.PKCEMethods, "S256") {
		return nil, ErrDiscovery
	}
	switch {
	case metadata.TokenAuth == nil || slices.Contains(metadata.TokenAuth, "client_secret_basic"):
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case slices.Contains(metadata.TokenAuth, "client_secret_post"):
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	default:
		return nil, ErrDiscovery
	}
	return &Provider{
		issuer:      config.Issuer,
		requiredACR: config.RequiredACR,
		client:      client,
		oauth: oauth2.Config{
			ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: config.RedirectURI,
			Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID},
		},
		verifier: discovered.VerifierContext(ctx, &oidc.Config{ClientID: config.ClientID}),
	}, nil
}

func providerURL(raw string) (url.URL, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || strings.ContainsAny(raw, "#\\") {
		return url.URL{}, false
	}
	switch parsed.Scheme {
	case "https":
		return *parsed, true
	case "http":
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		return *parsed, host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host).IsLoopback()
	default:
		return url.URL{}, false
	}
}

func validEndpoint(issuer url.URL, raw string) bool {
	u, ok := providerURL(raw)
	return ok && (u.Scheme == "https" || issuer.Scheme == "http" && strings.EqualFold(u.Host, issuer.Host))
}

// Issuer returns the configured issuer using its exact discovered identifier.
func (p *Provider) Issuer() string { return p.issuer }

// NewAttempt generates independent values for state, nonce and PKCE.
func NewAttempt() (Attempt, error) {
	var random [96]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Attempt{}, err
	}
	return Attempt{
		State:    base64.RawURLEncoding.EncodeToString(random[:32]),
		Nonce:    base64.RawURLEncoding.EncodeToString(random[32:64]),
		Verifier: base64.RawURLEncoding.EncodeToString(random[64:]),
	}, nil
}

func (attempt Attempt) valid() bool {
	for _, value := range []string{attempt.State, attempt.Nonce, attempt.Verifier} {
		if len(value) != base64.RawURLEncoding.EncodedLen(32) {
			return false
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) != 32 {
			return false
		}
	}
	return true
}

// AuthorizationURL starts an authorization code request with S256 PKCE.
func (p *Provider) AuthorizationURL(attempt Attempt) (string, error) {
	return p.authorizationURL(attempt, false)
}

// PassiveAuthorizationURL requests sign-in using only the existing issuer session.
func (p *Provider) PassiveAuthorizationURL(attempt Attempt) (string, error) {
	return p.authorizationURL(attempt, true)
}

func (p *Provider) authorizationURL(attempt Attempt, passive bool) (string, error) {
	if !attempt.valid() {
		return "", ErrAuthentication
	}
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(attempt.Verifier), oidc.Nonce(attempt.Nonce)}
	if p.requiredACR != "" {
		options = append(options, oauth2.SetAuthURLParam("acr_values", p.requiredACR))
	}
	if passive {
		options = append(options, oauth2.SetAuthURLParam("prompt", "none"))
	}
	return p.oauth.AuthCodeURL(attempt.State, options...), nil
}

// Exchange verifies the signed ID token returned for a consumed attempt.
// Provider response bodies and tokens are kept out of the returned error.
func (p *Provider) Exchange(ctx context.Context, code string, attempt Attempt) (Identity, error) {
	if !attempt.valid() || !visibleASCII(code, 4096) {
		return Identity{}, ErrAuthentication
	}
	ctx = oidc.ClientContext(ctx, p.client)
	response, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(attempt.Verifier))
	if err != nil {
		return Identity{}, ErrAuthentication
	}
	raw, ok := response.Extra("id_token").(string)
	if !ok || raw == "" || len(raw) > 64<<10 {
		return Identity{}, ErrAuthentication
	}
	token, err := p.verifier.Verify(ctx, raw)
	if err != nil || token.Issuer != p.issuer || !ValidSubject(token.Subject) ||
		len(token.Audience) != 1 || token.Audience[0] != p.oauth.ClientID ||
		!token.IssuedAt.After(time.Unix(0, 0)) || token.IssuedAt.After(time.Now().Add(2*time.Minute)) ||
		!token.Expiry.After(token.IssuedAt) ||
		subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(attempt.Nonce)) != 1 {
		return Identity{}, ErrAuthentication
	}
	var claims signingClaims
	if err := token.Claims(&claims); err != nil ||
		len(claims.AuthorizedParty) != 0 && !matchesStringClaim(claims.AuthorizedParty, p.oauth.ClientID) ||
		token.AccessTokenHash != "" && token.VerifyAccessToken(response.AccessToken) != nil ||
		p.requiredACR != "" && !matchesStringClaim(claims.ACR, p.requiredACR) {
		return Identity{}, ErrAuthentication
	}
	return Identity{Issuer: p.issuer, Subject: token.Subject, MFAConfirmed: p.requiredACR != ""}, nil
}

type signingClaims struct {
	AuthorizedParty jsontext.Value `json:"azp"`
	ACR             jsontext.Value `json:"acr"`
}

func (c *signingClaims) UnmarshalJSON(raw []byte) error {
	// Reject duplicate names in the signed claim object.
	type claims signingClaims
	return json.Unmarshal(raw, (*claims)(c))
}

func matchesStringClaim(raw jsontext.Value, expected string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && value == expected
}

func visibleASCII(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
