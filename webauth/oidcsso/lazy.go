package oidcsso

import (
	"context"
	"sync"
	"time"
)

const discoveryRetryDelay = 2 * time.Second

// LazyProvider defers issuer discovery until the first authorization or
// callback. The fixed configuration is checked without reaching the issuer.
type LazyProvider struct {
	config Config

	mu          sync.Mutex
	provider    *Provider
	discovering chan struct{}
	retryAfter  time.Time
}

// NewLazyProvider validates local settings without making a network request.
func NewLazyProvider(config Config) (*LazyProvider, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &LazyProvider{config: config}, nil
}

// Issuer returns the exact configured issuer, even during an outage.
func (p *LazyProvider) Issuer() string { return p.config.Issuer }

// AuthorizationURL prepares the browser redirect, discovering the issuer on
// first use. Rejected attempts do not trigger discovery.
func (p *LazyProvider) AuthorizationURL(ctx context.Context, attempt Attempt) (string, error) {
	return p.authorizationURL(ctx, attempt, false)
}

// PassiveAuthorizationURL requests sign-in using only the existing issuer session.
// Handle a provider error such as login_required after validating the returned state.
func (p *LazyProvider) PassiveAuthorizationURL(ctx context.Context, attempt Attempt) (string, error) {
	return p.authorizationURL(ctx, attempt, true)
}

func (p *LazyProvider) authorizationURL(ctx context.Context, attempt Attempt, passive bool) (string, error) {
	if !attempt.valid() {
		return "", ErrAuthentication
	}
	provider, err := p.load(ctx)
	if err != nil {
		return "", err
	}
	return provider.authorizationURL(attempt, passive)
}

// Exchange can complete an attempt previously started by another instance.
func (p *LazyProvider) Exchange(ctx context.Context, code string, attempt Attempt) (Identity, error) {
	if !attempt.valid() || !visibleASCII(code, 4096) {
		return Identity{}, ErrAuthentication
	}
	provider, err := p.load(ctx)
	if err != nil {
		return Identity{}, err
	}
	return provider.Exchange(ctx, code, attempt)
}

func (p *LazyProvider) load(ctx context.Context) (*Provider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.provider != nil || time.Now().Before(p.retryAfter) {
		provider := p.provider
		p.mu.Unlock()
		if provider == nil {
			return nil, ErrDiscovery
		}
		return provider, nil
	}
	pending := p.discovering
	if pending == nil {
		pending = make(chan struct{})
		p.discovering = pending
		go p.discover(pending) //nolint:gosec // Shared discovery has its own bounded timeout.
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-pending:
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider == nil {
		return nil, ErrDiscovery
	}
	return p.provider, nil
}

func (p *LazyProvider) discover(pending chan struct{}) {
	// Discovery serves all waiting requests. A canceled request cannot cancel
	// the shared attempt or leave the next request behind a failed retry.
	ctx, cancel := context.WithTimeout(context.Background(), providerRequestTimeout)
	defer cancel()
	provider, err := NewProvider(ctx, p.config)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.retryAfter = time.Now().Add(discoveryRetryDelay)
	} else {
		p.provider = provider
	}
	p.discovering = nil
	close(pending)
}
