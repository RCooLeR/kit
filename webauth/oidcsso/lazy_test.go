package oidcsso

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLazyProviderOutageRecoveryAndReplicaExchange(t *testing.T) {
	issuer := newTestIssuer(t)
	config := issuer.config("app")
	issuer.discoveryDown.Store(true)
	provider, err := NewLazyProvider(config)
	if err != nil || provider.Issuer() != config.Issuer || issuer.discoveryCalls.Load() != 0 {
		t.Fatalf("startup touched the unavailable issuer: %v", err)
	}
	attempt, err := NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() {
			_, err := provider.AuthorizationURL(t.Context(), attempt)
			results <- err
		}()
	}
	for range callers {
		if err := <-results; !errors.Is(err, ErrDiscovery) {
			t.Fatalf("outage failed with an unexpected error: %v", err)
		}
	}
	if issuer.discoveryCalls.Load() != 1 {
		t.Fatalf("outage sent %d discovery requests", issuer.discoveryCalls.Load())
	}
	issuer.discoveryDown.Store(false)
	if _, err := provider.AuthorizationURL(t.Context(), attempt); !errors.Is(err, ErrDiscovery) ||
		issuer.discoveryCalls.Load() != 1 {
		t.Fatal("provider retried immediately without backoff")
	}
	time.Sleep(discoveryRetryDelay)
	for range callers {
		go func() {
			redirect, err := provider.AuthorizationURL(t.Context(), attempt)
			if err == nil && !strings.HasPrefix(redirect, config.Issuer+"/authorize?") {
				err = errors.New("unexpected issuer redirect")
			}
			results <- err
		}()
	}
	for range callers {
		if err := <-results; err != nil {
			t.Fatalf("provider did not recover after backoff: %v", err)
		}
	}
	if issuer.discoveryCalls.Load() != 2 {
		t.Fatalf("recovery sent additional uncoalesced discoveries: %d", issuer.discoveryCalls.Load())
	}
	replica, err := NewLazyProvider(config)
	if err != nil || issuer.discoveryCalls.Load() != 2 {
		t.Fatalf("second replica discovered at startup: %v", err)
	}
	code := issuer.code(config, attempt, nil)
	identity, err := replica.Exchange(t.Context(), code, attempt)
	if err != nil || identity.Issuer != config.Issuer || identity.Subject != "Subject-Case-42" ||
		issuer.discoveryCalls.Load() != 3 {
		t.Fatalf("second replica did not complete the signed exchange: %+v, %v", identity, err)
	}
}
