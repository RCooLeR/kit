package oidcsso

import (
	"strings"
	"testing"
)

func TestValidIssuer(t *testing.T) {
	for _, valid := range []string{"https://identity.example/Realm/", "https://Identity.example:8443/a%2Fb", "http://127.0.0.1:8990/oidc", "http://[::1]/realm", "http://localhost"} {
		if !ValidIssuer(valid) {
			t.Errorf("valid issuer rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"identity.example", "http://identity.example", "http://127.1", "http://0.0.0.0", "https://user@identity.example",
		"https://identity.example/a#fragment", "https://identity.example?", "https://identity.example/a%0A", "https://identity.example/a\\b", "https://identity.example:0"} {
		if ValidIssuer(invalid) {
			t.Errorf("invalid issuer accepted: %q", invalid)
		}
	}
}

func TestValidSubject(t *testing.T) {
	for _, valid := range []string{"A", "subject within a realm", strings.Repeat("Z", 255)} {
		if !ValidSubject(valid) {
			t.Error("valid subject rejected")
		}
	}
	for _, invalid := range []string{"", "é", "credential\r\n", "one\x00two", strings.Repeat("z", 256)} {
		if ValidSubject(invalid) {
			t.Error("invalid subject accepted")
		}
	}
}
