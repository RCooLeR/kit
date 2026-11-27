package webauth_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/RCooLeR/kit/webauth"
)

const rfcTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPProvisioning(t *testing.T) {
	secret, err := webauth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	rawURI, err := webauth.TOTPProvisioningURI("Example / Team", "member+test@example.org", secret)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(rawURI)
	if err != nil {
		t.Fatal(err)
	}
	if uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Path != "/Example / Team:member+test@example.org" {
		t.Fatal("unexpected provisioning URI structure")
	}
	query := uri.Query()
	if query.Get("secret") != secret || len(secret) != 32 || query.Get("issuer") != "Example / Team" ||
		query.Get("algorithm") != "SHA1" || query.Get("digits") != "6" || query.Get("period") != "30" {
		t.Fatal("unexpected provisioning URI parameters")
	}
	for _, badLabel := range []string{"", " ", "a:b", "a\n", strings.Repeat("a", 257)} {
		if _, err := webauth.TOTPProvisioningURI("Example", badLabel, secret); err == nil {
			t.Error("provisioning accepted an invalid label")
		}
	}
	for _, badSecret := range []string{"", strings.ToLower(rfcTOTPSecret), strings.Repeat("A", 31) + "\n"} {
		if _, err := webauth.TOTPProvisioningURI("Example", "member", badSecret); err == nil {
			t.Error("provisioning accepted an invalid secret")
		}
	}
}

func TestMatchTOTPRFC6238(t *testing.T) {
	// The six-digit codes are the last six digits of the RFC 6238 SHA-1 vectors.
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, vector := range vectors {
		for _, skew := range []int64{-30, 0, 30} {
			counter, ok := webauth.MatchTOTP(rfcTOTPSecret, vector.code, time.Unix(vector.unix+skew, 0))
			if !ok || counter != vector.unix/30 {
				t.Errorf("time %d, skew %d: got counter %d, matched %t", vector.unix, skew, counter, ok)
			}
		}
		if _, ok := webauth.MatchTOTP(rfcTOTPSecret, vector.code, time.Unix(vector.unix+60, 0)); ok {
			t.Errorf("time %d: matched outside the allowed window", vector.unix)
		}
	}
}

func TestMatchTOTPInvalidInput(t *testing.T) {
	at := time.Unix(59, 0)
	for _, code := range []string{"", "287082 ", " 287082", "２８７０８２", "abcdef"} {
		if _, ok := webauth.MatchTOTP(rfcTOTPSecret, code, at); ok {
			t.Error("matched invalid code")
		}
	}
	for _, secret := range []string{"", strings.ToLower(rfcTOTPSecret), rfcTOTPSecret + "="} {
		if _, ok := webauth.MatchTOTP(secret, "287082", at); ok {
			t.Error("matched invalid secret")
		}
	}
	if _, ok := webauth.MatchTOTP(rfcTOTPSecret, "755224", time.Unix(-1, 0)); ok {
		t.Error("matched code before the Unix epoch")
	}
	if counter, ok := webauth.MatchTOTP(rfcTOTPSecret, "755224", time.Unix(0, 0)); !ok || counter != 0 {
		t.Error("failed to match the first counter")
	}
}
