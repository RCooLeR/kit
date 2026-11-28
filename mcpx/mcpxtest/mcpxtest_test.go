package mcpxtest

import "testing"

func TestFindSecret(t *testing.T) {
	planted := "Zq9-planted-value-77"
	found := []string{
		`{"title":"x","note":"` + planted + `"}`,
		"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE...",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
		"postgres://app:pw@db.example.test:5432/app",
		"host=db.example.test password=pw dbname=app",
		"Authorization: Bearer abcdefgh12345678",
		`{"api_key":"k-123"}`,
		`{"access_token": "t"}`,
	}
	for _, text := range found {
		if FindSecret(text, planted) == "" {
			t.Errorf("FindSecret(%q) found nothing", text)
		}
	}
	clean := []string{
		`{"id":"0190a5e2-7b3c-7d4e-8f5a-1b2c3d4e5f60","title":"Рахунок до 30 листопада","url":"https://example.test/bills/7"}`,
		`{"has_key":true,"key_prefix":"hk_2a","problem_secret":"bot_token","token_count":3}`,
		// An API may name an identifier "token", as Herald does for its producers and apps.
		`{"token":"homeledger","display_name":"HomeLedger"}`,
		"the password was changed yesterday",
		"short pw",
	}
	for _, text := range clean {
		if match := FindSecret(text, planted, "pw"); match != "" {
			t.Errorf("FindSecret(%q) = %q, want nothing", text, match)
		}
	}
}
