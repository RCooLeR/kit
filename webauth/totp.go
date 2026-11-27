package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the default interoperable TOTP algorithm.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	totpSecretBytes = 20
	totpPeriod      = 30
	totpDigits      = 6
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret creates a random 160-bit TOTP secret encoded in unpadded Base32.
func NewTOTPSecret() (string, error) {
	var key [totpSecretBytes]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(key[:]), nil
}

// TOTPProvisioningURI creates an authenticator enrollment URI for a secret
// from NewTOTPSecret. Treat the URI with the same care as the secret.
func TOTPProvisioningURI(issuer, account, secret string) (string, error) {
	for _, label := range []string{issuer, account} {
		if len(label) > 256 || strings.TrimSpace(label) == "" || strings.ContainsRune(label, ':') ||
			strings.IndexFunc(label, unicode.IsControl) >= 0 {
			return "", errors.New("invalid TOTP issuer or account")
		}
	}
	if _, ok := decodeTOTPSecret(secret); !ok {
		return "", errors.New("invalid TOTP secret")
	}

	params := url.Values{
		"algorithm": {"SHA1"},
		"digits":    {"6"},
		"issuer":    {issuer},
		"period":    {"30"},
		"secret":    {secret},
	}
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + params.Encode(), nil
}

// MatchTOTP matches a six-digit TOTP at the supplied time, allowing one
// 30-second step on either side. If several steps match, it returns the newest.
// For each enrolled credential, the caller must atomically accept and record
// only a counter greater than the last accepted counter. Apply rate limiting
// before checking codes.
func MatchTOTP(secret, code string, at time.Time) (counter int64, ok bool) {
	if len(code) != totpDigits || at.Unix() < 0 {
		return 0, false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	key, ok := decodeTOTPSecret(secret)
	if !ok {
		return 0, false
	}

	current := at.Unix() / totpPeriod
	var matched int
	for step := max(0, current-1); step <= current+1; step++ {
		equal := subtle.ConstantTimeCompare([]byte(code), []byte(totpCode(key, uint64(step))))
		mask := -int64(equal)
		counter = (counter &^ mask) | (step & mask)
		matched |= equal
	}
	return counter, matched == 1
}

func decodeTOTPSecret(secret string) ([]byte, bool) {
	if len(secret) != totpEncoding.EncodedLen(totpSecretBytes) {
		return nil, false
	}
	// DecodeString accepts line breaks, so check the decoded length too.
	key, err := totpEncoding.DecodeString(secret)
	return key, err == nil && len(key) == totpSecretBytes
}

func totpCode(key []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
