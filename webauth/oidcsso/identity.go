package oidcsso

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidIssuer accepts an HTTPS issuer URL or a loopback HTTP development
// issuer. It validates without changing the spelling of the identifier.
func ValidIssuer(value string) bool {
	if !utf8.ValidString(value) || strings.ContainsAny(value, "?#\\") || strings.ContainsFunc(value, invalidURLRune) {
		return false
	}
	u, ok := providerURL(value)
	if !ok || strings.ContainsFunc(u.Path, invalidURLRune) {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	addr, addrErr := netip.ParseAddr(host)
	if strings.HasPrefix(u.Host, "[") {
		if addrErr != nil || !addr.Is6() || addr.Zone() != "" {
			return false
		}
	} else {
		if len(host) > 253 || addrErr != nil && numericHostEnding(host) {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if !dnsLabel.MatchString(label) {
				return false
			}
		}
	}
	if port := u.Port(); port != "" {
		if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}
	return u.Scheme == "https" || host == "localhost" || addrErr == nil && addr.Unmap().IsLoopback()
}

func invalidURLRune(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsControl(r)
}

// ValidSubject accepts a nonempty case-sensitive ASCII identifier of at most
// 255 characters. An identifier never contains control characters.
func ValidSubject(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Browsers may interpret an all-numeric final label as an IPv4 alias.
func numericHostEnding(host string) bool {
	label := host[strings.LastIndexByte(host, '.')+1:]
	if strings.HasPrefix(label, "0x") {
		return strings.Trim(label[2:], "0123456789abcdef") == ""
	}
	return strings.Trim(label, "0123456789") == ""
}
