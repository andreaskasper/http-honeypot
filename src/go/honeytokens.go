package main

import (
	"net/http"
	"strings"
)

/* ═══════════════════════════════════════════════════════════════════════════
   HONEYTOKENS
   Format: hp_live_{md5(ip+"-"+tag)[:20]}
   Embedded in fake responses so we detect when an attacker reuses them.
═══════════════════════════════════════════════════════════════════════════ */

const honeytokenPrefix = "hp_live_"

// honeytoken generates a deterministic fake API key for a given IP + trap.
// The token is unique per IP so if attacker A shares it with attacker B,
// we can correlate both events back to the original theft.
func honeytoken(ip, tag string) string {
	return honeytokenPrefix + getMD5Hash(ip+"-"+tag)[:20]
}

// isHoneytoken returns true if the string looks like one of our fake tokens.
func isHoneytoken(s string) bool {
	return strings.HasPrefix(s, honeytokenPrefix) && len(s) == len(honeytokenPrefix)+20
}

// isTokenSeparator reports whether a rune can sit next to a credential.
// A stolen token comes back in many shapes — "Bearer hp_live_...", a cookie
// value ("NSC_AAAC=hp_live_..."), a query parameter or a JSON field — so we
// split on every delimiter that can surround one, not just whitespace.
func isTokenSeparator(c rune) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '=', '&', ';', ',', ':', '"', '\'', '{', '}', '[', ']', '(', ')':
		return true
	}
	return false
}

// findHoneytoken returns the first hp_live_ token contained in s, or "".
func findHoneytoken(s string) string {
	if !strings.Contains(s, honeytokenPrefix) {
		return ""
	}
	for _, word := range strings.FieldsFunc(s, isTokenSeparator) {
		if isHoneytoken(word) {
			return word
		}
	}
	return ""
}

// detectHoneytokenInRequest scans the already-captured apiKey, every request
// header (cookies included) and every query parameter for a hp_live_ token.
// Returns the token if found, empty string otherwise.
func detectHoneytokenInRequest(r *http.Request, capturedKey string) string {
	if isHoneytoken(capturedKey) {
		return capturedKey
	}
	for _, vals := range r.Header {
		for _, v := range vals {
			if tk := findHoneytoken(v); tk != "" {
				return tk
			}
		}
	}
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if tk := findHoneytoken(v); tk != "" {
				return tk
			}
		}
	}
	return ""
}
