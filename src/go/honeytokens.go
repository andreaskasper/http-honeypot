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

// detectHoneytokenInRequest scans all request headers (and the already-captured
// apiKey) for a hp_live_ token.  Returns the token if found, empty string otherwise.
func detectHoneytokenInRequest(r *http.Request, capturedKey string) string {
	if isHoneytoken(capturedKey) {
		return capturedKey
	}
	for _, vals := range r.Header {
		for _, v := range vals {
			// A header might contain the token inline (e.g. "Bearer hp_live_...")
			for _, word := range strings.Fields(v) {
				word = strings.Trim(word, `"',;`)
				if isHoneytoken(word) {
					return word
				}
			}
		}
	}
	return ""
}
