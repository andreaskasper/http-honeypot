package main

import (
	"crypto/rand"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

/* ═══════════════════════════════════════════════════════════════════════════
   HELPERS  (functions not in other files)
═══════════════════════════════════════════════════════════════════════════ */

// detectLog4Shell scans all request headers and the query string for JNDI injection.
func detectLog4Shell(r *http.Request) bool {
	payload := "${jndi:"
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), payload) {
				return true
			}
		}
	}
	return strings.Contains(r.URL.RawQuery, payload)
}

// captureAPIKey returns any API key or Bearer token present in the request.
func captureAPIKey(r *http.Request) string {
	if key := r.Header.Get("X-Api-Key"); key != "" {
		return key
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Token ") {
		return strings.TrimPrefix(auth, "Token ")
	}
	return ""
}

// randomDelay returns a cryptographically random duration in [0, TAR_PIT_MAX_SEC].
func randomDelay() time.Duration {
	maxSec := int64(getenvInt("TAR_PIT_MAX_SEC", 20))
	if maxSec <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(maxSec*1000))
	if err != nil {
		return 5 * time.Second
	}
	return time.Duration(n.Int64()) * time.Millisecond
}

// wpLoginHTML returns a minimal but convincing fake WordPress login page.
func wpLoginHTML() string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title></head><body class="login"><div id="login"><h1><a href="https://wordpress.org/">WordPress</a></h1><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address<br/><input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="none" autocomplete="username"/></label></p><p><label for="user_pass">Password<br/><input type="password" name="pwd" id="user_pass" class="input" size="20" autocomplete="current-password"/></label></p><input type="hidden" name="redirect_to" value="/wp-admin/"/><input type="hidden" name="testcookie" value="1"/><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In"/></p></form></div></body></html>`
}
