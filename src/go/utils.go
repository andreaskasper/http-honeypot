package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func serveFile(w http.ResponseWriter, filename string) {
	f, err := os.Open(filename)
	if err != nil {
		http.Error(w, "File not found.", 404)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func basicAuth(w http.ResponseWriter, r *http.Request) bool {
	admin := getenv("METRICS_USER", "admin")
	password := getenv("METRICS_PASSWORD", "password")
	realm := getenv("METRICS_REALM", "Prometheus Server")
	user, pass, ok := r.BasicAuth()
	if !ok ||
		subtle.ConstantTimeCompare([]byte(user), []byte(admin)) != 1 ||
		subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized.\n"))
		return false
	}
	return true
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func ipinfo(ip string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.goo1.de/ipinfo.scan.json?ip="+ip, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var results map[string]map[string]interface{}
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	result := results["result"]

	// If API didn't provide a hostname, try DNS PTR lookup
	if result != nil {
		hostnameVal, hasHostname := result["hostname"]
		hostname, _ := hostnameVal.(string)

		if !hasHostname || hostname == "" || hostname == ip {
			// Try PTR lookup
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				ptrHost := strings.TrimSuffix(names[0], ".")
				// Only use PTR if it's not just the IP address
				if ptrHost != ip && ptrHost != "" {
					result["hostname"] = ptrHost
				}
			}
		}
	}

	return result, nil
}

func getHoneypotCookie(r *http.Request) string {
	for _, c := range r.Cookies() {
		if c.Name == "akhp" {
			return c.Value
		}
	}
	return ""
}

func getMD5Hash(text string) string {
	h := md5.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// getIPAddress extracts the real client IP, respecting Cloudflare → HAProxy → Traefik headers.
func getIPAddress(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
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
