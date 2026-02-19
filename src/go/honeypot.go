package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* ═══════════════════════════════════════════════════════════════════════════
   RATE LIMITER  —  per-IP sliding window, 1-minute buckets
═══════════════════════════════════════════════════════════════════════════ */

type rateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	limit   int
	resetAt time.Time
}

var rl = &rateLimiter{
	counts:  make(map[string]int),
	resetAt: time.Now().Add(time.Minute),
}

func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().After(r.resetAt) {
		r.counts = make(map[string]int)
		r.resetAt = time.Now().Add(time.Minute)
	}
	r.counts[ip]++
	return r.counts[ip] <= r.limit
}

/* ═══════════════════════════════════════════════════════════════════════════
   ABUSEIPDB REPORTER  —  per-IP cooldown, async, non-fatal
═══════════════════════════════════════════════════════════════════════════ */

type abuseReporter struct {
	mu         sync.Mutex
	lastReport map[string]time.Time // key = IP
}

var abuser = &abuseReporter{
	lastReport: make(map[string]time.Time),
}

// reportAbuseIPDB reports the attacker's IP to AbuseIPDB if the configured cooldown
// has elapsed since the last report for that IP.  Runs in its own goroutine.
func (a *abuseReporter) report(info HoneypotRequest) {
	apiKey := getenv("ABUSEIPDB_KEY", "")
	if apiKey == "" {
		return
	}
	sleepSec := time.Duration(getenvInt("ABUSEIPDB_SLEEP", 86400)) * time.Second

	a.mu.Lock()
	last, seen := a.lastReport[info.ip]
	if seen && time.Since(last) < sleepSec {
		a.mu.Unlock()
		return
	}
	a.lastReport[info.ip] = time.Now()
	a.mu.Unlock()

	// Category 21 = Web App Attack; add 14 (Port Scan) for broad scanners.
	categories := "21"
	if strings.Contains(info.attackTag, "scan") || strings.Contains(info.attackTag, "cgi") {
		categories = "14,21"
	}

	comment := fmt.Sprintf(
		"HTTP honeypot [%s]: %s | %s %s | UA: %s",
		getenv("NAME", "honeypot"),
		info.attackTag,
		info.http.Method,
		info.http.URL.Path,
		info.http.Header.Get("User-Agent"),
	)
	// AbuseIPDB comment max is 1024 chars
	if len(comment) > 1024 {
		comment = comment[:1021] + "..."
	}

	form := url.Values{}
	form.Set("ip", info.ip)
	form.Set("categories", categories)
	form.Set("comment", comment)

	req, err := http.NewRequest(http.MethodPost,
		"https://api.abuseipdb.com/api/v2/report",
		strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("abuseipdb build error: %v", err)
		return
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("abuseipdb send error for %s: %v", info.ip, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("abuseipdb reported ip=%s tag=%s http=%d", info.ip, info.attackTag, resp.StatusCode)
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN
═══════════════════════════════════════════════════════════════════════════ */

func main() {
	rl.limit = getenvInt("RATE_LIMIT_PER_MIN", 1000)
	log.Printf(
		"honeypot starting | rate_limit=%d/min | log_disabled=%s | tar_pit_max=%ds | "+
			"metrics_disabled=%s | abuseipdb=%s",
		rl.limit,
		getenv("LOG_DISABLED", "false"),
		getenvInt("TAR_PIT_MAX_SEC", 20),
		getenv("METRICS_DISABLED", "false"),
		func() string {
			if getenv("ABUSEIPDB_KEY", "") != "" {
				return fmt.Sprintf("enabled (sleep=%ds)", getenvInt("ABUSEIPDB_SLEEP", 86400))
			}
			return "disabled"
		}(),
	)

	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":80", nil))
}

/* ═══════════════════════════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
   LOGGING
═══════════════════════════════════════════════════════════════════════════ */

// logJSON writes a structured JSON line to /var/log/honeypot.jsonl.
func logJSON(info HoneypotRequest) {
	if strings.EqualFold(getenv("LOG_DISABLED", "false"), "true") {
		return
	}

	entry := LogEntry{
		Timestamp:       info.timestamp.Format(time.RFC3339),
		IP:              info.ip,
		WaitSec:         float64(info.wait.Milliseconds()) / 1000,
		Method:          info.http.Method,
		Host:            info.http.Host,
		Path:            info.http.URL.Path,
		UserAgent:       info.http.Header.Get("User-Agent"),
		Cookie:          info.cookie,
		IsAttack:        info.isAttack,
		AttackTag:       info.attackTag,
		PostBody:        info.postBody,
		APIKeyUsed:      info.apiKeyUsed,
		IsHoneytokenUse: info.isHoneytokenUse,
		IPInfo:          info.ipinfo,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("logJSON marshal error: %v", err)
		return
	}
	appendToLogFile("/var/log/honeypot.jsonl", append(data, '\n'))
}

// logIPBlacklist appends the attacker IP to the legacy plaintext blacklist.
func logIPBlacklist(info HoneypotRequest) {
	if strings.EqualFold(getenv("LOG_DISABLED", "false"), "true") {
		return
	}
	appendToLogFile("/var/log/honeypot.ip.blacklist.log", []byte(info.ip+"\n"))
}

// appendToLogFile handles rotation and appends data to a log file.
func appendToLogFile(path string, data []byte) {
	logMu.Lock()
	defer logMu.Unlock()

	maxBytes := int64(getenvInt("LOG_MAX_SIZE_MB", 100)) * 1024 * 1024
	if fi, err := os.Stat(path); err == nil && fi.Size() >= maxBytes {
		rotated := path + "." + time.Now().Format("20060102-150405")
		if err := os.Rename(path, rotated); err != nil {
			log.Printf("log rotate error for %s: %v", path, err)
		}
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("appendToLogFile open error %s: %v", path, err)
		return
	}
	defer f.Close()
	f.Write(data)
}

/* ═══════════════════════════════════════════════════════════════════════════
   UTILITY
═══════════════════════════════════════════════════════════════════════════ */

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
		!constantTimeCompare([]byte(user), []byte(admin)) ||
		!constantTimeCompare([]byte(pass), []byte(password)) {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(401)
		w.Write([]byte("Unauthorized.\n"))
		return false
	}
	return true
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
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
