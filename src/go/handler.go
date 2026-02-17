package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {

	/* ── Prometheus metrics ─────────────────────────────────────────────── */
	if r.URL.Path == "/metrics" {
		if strings.EqualFold(getenv("METRICS_DISABLED", "false"), "true") {
			http.Error(w, "Not found.", 404)
			return
		}
		if !basicAuth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP http_requests_all Total requests\n")
		fmt.Fprintf(w, "# TYPE http_requests_all counter\nhttp_requests_all{} %d\n", atomic.LoadInt64(&counterRequests))
		fmt.Fprintf(w, "# HELP http_requests Requests by class\n")
		fmt.Fprintf(w, "# TYPE http_requests counter\n")
		fmt.Fprintf(w, "http_requests{code=\"404\"} %d\n", atomic.LoadInt64(&counterRequests404))
		fmt.Fprintf(w, "http_requests{code=\"attack\"} %d\n", atomic.LoadInt64(&counterRequestsAttacks))
		fmt.Fprintf(w, "# HELP http_honeytokens_used Honeytoken reuse events\n")
		fmt.Fprintf(w, "# TYPE http_honeytokens_used counter\nhttp_honeytokens_used{} %d\n", atomic.LoadInt64(&counterHoneytokensUsed))
		fmt.Fprintf(w, "# HELP http_duration_ms Cumulative tar-pit delay ms\n")
		fmt.Fprintf(w, "# TYPE http_duration_ms counter\nhttp_duration_ms{} %d\n", atomic.LoadInt64(&statsDurationWaitMS))
		return
	}

	/* ── Build request context ──────────────────────────────────────────── */
	info := HoneypotRequest{
		http:      r,
		timestamp: time.Now(),
		wait:      randomDelay(),
		ip:        getIPAddress(r),
	}

	atomic.AddInt64(&counterRequests, 1)
	atomic.AddInt64(&statsDurationWaitMS, info.wait.Milliseconds())
	log.Printf("%s  %s  %s  %s", info.timestamp.Format("2006-01-02 15:04:05"), info.ip, r.Method, r.URL.Path)

	/* ── Rate limiting ──────────────────────────────────────────────────── */
	if !rl.allow(info.ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	/* ── IP info lookup (non-fatal) ─────────────────────────────────────── */
	var ipErr error
	info.ipinfo, ipErr = ipinfo(info.ip)
	if ipErr != nil {
		log.Printf("ipinfo lookup failed for %s: %v", info.ip, ipErr)
	}

	/* ── Capture API keys / Bearer tokens ──────────────────────────────── */
	info.apiKeyUsed = captureAPIKey(r)

	/* ── Honeytoken reuse detection ────────────────────────────────────── */
	// Check EVERY header value for a hp_live_ token (some tools embed keys in
	// custom headers we might not explicitly capture via captureAPIKey).
	if tk := detectHoneytokenInRequest(r, info.apiKeyUsed); tk != "" {
		info.isHoneytokenUse = true
		info.apiKeyUsed = tk
		info.isAttack = true
		info.attackTag = "honeytoken-used"
		atomic.AddInt64(&counterHoneytokensUsed, 1)
		atomic.AddInt64(&counterRequestsAttacks, 1)
		go logIPBlacklist(info)
		go sendWebhook(info, "honeytoken_used") // high-priority event type
		go abuser.report(info)
		log.Printf("HONEYTOKEN USED by %s: %s", info.ip, tk)
	}

	/* ── Log4Shell detection in headers ────────────────────────────────── */
	if !info.isHoneytokenUse && detectLog4Shell(r) {
		info.attackTag = "log4shell"
	}

	/* ── Pushover country notification (throttled to once/hour) ────────── */
	notifyCountry := getenv("PUSHOVER_NOTIFY_COUNTRY", "")
	if notifyCountry != "" && info.ipinfo != nil && info.ipinfo["country"] == notifyCountry {
		notifyMu.Lock()
		canNotify := time.Since(dtLastPushoverNotifyCountry).Hours() >= 1
		if canNotify {
			dtLastPushoverNotifyCountry = time.Now()
		}
		notifyMu.Unlock()
		if canNotify {
			go sendPushover(info)
			go sendWebhook(info, "country_notify")
		}
	}

	/* ── Cookie: read existing or mint new ─────────────────────────────── */
	info.cookie = getHoneypotCookie(r)
	if info.cookie == "" {
		info.cookie = getMD5Hash(info.timestamp.String())
	}
	expire := time.Now().AddDate(24, 0, 0)
	http.SetCookie(w, &http.Cookie{
		Name:     "akhp",
		Value:    info.cookie,
		Path:     "/",
		Domain:   strings.Split(r.Host, ":")[0],
		Expires:  expire,
		MaxAge:   86400 * 365,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	})

	/* ── Read POST/PUT body (capped at 8 KB) ───────────────────────────── */
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
		if err == nil {
			info.postBody = string(body)
			// Also check POST body for honeytoken reuse
			if !info.isHoneytokenUse && strings.Contains(info.postBody, honeytokenPrefix) {
				for _, word := range strings.Fields(info.postBody) {
					word = strings.Trim(word, `"'{}:,`)
					if isHoneytoken(word) {
						info.isHoneytokenUse = true
						info.apiKeyUsed = word
						info.isAttack = true
						info.attackTag = "honeytoken-used"
						atomic.AddInt64(&counterHoneytokensUsed, 1)
						atomic.AddInt64(&counterRequestsAttacks, 1)
						go logIPBlacklist(info)
						go sendWebhook(info, "honeytoken_used")
						go abuser.report(info)
						log.Printf("HONEYTOKEN IN POST BODY used by %s: %s", info.ip, word)
						break
					}
				}
			}
		}
	}

	/* ── Tar-pit delay ──────────────────────────────────────────────────── */
	time.Sleep(info.wait)

	/* ── Always log after handler returns ──────────────────────────────── */
	defer func() { go logJSON(info) }()

	/* ══════════════════════════════════════════════════════════════════════
	   ROUTING
	══════════════════════════════════════════════════════════════════════ */

	// If a honeytoken was the only trigger, still respond normally so the attacker
	// doesn't know they were detected.

	handleRoutes(w, r, &info)
}
