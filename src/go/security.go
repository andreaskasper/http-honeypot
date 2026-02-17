package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
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
