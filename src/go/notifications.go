package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gregdel/pushover"
)

func sendPushover(info HoneypotRequest) {
	app := getenv("PUSHOVER_APP", "")
	recipient := getenv("PUSHOVER_RECIPIENT", "")
	if app == "" || recipient == "" {
		return
	}
	po := pushover.New(app)
	rec := pushover.NewRecipient(recipient)

	msg := "Honeypot hit from notify country\n"
	msg += "URL: " + info.http.Host + info.http.URL.Path + "\n"
	msg += "Server: " + getenv("NAME", "") + "\n"
	msg += "IP: " + info.ip + "\n"
	if info.ipinfo != nil {
		msg += fmt.Sprintf("Location: %v %v; %v; %v\n",
			info.ipinfo["postal"], info.ipinfo["city"],
			info.ipinfo["region"], info.ipinfo["country"])
	}

	message := &pushover.Message{
		Title:     "Honeypot: country " + getenv("PUSHOVER_NOTIFY_COUNTRY", ""),
		Message:   msg,
		Priority:  pushover.PriorityNormal,
		Timestamp: time.Now().Unix(),
		Retry:     60 * time.Second,
		Expire:    time.Hour,
		Sound:     pushover.SoundGamelan,
	}
	if _, err := po.SendMessage(message, rec); err != nil {
		log.Printf("pushover send error: %v", err)
	}
}

func sendWebhook(info HoneypotRequest, event string) {
	webhookURL := getenv("WEBHOOK_URL", "")
	if webhookURL == "" {
		return
	}

	// Rate limiting per IP (optional)
	if rateLimitStr := getenv("WEBHOOK_URL_RATE_LIMIT_SEC", ""); rateLimitStr != "" {
		rateLimitSec, err := strconv.Atoi(rateLimitStr)
		if err == nil && rateLimitSec > 0 {
			webhookURLRateLimitMu.Lock()
			lastCall, exists := webhookURLRateLimit[info.ip]
			if exists && time.Since(lastCall).Seconds() < float64(rateLimitSec) {
				webhookURLRateLimitMu.Unlock()
				log.Printf("webhook rate limited for IP %s", info.ip)
				return
			}
			webhookURLRateLimit[info.ip] = time.Now()
			webhookURLRateLimitMu.Unlock()
		}
	}

	payload := map[string]interface{}{
		"event":             event,
		"server":            getenv("NAME", ""),
		"timestamp":         info.timestamp.Format(time.RFC3339),
		"ip":                info.ip,
		"method":            info.http.Method,
		"host":              info.http.Host,
		"path":              info.http.URL.Path,
		"user_agent":        info.http.Header.Get("User-Agent"),
		"is_attack":         info.isAttack,
		"attack_tag":        info.attackTag,
		"api_key_used":      info.apiKeyUsed,
		"is_honeytoken_use": info.isHoneytokenUse,
		"ipinfo":            info.ipinfo,
	}
	if info.postBody != "" {
		payload["post_body"] = info.postBody
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("webhook marshal error: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := getenv("WEBHOOK_SECRET", ""); secret != "" {
		req.Header.Set("X-Honeypot-Secret", secret)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("webhook send error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("webhook fired event=%s attack_tag=%s status=%d", event, info.attackTag, resp.StatusCode)
}

// sendNewURLWebhook sends comprehensive request details to WEBHOOK_NEW_URL
// Returns a WebhookResponse if the webhook provides custom content, nil otherwise
func sendNewURLWebhook(info HoneypotRequest) *WebhookResponse {
	webhookURL := getenv("WEBHOOK_NEW_URL", "")
	if webhookURL == "" {
		return nil
	}

	atomic.AddInt64(&counterWebhookNewURLCalls, 1)

	// Check cache first
	cacheSec := getenvInt("WEBHOOK_NEW_URL_CACHE_SEC", 60)
	if cacheSec > 0 {
		cacheKey := info.http.Method + ":" + info.http.URL.Path
		webhookNewURLCacheMu.RLock()
		entry, exists := webhookNewURLCache[cacheKey]
		webhookNewURLCacheMu.RUnlock()

		if exists && time.Since(entry.Timestamp).Seconds() < float64(cacheSec) {
			atomic.AddInt64(&counterWebhookNewURLCacheHits, 1)
			log.Printf("webhook_new_url cache hit for %s", cacheKey)
			return entry.Response
		}
		atomic.AddInt64(&counterWebhookNewURLCacheMiss, 1)
	}

	// Build comprehensive payload
	headers := make(map[string]string)
	for k, v := range info.http.Header {
		headers[k] = strings.Join(v, ", ")
	}

	queryParams := make(map[string]string)
	for k, v := range info.http.URL.Query() {
		queryParams[k] = strings.Join(v, ", ")
	}

	cookies := make(map[string]string)
	for _, cookie := range info.http.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	payload := map[string]interface{}{
		"server":        getenv("NAME", ""),
		"timestamp":     info.timestamp.Format(time.RFC3339),
		"ip":            info.ip,
		"method":        info.http.Method,
		"host":          info.http.Host,
		"path":          info.http.URL.Path,
		"query_string":  info.http.URL.RawQuery,
		"query_params":  queryParams,
		"headers":       headers,
		"cookies":       cookies,
		"user_agent":    info.http.Header.Get("User-Agent"),
		"content_type":  info.http.Header.Get("Content-Type"),
		"remote_addr":   info.http.RemoteAddr,
		"request_uri":   info.http.RequestURI,
		"proto":         info.http.Proto,
		"tls":           info.http.TLS != nil,
		"api_key_used":  info.apiKeyUsed,
		"ipinfo":        info.ipinfo,
	}

	if info.postBody != "" {
		payload["post_body"] = info.postBody
		payload["content_length"] = len(info.postBody)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("webhook_new_url marshal error: %v", err)
		return nil
	}

	// Make synchronous request with timeout
	timeoutSec := getenvInt("WEBHOOK_NEW_URL_TIMEOUT_SEC", 5)
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook_new_url request build error: %v", err)
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	if secret := getenv("WEBHOOK_NEW_URL_SECRET", ""); secret != "" {
		req.Header.Set("X-Honeypot-Secret", secret)
	}

	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	atomic.AddInt64(&counterWebhookNewURLTimeoutMS, elapsed.Milliseconds())

	if err != nil {
		log.Printf("webhook_new_url error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	log.Printf("webhook_new_url called for %s %s - status=%d duration=%dms",
		info.http.Method, info.http.URL.Path, resp.StatusCode, elapsed.Milliseconds())

	// Read response body (limit to 1MB)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		log.Printf("webhook_new_url read error: %v", err)
		return nil
	}

	if len(respBody) == 0 {
		return nil
	}

	// Try to parse as JSON first
	var webhookResp WebhookResponse
	if err := json.Unmarshal(respBody, &webhookResp); err == nil {
		// Valid JSON response
		if webhookResp.Status == 0 {
			webhookResp.Status = 200 // Default to 200 if not specified
		}

		// Validate response
		if webhookResp.Status < 100 || webhookResp.Status > 599 {
			log.Printf("webhook_new_url invalid status code: %d", webhookResp.Status)
			return nil
		}

		// Handle redirect shorthand
		if webhookResp.Redirect != "" {
			if webhookResp.Status == 200 {
				webhookResp.Status = 301 // Default to 301 for redirects
			}
			if webhookResp.Headers == nil {
				webhookResp.Headers = make(map[string]string)
			}
			webhookResp.Headers["Location"] = webhookResp.Redirect
		}

		// Set default content type
		if webhookResp.ContentType == "" && webhookResp.Body != "" {
			webhookResp.ContentType = "text/html; charset=utf-8"
		}

		atomic.AddInt64(&counterWebhookNewURLCustomResp, 1)

		// Cache the response
		if cacheSec > 0 {
			cacheKey := info.http.Method + ":" + info.http.URL.Path
			webhookNewURLCacheMu.Lock()
			webhookNewURLCache[cacheKey] = &WebhookCacheEntry{
				Response:  &webhookResp,
				Timestamp: time.Now(),
			}
			webhookNewURLCacheMu.Unlock()
		}

		return &webhookResp
	}

	// Not JSON - treat as plain text/html
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		// Try to detect if it's HTML
		bodyStr := string(respBody)
		if strings.Contains(strings.ToLower(bodyStr), "<html") || strings.Contains(strings.ToLower(bodyStr), "<!doctype") {
			contentType = "text/html; charset=utf-8"
		} else {
			contentType = "text/plain; charset=utf-8"
		}
	}

	webhookResp = WebhookResponse{
		Status:      resp.StatusCode,
		Body:        string(respBody),
		ContentType: contentType,
	}

	atomic.AddInt64(&counterWebhookNewURLCustomResp, 1)

	// Cache the response
	if cacheSec > 0 {
		cacheKey := info.http.Method + ":" + info.http.URL.Path
		webhookNewURLCacheMu.Lock()
		webhookNewURLCache[cacheKey] = &WebhookCacheEntry{
			Response:  &webhookResp,
			Timestamp: time.Now(),
		}
		webhookNewURLCacheMu.Unlock()
	}

	return &webhookResp
}
