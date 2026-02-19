package main

import (
	"sync"
	"time"
)

// Global state - all accesses are thread-safe
var (
	counterRequests        int64 // atomic
	counterRequests404     int64 // atomic
	counterRequestsAttacks int64 // atomic
	counterHoneytokensUsed int64 // atomic
	statsDurationWaitMS    int64 // atomic, milliseconds

	// Metrics for WEBHOOK_NEW_URL
	counterWebhookNewURLCalls      int64 // atomic
	counterWebhookNewURLTimeoutMS  int64 // atomic
	counterWebhookNewURLCacheHits  int64 // atomic
	counterWebhookNewURLCacheMiss  int64 // atomic
	counterWebhookNewURLCustomResp int64 // atomic

	notifyMu                    sync.Mutex
	dtLastPushoverNotifyCountry = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	// logMu serialises writes + rotations so two goroutines don't race on Rename
	logMu sync.Mutex

	// Cache for WEBHOOK_NEW_URL responses
	webhookNewURLCache   = make(map[string]*WebhookCacheEntry)
	webhookNewURLCacheMu sync.RWMutex

	// Rate limiting for WEBHOOK_URL per IP
	webhookURLRateLimit   = make(map[string]time.Time)
	webhookURLRateLimitMu sync.Mutex
)

// WebhookCacheEntry stores cached webhook responses
type WebhookCacheEntry struct {
	Response  *WebhookResponse
	Timestamp time.Time
}
