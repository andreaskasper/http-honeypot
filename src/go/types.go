package main

import (
	"net/http"
	"time"
)

type HoneypotRequest struct {
	http            *http.Request
	timestamp       time.Time
	wait            time.Duration
	ip              string
	ipinfo          map[string]interface{}
	cookie          string
	postBody        string
	apiKeyUsed      string // captured from X-Api-Key / Authorization headers
	isAttack        bool
	attackTag       string
	isHoneytokenUse bool // true when a hp_live_ token was submitted
}

// LogEntry is the structured JSON line written per request.
type LogEntry struct {
	Timestamp       string                 `json:"timestamp"`
	IP              string                 `json:"ip"`
	WaitSec         float64                `json:"wait_sec"`
	Method          string                 `json:"method"`
	Host            string                 `json:"host"`
	Path            string                 `json:"path"`
	UserAgent       string                 `json:"user_agent"`
	Cookie          string                 `json:"cookie"`
	IsAttack        bool                   `json:"is_attack"`
	AttackTag       string                 `json:"attack_tag,omitempty"`
	PostBody        string                 `json:"post_body,omitempty"`
	APIKeyUsed      string                 `json:"api_key_used,omitempty"`
	IsHoneytokenUse bool                   `json:"is_honeytoken_use,omitempty"`
	IPInfo          map[string]interface{} `json:"ipinfo,omitempty"`
}
