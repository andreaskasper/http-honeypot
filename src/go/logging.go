package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"
)

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
