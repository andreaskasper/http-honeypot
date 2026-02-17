package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
