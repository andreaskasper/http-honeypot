---
title: Webhooks & Notifications
nav_order: 4
---

# Webhooks & Notifications
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Webhook payload

On every attack event the honeypot fires a JSON `POST` to `WEBHOOK_URL`:

```json
{
  "event": "attack",
  "server": "my-honeypot",
  "timestamp": "2025-02-12T14:32:00Z",
  "ip": "1.2.3.4",
  "method": "GET",
  "host": "honeypot.example.com",
  "path": "/actuator/env",
  "user_agent": "python-requests/2.31.0",
  "is_attack": true,
  "attack_tag": "spring-actuator-env",
  "api_key_used": "",
  "post_body": "",
  "ipinfo": {
    "country": "CN",
    "city": "Beijing",
    "org": "AS4134 CHINANET-BACKBONE"
  }
}
```

`event` is either `"attack"` or `"country_notify"` (for Pushover country notifications).

`api_key_used` captures any `X-Api-Key`, `Authorization: Bearer`, or `Authorization: Token` header the attacker sent — useful for tracking key-testing scanners.

---

## Authentication

Set `WEBHOOK_SECRET` to a random string. The honeypot sends it in the `X-Honeypot-Secret` header on every request, so your receiver can verify origin:

```python
# Example Flask receiver
from flask import request, abort
SECRET = "your_secret_here"

@app.post("/honeypot")
def honeypot():
    if request.headers.get("X-Honeypot-Secret") != SECRET:
        abort(403)
    data = request.json
    # ... process
```

---

## Routing by attack_tag

The `attack_tag` field lets you build smart conditional flows in n8n, Make, or Zapier.

### Example n8n routing

```
Webhook node
  └─ Switch node on attack_tag
       ├─ "log4shell"       → Slack #security-critical + PagerDuty
       ├─ "k8s-secrets"     → Slack #security-critical
       ├─ "spring-actuator-env" → Slack #devops-alerts
       ├─ "wp-login"        → Log only (very noisy)
       └─ default           → Write to Google Sheet
```

### Example n8n deduplication

To avoid alert storms from a single scanner:

1. After the Switch, add a **Set** node that combines `{{ $json.ip }}` + `{{ $json.attack_tag }}` as a dedup key.
2. Use an **If** node that checks Redis / a Google Sheet for the key in the last 60 minutes.
3. Only pass through new combinations.

---

## Multi-honeypot correlation

The `server` field in every payload contains your `NAME` environment variable. If you run multiple honeypots (different regions, different IPs), a single n8n workflow can aggregate all of them:

```
Honeypot EU  ──┐
Honeypot US  ──┤→  n8n Webhook  →  Correlate by IP + tag  →  Alert if 2+ instances hit
Honeypot AS  ──┘
```

This lets you detect coordinated scans across regions.

---

## Pushover

[Pushover](https://pushover.net/) delivers push notifications to iOS and Android.

The honeypot sends a Pushover message when a request arrives **from the configured country**. The notification is **throttled to once per hour** — even if thousands of requests come in, you get at most one push per hour per honeypot instance.

Notification content includes:
- URL that was hit
- Attacker IP
- Geo info (city, region, country, postal code)
- Honeypot instance name
