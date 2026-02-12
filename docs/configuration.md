---
title: Configuration
nav_order: 3
---

# Configuration
{: .no_toc }

All configuration is done via environment variables. Copy `.env.example` to `.env` and edit it before starting the container.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## General

| Variable | Default | Description |
|---|---|---|
| `NAME` | _(empty)_ | Human-readable name for this honeypot instance. Included in all Pushover and webhook messages — useful when running multiple honeypots. |
| `HONEYPOT_PORT` | `80` | Host port in docker-compose. The container always listens on 80 internally. |

---

## Tar-pit

| Variable | Default | Description |
|---|---|---|
| `TAR_PIT_MAX_SEC` | `20` | Maximum random delay per request in seconds. The actual delay is chosen using `crypto/rand` in the range `[0, TAR_PIT_MAX_SEC]`. Set `0` to disable. |

The tar-pit is the honeypot's primary weapon: every request is held open for a random duration, wasting the scanner's threads and connection pool. The use of `crypto/rand` (instead of the predictable `math/rand`) prevents honeypot fingerprinting via timing analysis.

---

## Rate limiting

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_PER_MIN` | `1000` | Maximum requests per IP address per minute. Requests exceeding this return HTTP 429. The default is intentionally high so the honeypot collects as much attack data as possible. Lower this if you want to protect server resources. |

---

## Logging

| Variable | Default | Description |
|---|---|---|
| `LOG_DISABLED` | `false` | Set `true` to disable all file logging. **Pushover and webhook notifications still fire.** Useful for low-disk or serverless environments. |
| `LOG_MAX_SIZE_MB` | `100` | Rotate `/var/log/honeypot.jsonl` (and the IP blacklist) when the file reaches this size in MB. The rotated file is renamed to `honeypot.jsonl.YYYYMMDD-HHMMSS`. Rotation is built-in — no logrotate needed. |

### Log fields

Every line in `honeypot.jsonl` is a JSON object:

```json
{
  "timestamp": "2025-02-12T14:32:00Z",
  "ip": "1.2.3.4",
  "wait_sec": 12.4,
  "method": "GET",
  "host": "honeypot.example.com",
  "path": "/actuator/env",
  "user_agent": "python-requests/2.31.0",
  "cookie": "c3f2a1b4...",
  "is_attack": true,
  "attack_tag": "spring-actuator-env",
  "post_body": "",
  "api_key_used": "",
  "ipinfo": { "country": "CN", "city": "Beijing", "org": "AS4134" }
}
```

### Analysing logs with jq

```bash
# All attacks in the last 10 minutes
jq 'select(.is_attack == true)' /var/log/honeypot.jsonl

# Top attack tags
jq -r 'select(.is_attack) | .attack_tag' /var/log/honeypot.jsonl | sort | uniq -c | sort -rn

# Top attacking IPs
jq -r '.ip' /var/log/honeypot.jsonl | sort | uniq -c | sort -rn | head -20

# All Log4Shell probes
jq 'select(.attack_tag == "log4shell")' /var/log/honeypot.jsonl
```

---

## Pushover

[Pushover](https://pushover.net/) sends push notifications to your phone.

| Variable | Default | Description |
|---|---|---|
| `PUSHOVER_APP` | _(empty)_ | Your Pushover application API token. |
| `PUSHOVER_RECIPIENT` | _(empty)_ | Your Pushover user or group key. |
| `PUSHOVER_NOTIFY_COUNTRY` | _(empty)_ | ISO 3166-1 alpha-2 country code (e.g. `CN`, `RU`, `US`). When a request originates from this country, a Pushover notification is sent — throttled to **once per hour** to avoid alert fatigue. |

---

## Webhook

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | _(empty)_ | HTTP endpoint that receives a JSON POST for every attack event and country notification. Works with n8n, Slack incoming webhooks, Make, Zapier, Discord, etc. |
| `WEBHOOK_SECRET` | _(empty)_ | If set, sent as the `X-Honeypot-Secret` request header so your receiver can verify the request came from the honeypot. |

See the [Webhooks](webhooks) page for payload format and routing ideas.

---

## Prometheus metrics

| Variable | Default | Description |
|---|---|---|
| `METRICS_USER` | `admin` | Username for HTTP Basic Auth on `/metrics`. |
| `METRICS_PASSWORD` | `password` | Password for HTTP Basic Auth on `/metrics`. **Change this before exposing to the internet!** |
| `METRICS_REALM` | `Prometheus Server` | HTTP Basic Auth realm name. |
| `METRICS_DISABLED` | `false` | Set `true` to disable the `/metrics` endpoint entirely. |

{: .warning }
The `/metrics` endpoint is exposed on the **same port as the honeypot** (port 80). If your honeypot is on the public internet, either set strong credentials, use `METRICS_DISABLED=true`, or restrict access via Traefik middleware.
