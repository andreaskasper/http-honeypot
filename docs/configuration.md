---
title: Configuration
nav_order: 3
---

# Configuration
{: .no_toc }

All configuration is done via environment variables. Copy `.env.example` to `.env` and edit it.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## General

| Variable | Default | Description |
|---|---|---|
| `NAME` | _(empty)_ | Human-readable name for this honeypot instance. Included in all Pushover and webhook messages. |
| `HONEYPOT_PORT` | `80` | Host port in docker-compose. The container always listens on 80 internally. |

---

## Tar-pit

| Variable | Default | Description |
|---|---|---|
| `TAR_PIT_MAX_SEC` | `20` | Max random delay per request in seconds. Uses `crypto/rand`. Set `0` to disable. |

---

## Rate limiting

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_PER_MIN` | `1000` | Max requests per IP per minute. Requests exceeding this return HTTP 429. |

---

## Logging

| Variable | Default | Description |
|---|---|---|
| `LOG_DISABLED` | `false` | Set `true` to disable all file logging. Pushover and webhook notifications still fire. |
| `LOG_MAX_SIZE_MB` | `100` | Rotate `/var/log/honeypot.jsonl` when it reaches this size. Built-in, no logrotate needed. |

### Log fields

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
  "api_key_used": "hp_live_a1b2c3d4e5f6789012ab",
  "is_honeytoken_use": true,
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

# All honeytoken reuse events
jq 'select(.is_honeytoken_use == true)' /var/log/honeypot.jsonl

# All Log4Shell probes
jq 'select(.attack_tag == "log4shell")' /var/log/honeypot.jsonl
```

---

## Pushover

| Variable | Default | Description |
|---|---|---|
| `PUSHOVER_APP` | _(empty)_ | Your Pushover application API token. |
| `PUSHOVER_RECIPIENT` | _(empty)_ | Your Pushover user or group key. |
| `PUSHOVER_NOTIFY_COUNTRY` | _(empty)_ | ISO 3166-1 alpha-2 code. Throttled to once per hour. |

---

## Webhook

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | _(empty)_ | HTTP endpoint for JSON attack events. |
| `WEBHOOK_SECRET` | _(empty)_ | Sent as `X-Honeypot-Secret` header. |

See the [Webhooks](webhooks) page for payload and routing examples.

---

## Prometheus metrics

| Variable | Default | Description |
|---|---|---|
| `METRICS_USER` | `admin` | Username for `/metrics` Basic Auth. |
| `METRICS_PASSWORD` | `password` | Password for `/metrics` Basic Auth. **Change before exposing to the internet!** |
| `METRICS_REALM` | `Prometheus Server` | HTTP Basic Auth realm. |
| `METRICS_DISABLED` | `false` | Disable the `/metrics` endpoint entirely. |

{: .warning }
The `/metrics` endpoint is on the same port as the honeypot. Either set strong credentials or restrict access via Traefik middleware.

---

## AbuseIPDB

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_KEY` | _(empty)_ | AbuseIPDB API key. Leave empty to disable. |
| `ABUSEIPDB_SLEEP` | `86400` | Cooldown in seconds before reporting the same IP again. |

See the [AbuseIPDB](abuseipdb) page for details.
