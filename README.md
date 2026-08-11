# 🍯 HTTP Honeypot

A high-interaction HTTP honeypot written in **Go**. It simulates **85+ real attack surfaces**, tarpits every request with a cryptographically random delay, embeds **honeytokens** in fake responses to detect credential reuse, and automatically reports attackers to **AbuseIPDB**.

📖 **Full documentation:** https://andreaskasper.github.io/http-honeypot/

---

## Features

- 🎣 **85+ attack traps** — Spring Actuator, WordPress, Exchange/OWA, SharePoint, ColdFusion, Citrix NetScaler, PAN-OS GlobalProtect, Fortinet, Kubernetes, Docker API, AWS/GCP metadata, Git leaks, phpMyAdmin, Jenkins, Confluence, Langflow, MCP/AI-agent recon, N-able N-central, web shells, and more
- 🍯 **Honeytokens** — IP-specific fake API keys (`hp_live_*`) embedded in responses; detected and flagged with a `honeytoken_used` webhook event when an attacker reuses them
- 🚀 **Dynamic response webhook** — Return custom content for unknown URLs via `WEBHOOK_NEW_URL` with caching
- 🚫 **AbuseIPDB integration** — automatically reports attacking IPs with configurable per-IP cooldown
- 🐢 **Tar-pit** — `crypto/rand` delay per request; prevents timing fingerprinting
- 🏷️ **`attack_tag`** — every matched trap produces a machine-readable tag for webhook routing
- 🔍 **Log4Shell detection** — scans all request headers and query strings for `${jndi:` payloads
- 🔑 **API key capture** — captures `X-Api-Key`, `Authorization: Bearer`, `Authorization: Token`
- 📋 **Structured JSON logging** — one JSON line per request; built-in size-based log rotation
- 🔇 **`LOG_DISABLED`** — disable all file logging while keeping notifications active
- 🔔 **Pushover** — country-based mobile push; throttled to once per hour
- 🔗 **Webhook** — POST JSON to any URL on every attack event with optional per-IP rate limiting
- 📊 **Prometheus `/metrics`** — HTTP Basic Auth protected; `METRICS_DISABLED` option
- 🐳 **~15 MB Docker image** — multi-stage build (Go 1.25 / Alpine 3.21)

---

## Quick Start

```sh
docker run -p 80:80 andreaskasper/http-honeypot
```

Or with docker-compose (recommended):

```sh
cp .env.example .env
# edit .env with your values
docker-compose up -d
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NAME` | _(empty)_ | Instance name — included in all notifications |
| `HONEYPOT_PORT` | `80` | Host port (docker-compose only) |
| **Tar-pit** | | |
| `TAR_PIT_MAX_SEC` | `20` | Max random delay per request in seconds (0 = disabled) |
| **Rate limiting** | | |
| `RATE_LIMIT_PER_MIN` | `1000` | Max requests per IP per minute |
| **Logging** | | |
| `LOG_DISABLED` | `false` | Disable all file logging (notifications still fire) |
| `LOG_MAX_SIZE_MB` | `100` | Rotate log file when it exceeds this size in MB |
| **Pushover** | | |
| `PUSHOVER_APP` | _(empty)_ | Pushover application token |
| `PUSHOVER_RECIPIENT` | _(empty)_ | Pushover user/group key |
| `PUSHOVER_NOTIFY_COUNTRY` | _(empty)_ | ISO 3166-1 alpha-2 country code for mobile alert (throttled 1/hour) |
| **Webhook (attack events)** | | |
| `WEBHOOK_URL` | _(empty)_ | HTTP POST endpoint for JSON attack events |
| `WEBHOOK_SECRET` | _(empty)_ | Sent in `X-Honeypot-Secret` header for receiver verification |
| `WEBHOOK_URL_RATE_LIMIT_SEC` | _(empty)_ | Optional: Rate limit per IP (seconds between calls) |
| **Webhook (unknown URLs)** | | |
| `WEBHOOK_NEW_URL` | _(empty)_ | HTTP POST endpoint for unknown/new URLs (synchronous) |
| `WEBHOOK_NEW_URL_SECRET` | _(empty)_ | Sent in `X-Honeypot-Secret` header for receiver verification |
| `WEBHOOK_NEW_URL_CACHE_SEC` | `60` | Cache responses for identical paths (seconds) |
| `WEBHOOK_NEW_URL_TIMEOUT_SEC` | `5` | Timeout for webhook call (seconds) |
| `DEFAULT_REDIRECT` | `false` | Redirect to `/` instead of 404 when webhook doesn't respond |
| **Prometheus metrics** | | |
| `METRICS_USER` | `admin` | Username for `/metrics` Basic Auth |
| `METRICS_PASSWORD` | `password` | Password for `/metrics` Basic Auth |
| `METRICS_REALM` | `Prometheus Server` | HTTP Basic Auth realm |
| `METRICS_DISABLED` | `false` | Disable the `/metrics` endpoint entirely |
| **AbuseIPDB** | | |
| `ABUSEIPDB_KEY` | _(empty)_ | AbuseIPDB API key — leave empty to disable |
| `ABUSEIPDB_SLEEP` | `86400` | Cooldown in seconds before reporting the same IP again (default: 24 h) |

---

## Dynamic Response Webhook (WEBHOOK_NEW_URL)

The honeypot can call a webhook for **unknown/new URLs** (paths that don't match any attack trap) and serve custom responses. This enables:
- Implementing custom attack vectors dynamically
- A/B testing different response strategies
- Creating adaptive honeypot behavior
- Analyzing new attack patterns before hardcoding traps

### Request Payload

The webhook receives comprehensive request details:

```json
{
  "server": "my-honeypot",
  "timestamp": "2026-02-19T10:00:00Z",
  "ip": "1.2.3.4",
  "method": "GET",
  "host": "example.com",
  "path": "/custom/path",
  "query_string": "id=123&debug=true",
  "query_params": {"id": "123", "debug": "true"},
  "headers": {
    "User-Agent": "Mozilla/5.0...",
    "Accept": "text/html",
    "X-Forwarded-For": "1.2.3.4"
  },
  "cookies": {"session": "abc123"},
  "user_agent": "Mozilla/5.0...",
  "content_type": "application/json",
  "remote_addr": "1.2.3.4:54321",
  "request_uri": "/custom/path?id=123",
  "proto": "HTTP/1.1",
  "tls": false,
  "api_key_used": "",
  "post_body": "{\"data\":\"test\"}",
  "content_length": 15,
  "ipinfo": {"country": "DE", "city": "Berlin", "org": "AS3320"}
}
```

### Response Format

The webhook can return custom responses in two ways:

**1. JSON Response (structured):**
```json
{
  "status": 200,
  "body": "<html><body>Custom content</body></html>",
  "content_type": "text/html; charset=utf-8",
  "headers": {
    "X-Custom-Header": "value",
    "Cache-Control": "no-cache"
  }
}
```

**2. Plain Text/HTML Response:**
Return raw HTML or text directly (not JSON). The content-type will be auto-detected.

### Special Features

**Redirect Shorthand:**
```json
{
  "status": 301,
  "redirect": "/moved-here"
}
```
Automatically sets the `Location` header.

**Response Caching:**
Responses are cached by `METHOD:PATH` for `WEBHOOK_NEW_URL_CACHE_SEC` seconds (default: 60s). This prevents repeated webhook calls for the same URL pattern.

**Fallback Behavior:**
- If webhook is empty or returns no custom response → 404 (or 301 to `/` if `DEFAULT_REDIRECT=true`)
- If webhook times out or errors → 404 (or 301 to `/`)

### Prometheus Metrics

The `/metrics` endpoint includes:
- `webhook_new_url_calls` — Total webhook calls
- `webhook_new_url_timeout_ms` — Cumulative response time
- `webhook_new_url_cache_hits` — Cache hits
- `webhook_new_url_cache_miss` — Cache misses
- `webhook_new_url_custom_responses` — Custom responses served

---

## Honeytokens

Every fake response that contains credentials embeds an **IP-specific honeytoken** — a fake API key with a `hp_live_` prefix, derived from `md5(ip + trap_name)`.

Tokens appear in:
- `/actuator/env` → `AWS_SECRET_ACCESS_KEY`
- `/.env` → `STRIPE_SECRET_KEY`
- `/.aws/credentials` → `aws_secret_access_key`
- `/api/v*/users/{id}` → `api_key` field
- `/api/v1/api_key` (Langflow) → `api_keys[].api_key`
- `/api/v1/auto_login` (Langflow, CVE-2026-9198) → `access_token`
- `/p/u/doAuthentication.do` (CitrixBleed 2) → fake leaked memory in `<InitialValue>`
- `/global-protect/getconfig.esp` (PAN-OS) → `<portal-userauthcookie>`
- `/.claude/mcp.json` and friends → `env.GITHUB_PERSONAL_ACCESS_TOKEN`
- `/.claude/.credentials.json` → `claudeAiOauth.accessToken`
- `/api/auth/authenticate` (N-central) → `tokens.access.token`

If an attacker submits a token back to **any** endpoint (as a header, cookie, query parameter, or POST body), the honeypot:
1. Detects it in `detectHoneytokenInRequest()`
2. Sets `attack_tag = "honeytoken-used"` and `is_honeytoken_use = true`
3. Fires a `honeytoken_used` webhook event (separate from normal `attack` events)
4. Increments the `http_honeytokens_used` Prometheus counter
5. Reports to AbuseIPDB

This means you get alerted when a credential stolen from your honeypot is actually used — even from a completely different IP, indicating sharing or resale.

---

## AbuseIPDB

When `ABUSEIPDB_KEY` is set, every attack triggers an async report to [AbuseIPDB](https://www.abuseipdb.com/):

- **Category 21** (Web App Attack) for most traps
- **Category 14 + 21** (Port Scan + Web App Attack) for scanner-style traps (any `attack_tag` containing `scan`, plus `cgi-scan`)
- **Cooldown**: the same IP is not reported more than once per `ABUSEIPDB_SLEEP` seconds (default: 24 h)
- Fully async — never blocks the response
- Non-fatal — errors are logged but don't affect honeypot operation

Report comment format:
```
HTTP honeypot [my-honeypot]: spring-actuator-env | GET /actuator/env | UA: python-requests/2.31.0
```

[![donate via Patreon](https://www.abuseipdb.com/contributor/252827.svg)](https://www.abuseipdb.com/user/252827)

---

## Webhook Payload (Attack Events)

```json
{
  "event": "attack",
  "server": "my-honeypot",
  "timestamp": "2025-02-12T14:32:00Z",
  "ip": "1.2.3.4",
  "method": "GET",
  "host": "example.com",
  "path": "/actuator/env",
  "user_agent": "python-requests/2.31.0",
  "is_attack": true,
  "attack_tag": "spring-actuator-env",
  "api_key_used": "",
  "is_honeytoken_use": false,
  "ipinfo": { "country": "CN", "city": "Beijing", "org": "AS4134" }
}
```

For honeytoken reuse events, `event` is `"honeytoken_used"` and `is_honeytoken_use` is `true`. Route these with highest priority in your n8n/Slack flows.

---

## Trap Coverage

| Category | Tags |
|---|---|
| Spring Boot Actuator | `spring-actuator-health/env/beans/heapdump/shutdown` |
| WordPress | `wp-login`, `wp-admin`, `xmlrpc`, `wp-wlwmanifest`, `wordpress-scan` |
| Joomla | `joomla-admin` |
| phpMyAdmin | `phpmyadmin-index`, `phpmyadmin-setup` |
| Apache Tomcat | `tomcat-manager` |
| Apache Solr | `apache-solr` |
| Jenkins | `jenkins-script`, `jenkins-api` |
| H2 / JBoss | `h2-console` |
| Microsoft Exchange | `owa-login`, `exchange-ews`, `exchange-proxylogon`, `exchange-ecp`, `owa-xjs` |
| Microsoft SharePoint | `sharepoint-toolpane`, `sharepoint-scan` |
| Adobe ColdFusion | `coldfusion-admin`, `coldfusion-scan` |
| Fortinet / VPN | `fortinet-fgt`, `sonicwall-vpn`, `pulse-secure`, `cisco-asa-vpn` |
| Citrix NetScaler 🍯 | `citrix-netscaler-bleed`, `citrix-netscaler-logon`, `citrix-netscaler-scan` |
| PAN-OS GlobalProtect 🍯 | `panos-globalprotect-login`, `panos-globalprotect-prelogin`, `panos-globalprotect-config`, `panos-globalprotect-scan` |
| N-able N-central 🍯 | `nable-ncentral-auth`, `nable-ncentral-soap`, `nable-ncentral-scan` |
| Kubernetes | `k8s-pods`, `k8s-secrets` |
| Docker API | `docker-api` |
| Grafana | `grafana` |
| Confluence | `confluence-rce` |
| Liferay | `liferay-rce` |
| PHP | `phpunit-rce`, `phpinfo` |
| Apache | `apache-server-status` |
| Routers / legacy | `fritzbox`, `admin-config`, `bag2`, `config-getuser` |
| Cloud Metadata | `aws-metadata`, `gcp-metadata`, `do-metadata` |
| AI / LLM tooling 🍯 | `langflow-rce`, `langflow-autologin`, `langflow-apikey`, `langflow-scan` |
| AI agents / MCP 🍯 | `mcp-server-probe`, `ai-assistant-config`, `ai-assistant-credentials`, `llm-openai-models`, `ollama-tags`, `ssrf-metadata-probe` |
| REST API IDOR 🍯 | `rest-api-idor-users/accounts/admin/customers/employees` |
| Credential leaks 🍯 | `env-file`, `aws-credentials`, `htpasswd`, `ssh-key` |
| Git leaks | `git-config`, `git-head` |
| Config leaks | `spring-config-leak`, `docker-compose-leak` |
| API specs | `swagger` |
| Backup files | `backup-file` |
| Webshells | `webshell` |
| Path traversal | `path-traversal-passwd` |
| Log4Shell | `log4shell` |
| CGI scanning | `cgi-scan` |
| Honeytokens 🍯 | `honeytoken-used` |

🍯 = embeds honeytoken in response

---

## Build Status

[![Docker Pulls](https://img.shields.io/docker/pulls/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)
![Image Size](https://img.shields.io/docker/image-size/andreaskasper/http-honeypot/latest)
[![GitHub Issues](https://img.shields.io/github/issues/andreaskasper/http-honeypot.svg)](https://github.com/andreaskasper/http-honeypot/issues)

---

## Support

[![donate via Patreon](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/AndreasKasper)
[![donate via PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/AndreasKasper)
[![donate via Ko-fi](https://img.shields.io/badge/Donate-Ko--fi-green.svg)](https://ko-fi.com/andreaskasper)
[![Sponsors](https://img.shields.io/github/sponsors/andreaskasper)](https://github.com/sponsors/andreaskasper)
