# 🍯 HTTP Honeypot

A high-interaction HTTP honeypot written in Go. It simulates **40+ real attack surfaces** — WordPress, Spring Boot, Exchange, Kubernetes, VPN appliances, cloud metadata endpoints and more — responds with convincing fake data to keep attackers engaged, and tarpits every request with a cryptographically random delay.

All hits are logged as structured JSON and can be forwarded in real time to **Pushover**, any **webhook** (n8n, Slack, Make, Zapier…), or **Prometheus**.

📖 **Full documentation:** https://andreaskasper.github.io/http-honeypot/

---

## Features

- 🎣 **40+ attack traps** — Spring Actuator, WordPress, Exchange/OWA, Fortinet, Kubernetes, Docker API, AWS/GCP metadata, Git leaks, phpMyAdmin, Jenkins, Confluence, web shells, and more
- 🐢 **Tar-pit** — every response is delayed by a cryptographically random `[0, TAR_PIT_MAX_SEC]` seconds
- 🏷️ **`attack_tag`** — every matched trap is tagged (e.g. `spring-actuator-env`, `log4shell`, `k8s-secrets`) so webhooks can route by attack type
- 🔍 **Log4Shell detection** — scans all request headers and query strings for `${jndi:` payloads
- 📋 **Structured JSON logging** — one JSON line per request to `/var/log/honeypot.jsonl`
- 🔔 **Pushover** push notifications with country-based throttling
- 🔗 **Generic webhook** — POST JSON to any URL on every attack event
- 📊 **Prometheus `/metrics`** endpoint with Basic Auth
- 🔄 **Log rotation** — built-in, size-based, no external tools required
- 🔇 **`LOG_DISABLED`** — disable all file logging while keeping notifications active
- 🐳 **Multi-stage Docker build** — final image ~15 MB (Go 1.25 / Alpine 3.21)

---

## Build Status

[![Automated Build](https://img.shields.io/docker/cloud/automated/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)
[![Docker Pulls](https://img.shields.io/docker/pulls/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)
![Image Size](https://img.shields.io/docker/image-size/andreaskasper/http-honeypot/latest)
[![GitHub Issues](https://img.shields.io/github/issues/andreaskasper/http-honeypot.svg)](https://github.com/andreaskasper/http-honeypot/issues)

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
| `NAME` | _(empty)_ | Instance name — included in all notifications (useful for multi-honeypot setups) |
| `HONEYPOT_PORT` | `80` | Host port mapping (docker-compose only) |
| **Tar-pit** | | |
| `TAR_PIT_MAX_SEC` | `20` | Max random delay per request in seconds (0 = disabled) |
| **Rate limiting** | | |
| `RATE_LIMIT_PER_MIN` | `1000` | Max requests per IP per minute (very high by default to capture maximum data) |
| **Logging** | | |
| `LOG_DISABLED` | `false` | Set `true` to disable all file logging (Pushover/webhooks still fire) |
| `LOG_MAX_SIZE_MB` | `100` | Rotate `/var/log/honeypot.jsonl` when it exceeds this size in MB |
| **Pushover** | | |
| `PUSHOVER_APP` | _(empty)_ | Pushover application token |
| `PUSHOVER_RECIPIENT` | _(empty)_ | Pushover user/group key |
| `PUSHOVER_NOTIFY_COUNTRY` | _(empty)_ | ISO 3166-1 alpha-2 code — notify when a request comes from this country (throttled 1/hour) |
| **Webhook** | | |
| `WEBHOOK_URL` | _(empty)_ | HTTP POST endpoint for JSON attack events |
| `WEBHOOK_SECRET` | _(empty)_ | Sent in `X-Honeypot-Secret` header for receiver verification |
| **Prometheus metrics** | | |
| `METRICS_USER` | `admin` | Username for `/metrics` Basic Auth |
| `METRICS_PASSWORD` | `password` | Password for `/metrics` Basic Auth |
| `METRICS_REALM` | `Prometheus Server` | HTTP Basic Auth realm name |
| `METRICS_DISABLED` | `false` | Set `true` to disable the `/metrics` endpoint entirely |

---

## Webhook Payload

Every attack fires a JSON POST to `WEBHOOK_URL`:

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
  "post_body": "",
  "ipinfo": { "country": "CN", "city": "Beijing", "org": "AS4134" }
}
```

The `attack_tag` field lets you build conditional webhook flows — e.g. route `log4shell` hits to a Slack alert channel while logging everything else quietly.

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
| H2 / JBoss Console | `h2-console` |
| Microsoft Exchange | `owa-login`, `exchange-ews`, `exchange-proxylogon`, `exchange-ecp` |
| Fortinet / VPN | `fortinet-fgt`, `sonicwall-vpn`, `pulse-secure`, `cisco-asa-vpn` |
| Kubernetes API | `k8s-pods`, `k8s-secrets` |
| Docker API | `docker-api` |
| Grafana | `grafana` |
| Confluence | `confluence-rce` |
| Liferay | `liferay-rce` |
| AWS / GCP / DO Metadata | `aws-metadata`, `gcp-metadata`, `do-metadata` |
| AWS Credentials | `aws-credentials` |
| Git source leaks | `git-config`, `git-head` |
| REST API IDOR | `rest-api-idor-users/accounts/admin/customers` |
| Credential files | `env-file`, `htpasswd`, `aws-credentials` |
| SSH keys | `ssh-key` |
| Web shells | `webshell` |
| Path traversal | `path-traversal-passwd` |
| Config leaks | `spring-config-leak`, `docker-compose-leak` |
| Database dumps | `backup-file` |
| phpinfo | `phpinfo` |
| FritzBox | `fritzbox` |
| Apache server-status | `apache-server-status` |
| Log4Shell (headers) | `log4shell` |
| CGI scanning | `cgi-scan` |

---

## Support the Project

[![donate via Patreon](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/AndreasKasper)
[![donate via PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/AndreasKasper)
[![donate via Ko-fi](https://img.shields.io/badge/Donate-Ko--fi-green.svg)](https://ko-fi.com/andreaskasper)
[![Sponsors](https://img.shields.io/github/sponsors/andreaskasper)](https://github.com/sponsors/andreaskasper)
