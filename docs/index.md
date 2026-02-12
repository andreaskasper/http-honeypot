---
title: Home
nav_order: 1
---

# 🍯 HTTP Honeypot
{: .no_toc }

A high-interaction HTTP honeypot written in **Go** that simulates real vulnerable web services, tarpits every attacker with a cryptographically random delay, and fires structured attack events to Pushover, any webhook, and Prometheus.

[![Docker Pulls](https://img.shields.io/docker/pulls/andreaskasper/http-honeypot.svg)](https://hub.docker.com/r/andreaskasper/http-honeypot)
[![Image Size](https://img.shields.io/docker/image-size/andreaskasper/http-honeypot/latest)](https://hub.docker.com/r/andreaskasper/http-honeypot)
[![GitHub Issues](https://img.shields.io/github/issues/andreaskasper/http-honeypot.svg)](https://github.com/andreaskasper/http-honeypot/issues)

---

## What it does

The honeypot listens on port 80 and pretends to be a real vulnerable web server. When a scanner hits a known exploit path:

1. **It responds convincingly** — a real Spring Boot `/actuator/env` response with fake AWS keys, a real WordPress login page, a real Exchange OWA login, etc.
2. **It delays every response** by a random duration (0–`TAR_PIT_MAX_SEC` seconds, using `crypto/rand`) so scanners waste time and resources.
3. **It tags the attack** with a specific `attack_tag` like `spring-actuator-env`, `log4shell`, or `k8s-secrets`.
4. **It fires notifications** — Pushover on your phone, a webhook POST to n8n/Slack/Make, and increments Prometheus counters.
5. **It logs everything** as structured JSON to `/var/log/honeypot.jsonl`.

---

## Feature overview

| Feature | Details |
|---|---|
| 🎣 **40+ attack traps** | Spring, WordPress, Exchange, Fortinet, K8s, Docker, AWS/GCP metadata, Git leaks, web shells, and more |
| 🐢 **Tar-pit** | `crypto/rand` delay per request; prevents timing fingerprinting |
| 🏷️ **attack_tag** | Every matched trap produces a machine-readable tag for webhook routing |
| 🔍 **Log4Shell** | Scans all request headers + query string for `${jndi:` payloads |
| 🔑 **API key capture** | Captures `X-Api-Key`, `Authorization: Bearer`, `Authorization: Token` sent by scanners |
| 📋 **JSON logging** | One JSON line per request; built-in size-based log rotation |
| 🔇 **LOG_DISABLED** | Disable all file I/O while keeping Pushover + webhook active |
| 🔔 **Pushover** | Country-based mobile push; throttled to once per hour |
| 🔗 **Webhook** | POST JSON to any URL; `X-Honeypot-Secret` header for auth |
| 📊 **Prometheus** | `/metrics` endpoint with HTTP Basic Auth; `METRICS_DISABLED` option |
| 🐳 **Tiny image** | ~15 MB via multi-stage build (Go 1.25 → Alpine 3.21) |

---

## Quick start

```bash
docker run -p 80:80 andreaskasper/http-honeypot
```

Or with Docker Compose (recommended — preserves logs across restarts):

```bash
git clone https://github.com/andreaskasper/http-honeypot.git
cd http-honeypot
cp .env.example .env
# edit .env with your values
docker-compose up -d
```

→ **Next:** [Installation guide](installation)
