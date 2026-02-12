---
title: Installation
nav_order: 2
---

# Installation
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Prerequisites

- Docker 20.10+ (and optionally Docker Compose v2)
- A public IP or a domain pointing to your server
- Ports 80 (and optionally 443) open in your firewall

{: .note }
The honeypot is designed to be placed **in front of** your real web server. Run your actual site on a non-standard port and expose only the honeypot on 80.

---

## Option A — Docker Run (quickest)

```bash
docker run -d \
  --name honeypot \
  --restart unless-stopped \
  -p 80:80 \
  -e NAME=my-honeypot \
  -e PUSHOVER_APP=your_app_token \
  -e PUSHOVER_RECIPIENT=your_user_key \
  -v honeypot_logs:/var/log \
  andreaskasper/http-honeypot
```

---

## Option B — Docker Compose (recommended)

```bash
git clone https://github.com/andreaskasper/http-honeypot.git
cd http-honeypot
cp .env.example .env
```

Edit `.env` with your values, then:

```bash
docker-compose up -d

# Check logs
docker-compose logs -f

# Read JSON attack log
docker exec honeypot tail -f /var/log/honeypot.jsonl | jq .
```

---

## Option C — Behind Traefik

Uncomment the `labels` and `networks` sections in `docker-compose.yml`:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.honeypot.rule=Host(`honeypot.example.com`)"
  - "traefik.http.routers.honeypot.entrypoints=websecure"
  - "traefik.http.routers.honeypot.tls.certresolver=letsencrypt"
  - "traefik.http.services.honeypot.loadbalancer.server.port=80"
networks:
  - traefik_proxy
```

And add the external network at the bottom:

```yaml
networks:
  traefik_proxy:
    external: true
```

{: .tip }
When running behind Traefik (or Cloudflare), the honeypot automatically extracts the real client IP from `CF-Connecting-IP`, `X-Forwarded-For`, or `X-Real-IP` headers.

---

## Option D — Build from source

```bash
git clone https://github.com/andreaskasper/http-honeypot.git
cd http-honeypot
docker build -t http-honeypot .
docker run -p 80:80 http-honeypot
```

The `Dockerfile` uses a multi-stage build:
- **Build stage:** `golang:1.25-alpine` compiles the binary
- **Runtime stage:** `alpine:3.21` — final image is ~15 MB

---

## Verifying it works

```bash
# Hit a known attack path
curl http://localhost/actuator/env
curl http://localhost/wp-login.php
curl http://localhost/.env

# Watch the JSON log
docker exec honeypot tail -f /var/log/honeypot.jsonl | jq .

# Check Prometheus metrics (replace user:pass with your values)
curl http://admin:password@localhost/metrics
```

---

## Updating

```bash
docker-compose pull
docker-compose up -d
```
