---
title: Prometheus Metrics
nav_order: 5
---

# Prometheus Metrics
{: .no_toc }

The honeypot exposes a `/metrics` endpoint in the Prometheus text format.

---

## Enabling & securing

The endpoint is **protected by HTTP Basic Auth** using the `METRICS_USER` / `METRICS_PASSWORD` environment variables.

```bash
# Test with curl
curl http://admin:password@your-honeypot/metrics

# Disable entirely
METRICS_DISABLED=true
```

{: .warning }
**Change the default credentials** (`admin` / `password`) before exposing to the internet. The endpoint is on the same port as the honeypot — anyone who finds `/metrics` could see your counters or brute-force credentials.

---

## Available metrics

| Metric | Type | Description |
|---|---|---|
| `http_requests_all` | counter | Total number of requests received |
| `http_requests{code="404"}` | counter | Requests that fell through to the default 404 |
| `http_requests{code="attack"}` | counter | Requests matched by an attack trap |
| `http_duration_ms` | counter | Cumulative tar-pit delay in milliseconds (total attacker time wasted) |

---

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: honeypot
    static_configs:
      - targets: ["honeypot.example.com:80"]
    basic_auth:
      username: admin
      password: your_secure_password
```

---

## Example Grafana queries

```promql
# Attack rate (per minute)
rate(http_requests{code="attack"}[1m]) * 60

# Ratio of attacks vs total traffic
http_requests{code="attack"} / http_requests_all

# Total attacker time wasted (hours)
http_duration_ms / 1000 / 3600
```
