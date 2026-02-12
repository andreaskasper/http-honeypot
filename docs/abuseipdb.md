---
title: AbuseIPDB
nav_order: 8
---

# AbuseIPDB Integration
{: .no_toc }

The honeypot can automatically report attacking IP addresses to [AbuseIPDB](https://www.abuseipdb.com/) — a collaborative blocklist that security teams and firewall operators use to block known bad actors.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Setup

1. Create a free account at [abuseipdb.com](https://www.abuseipdb.com/)
2. Go to **Account → API** and create an API key
3. Set the environment variable:

```bash
ABUSEIPDB_KEY=your_api_key_here
```

That's it. The honeypot starts reporting immediately on the next attack.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_KEY` | _(empty)_ | Your AbuseIPDB API key. Leave empty to disable. |
| `ABUSEIPDB_SLEEP` | `86400` | Cooldown in seconds before the same IP is reported again. Default is 24 hours. |

The cooldown prevents your API quota from being consumed by a single persistent scanner. AbuseIPDB's free tier allows 1,000 reports per day.

---

## What gets reported

Every attack (any matched trap) triggers a report. The report includes:

**Categories:**
- `21` (Web App Attack) — for most traps
- `14, 21` (Port Scan + Web App Attack) — for traps that signal broad scanning behaviour (`cgi-scan`, `wordpress-scan`, etc.)

**Comment format:**
```
HTTP honeypot [my-honeypot]: spring-actuator-env | GET /actuator/env | UA: python-requests/2.31.0
```

The comment includes your honeypot's `NAME`, the `attack_tag`, the HTTP method and path, and the attacker's User-Agent. This gives AbuseIPDB reviewers enough context to assess the report.

---

## Behaviour

- **Fully async** — the report fires in a background goroutine and never delays the honeypot response
- **Non-fatal** — network errors or API errors are logged but do not affect honeypot operation
- **Per-IP cooldown** — an in-memory map tracks the last report time per IP; if the same IP attacks again within `ABUSEIPDB_SLEEP` seconds, the second report is silently skipped
- **Honeytoken reuse** — honeytoken usage events also trigger an AbuseIPDB report

{: .note }
The cooldown map is in-memory and resets on container restart. If you restart the container frequently, the same IP might be reported more often than intended. For most deployments this is not a concern.

---

## AbuseIPDB free tier limits

| Limit | Value |
|---|---|
| Reports per day | 1,000 |
| Checks per day | 1,000 |
| Max comment length | 1,024 characters |

With the default 24 h cooldown per IP, you would need 1,000 unique attacking IPs per day to hit the limit — typical for a busy honeypot on a residential or small VPS IP.

If you run a high-traffic honeypot, increase `ABUSEIPDB_SLEEP` or upgrade to a paid AbuseIPDB plan.
