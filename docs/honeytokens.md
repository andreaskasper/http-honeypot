---
title: Honeytokens
nav_order: 7
---

# Honeytokens
{: .no_toc }

Honeytokens are fake credentials embedded in the honeypot's fake responses. When an attacker steals them and later reuses them — even from a different IP, days later — the honeypot detects and alerts on the reuse.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## What are honeytokens?

A honeytoken is a fake credential that looks real enough to fool automated tools, but is unique to the honeypot and functionally useless. The goal is not to protect anything, but to **detect post-theft behaviour**: did the attacker actually try to use what they stole?

This is high-signal detection. A scanner blindly hitting your honeypot is background noise. An attacker sending back a token they received from your honeypot means:

- They collected credentials from your fake endpoint
- They tried to authenticate with them somewhere
- You now know their attack IP, user agent, and timing

---

## Token format

Every token follows the pattern:

```
hp_live_{md5(ip + "-" + trap_name)[:20]}
```

Examples:
- `hp_live_a1b2c3d4e5f6789012ab`  (from `/.env` for IP `1.2.3.4`)
- `hp_live_f09e8d7c6b5a432109de`  (from `/actuator/env` for the same IP)

The `hp_live_` prefix is recognizable at a glance. The 20-hex suffix is deterministic per IP + trap, so if an attacker from `1.2.3.4` steals your fake AWS key and then `5.6.7.8` sends it back, you can trace the token back to the original theft.

---

## Where tokens are embedded

| Trap | Field | Token used as |
|---|---|---|
| `/actuator/env` | `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `/.env` | `STRIPE_SECRET_KEY` | Stripe live key |
| `/.aws/credentials` | `aws_secret_access_key` | AWS secret key |
| `/api/v*/users/{id}` | `api_key` | REST API key |
| `/api/v1/api_key` | `api_keys[].api_key` | Langflow API key |
| `/api/v1/auto_login` | `access_token` | Langflow SUPERUSER JWT (CVE-2026-9198) |
| `/api/session/properties` | `setup-token` | Metabase setup token (CVE-2023-38646 chain) |
| `/api/database` | `data[].details.password` | Password of a connected database (CVE-2026-72898 target) |
| `/p/u/doAuthentication.do` | `<InitialValue>` | NetScaler session material in fake leaked memory |
| `/global-protect/getconfig.esp` | `<portal-userauthcookie>` | GlobalProtect portal auth cookie |
| `/.claude/mcp.json` and friends | `env.GITHUB_PERSONAL_ACCESS_TOKEN` | GitHub PAT in an MCP server config |
| `/.claude/.credentials.json` | `claudeAiOauth.accessToken` | AI assistant OAuth token |
| `/api/auth/authenticate` | `tokens.access.token` | N-central admin bearer token |

They all mimic the format of real credentials that automated scanners and credential-harvesting tools look for specifically.

{: .note }
> The Langflow, Metabase and N-central carriers sit on endpoints an attacker reaches through an **authentication bypass**. The bypass appears to succeed, the attacker replays the token on the next request, and `detectHoneytokenInRequest` catches it — so the whole chain is observable end to end.

---

## Detection

The honeypot scans every incoming request for honeytoken reuse:

1. **All request headers** — including `Authorization: Bearer hp_live_...`, `X-Api-Key: hp_live_...`, `Cookie: NSC_AAAC=hp_live_...`, and any custom header
2. **Query parameters** — e.g. `?api_key=hp_live_...`
3. **POST/PUT body** — scanned after the standard 8 KB body read
4. **Already-captured API key** — from `captureAPIKey()` which reads `X-Api-Key` and `Authorization`

Header, cookie and query values are split on every delimiter that can surround a credential (whitespace, `=`, `&`, `;`, `,`, `:`, quotes, brackets), so a token pasted into a cookie or a JSON field is still found.

Detection is prefix-based (`hp_live_`) plus exact length check (28 characters total), so false positives are essentially impossible.

---

## What happens on detection

When a token is detected, the honeypot immediately (before path routing):

1. Sets `attack_tag = "honeytoken-used"` and `is_honeytoken_use = true`
2. Fires a **`honeytoken_used`** webhook event — a separate event type from `"attack"`
3. Increments `http_honeytokens_used` Prometheus counter
4. Adds the IP to the blacklist log
5. Reports to AbuseIPDB (if configured)
6. Logs `HONEYTOKEN USED by {ip}: {token}` to stdout
7. **Still responds normally** — the attacker has no indication they were detected

---

## n8n routing for honeytoken events

Filter on the `event` field:

```
Webhook node
  └─ Switch on event
       ├─ "honeytoken_used"  → 🚨 Slack #security-critical + PagerDuty + block IP
       ├─ "attack"           → Normal processing
       └─ "country_notify"   → Pushover (already sent)
```

To correlate original theft with reuse:

```javascript
// In n8n Code node
const token = $json.api_key_used;  // e.g. "hp_live_a1b2c3d4e5f6789012ab"
const thiefIP = $json.ip;
// Search your logs for the original request that returned this token
// (it will have the same token in the response body)
```

---

## Prometheus metric

```promql
# Total honeytoken reuse events
http_honeytokens_used

# Rate over last hour
rate(http_honeytokens_used[1h]) * 3600
```
