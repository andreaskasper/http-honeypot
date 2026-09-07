---
title: Supply Chain & AI Gateways
parent: Attack Traps
nav_order: 12
---

# Software Supply Chain & AI Gateway Traps 🍯
{: .no_toc }

Two surfaces that sit in the middle of something and hold every credential passing through it: the binary repository in the middle of a build, and the model gateway in the middle of an inference pipeline. Both were added to the CISA KEV catalog on **2026-09-02**, and both are worth more to an attacker than the host they run on.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## JFrog Artifactory 🍯

**Tags:** `artifactory-token-mint`, `artifactory-system`, `artifactory-scan`

[CVE-2026-82329](https://nvd.nist.gov/vuln/detail/CVE-2026-82329) is an improper-authentication flaw, CVSS 9.8, that lets an unauthenticated caller with network access reach administrative privileges under Artifactory's default configuration. JFrog disclosed and patched it on **2026-08-28**. By **2026-09-01** watchTowr was already seeing it exploited: attackers minted administrator access tokens, then used them to enumerate users, groups, credentials and federated access relationships, and in a small number of cases created backdoor accounts for persistence. CISA listed it the next day.

JFrog Cloud tenants were fixed server-side. Everything self-managed — on-premises, or on a customer's own AWS or Azure — had to be patched by hand, which is what makes this a mass-scanning target rather than a targeted one.

### `/access/api/v1/tokens`, `/artifactory/api/security/token` 🍯

**Tag:** `artifactory-token-mint`

The arm that matters. This is where a successful bypass hands back a freshly minted access token, so the fake response has the real shape — `access_token`, `expires_in`, `token_type`, and a `scope` of `applied-permissions/admin` — with an **IP-specific honeytoken** (`hp_live_*`) in `access_token`.

That is the closest a honeypot gets to watching the second stage of this campaign. The observed pattern is mint-then-enumerate, so a token that comes back on a later request — from this address or any other — is caught by `detectHoneytokenInRequest`, fires a `honeytoken_used` webhook event and tells you the credential is being used.

{: .note }
> This trap has to run **before** `loadMasterTrap`, which claims the whole of `/access/`. Artifactory's token endpoint lives at `/access/api/v1/tokens`, so `artifactoryTrap` takes only the `/access/api/` subtree and lets everything else under `/access/` fall through to the LoadMaster trap with its own `loadmaster-api` tag.

### `/artifactory/api/system/ping`, `/artifactory/api/system/version`

**Tag:** `artifactory-system`

The two unauthenticated fingerprinting endpoints. `ping` answers `OK` in plain text, exactly as a real instance does; `version` returns a version, revision and licence type. Both set `X-JFrog-Version`, which is what a scanner reads to decide whether the host is worth a payload.

### Everything else under `/artifactory/` and `/access/api/`

**Tag:** `artifactory-scan`

A `401` with Artifactory's own error envelope (`{"errors":[{"status":401,"message":"Bad credentials"}]}`). Because the tag contains `scan`, these are reported to AbuseIPDB as **category 14 + 21** (Port Scan + Web App Attack) rather than 21 alone.

No repository contents are served and no token is ever validated. There is nothing behind these paths to fetch.

---

## LiteLLM proxy 🍯

**Tags:** `litellm-key-generate`, `litellm-key-info`, `litellm-model-info`, `litellm-scan`

LiteLLM is the OpenAI-compatible gateway organisations put in front of their model providers. That position is the whole problem: it holds every upstream provider key and every virtual key issued to internal teams, so compromising the proxy is worth far more than compromising any one application behind it.

[CVE-2026-59822](https://nvd.nist.gov/vuln/detail/CVE-2026-59822) — KEV, **2026-09-02** — is an authentication bypass in the MCP Streamable HTTP endpoint. Before 1.84.0, a fabricated `Authorization` header triggered an OAuth2 passthrough fallback that replaced failed LiteLLM key validation with an empty `UserAPIKeyAuth()`, letting an unauthenticated caller list and call every configured MCP tool — and reach the services behind them. Its sibling [CVE-2026-35029](https://nvd.nist.gov/vuln/detail/CVE-2026-35029) targets the admin API that mints virtual keys.

{: .note }
> The bare `/mcp` and `/v1/models` probes are answered one block later by [the AI-agent trap](ai-agents) and keep their `mcp-server-probe` and `llm-openai-models` tags. This trap claims the management surface, which is where the credentials actually are.

### `/key/generate`, `/sso/key/generate` 🍯

**Tag:** `litellm-key-generate`

Mints a virtual key. The response carries an **IP-specific honeytoken** in the `key` field — precisely the value an attacker would then replay against `/v1/chat/completions` to spend someone else's inference budget. Around it sits a plausible key record: alias, team, model list, null budget.

### `/key/info`, `/key/list`, `/user/info` 🍯

**Tag:** `litellm-key-info`

Enumeration of keys already issued, with spend and budget. Also honeytokened, because this is the read-only path to the same prize.

### `/model/info`, `/v1/model/info` 🍯

**Tag:** `litellm-model-info`

The deployment list. On a real proxy the `litellm_params` block is where the **upstream provider key** lives, so that is where the honeytoken goes — an Azure OpenAI deployment with an `api_base`, an `api_version` and a fake `api_key`.

### `/health/liveliness`, `/health/readiness`, `/spend/logs`, `/global/spend/report`, `/model/settings`

**Tag:** `litellm-scan`

A `401` in LiteLLM's own error shape. `liveliness` is LiteLLM's own spelling, so an uptime monitor pointed at this host will not hit these by accident. The generic `/health` is **deliberately left unclaimed** for exactly that reason — the same call that was made for Metabase's `/api/health`. An ordinary monitor should never end up reported to AbuseIPDB.

---

## Related

- [AI Agents & MCP](ai-agents) — the MCP handshake, assistant config files and unauthenticated LLM endpoints
- [Other Services](other-services) — Langflow, Metabase, N-central, vCenter and the rest
- [Honeytokens](../honeytokens) — how the `hp_live_*` tokens work and what happens on reuse
- [AbuseIPDB](../abuseipdb) — why `*-scan` tags report as category 14 + 21
