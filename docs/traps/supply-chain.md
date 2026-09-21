---
title: Supply Chain & AI Gateways
parent: Attack Traps
nav_order: 12
---

# Software Supply Chain & AI Gateway Traps 🍯
{: .no_toc }

Four surfaces that sit in the middle of something and hold every credential passing through it: the binary repository in the middle of a build, the model gateway in the middle of an inference pipeline, the DevOps platform that holds the source and the pipeline both, and the workflow orchestrator that runs the jobs and keeps the secrets they need. All four are worth more to an attacker than the host they run on, and all four were added to the CISA KEV catalog inside a fortnight in September 2026.

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

## GitLab 🍯

**Tags:** `gitlab-commits-traversal`, `gitlab-api-scan`, `gitlab-login`, `gitlab-scan`

A self-managed GitLab is the whole pipeline in one box: source, deploy tokens, CI/CD variables, registry credentials and the Rails secrets that sign every session. Reading arbitrary files off one is not a step towards the prize, it *is* the prize.

[CVE-2026-85706](https://nvd.nist.gov/vuln/detail/CVE-2026-85706) — **CVSS 10.0** — is a path traversal in the repository commits API. Improper path confinement combined with missing authentication enforcement lets an unauthenticated caller read any file the GitLab process can read, in a single HTTP request. GitLab shipped 19.3.2, 19.2.6 and 19.1.8 on **2026-09-10**; watchTowr saw internet-wide probes from **06:00 UTC on 2026-09-11** and CISA added it to KEV the same day, with a federal remediation deadline of **2026-09-14**. Four days from patch to deadline is what indiscriminate scanning looks like.

### `/api/v4/projects/<id>/repository/commits` 🍯

**Tag:** `gitlab-commits-traversal`

The exact URI watchTowr told defenders to hunt for — POST requests carrying a `file.path` parameter. The trap answers the whole subtree regardless of method, because a scanner confirming the endpoint exists probes it with `GET` first and would otherwise walk away on a 404.

The response serves what an attacker actually reaches for on a self-managed instance: `/etc/gitlab/gitlab.rb`, with a database password, an SMTP password and an **IP-specific honeytoken** standing in for `initial_root_password`. Replaying that value — here or anywhere else — is caught by `detectHoneytokenInRequest`.

{: .note }
> The commit envelope wrapped around the fake file content is a best-effort reconstruction of the success shape; the honeypot never parses a request body, so it cannot tailor the response to the `file.path` actually asked for. The bait inside the envelope is what matters, and a scanner grepping a response for credential-shaped strings finds it either way.

### `/api/v4/version`, `/api/v4/metadata`, `/api/v4/projects`, `/api/v4/groups`, `/api/v4/runners/all`, `/api/v4/personal_access_tokens`

**Tag:** `gitlab-api-scan`

The unauthenticated fingerprinting endpoints, answered with GitLab's own `{"message":"401 Unauthorized"}` envelope and an `X-Request-Id`. Because the tag contains `scan`, these report to AbuseIPDB as **category 14 + 21**.

### `/users/sign_in`

**Tag:** `gitlab-login`

A GitLab CE sign-in page with a version string in the footer — the page a scanner reads to decide the host is a GitLab worth a payload.

### `/-/health`, `/-/liveness`, `/-/readiness`

**Tag:** `gitlab-scan`

GitLab's own `/-/` spelling, so an uptime monitor pointed at this host cannot reach them by accident. Same reasoning as LiteLLM's `/health/liveliness` above.

{: .note }
> **Deliberately not claimed:** `/explore`, `/help` and `/users/password/new`. All three are plain Rails or Devise defaults that other applications serve too. A mislabelled AbuseIPDB report is worse than a missed one.
>
> **Ordering:** `restAPITrap` is dispatched much further up and matches `/api/v<N>/(users|accounts|admin|customers|employees)/<digits>`, so `/api/v4/users/5` keeps its `rest-api-idor-users` tag and never reaches this trap. That is the right outcome — a bare numbered-user probe is IDOR scanning, not GitLab exploitation.

---

## Kestra 🍯

**Paths:** any `/api/` path ending in `/configs` (except the real `/api/v1/configs`), `/api/v1/configs`, `/api/v1/*/namespaces/*/kv/*`, the `/api/v1/main/` subtree and `/api/v1/instance`  
**Tags:** `kestra-auth-bypass`, `kestra-scan`, `kestra-kv-read`

Kestra is an open-source workflow orchestrator. It sits in the middle of a data platform and holds, in its namespace KV store, the credentials for everything its flows talk to: cloud accounts, warehouses, internal APIs.

[CVE-2026-49869](https://nvd.nist.gov/vuln/detail/CVE-2026-49869) — **CVSS 10.0**, added to the CISA KEV catalog on **2026-09-02** — is an authentication bypass that becomes unauthenticated OS command execution. Kestra's `AuthenticationFilter` exempted the public configuration endpoint from Basic Auth with `request.getPath().endsWith("/configs")`. Kestra also accepts a caller-controlled flow or namespace identifier in that same path position, so a flow named `configs` produces an API path that ends with the exempted string and skips authentication entirely. Past the filter, the attacker creates and runs a flow; the shell script plugin ships enabled by default, so the flow runs as root inside the worker container. Fixed in **1.0.45** and **1.3.21**.

The lesson generalises past this product: authorization should be a decision about a matched route and a caller, not about the spelling of a URL.

### Any `/api/…/configs` that is not `/api/v1/configs` 🍯

**Tag:** `kestra-auth-bypass`

The suffix the filter trusted, in a position the caller controls. That is the whole exploit signature, and matching on it is deliberately narrow — an `/api/` path ending in `/configs` that is not the real endpoint is the attack and nothing else.

The response is a fabricated flow execution in `SUCCESS` state whose shell task "output" carries an IP-specific [honeytoken](../honeytokens) as `KESTRA_API_TOKEN` — standing in for the environment a real worker would have leaked to the injected command. Replaying that value, here or anywhere else, is caught by `detectHoneytokenInRequest`.

### `/api/v1/configs`

**Tag:** `kestra-scan`

The genuinely public configuration endpoint, and the fingerprint a scanner reads first. Only Kestra serves that exact path, so a probe here is not an accident. The version reported is below the fixed release, which is what keeps a scanner talking instead of moving on.

### `/api/v1/*/namespaces/*/kv/*` 🍯

**Tag:** `kestra-kv-read`

The namespace KV store — where a real deployment keeps the secrets its flows use, and the first thing an attacker reads after the bypass. The returned `value` is an IP-specific honeytoken.

### `/api/v1/main/*`, `/api/v1/instance`

**Tag:** `kestra-scan`

The tenant-scoped management surface, answered with Micronaut's `401` envelope. `/api/v1/main/` is Kestra's own spelling and is claimed nowhere else in the honeypot.

{: .note }
> **Deliberately not claimed:** the bare `/ui/` shell — `ciscoFMCTrap` owns `/ui/login`, and a Kestra UI probe is not worth the collision — and the unversioned `/api/v1/flows` prefix, which belongs to Langflow.
>
> **Ordering:** this trap is dispatched **before** `langflowTrap`, which claims the whole `/api/v1/flows` prefix. `/api/v1/flows/configs` is a Kestra bypass attempt rather than a Langflow probe, and the bypass arm is narrow enough that everything else Langflow owns stays with it.

---

## Related

- [AI Agents & MCP](ai-agents) — the MCP handshake, assistant config files and unauthenticated LLM endpoints
- [Other Services](other-services) — Langflow, Metabase, N-central, vCenter, LoadMaster and the rest
- [Edge Appliances & VPN](vpn) — NetScaler, GlobalProtect and the Cisco FMC and ISE management consoles
- [Honeytokens](../honeytokens) — how the `hp_live_*` tokens work and what happens on reuse
- [AbuseIPDB](../abuseipdb) — why `*-scan` tags report as category 14 + 21
