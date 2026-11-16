---
title: AI Infrastructure
parent: Attack Traps
nav_order: 19
---

# AI Infrastructure Traps 🍯
{: .no_toc }

The layer under the model gateway: the cluster managers that decide which model runs on which GPU and issue the keys to reach them. A compromised one hands over every model endpoint, every key and the GPUs themselves.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## GPUStack 🍯

**Tags:** `gpustack-apikey-mint`, `gpustack-backend-rce`, `gpustack-auth-bypass`, `gpustack-scan`

GPUStack is an open-source GPU cluster manager for LLM inference (about 940,000 Docker Hub pulls).

[CVE-2026-102895](https://nvd.nist.gov/vuln/detail/CVE-2026-102895), **CVSS 9.8**, CISA KEV **2026-11-09**: before 2.2.0, `get_current_user` treats any request from a loopback address as the built-in admin while `force_auth_localhost` is false, which is the default. There are two ways in. Behind a same-host reverse proxy (`proxy_pass http://127.0.0.1:<port>`) every request arrives from 127.0.0.1, so no header and no credential is needed. Otherwise the header `X-GPUStack-Real-IP: 127.0.0.1` does it.

The fix shipped in 2.2.0 on 2026-06-18, but the CVE was only published on 2026-11-04. The vendor reported in-the-wild exploitation of a 2.1.1 deployment: the attacker minted an admin API key and registered a custom inference backend whose run command opened a reverse shell. Sources: the [GitLab advisory](https://advisories.gitlab.com/pypi/gpustack/CVE-2026-102895/) (GHSA-gj9m-f8ph-pmhr), [Ostorlab](https://blog.ostorlab.co/gpustack-auth-bypass-rce-cve-2026-102895.html) and the [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-gpustack-cve-2026-102895-kev-20261110-csa/). The routes and response shapes below come from the GPUStack source (`gpustack/routes/routes.py`, versioned prefix `/v2`, and the `ApiKeyPublic` and `InferenceBackend` schemas).

### `POST /v2/api-keys` 🍯

**Tag:** `gpustack-apikey-mint`

The persistence step. The reply is an `ApiKeyPublic` document whose one-time `value` is an **IP-specific honeytoken**. GPUStack accepts custom-format keys, so a value without the usual `gpustack_` prefix is plausible. The attacker's next move is to replay it as a `Bearer` token against `/v1/chat/completions` or the `/v2` management API, and that request fires `honeytoken_used`.

### `POST /v2/inference-backends`, `POST /v2/inference-backends/from-yaml`

**Tag:** `gpustack-backend-rce`

The code-execution step: whoever creates an inference backend chooses its run command. The trap answers with a created-backend document. It does not parse the body and runs nothing.

### Any other `/v2/` or `/auth/` request carrying `X-GPUStack-Real-IP`

**Tag:** `gpustack-auth-bypass`

No legitimate client sends this header from the internet, so its presence is the signal. `/v2/users/me` answers with the built-in admin (`"is_admin":true`), everything else with an empty paginated list.

### `/v2/users/me`, `GET /v2/api-keys` without the header

**Tag:** `gpustack-scan`

The reverse-proxy variant needs no header, so a bare request for the current user is how a scanner checks whether the bypass works. Answered `401` in GPUStack's error shape, like a patched server.

{: .note }
> **Deliberately not claimed:** the bare `/v2/` prefix and `/v2/_catalog` (Docker registry probes), `/auth/login` and `/auth/config` without the header (other products use those names), and `/v1/`, which stays with the [LLM endpoint traps](ai-agents#unauthenticated-llm-endpoints). `/v1/models` keeps `llm-openai-models` even when the header is set.
>
> **Ordering:** `gpustackTrap` closes the edge-appliance dispatch line; nothing above it claims a `/v2/` path.

---

## Related

- [AI Agents & MCP](ai-agents) — MCP handshakes, assistant config files and unauthenticated LLM endpoints
- [Supply Chain & AI Gateways](supply-chain) — the LiteLLM proxy, which sits in front of clusters like this one
- [Honeytokens](../honeytokens) — how the `hp_live_*` tokens work and what happens on reuse
- [AbuseIPDB](../abuseipdb) — why `*-scan` tags report as category 14 + 21
