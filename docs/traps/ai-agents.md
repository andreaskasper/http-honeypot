---
title: AI Agents & MCP
parent: Attack Traps
nav_order: 11
---

# AI Agent & MCP Traps 🍯
{: .no_toc }

In July 2026 the SANS Internet Storm Center [documented](https://isc.sans.edu/diary/33150) a distributed scan looking for Model Context Protocol servers, AI coding-assistant configuration files and unauthenticated local LLM endpoints — on a small web host that ran none of them. The MCP handshake category came from **49 distinct source IPs**, more spread than any other category in that dataset.

The scanners did not wait for these deployments to become common. Your attack surface grew when your organisation adopted AI agents, and this is the trap set for it.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## MCP server probe

**Paths:** `/mcp`, `/mcp/`, `/sse`, `/mcp/sse`  
**Tag:** `mcp-server-probe`

These probes are not dumb URL requests. Every one carries a well-formed JSON-RPC 2.0 `initialize` call:

```json
{"id":1,"jsonrpc":"2.0","method":"initialize",
 "params":{"capabilities":{},
           "clientInfo":{"name":"client","version":"0"},
           "protocolVersion":"2025-03-26"}}
```

The scanner is speaking the protocol and waiting to see whether something answers like an MCP server. A plain `404` ends the conversation immediately, so this trap answers with a valid `initialize` result advertising tool, prompt and resource capabilities. An exposed MCP server is a machine-readable inventory of everything an agent can touch, which is why it is worth this much scanner effort — and why it is worth simulating.

{: .note }
> If you run a real MCP server, any `POST /mcp` from an address you do not recognise is pure reconnaissance. Confirm it requires authentication and is not reachable from the internet.

---

## AI assistant configuration 🍯

**Paths:** `/.claude/*`, `/.cursor/*`, `/.mcp/*`, `/.vscode/mcp.json`  
**Tag:** `ai-assistant-config`

The files AI coding assistants write into a project directory. When a developer accidentally deploys one to a web root, it leaks the MCP servers the project talks to — and frequently the credentials they use. The observed wordlist was specific and current (`/.claude/mcp.json`, `/.cursor/mcp.json`, `/.cursor/mcp_config.json`, `/.vscode/mcp.json`, `/.mcp/config.json`, `/.claude/settings.local.json`), which means it was built recently and from real knowledge of how these tools store settings.

The honeypot returns a fake `mcpServers` block whose `GITHUB_PERSONAL_ACCESS_TOKEN` is an **IP-specific honeytoken** (`hp_live_*`), alongside a fake Postgres connection string.

---

## AI assistant credentials 🍯

**Paths:** `**/.credentials.json`, `**/credentials.json`  
**Tag:** `ai-assistant-credentials`

Stored OAuth material for an AI coding assistant — `/.claude/.credentials.json`, `/.config/claude/.credentials.json` — plus the generic `credentials.json` that rides along in the same wordlist as the GCP, AWS and Azure variants. The tooling authors now treat AI assistant secrets as just another cloud credential worth harvesting.

These were requested with **`HEAD`**, not `GET`: the scanner checks whether the file exists before spending bandwidth downloading it. That is an optimisation you build when you are scanning a very large number of hosts and expect most to be misses — a tell for a mature, wide campaign rather than a one-off probe.

The fake response carries an **IP-specific honeytoken** as the OAuth access token.

{: .note }
> `.aws/credentials` is matched earlier in the routing chain and keeps its own `aws-credentials` tag.

---

## Unauthenticated LLM endpoints

**Path:** `/v1/models` — **Tag:** `llm-openai-models`  
**Paths:** `/api/tags`, `/api/ps` — **Tag:** `ollama-tags`

The two signatures that dominated the LLM probing:

- `/v1/models` is the OpenAI-compatible model-listing endpoint that dozens of self-hosted inference servers expose. If it answers without authentication, the host is running a model anyone can query — free compute for the attacker and a pivot point.
- `/api/tags` lists the models installed in Ollama. Ollama binds to localhost by default but is very commonly exposed to the network by accident, so a response here is a strong signal of an unauthenticated local LLM.

Both return plausible fake model listings.

---

## Cloud metadata SSRF

**Paths:** `/fetch`, `/proxy`, `/api/fetch`, `/api/proxy`  
**Tag:** `ssrf-metadata-probe`

A classic that rides along with the AI-agent recon. The scanner rotates the parameter name across `url`, `uri`, `path` and `dest`, looking for any endpoint that will follow a supplied URL to the cloud metadata service and return a service-account token:

```
GET /fetch?url=http://metadata.google.internal/...token
GET /fetch?dest=http://metadata.google.internal/...token
```

This belongs in the AI context because agent and LLM tooling routinely ships fetch-style helpers that take a URL and retrieve it — a ready-made SSRF primitive.

The trap only fires when a query value actually references a metadata address (`metadata.google.internal`, `169.254.169.254`, `metadata.azure.com`); a bare `/fetch` falls through to the normal 404. The honeypot never contacts any metadata service — it returns a fabricated connection error.

---

## Related

- [Langflow](other-services#langflow--ai-agent-platforms-) — the AI agent platform traps, including the `auto_login` bypass
- [Cloud Metadata](cloud-metadata) — the direct `/latest/meta-data` and `/computeMetadata/v1` traps
- [Honeytokens](../honeytokens) — how the `hp_live_*` tokens work and what happens on reuse
