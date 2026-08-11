---
title: Attack Traps
nav_order: 6
has_children: true
---

# Attack Traps

The honeypot simulates **85+ real attack surfaces** that are actively scanned on the public internet every day. Each trap responds with convincing fake data — the same response format a real vulnerable server would return — to keep scanners engaged and wasting time.

Every matched trap sets an `attack_tag` in the JSON log and webhook payload, letting you route and analyse by attack type.

## Trap categories

| Category | Page | Tags |
|---|---|---|
| Spring Boot Actuator | [Spring Boot](spring-boot) | `spring-actuator-*` |
| WordPress & CMS | [CMS](cms) | `wp-login`, `xmlrpc`, `joomla-admin`, ... |
| Microsoft Exchange | [Exchange](exchange) | `owa-login`, `exchange-ews`, `exchange-proxylogon` |
| VPN Appliances | [VPN](vpn) | `fortinet-fgt`, `sonicwall-vpn`, `pulse-secure`, `cisco-asa-vpn`, `citrix-netscaler-*`, `panos-globalprotect-*` |
| AI Agents & MCP | [AI Agents & MCP](ai-agents) | `mcp-server-probe`, `ai-assistant-config`, `ai-assistant-credentials`, `llm-openai-models`, `ollama-tags`, `ssrf-metadata-probe` |
| Kubernetes & Docker | [Kubernetes & Docker](kubernetes-docker) | `k8s-pods`, `k8s-secrets`, `docker-api` |
| Cloud Metadata | [Cloud Metadata](cloud-metadata) | `aws-metadata`, `gcp-metadata`, `do-metadata` |
| Credential & File Leaks | [Credential Leaks](credential-leaks) | `env-file`, `git-config`, `aws-credentials`, `ssh-key`, ... |
| REST API IDOR | [REST API](rest-api) | `rest-api-idor-users`, `rest-api-idor-accounts`, ... |
| SharePoint, ColdFusion, Langflow, N-central & co. | [Other Services](other-services) | `sharepoint-toolpane`, `coldfusion-admin`, `langflow-apikey`, `nable-ncentral-auth`, `apache-solr`, `jenkins-script`, `h2-console`, `grafana`, ... |
| Log4Shell | [Log4Shell](log4shell) | `log4shell` |
