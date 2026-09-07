package main

import (
	"fmt"
	"net/http"
	"strings"
)

// artifactoryTrap covers JFrog Artifactory, the self-managed binary repository
// that sits at the centre of a software supply chain. CVE-2026-82329 —
// improper authentication, CVSS 9.8, disclosed and patched by JFrog on
// 2026-08-28 — lets an unauthenticated caller with network access reach
// administrative privileges under the default configuration. watchTowr
// observed exploitation in the wild by 2026-09-01: attackers minted
// administrator access tokens, enumerated users, groups, credentials and
// federated access relationships, and in a few cases created backdoor accounts
// for persistence. CISA listed it on 2026-09-02.
//
// The token arm is the one that matters here. It answers where a successful
// bypass would hand back a freshly minted admin token and puts an IP-specific
// honeytoken in access_token, so anything replaying that token is caught by
// detectHoneytokenInRequest — which is as close as a honeypot gets to watching
// the second stage of this campaign.
//
// Ordering: this trap has to run before loadMasterTrap, which claims the whole
// of /access/, because Artifactory's token endpoint is /access/api/v1/tokens.
// Only the /access/api/ subtree is taken here; the rest of /access/ stays with
// the LoadMaster trap.
//
// Nothing is validated and no repository content exists; every response is
// fabricated.
func artifactoryTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	switch {
	case p == "/access/api/v1/tokens", strings.HasPrefix(p, "/access/api/v1/tokens/"),
		p == "/artifactory/api/security/token":
		markAttack(info, "artifactory-token-mint")
		token := honeytoken(info.ip, "artifactory-token-mint")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-JFrog-Version", "Artifactory/7.98.11 79811900")
		fmt.Fprintf(w,
			`{"access_token":%q,"expires_in":3600,"token_type":"Bearer",`+
				`"scope":"applied-permissions/admin","subject":"jfac@01h2/users/admin",`+
				`"token_id":"7f3c1e28-0000-4000-8000-0000000000aa"}`, token)
		return true
	case p == "/artifactory/api/system/ping":
		markAttack(info, "artifactory-system")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-JFrog-Version", "Artifactory/7.98.11 79811900")
		fmt.Fprint(w, "OK")
		return true
	case p == "/artifactory/api/system/version":
		markAttack(info, "artifactory-system")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-JFrog-Version", "Artifactory/7.98.11 79811900")
		fmt.Fprint(w, `{"version":"7.98.11","revision":"79811900","license":"Enterprise"}`)
		return true
	case p == "/artifactory", strings.HasPrefix(p, "/artifactory/"),
		strings.HasPrefix(p, "/access/api/"):
		markAttack(info, "artifactory-scan")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-JFrog-Version", "Artifactory/7.98.11 79811900")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"errors":[{"status":401,"message":"Bad credentials"}]}`)
		return true
	}
	return false
}

// litellmTrap covers the LiteLLM proxy, the OpenAI-compatible gateway that
// organisations put in front of their model providers — which means it holds
// every upstream provider key and every virtual key issued to internal teams.
// CVE-2026-59822 was added to the CISA KEV catalog on 2026-09-02: before
// 1.84.0 the MCP Streamable HTTP endpoint accepted a fabricated Authorization
// header, fell through an OAuth2 passthrough path that replaced failed
// LiteLLM key validation with an empty UserAPIKeyAuth(), and let an
// unauthenticated caller list and call every configured MCP tool and the
// services behind them. Its sibling CVE-2026-35029 targets the admin API that
// mints those virtual keys.
//
// The bare /mcp and /v1/models probes are answered by aiAgentTrap further down
// and keep their own tags. What this trap claims is the LiteLLM management
// surface nothing else touches, which is where the credentials live:
//
//   - /key/generate — mints a virtual key. The arm returns an IP-specific
//     honeytoken in the `key` field, which is exactly the value an attacker
//     would replay against /v1/chat/completions.
//   - /key/info, /key/list, /user/info — enumerate issued keys and budgets.
//   - /model/info — the deployment list, whose litellm_params block is where a
//     real proxy keeps the upstream provider key.
//
// The scan arm is limited to paths only a LiteLLM proxy serves.
// /health/liveliness and /health/readiness are LiteLLM's own spellings, so an
// uptime monitor pointed at this host would not hit them by accident; the
// generic /health is deliberately left out for that reason.
func litellmTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	switch strings.ToLower(r.URL.Path) {
	case "/key/generate", "/sso/key/generate":
		markAttack(info, "litellm-key-generate")
		token := honeytoken(info.ip, "litellm-key-generate")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"key":%q,"key_alias":"prod-agent","team_id":"prod-agents",`+
				`"user_id":"a1b2c3d4-0000-4000-8000-000000000001","expires":null,`+
				`"models":["gpt-4o","claude-sonnet-4","llama3.1-8b"],`+
				`"max_budget":null,"tpm_limit":null,"rpm_limit":null}`, token)
		return true
	case "/key/info", "/key/list", "/user/info":
		markAttack(info, "litellm-key-info")
		token := honeytoken(info.ip, "litellm-key-info")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"total_count":1,"keys":[{"token":%q,"key_alias":"prod-agent",`+
				`"team_id":"prod-agents","spend":184.22,"max_budget":500,`+
				`"models":["gpt-4o"],"created_at":"2026-04-18T07:55:31Z"}]}`, token)
		return true
	case "/model/info", "/v1/model/info":
		markAttack(info, "litellm-model-info")
		token := honeytoken(info.ip, "litellm-model-info")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"data":[{"model_name":"gpt-4o","litellm_params":{"model":"azure/gpt-4o",`+
				`"api_base":"https://contoso-openai.openai.azure.com/",`+
				`"api_version":"2024-10-21","api_key":%q},`+
				`"model_info":{"id":"7f3c1e28-0000-4000-8000-0000000000aa",`+
				`"mode":"chat","supports_function_calling":true}}]}`, token)
		return true
	case "/health/liveliness", "/health/readiness", "/spend/logs",
		"/global/spend/report", "/model/settings":
		markAttack(info, "litellm-scan")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":{"message":"Authentication Error, No api key passed in.","type":"auth_error","param":"None","code":"401"}}`)
		return true
	}
	return false
}
