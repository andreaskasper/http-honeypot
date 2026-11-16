package main

import (
	"fmt"
	"net/http"
	"strings"
)

// gpustackTrap covers CVE-2026-102895 in GPUStack, the open-source GPU cluster
// manager for LLM inference (gpustack/gpustack, ~940k Docker Hub pulls).
// Versions before 2.2.0 treat any request from a loopback source as the
// built-in admin while force_auth_localhost is false, which is the default.
// Two ways in: a same-host reverse proxy (proxy_pass http://127.0.0.1:<port>,
// so every request arrives from 127.0.0.1 with no credential at all), or the
// header "X-GPUStack-Real-IP: 127.0.0.1". CVSS 9.8; fix in 2.2.0 (2026-06-18),
// CVE published 2026-11-04, CISA KEV 2026-11-09. In-the-wild exploitation
// against a 2.1.1 deployment: the attacker minted an admin API key and
// registered a custom inference backend whose run command opened a reverse
// shell. Sources: GHSA-gj9m-f8ph-pmhr / GitLab advisory, Ostorlab and CSA
// research notes; the route shapes below come from gpustack/routes/routes.py
// (versioned prefix /v2) and the ApiKeyPublic / InferenceBackend schemas.
//
// Four tags:
//
//   - gpustack-apikey-mint — POST /v2/api-keys, the persistence step. The
//     reply is an ApiKeyPublic document whose one-time "value" is an
//     IP-specific honeytoken (GPUStack accepts custom-format keys, so a
//     non-gpustack_ prefix is plausible). Coming back as a Bearer token on the
//     OpenAI-compatible /v1 API is the next request the attacker makes.
//
//   - gpustack-backend-rce — POST /v2/inference-backends and
//     /v2/inference-backends/from-yaml, the RCE step (the backend's run
//     command is attacker-chosen). Answered with a created-backend document;
//     nothing is run, nothing is parsed.
//
//   - gpustack-auth-bypass — any other /v2/ or /auth/ request that carries
//     the X-GPUStack-Real-IP header, which no legitimate client sends from the
//     internet. /v2/users/me gets the built-in admin, everything else an empty
//     paginated list.
//
//   - gpustack-scan — /v2/users/me and GET /v2/api-keys without the header
//     (the reverse-proxy variant needs no header, so this is the probe that
//     checks whether the bypass works), answered 401 like a patched server.
//
// Deliberately not claimed: /auth/login, /auth/config and the bare /v2/
// prefix (other products and the Docker registry API use those), and /v1/
// (the OpenAI-compatible API, already owned by the LLM traps).
//
// Nothing reads the body, runs a command or stores anything; every response
// is fabricated.
func gpustackTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.TrimSuffix(strings.ToLower(r.URL.Path), "/")
	spoofed := r.Header.Get("X-GPUStack-Real-IP") != ""
	post := r.Method == http.MethodPost

	switch {
	case post && p == "/v2/api-keys":
		markAttack(info, "gpustack-apikey-mint")
		token := honeytoken(info.ip, "gpustack-apikey-mint")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"name":"ops-automation","description":null,"id":7,"user_name":"admin",`+
				`"value":%q,"masked_value":"%s******","is_custom":true,`+
				`"owner_principal_id":null,"created_at":"2026-11-16T07:21:44Z",`+
				`"updated_at":"2026-11-16T07:21:44Z","expires_at":null}`, token, token[:12])
		return true

	case post && (p == "/v2/inference-backends" || p == "/v2/inference-backends/from-yaml"):
		markAttack(info, "gpustack-backend-rce")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w,
			`{"id":12,"backend_name":"custom-runtime","default_version":"latest",`+
				`"version_configs":{"latest":{"image_name":null,"run_command":null,"env":null}},`+
				`"default_backend_param":[],"default_run_command":null,"default_entrypoint":null,`+
				`"description":null,"health_check_path":"/v1/models","is_built_in":false,`+
				`"owner_principal_id":null,"created_at":"2026-11-16T07:22:03Z",`+
				`"updated_at":"2026-11-16T07:22:03Z"}`)
		return true

	case spoofed && (strings.HasPrefix(p, "/v2/") || strings.HasPrefix(p, "/auth/")):
		markAttack(info, "gpustack-auth-bypass")
		w.Header().Set("Content-Type", "application/json")
		if p == "/v2/users/me" {
			fmt.Fprint(w,
				`{"username":"admin","is_admin":true,"is_active":true,"full_name":"Default System Admin",`+
					`"avatar_url":null,"source":"Local","require_password_change":false,"id":1,`+
					`"created_at":"2026-03-02T09:14:11Z","updated_at":"2026-03-02T09:14:11Z"}`)
			return true
		}
		fmt.Fprint(w, `{"items":[],"pagination":{"page":1,"perPage":100,"total":0,"totalPage":0}}`)
		return true

	case p == "/v2/users/me", p == "/v2/api-keys":
		markAttack(info, "gpustack-scan")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"code":401,"reason":"Unauthorized","message":"Invalid authentication credentials"}`)
		return true
	}
	return false
}
