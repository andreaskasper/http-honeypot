package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// GPUStack (CVE-2026-102895) and the Claude Code settings files. Own file so
// the shared table in routes_test.go does not have to be rewritten.

func TestGPUStackClaudeRouteTags(t *testing.T) {
	cases := []struct {
		method, path, realIP string
		want, why            string
	}{
		{"POST", "/v2/api-keys", "", "gpustack-apikey-mint", "key mint via reverse-proxy bypass"},
		{"POST", "/v2/api-keys", "127.0.0.1", "gpustack-apikey-mint", "key mint via header bypass"},
		{"POST", "/v2/inference-backends/from-yaml", "127.0.0.1", "gpustack-backend-rce", "backend from YAML"},
		{"POST", "/v2/inference-backends", "", "gpustack-backend-rce", "backend create"},
		{"GET", "/v2/users/me", "127.0.0.1", "gpustack-auth-bypass", "admin check with header"},
		{"GET", "/v2/workers", "127.0.0.1", "gpustack-auth-bypass", "any /v2/ with header"},
		{"GET", "/auth/config", "127.0.0.1", "gpustack-auth-bypass", "/auth/ with header"},
		{"GET", "/v2/users/me", "", "gpustack-scan", "admin check without header"},
		{"GET", "/v2/api-keys", "", "gpustack-scan", "key listing without header"},
		{"GET", "/v2/", "", "", "bare /v2/ (Docker registry) is not claimed"},
		{"GET", "/v2/_catalog", "", "", "registry catalog is not claimed"},
		{"GET", "/v2/workers", "", "", "other /v2/ without header is not claimed"},
		{"GET", "/auth/config", "", "", "/auth/config without header is not claimed"},
		{"GET", "/v1/models", "127.0.0.1", "llm-openai-models", "LLM trap keeps /v1/models"},
		{"GET", "/.claude/settings.local.json", "", "ai-assistant-settings", "settings file at web root"},
		{"GET", "/app/.claude/settings.json", "", "ai-assistant-settings", "settings file below web root"},
		{"GET", "/.claude/mcp.json", "", "ai-assistant-config", "rest of /.claude/ keeps its tag"},
		{"GET", "/.claude/.credentials.json", "", "ai-assistant-credentials", "credentials keep their tag"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path+" "+c.realIP, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.path, nil)
			if c.realIP != "" {
				r.Header.Set("X-GPUStack-Real-IP", c.realIP)
			}
			got, _ := routeReq(t, r)
			if got != c.want {
				t.Errorf("attack_tag = %q, want %q (%s)", got, c.want, c.why)
			}
		})
	}
}

func TestGPUStackClaudeHoneytokens(t *testing.T) {
	for _, c := range []struct{ path, tag string }{
		{"/v2/api-keys", "gpustack-apikey-mint"},
		{"/.claude/settings.local.json", "ai-assistant-settings"},
	} {
		method := "GET"
		if strings.HasPrefix(c.path, "/v2/") {
			method = "POST"
		}
		_, w := routeReq(t, httptest.NewRequest(method, c.path, nil))
		tok := findHoneytoken(w.Body.String())
		if tok == "" {
			t.Fatalf("%s: no honeytoken in body: %s", c.path, w.Body.String())
		}
		if tok != honeytoken("198.51.100.7", c.tag) {
			t.Errorf("%s: honeytoken %q is not the IP-specific one for %s", c.path, tok, c.tag)
		}
	}
}

func TestGPUStackScanIs401(t *testing.T) {
	_, w := routeReq(t, httptest.NewRequest("GET", "/v2/users/me", nil))
	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
	r := httptest.NewRequest("GET", "/v2/users/me", nil)
	r.Header.Set("X-GPUStack-Real-IP", "127.0.0.1")
	_, w = routeReq(t, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"is_admin":true`) {
		t.Errorf("bypass reply = %d %s, want 200 with the admin user", w.Code, w.Body.String())
	}
}
