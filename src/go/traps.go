package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// restAPITrap catches IDOR-style scanners probing /api/v*/users/{id} etc.
// The fake response embeds an IP-specific honeytoken as the api_key field.
func restAPITrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	apiRe := regexp.MustCompile(`^/api/v\d+/(users|accounts|admin|customers|employees)/(\d+)`)
	m := apiRe.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return false
	}
	resource := m[1]
	id := m[2]
	markAttack(info, "rest-api-idor-"+resource)
	token := honeytoken(info.ip, "rest-api-idor-"+resource)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w,
		`{"id":%s,"email":"user%s@contoso.internal","role":"user",`+
			`"password_hash":"$2b$12$FakeHashForHoneypotXXXXXXXXXXXXXXX",`+
			`"api_key":%q,"created_at":"2024-01-15T10:30:00Z"}`,
		id, id, token)
	return true
}

// sharePointTrap covers on-premises Microsoft SharePoint, the "ToolShell"
// exploit chain (CVE-2025-53770 and the 2026 follow-ups CVE-2026-56164 /
// CVE-2026-58644) and the broad /_vti_bin/ + /_api/ scanning around it.
// Attackers POST to ToolPane.aspx with DisplayMode=Edit and a spoofed Referer;
// we answer with an inert maintenance page so the scanner keeps talking.
func sharePointTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	switch {
	case strings.HasPrefix(p, "/_layouts/15/toolpane.aspx"), strings.HasPrefix(p, "/_layouts/16/toolpane.aspx"):
		markAttack(info, "sharepoint-toolpane")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("MicrosoftSharePointTeamServices", "16.0.0.10417")
		w.Header().Set("X-SharePointHealthScore", "0")
		fmt.Fprint(w, `<html><head><title>Web Part Page Maintenance</title></head><body><h2>Web Part Page Maintenance</h2><p>To close a Web Part, select the check box and click Close.</p></body></html>`)
		return true
	case strings.HasPrefix(p, "/_vti_bin/"), strings.HasPrefix(p, "/_api/web"), strings.HasPrefix(p, "/_layouts/"):
		markAttack(info, "sharepoint-scan")
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("MicrosoftSharePointTeamServices", "16.0.0.10417")
		w.WriteHeader(401)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><m:error xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><m:code>-2147024891, System.UnauthorizedAccessException</m:code><m:message xml:lang="en-US">Access denied. You do not have permission to perform this action or access this resource.</m:message></m:error>`)
		return true
	}
	return false
}

// coldFusionTrap covers Adobe ColdFusion, added to CISA KEV in July 2026 with
// CVE-2026-48282 (path traversal to RCE, CVSS 10.0) and mass-scanned via the
// classic /CFIDE/administrator entry point (CVE-2023-26360).
func coldFusionTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	switch {
	case strings.HasPrefix(p, "/cfide/administrator"):
		markAttack(info, "coldfusion-admin")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>ColdFusion Administrator Login</title></head><body><h1>ColdFusion Administrator Login</h1><form name="loginform" action="/CFIDE/administrator/enter.cfm" method="post"><input type="hidden" name="cfadminUserId" value="admin"/><input type="password" name="cfadminPassword" size="20"/><input type="submit" value="Login"/></form><p>Adobe ColdFusion 2023, 0, 06, 330468</p></body></html>`)
		return true
	case strings.HasPrefix(p, "/cfide/"), strings.HasPrefix(p, "/cf_scripts/"),
		strings.HasSuffix(p, ".cfm"), strings.HasSuffix(p, ".cfc"):
		markAttack(info, "coldfusion-scan")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>Error Occurred While Processing Request</title></head><body><h1>Error Occurred While Processing Request</h1><p>File not found.</p><p>ColdFusion Server Standard 2023, 0, 06, 330468</p></body></html>`)
		return true
	}
	return false
}

// langflowTrap covers Langflow, the first AI agent platform added to the CISA
// KEV catalog (CVE-2026-55255 cross-tenant IDOR; CVE-2025-3248 unauthenticated
// code execution via /api/v1/validate/code, still botnet-scanned).
// The API-key listing embeds an IP-specific honeytoken.
func langflowTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := r.URL.Path
	switch {
	case p == "/api/v1/validate/code":
		markAttack(info, "langflow-rce")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"imports":{"errors":[]},"function":{"errors":[]}}`)
		return true
	case p == "/api/v1/api_key", p == "/api/v1/api_key/", p == "/api/v1/variables":
		markAttack(info, "langflow-apikey")
		token := honeytoken(info.ip, "langflow-apikey")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"total_count":1,"user_id":"a1b2c3d4-0000-4000-8000-000000000001",`+
				`"api_keys":[{"id":"7f3c1e28-0000-4000-8000-0000000000aa","name":"prod-agent",`+
				`"created_at":"2026-03-04T08:12:44Z","last_used_at":"2026-07-29T21:03:11Z",`+
				`"total_uses":417,"is_active":true,"api_key":%q}]}`, token)
		return true
	case strings.HasPrefix(p, "/api/v1/flows"), strings.HasPrefix(p, "/api/v1/store"),
		p == "/api/v1/version":
		markAttack(info, "langflow-scan")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"1.0.19","package":"Langflow","main":"ok"}`)
		return true
	}
	return false
}
