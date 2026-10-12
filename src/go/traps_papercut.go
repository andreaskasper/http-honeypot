package main

import (
	"fmt"
	"net/http"
	"strings"
)

// paperCutTrap covers the PaperCut NG / MF print-management web console, which
// has been a repeat target: authentication-bypass and pre-auth RCE chains in
// 2023, and again in 2026 (CVE-2026-81578, CVE-2026-82077, CVE-2026-82078,
// patch-bypass series WT-2026-0141 to 0144). watchTowr's honeypots captured
// exploitation of the earlier 26.0.3 chain; their write-up of the later one
// names the request shapes.
//
// The whole console is a single Apache Tapestry servlet at /app, and every
// page is selected by a "service" query parameter. That is the useful
// fingerprint: /app alone is a name other products use, but /app together with
// service=page/... or service=direct/... is PaperCut and nothing else.
//
//   - papercut-setup-bypass — service names containing "setup", which is the
//     first-run wizard (SetupCompleted, Home/SetupAdmin, SetupOrgType,
//     SetupUserSource, SetupVerify). Reaching it on an installed system
//     unauthenticated is the bypass. The reply "accepts" it and sets a session
//     cookie whose value is an IP-specific honeytoken.
//   - papercut-scan — every other Tapestry service, answered with a login page
//     so a scanner can confirm the product and its version.
//
// Deliberately not claimed: /app without a Tapestry service parameter, and the
// bare /user and /admin names. Other products serve those and a mislabelled
// AbuseIPDB report is worse than a missed one.
//
// Ordering: nothing above claims /app.
//
// Nothing here parses a form, creates an account or touches a print queue;
// every response is fabricated.
func paperCutTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	if strings.ToLower(r.URL.Path) != "/app" {
		return false
	}
	service := strings.ToLower(r.URL.Query().Get("service"))
	if !strings.HasPrefix(service, "page/") && !strings.HasPrefix(service, "direct/") {
		return false
	}

	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	if strings.Contains(service, "setup") {
		markAttack(info, "papercut-setup-bypass")
		token := honeytoken(info.ip, "papercut-setup-bypass")
		w.Header().Add("Set-Cookie", fmt.Sprintf("JSESSIONID=%s; Path=/; HttpOnly", token))
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>PaperCut MF - Setup</title></head>`+
			`<body><h1>Set the administrator password</h1>`+
			`<form action="/app?service=direct/1/Home/SetupAdmin/$Form" method="post">`+
			`<input type="password" name="password"/><input type="password" name="confirm"/>`+
			`<input type="submit" value="Next"/></form></body></html>`)
		return true
	}

	markAttack(info, "papercut-scan")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>PaperCut MF - Login</title></head>`+
		`<body><h1>Log in</h1><form action="/app" method="post">`+
		`<input type="text" name="inputUsername"/><input type="password" name="inputPassword"/>`+
		`<input type="submit" value="Log in"/></form>`+
		`<p class="version">PaperCut MF 26.0.3</p></body></html>`)
	return true
}
