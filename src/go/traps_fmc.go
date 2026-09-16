package main

import (
	"fmt"
	"net/http"
	"strings"
)

// ciscoFMCTrap covers Cisco Secure Firewall Management Center, the console
// that manages an estate of Cisco firewalls — so one compromised console
// reaches every policy sitting in front of the network.
//
// CVE-2026-20079 (CVSS 10.0, CWE-288 authentication bypass using an alternate
// path or channel) was added to the CISA KEV catalog on 2026-09-09 with a
// remediation deadline of 2026-09-12. A process created at boot leaves a
// session for an internal machine account reachable over HTTP; a crafted
// request rides that session into the management UI and from there into
// command execution as root. Cisco PSIRT confirmed exploitation from August
// 2026, by both state-sponsored and ransomware actors. Censys counts roughly
// 300 internet-facing instances and FOFA 600-700.
//
// Paths are taken from VulnCheck's published analysis of the bypass chain and
// from Cisco's own REST API documentation. The token arm is the one that
// matters: a real FMC answers /api/fmc_platform/v1/auth/generatetoken with a
// 204 and puts the credential in response headers, so that is where the
// IP-specific honeytokens go. Replaying either of them is caught by
// detectHoneytokenInRequest.
//
// Deliberately not claimed: the bare /login.cgi. It appears in the published
// chain, but routers, NAS boxes and DVRs serve it too, and a probe of one of
// those should not be reported to AbuseIPDB as a Cisco FMC attack.
//
// Nothing here parses a request, validates a session or checks a token; every
// response is fabricated and inert.
func ciscoFMCTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	switch {
	case p == "/api/fmc_platform/v1/auth/generatetoken":
		markAttack(info, "cisco-fmc-token")
		// Two distinct tokens so a replayed access token can be told apart
		// from a replayed refresh token in the honeytoken_used event.
		w.Header().Set("X-auth-access-token", honeytoken(info.ip, "cisco-fmc-token"))
		w.Header().Set("X-auth-refresh-token", honeytoken(info.ip, "cisco-fmc-refresh"))
		w.Header().Set("DOMAIN_UUID", "e276abec-e0f2-11e3-8169-6d9ed49b625f")
		w.Header().Set("USER_UUID", "005056a6-2b6a-0ed3-0000-004294969621")
		w.Header().Set("global", "e276abec-e0f2-11e3-8169-6d9ed49b625f")
		w.WriteHeader(204)
		return true

	case p == "/sajaxintf.cgi", p == "/pjb.cgi":
		// The two CGI scripts the published chain abuses: sajaxintf.cgi for
		// the arbitrary write and the Storable deserialisation, pjb.cgi for
		// the privileged bulk call that executes the result. Reaching either
		// of these unauthenticated is the exploit, not recon.
		markAttack(info, "cisco-fmc-authbypass")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, `+:{"status":"OK","result":"","error":null}`)
		return true

	case p == "/ui/login", p == "/ui/login/":
		markAttack(info, "cisco-fmc-login")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Cisco Secure Firewall Management Center</title></head>`+
			`<body><div id="login"><h1>Secure Firewall Management Center</h1>`+
			`<form method="post" action="/login.cgi?logon=Continue">`+
			`<input name="username" id="username" autocomplete="off"/>`+
			`<input type="password" name="password" id="password"/>`+
			`<input type="submit" value="Log In"/></form>`+
			`<p>Version 7.7.11 (build 1061)</p></div></body></html>`)
		return true

	case p == "/help/about.cgi", strings.HasPrefix(p, "/platinum/"):
		// What a real appliance does with an unauthenticated CGI request:
		// bounce it to the login page with the original target preserved.
		markAttack(info, "cisco-fmc-scan")
		w.Header().Set("Location", "/ui/login?target=%2Fmojo-async%2F")
		w.WriteHeader(302)
		return true

	case strings.HasPrefix(p, "/api/fmc_platform/"), strings.HasPrefix(p, "/api/fmc_config/"),
		strings.HasPrefix(p, "/api/fmc_troubleshoot/"):
		markAttack(info, "cisco-fmc-scan")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":{"category":"FRAMEWORK","severity":"ERROR",`+
			`"messages":[{"description":"Access denied"}]}}`)
		return true
	}
	return false
}
