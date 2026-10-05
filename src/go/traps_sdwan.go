package main

import (
	"fmt"
	"net/http"
	"strings"
)

// ciscoSDWANTrap covers Cisco Catalyst SD-WAN Manager (formerly vManage), the
// management plane that holds policy, device onboarding and configuration for
// an entire SD-WAN fabric.
//
// CVE-2026-76504 — CVSS 9.8, CWE-177 — is an authentication bypass caused by
// improper handling of URI encoding: a request for the authentication endpoint
// with an encoded character in its name (Cisco's own example is
// /%6a_security_check, where %6a is "j") slips past the rule that locks the
// endpoint down and yields API access as the admin user. Cisco published the
// advisory on 2026-09-29, Rapid7 and Qualys reported exploitation in the wild
// straight away, and CISA added it to the KEV catalog on 2026-09-30 with a
// remediation deadline of 2026-10-03. There is no workaround; only patching
// fixes it.
//
// Go decodes the request path before it reaches a handler, so both the plain
// /j_security_check and any encoded spelling of it arrive here as
// "/j_security_check" — one comparison covers every variant of the probe.
//
// Three arms, all on paths that belong to this product alone:
//
//   - cisco-sdwan-authbypass — /j_security_check. Reaching it with a mangled
//     name is the exploit, so the bypass "succeeds": the reply sets a
//     JSESSIONID that is an IP-specific honeytoken, which is exactly the
//     credential the attacker would carry into the next request.
//   - cisco-sdwan-token — /dataservice/client/token, the CSRF token endpoint
//     every authenticated API session fetches first. The body is the
//     honeytoken, since the real one is a bare string.
//   - cisco-sdwan-api — the rest of /dataservice/, the REST API that the
//     bypass opens up. Answered 200 with a device inventory rather than a 401,
//     because getting that far unauthenticated is the bypass working and an
//     inventory is what keeps the scanner talking.
//
// Deliberately not claimed: /login and /, which are served by far too many
// products to be reported as SD-WAN attacks.
//
// Ordering: nothing above claims /j_security_check or /dataservice/. No
// request is parsed, no session is validated and no inventory exists; every
// response is fabricated.
func ciscoSDWANTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)

	switch {
	case p == "/j_security_check":
		markAttack(info, "cisco-sdwan-authbypass")
		token := honeytoken(info.ip, "cisco-sdwan-authbypass")
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: token, Path: "/", HttpOnly: true})
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.WriteHeader(200)
		return true

	case p == "/dataservice/client/token":
		markAttack(info, "cisco-sdwan-token")
		token := honeytoken(info.ip, "cisco-sdwan-token")
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		fmt.Fprint(w, token)
		return true

	case strings.HasPrefix(p, "/dataservice/"), p == "/dataservice":
		markAttack(info, "cisco-sdwan-api")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w,
			`{"header":{"generatedOn":1790000000000,"viewKeys":{"uniqueKey":["system-ip"],"preferenceKey":"grid-Device"}},`+
				`"data":[{"deviceId":"10.255.0.1","system-ip":"10.255.0.1","host-name":"vmanage-01",`+
				`"reachability":"reachable","status":"normal","personality":"vmanage",`+
				`"device-type":"vmanage","platform":"vmanage","version":"20.12.4"}]}`)
		return true
	}
	return false
}
