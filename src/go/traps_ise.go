package main

import (
	"fmt"
	"net/http"
	"strings"
)

// ciscoISETrap covers Cisco Identity Services Engine and the ISE Passive
// Identity Connector — the identity and network-access control plane that
// decides who and what gets onto an enterprise network, and that stores the
// RADIUS shared secret of every switch, WLC and firewall it fronts.
//
// CVE-2026-76460 — CVSS 10.0, CWE-648, Cisco advisory
// cisco-sa-ISE-ABP-VNSW7Tn5 of 2026-09-16 — is insufficient authentication
// control on an API endpoint: a crafted request bypasses the web-based
// management interface, and Cisco states exploitation may yield command
// execution as root. Cisco PSIRT confirmed active exploitation on the day of
// disclosure and CISA added it to the KEV catalog the same day, with a federal
// remediation deadline of 2026-09-19. Products are affected regardless of
// configuration and there is no workaround; only patching fixes it. The same
// September advisory set brought a REST API SQL injection (CVE-2026-20284), an
// IPsec Open API command injection (CVE-2026-20283) and an authenticated write
// primitive (CVE-2026-20282), so the whole API surface is being swept.
//
// Cisco deliberately did not publish the vulnerable endpoint while exploitation
// was ongoing, so this trap does not pretend to know it. What it answers is the
// documented ISE API surface an operator would scan for and an attacker would
// walk after the bypass, and it puts the honeytokens where the credentials
// actually live:
//
//   - cisco-ise-ers-device — /ers/config/networkdevice. An ERS network-device
//     object carries the RADIUS shared secret in
//     authenticationSettings.radiusSharedSecret, which is the single most
//     reusable credential on the box: it authenticates every switch and
//     firewall in the estate. That field is an IP-specific honeytoken.
//   - cisco-ise-ers-identity — /ers/config/internaluser and /ers/config/adminuser.
//     The local identity store. The password field is honeytokened.
//   - cisco-ise-openapi — the ISE OpenAPI subtrees (/api/v1/deployment,
//     /api/v1/system-certificate, /api/v1/trustsec, /api/v1/license). Reaching
//     these unauthenticated is the bypass, not recon.
//   - cisco-ise-login — /admin/login.jsp, the page an unauthenticated caller is
//     bounced to and the one a scanner reads to confirm the product.
//   - cisco-ise-scan — /ers/sdk and the rest of /ers/, the MnT and
//     NetworkAccessConfig APIs under /admin/API/, and the pxGrid control
//     subtree, answered with ISE's own ERS error envelope.
//
// Deliberately not claimed: the bare /admin/ and /portal/ paths, and the rest
// of /admin/API/. All three are served by a great many products that are not
// ISE, and a mislabelled AbuseIPDB report is worse than a missed one. The same
// reasoning that left /login.cgi off the FMC trap.
//
// Ordering: none of these paths is claimed above. The exact match
// /admin/config.php in the legacy-admin switch is untouched by /admin/login.jsp
// and the two /admin/API/ subtrees, langflowTrap owns different /api/v1 leaves
// (/api/v1/flows, /api/v1/store, /api/v1/version and the auto_login and
// api_key arms), kestraTrap owns /api/v1/main and the /configs suffix, and
// restAPITrap only matches /api/v<N>/(users|accounts|admin|customers|
// employees)/<digits>. So /api/v1/admin/7 keeps its rest-api-idor-admin tag.
//
// No request is parsed, no session is validated and no identity store exists;
// every response is fabricated.
func ciscoISETrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)

	switch {
	case strings.HasPrefix(p, "/ers/config/networkdevice"):
		markAttack(info, "cisco-ise-ers-device")
		token := honeytoken(info.ip, "cisco-ise-ers-device")
		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		fmt.Fprintf(w,
			`{"NetworkDevice":{"id":"5b2c1e28-0000-4000-8000-0000000000aa",`+
				`"name":"core-sw-01","description":"Campus core switch",`+
				`"authenticationSettings":{"networkProtocol":"RADIUS",`+
				`"radiusSharedSecret":%q,"enableKeyWrap":false},`+
				`"NetworkDeviceIPList":[{"ipaddress":"10.20.0.11","mask":32}],`+
				`"profileName":"Cisco","coaPort":1700}}`, token)
		return true

	case strings.HasPrefix(p, "/ers/config/internaluser"),
		strings.HasPrefix(p, "/ers/config/adminuser"):
		markAttack(info, "cisco-ise-ers-identity")
		token := honeytoken(info.ip, "cisco-ise-ers-identity")
		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		fmt.Fprintf(w,
			`{"InternalUser":{"id":"7f3c1e28-0000-4000-8000-0000000000ab",`+
				`"name":"svc-nac","enabled":true,"email":"nac@contoso.example",`+
				`"password":%q,"changePassword":false,`+
				`"identityGroups":"Employee","passwordIDStore":"Internal Users"}}`,
			token)
		return true

	case strings.HasPrefix(p, "/api/v1/deployment"),
		strings.HasPrefix(p, "/api/v1/system-certificate"),
		strings.HasPrefix(p, "/api/v1/trustsec"),
		strings.HasPrefix(p, "/api/v1/license"):
		markAttack(info, "cisco-ise-openapi")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w,
			`{"response":[{"hostname":"ise-pan-01","fqdn":"ise-pan-01.contoso.example",`+
				`"ipAddress":"10.20.0.40","roles":["PrimaryAdmin","MonitoringPrimary"],`+
				`"services":["Session","Profiler"],"nodeStatus":"Connected"}],`+
				`"version":"1.0.0"}`)
		return true

	case p == "/admin/login.jsp", p == "/admin/loginaction.do":
		markAttack(info, "cisco-ise-login")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Identity Services Engine</title></head>`+
			`<body class="cisco-ise"><div id="loginPanel"><h1>Identity Services Engine</h1>`+
			`<form name="loginForm" action="/admin/LoginAction.do" method="post">`+
			`<input type="text" name="username" id="userNameField"/>`+
			`<input type="password" name="password" id="passwordField"/>`+
			`<input type="submit" value="Login"/></form>`+
			`<p class="version">Version 3.4.0.608</p></div></body></html>`)
		return true

	case p == "/ers/sdk", strings.HasPrefix(p, "/ers/"),
		strings.HasPrefix(p, "/admin/api/mnt"),
		strings.HasPrefix(p, "/admin/api/networkaccessconfig"),
		strings.HasPrefix(p, "/pxgrid/control"):
		markAttack(info, "cisco-ise-scan")
		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		w.WriteHeader(401)
		fmt.Fprint(w,
			`{"ERSResponse":{"operation":"GET","requestId":"01K4Q7V9ZP8M3N0R2T5W7Y9B1D",`+
				`"messages":[{"title":"Unauthorized","type":"ERROR","code":"401"}],`+
				`"link":{"rel":"related","type":"application/json"}}}`)
		return true
	}
	return false
}
