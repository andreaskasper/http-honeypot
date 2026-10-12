package main

import (
	"fmt"
	"net/http"
	"strings"
)

// hfsTrap covers Rejetto HFS 3 (HTTP File Server), a small file-sharing server
// that people expose to the internet on purpose and then forget.
//
// CVE-2026-61500 — CVSS 9.3 — is a session forgery: HFS 3.0.0 through 3.2.0
// derives its session-cookie signing key from Math.random(). Anyone can fetch a
// handful of unauthenticated login responses (the first step of the SRP login,
// loginSrp1, needs no credentials), reconstruct the generator state, recover the
// key and sign an administrator cookie. The admin API then accepts a
// "server_code" setting that is executed as server-side JavaScript. The fix
// shipped in 3.2.1 in July 2026; Horizon3 published the write-up and a public
// proof of concept on 2026-09-30 and VulnCheck's canaries saw the first
// probing on 2026-10-01.
//
// Everything HFS 3 exposes beyond the shared files lives under the reserved
// /~/ prefix, which is what makes the product recognisable from the path alone:
//
//   - hfs-session-forge — /~/api/loginSrp1, the unauthenticated request an
//     exploit repeats to harvest session cookies. The reply carries a session
//     cookie whose value is an IP-specific honeytoken.
//   - hfs-admin-config — /~/api/get_config and /~/api/set_config, what a forged
//     administrator session is used for. The config dump carries a
//     honeytoken in an upload credential field; a set_config is acknowledged.
//   - hfs-scan — the rest of /~/ (admin UI, frontend assets, other API calls),
//     answered with a small JSON object so a scanner keeps talking.
//
// Only the /~/ prefix is claimed. The bare "~user" home-directory convention
// of Apache (/~alice/) does not start with "/~/" and is untouched.
//
// Ordering: nothing above claims a path that starts with "/~/".
//
// Nothing here signs, verifies or parses a cookie, and no code is executed;
// every response is fabricated.
func hfsTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	if !strings.HasPrefix(p, "/~/") {
		return false
	}

	switch {
	case strings.HasPrefix(p, "/~/api/loginsrp1"):
		markAttack(info, "hfs-session-forge")
		token := honeytoken(info.ip, "hfs-session-forge")
		w.Header().Add("Set-Cookie", fmt.Sprintf("hfs_$id=%s; Path=/; HttpOnly", token))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"salt":"9c1e5a47f0b24d38a6e1c7d20b93f845","pubKey":"2f8a3b7c61d94e05"}`)
		return true

	case strings.HasPrefix(p, "/~/api/get_config"), strings.HasPrefix(p, "/~/api/set_config"):
		markAttack(info, "hfs-admin-config")
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(p, "/~/api/set_config") {
			fmt.Fprint(w, `{}`)
			return true
		}
		token := honeytoken(info.ip, "hfs-admin-config")
		fmt.Fprintf(w,
			`{"port":80,"https_port":443,"server_code":"","allow_session_ip_change":false,`+
				`"zip_calculate_size_for_seconds":1,"upload_token":%q,"max_dl_speed":0}`, token)
		return true

	default:
		markAttack(info, "hfs-scan")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"HFS","version":"3.2.0","api":2}`)
		return true
	}
}
