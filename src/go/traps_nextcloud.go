package main

import (
	"fmt"
	"net/http"
	"strings"
)

// nextcloudCodeTrap covers the Collabora Online "built-in CODE server" app for
// Nextcloud (richdocumentscode, and its richdocumentscode_arm64 sibling), the
// small PHP proxy that lets a Nextcloud host run its own document editor.
//
// CVE-2026-110447 — CVSS 9.2 — is an unauthenticated OS command injection in the
// app's proxy.php. Release 26.4.302 shipped on 2026-08-31 and 26.4.303 fixed
// it on 2026-09-11; the first attacks show up in access logs on 2026-09-10/11,
// a forum warned about active exploitation on 2026-10-03, and the CVE and
// advisory were published on 2026-10-14. CISA listed it in the KEV catalog the
// same month. Attackers inject a shell command through the request path, plant
// a one-line PHP webshell next to proxy.php and then use it to look for
// password databases, password-manager files and wallets.
//
// The request shape, as reported by victims — the traversal and the shell
// metacharacters are in the path itself, not in the query string:
//
//	/apps/richdocumentscode/proxy.php?status
//	/apps/richdocumentscode/proxy.php/%2e%2e/$(echo${IFS}...|base64${IFS}-d|sh)
//
// Three tags:
//
//   - nextcloud-code-proxy-rce — proxy.php of the app. The injection appears
//     to work: the reply is the small status document the real proxy returns.
//
//   - nextcloud-code-webshell — the follow-up request, a shx<random>.php file
//     in the same directory taking a command in the "c" parameter (default
//     "id"). The reply is a fabricated "id" output; a request that asks to read
//     a config file gets a fabricated Nextcloud config.php whose dbpassword and
//     secret are IP-specific honeytokens, which is what the attacker is
//     hunting for.
//
//   - nextcloud-code-scan — anything else under the app directory (version
//     files, appinfo, other PHP names), answered 404 like a file that is not
//     there.
//
// Only paths under /apps/richdocumentscode (and the _arm64 variant) are
// claimed; a bare proxy.php elsewhere is left alone.
//
// Ordering: nothing above claims a path under /apps/. The generic webshell
// suffix block only matches shell.php, cmd.php, c99.php, r57.php and
// webshell.php, none of which is a shx*.php name.
//
// Nothing here runs a command or touches a file; every response is fabricated.
func nextcloudCodeTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	if !strings.HasPrefix(p, "/apps/richdocumentscode/") &&
		!strings.HasPrefix(p, "/apps/richdocumentscode_arm64/") {
		return false
	}

	rest := p[strings.Index(p[1:], "/")+2:]  // drop "/apps/"
	rest = rest[strings.Index(rest, "/")+1:] // drop the app directory

	switch {
	case strings.HasPrefix(rest, "proxy.php"):
		markAttack(info, "nextcloud-code-proxy-rce")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"OK","version":"26.4.302","server":"Collabora Online Development Edition"}`)
		return true

	case strings.HasPrefix(rest, "shx") && strings.HasSuffix(rest, ".php"):
		markAttack(info, "nextcloud-code-webshell")
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		cmd := strings.ToLower(r.URL.Query().Get("c"))
		if strings.Contains(cmd, "config.php") {
			fmt.Fprintf(w, "<?php\n$CONFIG = array (\n"+
				"  'instanceid' => 'oc9k2m4x7q1d',\n"+
				"  'passwordsalt' => '%s',\n"+
				"  'secret' => '%s',\n"+
				"  'trusted_domains' => array ( 0 => 'cloud.internal' ),\n"+
				"  'dbtype' => 'mysql',\n"+
				"  'dbhost' => 'localhost',\n"+
				"  'dbname' => 'nextcloud',\n"+
				"  'dbuser' => 'nextcloud',\n"+
				"  'dbpassword' => '%s',\n"+
				");\n",
				honeytoken(info.ip, "nextcloud-code-webshell-salt"),
				honeytoken(info.ip, "nextcloud-code-webshell-secret"),
				honeytoken(info.ip, "nextcloud-code-webshell"))
			return true
		}
		fmt.Fprint(w, "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
		return true
	}

	markAttack(info, "nextcloud-code-scan")
	http.NotFound(w, r)
	return true
}
