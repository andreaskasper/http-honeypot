package main

import (
	"fmt"
	"net/http"
	"strings"
)

// atlassianTrap covers the Atlassian Data Center family (Jira, Confluence,
// Bitbucket, Bamboo, Crowd, Fisheye/Crucible) — the issue tracker, wiki and
// source host that hold an organisation's tickets, documents and code.
//
// CVE-2026-21589 — CVSS 9.3 — is a pre-authentication arbitrary file read. The
// web-resource handler turns "..::" into "../", so a request for a static
// resource under .../download/resources/<plugin>/images/ can be walked out of
// the resource directory and into WEB-INF, where Crowd and Jira keep
// crowd.properties (the application's own Crowd credentials). Atlassian
// shipped the fix on 2026-10-05; the SANS ISC honeypots saw the first
// attempts on 2026-10-06, watchTowr published technical details shortly
// after, and CISA added the CVE to the KEV catalog on 2026-10-15 with a
// federal deadline of 2026-10-18. An attacker needs the exact file name, so
// the traffic is a sweep over a short list of well-known WEB-INF files.
//
// The request shape, as captured by honeypots — the "..::" marker is what
// makes it recognisable, the plugin key before it varies per product:
//
//	/download/resources/jira.webresources:color-picker-popup/images/..::..::WEB-INF::web.xml
//	/s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/..::..::WEB-INF::web.xml
//
// Two tags:
//
//   - atlassian-webinf-read — a traversal that ends in a file we know how to
//     fake: web.xml and urlrewrite.xml (what the scanner fingerprints with)
//     and crowd.properties (what it came for). crowd.properties carries an
//     IP-specific honeytoken as application.password.
//   - atlassian-traversal-scan — any other "..::" traversal under
//     /download/resources/, answered 404 like a real server answers a file
//     that does not exist.
//
// Deliberately not claimed: a plain /download/resources/ request without the
// "..::" marker. Every Atlassian page requests those; on a host that is not
// Atlassian it is just a 404, and the marker is the exploit.
//
// Ordering: nothing above claims a path containing "/download/resources/" —
// the only /download/ prefix in the chain is /download/current/.
//
// No file is read and nothing is traversed; every response is fabricated.
func atlassianTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	if !strings.Contains(p, "/download/resources/") || !strings.Contains(p, "..::") {
		return false
	}

	file := p[strings.LastIndexAny(p, ":/")+1:]

	switch file {
	case "web.xml":
		markAttack(info, "atlassian-webinf-read")
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
			`<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">`+"\n"+
			`  <display-name>Atlassian Application</display-name>`+"\n"+
			`  <filter><filter-name>urlrewrite</filter-name>`+
			`<filter-class>org.tuckey.web.filters.urlrewrite.UrlRewriteFilter</filter-class></filter>`+"\n"+
			`  <session-config><session-timeout>30</session-timeout></session-config>`+"\n"+
			`</web-app>`+"\n")
		return true

	case "urlrewrite.xml":
		markAttack(info, "atlassian-webinf-read")
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
			`<urlrewrite>`+"\n"+
			`  <rule><from>^/status$</from><to>/status.action</to></rule>`+"\n"+
			`</urlrewrite>`+"\n")
		return true

	case "crowd.properties":
		markAttack(info, "atlassian-webinf-read")
		token := honeytoken(info.ip, "atlassian-webinf-read")
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		fmt.Fprintf(w, "application.name                        jira\n"+
			"application.password                    %s\n"+
			"application.login.url                   https://crowd.internal:8095/crowd\n"+
			"crowd.server.url                        https://crowd.internal:8095/crowd/services/\n"+
			"session.isauthenticated                 session.isauthenticated\n"+
			"session.tokenkey                        session.tokenkey\n", token)
		return true
	}

	markAttack(info, "atlassian-traversal-scan")
	http.NotFound(w, r)
	return true
}
