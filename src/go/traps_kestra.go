package main

import (
	"fmt"
	"net/http"
	"strings"
)

// kestraTrap covers Kestra, the open-source workflow orchestrator that sits in
// the middle of a data platform and holds the credentials for everything it
// talks to — cloud accounts, warehouses, internal APIs — in its namespace KV
// store.
//
// CVE-2026-49869 — CVSS 10.0, added to the CISA KEV catalog on 2026-09-02 —
// is an authentication bypass that becomes unauthenticated OS command
// execution. Kestra's AuthenticationFilter exempted the public configuration
// endpoint with request.getPath().endsWith("/configs"). Kestra also accepts a
// caller-controlled flow or namespace identifier in that same path position,
// so a flow named "configs" produces an API path that ends with the exempted
// string and skips Basic Auth entirely. Past the filter, the attacker creates
// and runs a flow; the shell script plugin ships enabled by default, so the
// flow runs as root inside the worker container. Fixed in 1.0.45 and 1.3.21.
//
// The bypass arm is what matters. Matching is deliberately narrow: an /api/
// path that ends with /configs but is not the real /api/v1/configs endpoint is
// the exploit shape and nothing else. The fabricated execution it returns
// carries an IP-specific honeytoken in the task output, standing in for the
// environment a real worker would have leaked to the injected command, so a
// replay of that value is caught by detectHoneytokenInRequest.
//
// Ordering: this trap has to run before langflowTrap, which claims the whole
// /api/v1/flows prefix. /api/v1/flows/configs is a Kestra bypass attempt, not
// a Langflow probe, and the suffix arm is narrow enough that nothing else
// changes hands. Everything else langflowTrap claims stays with it.
//
// Deliberately not claimed: the bare /ui/ shell (ciscoFMCTrap owns /ui/login
// and a Kestra UI probe is not worth the collision) and the unversioned
// /api/v1/flows prefix (Langflow's, per above).
//
// Nothing here parses a request body, creates a flow or executes anything;
// every response is fabricated and inert.
func kestraTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)

	switch {
	// CVE-2026-49869. The suffix the filter trusted, in a position the caller
	// controls. The real public endpoint is handled in the next arm.
	case strings.HasPrefix(p, "/api/") && strings.HasSuffix(p, "/configs") &&
		p != "/api/v1/configs" && p != "/api/v1/main/configs":
		markAttack(info, "kestra-auth-bypass")
		token := honeytoken(info.ip, "kestra-auth-bypass")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"id":"5vBQ2kZpN7xLmR0aTc9dYe","namespace":"company.team",`+
				`"flowId":"configs","flowRevision":1,`+
				`"state":{"current":"SUCCESS","startDate":"2026-09-21T06:12:04.118Z",`+
				`"endDate":"2026-09-21T06:12:05.902Z","duration":"PT1.784S"},`+
				`"taskRunList":[{"id":"1rJ8pQvWmK4sXb","taskId":"shell",`+
				`"state":{"current":"SUCCESS"},"outputs":{"exitCode":0,`+
				`"vars":{"KESTRA_API_TOKEN":%q,`+
				`"POSTGRES_PASSWORD":"Pr0dWarehouse!2026"}}}]}`, token)
		return true

	// The genuinely public configuration endpoint. Only Kestra serves it, so a
	// probe here is a fingerprint of this product and not an accident; the
	// version reported is below the fixed release, which is what keeps a
	// scanner talking instead of moving on.
	case p == "/api/v1/configs", p == "/api/v1/main/configs":
		markAttack(info, "kestra-scan")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w,
			`{"uuid":"9f14c0de-0000-4000-8000-0000000000a1","version":"1.3.20",`+
				`"isBasicAuthEnabled":true,"isAnonymousUsageEnabled":true,`+
				`"environment":{"name":"PROD","color":"#f5a623"},"url":"/",`+
				`"tenantId":"main"}`)
		return true

	// The namespace KV store: where a Kestra deployment keeps the secrets its
	// flows use. This is the first thing an attacker reads after the bypass,
	// so the value is an IP-specific honeytoken.
	case strings.HasPrefix(p, "/api/v1/") && strings.Contains(p, "/namespaces/") &&
		strings.Contains(p, "/kv"):
		markAttack(info, "kestra-kv-read")
		token := honeytoken(info.ip, "kestra-kv-read")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"type":"STRING","value":%q}`, token)
		return true

	// The tenant-scoped management surface. /api/v1/main/ is Kestra's own
	// spelling and is claimed nowhere else; /api/v1/instance is the instance
	// description a scanner reads next.
	case strings.HasPrefix(p, "/api/v1/main/"), p == "/api/v1/instance":
		markAttack(info, "kestra-scan")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w,
			`{"_embedded":{"errors":[{"message":"Unauthorized"}]},`+
				`"message":"Unauthorized","_links":{"self":{"href":"`+
				`/api/v1/main","templated":false}}}`)
		return true
	}
	return false
}
