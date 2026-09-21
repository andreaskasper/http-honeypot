package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The failure mode this repo actually has is not a compile error — it is a
// silent route collision. Every trap is inserted by hand into the dispatch
// chain in handleRoutes, and a new prefix that shadows an older one compiles
// fine, passes go vet, and quietly retags an existing trap. That is invisible
// until someone reads an AbuseIPDB report and finds the wrong product name on
// it.
//
// So this file asserts the chain rather than the handlers: for a given path,
// which trap wins. Paths are in the table for one of three reasons — a trap
// added recently, a neighbour it could plausibly have shadowed, or a path that
// must never be reported at all.
//
// No stubs and no fixtures: the tests drive the real handleRoutes. serveFile
// resolves assets/ relative to the working directory, which under `go test` is
// the package directory, so the few arms that serve a file work unchanged.

// TestMain sets LOG_DISABLED for the whole package rather than per test.
// markAttack fires logIPBlacklist in a goroutine that outlives the request, so
// a per-test t.Setenv is restored before the goroutine reads it and the output
// fills with permission-denied lines for /var/log/honeypot.ip.blacklist.log.
// sendWebhook and abuser.report already return early when their env vars are
// unset, so nothing else needs silencing and no test ever touches the network.
func TestMain(m *testing.M) {
	os.Setenv("LOG_DISABLED", "true")
	os.Exit(m.Run())
}

// route runs one request through handleRoutes and returns the attack tag it
// produced together with the recorded response.
func route(t *testing.T, method, path string) (string, *httptest.ResponseRecorder) {
	t.Helper()

	r := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	info := HoneypotRequest{
		http:      r,
		timestamp: time.Now(),
		ip:        "198.51.100.7", // TEST-NET-2, never a real attacker
	}
	handleRoutes(w, r, &info)
	return info.attackTag, w
}

func TestRouteTags(t *testing.T) {
	cases := []struct {
		path string
		want string // "" means the request must not be tagged as an attack
		why  string
	}{
		// ── Kestra, CVE-2026-49869 ────────────────────────────────────────
		{"/api/v1/flows/company.team/configs", "kestra-auth-bypass",
			"the bypass shape: an /api/ path ending in /configs"},
		{"/api/v1/main/flows/configs", "kestra-auth-bypass",
			"same, tenant-scoped"},
		{"/api/v1/configs", "kestra-scan",
			"the real public endpoint is not the bypass"},
		{"/api/v1/main/namespaces/prod/kv/DB_PASSWORD", "kestra-kv-read",
			"the secret store gets its own tag"},
		{"/api/v1/main/executions", "kestra-scan", "tenant management surface"},
		{"/api/v1/instance", "kestra-scan", "instance description"},

		// ── Cisco ISE, CVE-2026-76460 ─────────────────────────────────────
		{"/ers/config/networkdevice", "cisco-ise-ers-device",
			"RADIUS shared secret carrier"},
		{"/ers/config/internaluser/1", "cisco-ise-ers-identity",
			"local identity store"},
		{"/api/v1/deployment/node", "cisco-ise-openapi",
			"OpenAPI subtree reached unauthenticated"},
		{"/api/v1/system-certificate", "cisco-ise-openapi", ""},
		{"/admin/login.jsp", "cisco-ise-login", "product fingerprint"},
		{"/ers/sdk", "cisco-ise-scan", ""},
		{"/admin/API/mnt/Session/ActiveList", "cisco-ise-scan", "MnT API"},
		{"/pxgrid/control/AccountActivate", "cisco-ise-scan", ""},

		// ── Neighbours the two new traps could have shadowed ───────────────
		{"/api/v1/flows", "langflow-scan",
			"kestraTrap runs first but must only take the /configs suffix"},
		{"/api/v1/version", "langflow-scan", "Langflow keeps its own leaves"},
		{"/api/v1/api_key", "langflow-apikey", ""},
		{"/api/v1/pods", "k8s-pods",
			"the Kubernetes exact matches are dispatched far earlier"},
		{"/api/v1/namespaces/default/secrets", "k8s-secrets",
			"must not be read as a Kestra KV path"},
		{"/api/v1/admin/7", "rest-api-idor-admin",
			"a numbered-admin probe is IDOR scanning, not ISE exploitation"},
		{"/api/v1/users/5", "rest-api-idor-users", ""},
		{"/admin/config.php", "admin-config",
			"the legacy-admin switch must keep /admin/config.php"},
		{"/ui/login", "cisco-fmc-login",
			"ciscoFMCTrap owns /ui/login; Kestra's UI is deliberately unclaimed"},
		{"/api/v4/projects/1/repository/commits", "gitlab-commits-traversal", ""},
		{"/access/api/v1/tokens", "artifactory-token-mint",
			"must still beat loadMasterTrap"},
		{"/api/database", "metabase-database-list", ""},
		{"/cgi-bin/luci", "cgi-scan", ""},

		// ── Must never be reported to AbuseIPDB ───────────────────────────
		{"/", "", "the landing page"},
		{"/robots.txt", "", ""},
		{"/favicon.ico", "", ""},
		{"/.well-known/security.txt", "", ""},
		{"/definitely-not-a-trap", "", "plain 404"},
	}

	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, _ := route(t, http.MethodGet, c.path)
			if got != c.want {
				if c.why != "" {
					t.Errorf("attack_tag = %q, want %q (%s)", got, c.want, c.why)
					return
				}
				t.Errorf("attack_tag = %q, want %q", got, c.want)
			}
		})
	}
}

// TestHoneytokensReachTheClient checks the other half: a trap that is supposed
// to hand out a credential actually puts a recoverable hp_live_ token in the
// response. A format-verb slip or a renamed field would leave the trap looking
// fine while the honeytoken never arrives — and nothing else in the system
// would notice, because detection only ever sees what comes back.
func TestHoneytokensReachTheClient(t *testing.T) {
	for _, path := range []string{
		"/api/v1/flows/company.team/configs",     // Kestra task output
		"/api/v1/main/namespaces/prod/kv/SECRET", // Kestra KV value
		"/ers/config/networkdevice",              // ISE radiusSharedSecret
		"/ers/config/internaluser/1",             // ISE password
		"/api/v4/projects/1/repository/commits",  // GitLab gitlab.rb
		"/access/api/v1/tokens",                  // Artifactory access_token
		"/.env",                                  // STRIPE_SECRET_KEY
	} {
		t.Run(path, func(t *testing.T) {
			_, w := route(t, http.MethodGet, path)
			if tok := findHoneytoken(w.Body.String()); tok == "" {
				t.Errorf("no %s token in response body", honeytokenPrefix)
			}
		})
	}
}

// TestHoneytokensAreIPSpecific guards the property the whole scheme rests on:
// a token traces back to the address that was given it. Two addresses hitting
// the same trap must not receive the same value.
func TestHoneytokensAreIPSpecific(t *testing.T) {
	a := honeytoken("198.51.100.7", "cisco-ise-ers-device")
	b := honeytoken("203.0.113.9", "cisco-ise-ers-device")
	if a == b {
		t.Fatalf("two addresses got the same token: %s", a)
	}
	if !isHoneytoken(a) || !isHoneytoken(b) {
		t.Fatalf("minted tokens fail isHoneytoken: %q %q", a, b)
	}
	// And a token from one trap must not collide with another trap's.
	if honeytoken("198.51.100.7", "kestra-kv-read") == a {
		t.Fatal("two traps produced the same token for one address")
	}
}

// TestScanTagsPickCategory14 documents the coupling between a tag's name and
// the AbuseIPDB category it reports under: security.go switches to 14+21 when
// the tag contains "scan" or "cgi". That is easy to break by renaming a tag,
// and the consequence — a scanner reported as a targeted web-app attack, or
// the reverse — is invisible from inside the honeypot.
func TestScanTagsPickCategory14(t *testing.T) {
	scanners := []string{"kestra-scan", "cisco-ise-scan", "gitlab-api-scan", "cgi-scan"}
	targeted := []string{"kestra-auth-bypass", "kestra-kv-read",
		"cisco-ise-ers-device", "cisco-ise-ers-identity", "cisco-ise-openapi",
		"cisco-ise-login", "gitlab-commits-traversal"}

	isScanner := func(tag string) bool {
		return strings.Contains(tag, "scan") || strings.Contains(tag, "cgi")
	}
	for _, tag := range scanners {
		if !isScanner(tag) {
			t.Errorf("%q should report as category 14+21 but would not", tag)
		}
	}
	for _, tag := range targeted {
		if isScanner(tag) {
			t.Errorf("%q should report as category 21 alone but would not", tag)
		}
	}
}
