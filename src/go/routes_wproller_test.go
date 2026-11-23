package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// WordPress core upgrade-window race (CVE-2026-119977) and Apache Roller
// XML-RPC deserialization (CVE-2026-129448). Own file so the shared table in
// routes_test.go does not have to be rewritten.

func TestWPUpgradeRollerRouteTags(t *testing.T) {
	cases := []struct {
		method, path string
		want, why    string
	}{
		{"GET", "/wp-content/upgrade/wordpress-6.9.11/setup-config.php", "wp-upgrade-setup-config", "installer in version folder"},
		{"GET", "/wp-content/upgrade/wordpress-7.1.3/wordpress/wp-admin/setup-config.php", "wp-upgrade-setup-config", "installer one level deeper"},
		{"POST", "/wp-content/upgrade/wordpress-7.1.3/wp-admin/setup-config.php?step=2", "wp-upgrade-setup-config", "PoC step 2"},
		{"GET", "/wp-content/upgrade/wordpress-7.1.3/wp-admin/install.php", "wp-upgrade-install", "follow-up install"},
		{"GET", "/wp-content/upgrade/", "wp-upgrade-scan", "bare upgrade directory"},
		{"GET", "/wp-content/upgrade", "wp-upgrade-scan", "upgrade directory without slash"},
		{"GET", "/wp-content/upgrade/wordpress-7.1.3/index.php", "wp-upgrade-scan", "other file in staging folder"},
		{"GET", "/wp-content/plugins/akismet/readme.txt", "wordpress-scan", "rest of /wp-content keeps its tag"},
		{"GET", "/wp-content/upgrader/setup-config.php", "wordpress-scan", "lookalike prefix is not claimed"},
		{"GET", "/wp-admin/setup-config.php", "", "regular installer path is not claimed"},
		{"POST", "/xmlrpc.php", "xmlrpc", "WordPress XML-RPC keeps its tag"},
		{"POST", "/roller-services/xmlrpc", "roller-xmlrpc-rce", "servlet at root context"},
		{"POST", "/roller/roller-services/xmlrpc", "roller-xmlrpc-rce", "servlet under /roller"},
		{"POST", "/roller-services/xmlrpc/", "roller-xmlrpc-rce", "trailing slash"},
		{"GET", "/roller-services/xmlrpc", "roller-scan", "GET on the servlet"},
		{"GET", "/roller-services/other", "roller-scan", "other /roller-services/ path"},
		{"GET", "/roller-ui/login.rol", "roller-scan", "login fingerprint"},
		{"GET", "/roller/roller-ui/login.rol", "roller-scan", "login fingerprint under /roller"},
		{"GET", "/roller/", "", "bare /roller/ is not claimed"},
		{"GET", "/roller", "", "bare /roller is not claimed"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			got, _ := routeReq(t, httptest.NewRequest(c.method, c.path, nil))
			if got != c.want {
				t.Errorf("attack_tag = %q, want %q (%s)", got, c.want, c.why)
			}
		})
	}
}

func TestWPUpgradeRollerResponses(t *testing.T) {
	_, w := routeReq(t, httptest.NewRequest("GET", "/wp-content/upgrade/wordpress-6.9.11/setup-config.php", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Before getting started") {
		t.Errorf("setup-config GET = %d %q", w.Code, w.Body.String())
	}
	_, w = routeReq(t, httptest.NewRequest("POST", "/wp-content/upgrade/wordpress-6.9.11/setup-config.php?step=2", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "All right, sparky!") {
		t.Errorf("setup-config step 2 = %d %q", w.Code, w.Body.String())
	}
	_, w = routeReq(t, httptest.NewRequest("GET", "/wp-content/upgrade/", nil))
	if w.Code != 404 {
		t.Errorf("bare upgrade dir = %d, want 404", w.Code)
	}
	_, w = routeReq(t, httptest.NewRequest("POST", "/roller-services/xmlrpc", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Failed to load class for result object") {
		t.Errorf("roller xmlrpc = %d %q", w.Code, w.Body.String())
	}
	_, w = routeReq(t, httptest.NewRequest("GET", "/roller-services/xmlrpc", nil))
	if w.Code != 405 {
		t.Errorf("roller xmlrpc GET = %d, want 405", w.Code)
	}
}

// The tag name decides the AbuseIPDB category (see TestScanTagsPickCategory14).
func TestWPUpgradeRollerCategories(t *testing.T) {
	isScanner := func(tag string) bool {
		return strings.Contains(tag, "scan") || strings.Contains(tag, "cgi")
	}
	for _, tag := range []string{"wp-upgrade-scan", "roller-scan"} {
		if !isScanner(tag) {
			t.Errorf("%s should report as category 14+21", tag)
		}
	}
	for _, tag := range []string{"wp-upgrade-setup-config", "wp-upgrade-install", "roller-xmlrpc-rce"} {
		if isScanner(tag) {
			t.Errorf("%s should report as category 21 alone", tag)
		}
	}
}
