package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Magento PolyShell (CVE-2026-48356), Plex2Shell and PHP2Shell. Own file so the
// shared table in routes_test.go does not have to be rewritten for every trap.

func routeReq(t *testing.T, r *http.Request) (string, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	info := HoneypotRequest{http: r, timestamp: time.Now(), ip: "198.51.100.7"}
	handleRoutes(w, r, &info)
	return info.attackTag, w
}

func TestMagentoPlexPHPRouteTags(t *testing.T) {
	cases := []struct {
		method, path, ctype, ua string
		want, why               string
	}{
		{"POST", "/rest/V1/guest-carts", "", "", "magento-polyshell-upload", "cart creation"},
		{"POST", "/rest/default/V1/guest-carts/abc123/items", "", "", "magento-polyshell-upload", "item add with store code"},
		{"GET", "/rest/V1/products", "", "", "", "ordinary catalogue API is not claimed"},
		{"GET", "/rest/com/vmware/cis/session", "", "", "vmware-vcenter-session", "vCenter keeps its /rest/ prefix"},
		{"GET", "/pub/media/custom_options/quote/a/b/index.php", "", "", "magento-polyshell-scan", "uploaded shell lookup"},
		{"GET", "/pub/media/catalog/product/x.jpg", "", "", "", "rest of /pub/media is not claimed"},
		{"POST", "/player/timeline?protocol=http", "", "", "plex-timeline-ssrf", "SSRF entry"},
		{"GET", "/player/timeline/poll", "", "", "plex-timeline-ssrf", "poll below timeline"},
		{"GET", "/system/agents", "", "", "plex-scan", "agent list"},
		{"GET", "/player/navigation/home", "", "", "plex-scan", "companion API"},
		{"GET", "/player/", "", "", "", "bare /player/ is not claimed"},
		{"GET", "/identity", "", "", "", "/identity is deliberately unclaimed"},
		{"POST", "/upload.php", "multipart/form-data; boundary=x", "", "php-multipart-upload", "multipart upload"},
		{"POST", "/upload.php", "application/json", "", "", "non-multipart is not claimed"},
		{"GET", "/upload.php", "", "", "", "bare GET is not claimed"},
		{"POST", "/contact.php", "multipart/form-data; boundary=x", "", "", "other paths are not claimed"},
		{"GET", "/", "", "php2shell-scan/109618", "php2shell-scan", "scanner User-Agent on /"},
		{"GET", "/", "", "Mozilla/5.0", "", "ordinary client on / stays untagged"},
		{"GET", "/actuator/env", "", "php2shell-scan/109618", "php2shell-scan", "UA tag is set first"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.path, nil)
			if c.ctype != "" {
				r.Header.Set("Content-Type", c.ctype)
			}
			if c.ua != "" {
				r.Header.Set("User-Agent", c.ua)
			}
			got, _ := routeReq(t, r)
			if got != c.want {
				t.Errorf("attack_tag = %q, want %q (%s)", got, c.want, c.why)
			}
		})
	}
}

func TestMagentoResponses(t *testing.T) {
	_, w := routeReq(t, httptest.NewRequest("POST", "/rest/V1/guest-carts", nil))
	if b := w.Body.String(); len(b) != 34 || b[0] != '"' {
		t.Errorf("cart creation should answer a quoted 32-char id, got %q", b)
	}
	_, w = routeReq(t, httptest.NewRequest("POST", "/rest/V1/guest-carts/x/items", nil))
	if !strings.Contains(w.Body.String(), `"quote_id":"`) {
		t.Errorf("item add should answer a cart item, got %q", w.Body.String())
	}
	_, w = routeReq(t, httptest.NewRequest("GET", "/pub/media/custom_options/quote/a/b/c.php", nil))
	if w.Body.String() != "GIF89a" || w.Header().Get("Content-Type") != "image/gif" {
		t.Errorf("custom_options probe should answer a bare GIF header")
	}
}

func TestPlexUnauthorizedAndAccepted(t *testing.T) {
	_, w := routeReq(t, httptest.NewRequest("GET", "/system/agents", nil))
	if w.Code != 401 {
		t.Errorf("/system/agents should answer 401, got %d", w.Code)
	}
	_, w = routeReq(t, httptest.NewRequest("POST", "/player/timeline", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `code="200"`) {
		t.Errorf("timeline should look accepted, got %d %q", w.Code, w.Body.String())
	}
}

// The tag name decides the AbuseIPDB category (see TestScanTagsPickCategory14).
func TestOctTagsPickTheRightCategory(t *testing.T) {
	isScanner := func(tag string) bool {
		return strings.Contains(tag, "scan") || strings.Contains(tag, "cgi")
	}
	for _, tag := range []string{"magento-polyshell-scan", "plex-scan", "php2shell-scan"} {
		if !isScanner(tag) {
			t.Errorf("%s should report as category 14+21", tag)
		}
	}
	for _, tag := range []string{"magento-polyshell-upload", "plex-timeline-ssrf", "php-multipart-upload"} {
		if isScanner(tag) {
			t.Errorf("%s should report as category 21 alone", tag)
		}
	}
}
