package main

import (
	"net/http"
	"strings"
	"testing"
)

// Nextcloud Collabora CODE app, CVE-2026-110447, and the Hikvision
// /SDK/webLanguage probe. Own file so the shared table in routes_test.go does
// not have to be rewritten for every trap.

func TestNextcloudAndHikvisionRouteTags(t *testing.T) {
	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/apps/richdocumentscode/proxy.php", "nextcloud-code-proxy-rce", "the vulnerable proxy"},
		{"/apps/richdocumentscode/proxy.php?status", "nextcloud-code-proxy-rce", "the reported probe"},
		{"/apps/richdocumentscode/proxy.php/%2e%2e/$(id)", "nextcloud-code-proxy-rce",
			"injection rides in the path"},
		{"/apps/richdocumentscode_arm64/proxy.php", "nextcloud-code-proxy-rce", "arm64 variant"},
		{"/apps/richdocumentscode/shxa1b2c3.php?c=id", "nextcloud-code-webshell", "dropped shx*.php webshell"},
		{"/apps/richdocumentscode/appinfo/info.xml", "nextcloud-code-scan", "version fingerprint"},
		{"/apps/files/", "", "other Nextcloud apps are not claimed"},
		{"/proxy.php", "", "bare proxy.php elsewhere is not claimed"},
		{"/SDK/webLanguage", "hikvision-weblanguage", "CVE-2021-36260 probe"},
		{"/sdk/weblanguage/", "hikvision-weblanguage", "case and trailing slash"},
		{"/sdk", "vmware-vcenter-sdk", "vCenter keeps the SOAP endpoint"},
		{"/sdk/vimServiceVersions.xml", "vmware-vcenter-sdk", "vCenter keeps the version manifest"},
		{"/sdk/other", "vmware-vcenter-sdk", "rest of /sdk/ still reaches vCenter"},
		{"/ISAPI/Security/userCheck", "", "Hikvision ISAPI is deliberately unclaimed"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, _ := route(t, http.MethodGet, c.path)
			if got != c.want {
				t.Errorf("attack_tag = %q, want %q (%s)", got, c.want, c.why)
			}
		})
	}
}

// The webshell answers a config.php read with the file the attacker is after,
// so that response must carry a recoverable honeytoken; a plain id must not.
func TestNextcloudWebshellHoneytoken(t *testing.T) {
	_, w := route(t, http.MethodGet, "/apps/richdocumentscode/shxa1b2c3.php?c=cat+/var/www/html/config/config.php")
	if findHoneytoken(w.Body.String()) == "" {
		t.Errorf("no %s token in config.php response", honeytokenPrefix)
	}
	_, w = route(t, http.MethodGet, "/apps/richdocumentscode/shxa1b2c3.php")
	if !strings.Contains(w.Body.String(), "uid=33(www-data)") {
		t.Errorf("default command should answer a fabricated id, got %q", w.Body.String())
	}
}

// The tag name decides the AbuseIPDB category (see TestScanTagsPickCategory14).
func TestNextcloudTagsPickTheRightCategory(t *testing.T) {
	isScanner := func(tag string) bool {
		return strings.Contains(tag, "scan") || strings.Contains(tag, "cgi")
	}
	if !isScanner("nextcloud-code-scan") {
		t.Error("nextcloud-code-scan should report as category 14+21")
	}
	for _, tag := range []string{"nextcloud-code-proxy-rce", "nextcloud-code-webshell", "hikvision-weblanguage"} {
		if isScanner(tag) {
			t.Errorf("%s should report as category 21 alone", tag)
		}
	}
}
