package main

import (
	"net/http"
	"strings"
	"testing"
)

// Atlassian Data Center, CVE-2026-21589. Kept in its own file so the shared
// table in routes_test.go does not have to be rewritten for every trap.

func TestAtlassianRouteTags(t *testing.T) {
	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/download/resources/jira.webresources:color-picker-popup/images/..::..::..::..::..::WEB-INF::web.xml",
			"atlassian-webinf-read", "the path honeypots captured"},
		{"/s/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:avatar/avatar/..::..::..::..::..::WEB-INF::urlrewrite.xml",
			"atlassian-webinf-read", "Bitbucket variant"},
		{"/s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/..::..::..::..::WEB-INF::classes::crowd.properties",
			"atlassian-webinf-read", "the credential file the exploit is after"},
		{"/download/resources/jira.webresources:color-picker-popup/images/..::..::WEB-INF::lib::nope.jar",
			"atlassian-traversal-scan", "traversal to a file we do not fake"},
		{"/download/resources/jira.webresources:color-picker-popup/images/spectrum.png", "",
			"ordinary Atlassian static resource, no traversal marker"},
		{"/download/current/x.zip", "nable-ncentral-scan",
			"unrelated /download/ prefix keeps its own tag"},
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

// crowd.properties is the file the exploit is after, so it must carry a
// recoverable honeytoken.
func TestAtlassianHoneytokenReachesTheClient(t *testing.T) {
	_, w := route(t, http.MethodGet,
		"/download/resources/x:y/images/..::..::WEB-INF::classes::crowd.properties")
	if findHoneytoken(w.Body.String()) == "" {
		t.Errorf("no %s token in response body", honeytokenPrefix)
	}
}

// The tag name decides the AbuseIPDB category (see TestScanTagsPickCategory14).
func TestAtlassianTagsPickTheRightCategory(t *testing.T) {
	if !strings.Contains("atlassian-traversal-scan", "scan") {
		t.Error("atlassian-traversal-scan should report as category 14+21")
	}
	if strings.Contains("atlassian-webinf-read", "scan") || strings.Contains("atlassian-webinf-read", "cgi") {
		t.Error("atlassian-webinf-read should report as category 21 alone")
	}
}
