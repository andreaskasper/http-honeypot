package main

import (
	"fmt"
	"net/http"
	"strings"
)

// gitlabTrap covers self-managed GitLab, the DevOps platform that holds an
// organisation's source, deploy tokens, CI/CD variables and Rails secrets in
// one place.
//
// CVE-2026-85706 — CVSS 10.0, patched in 19.3.2 / 19.2.6 / 19.1.8 on
// 2026-09-10 — is a path traversal in the repository commits API. Improper
// path confinement combined with missing authentication enforcement lets an
// unauthenticated caller read any file the GitLab process can read, in a
// single HTTP request. watchTowr observed internet-wide probes from 06:00 UTC
// on 2026-09-11; CISA added it to the KEV catalog the same day with a federal
// remediation deadline of 2026-09-14.
//
// The traversal arm is the one that matters. The file an attacker reaches for
// first on a self-managed instance is /etc/gitlab/gitlab.rb, so that is what
// this arm serves, with an IP-specific honeytoken standing in for
// initial_root_password. Anything replaying that value — from this address or
// another — is caught by detectHoneytokenInRequest.
//
// Ordering: restAPITrap is dispatched further up and matches
// /api/v<N>/(users|accounts|admin|customers|employees)/<digits>, so
// /api/v4/users/5 keeps its rest-api-idor-users tag. Nothing in that regex
// touches /api/v4/projects/, which is where this trap lives.
//
// Deliberately not claimed: /explore, /help and /users/password/new. They are
// plain Rails or Devise defaults that other applications serve too, and a
// mislabelled AbuseIPDB report is worse than a missed one.
//
// Nothing here parses a request body, resolves a path or reads a repository;
// every response is fabricated and inert.
func gitlabTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)

	// CVE-2026-85706. watchTowr told defenders to hunt for POST requests to
	// /api/v4/projects/{id}/repository/commits/ carrying a file.path
	// parameter; we answer the whole subtree regardless of method, because a
	// scanner confirming the endpoint exists probes it with GET first.
	if strings.HasPrefix(p, "/api/v4/projects/") && strings.Contains(p, "/repository/commits") {
		markAttack(info, "gitlab-commits-traversal")
		token := honeytoken(info.ip, "gitlab-commits-traversal")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "01K4Q7V9ZP8M3N0R2T5W7Y9B1D")
		fmt.Fprintf(w,
			`{"id":"ed899a2f4b50b4370feeea94676502b42383c746",`+
				`"short_id":"ed899a2f","title":"Update omnibus configuration",`+
				`"author_name":"GitLab","author_email":"gitlab@contoso.example",`+
				`"created_at":"2026-09-12T08:14:22.000+00:00",`+
				`"file_path":"/etc/gitlab/gitlab.rb","encoding":"text",`+
				`"content":"external_url 'https://gitlab.contoso.example'\n`+
				`gitlab_rails['db_password'] = 'Pr0dGitlabDB!2026'\n`+
				`gitlab_rails['initial_root_password'] = '%s'\n`+
				`gitlab_rails['smtp_password'] = 'smtp-relay-2026'\n"}`, token)
		return true
	}

	switch p {
	case "/api/v4/version", "/api/v4/metadata", "/api/v4/projects",
		"/api/v4/groups", "/api/v4/runners/all", "/api/v4/personal_access_tokens":
		markAttack(info, "gitlab-api-scan")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "01K4Q7V9ZP8M3N0R2T5W7Y9B1D")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"401 Unauthorized"}`)
		return true
	case "/users/sign_in":
		markAttack(info, "gitlab-login")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Sign in &middot; GitLab</title></head>`+
			`<body class="login-page"><div class="login-box"><h1>GitLab</h1>`+
			`<form action="/users/sign_in" method="post" id="new_user">`+
			`<input name="user[login]" id="user_login" placeholder="Username or email"/>`+
			`<input type="password" name="user[password]" id="user_password" placeholder="Password"/>`+
			`<input type="submit" name="commit" value="Sign in"/></form>`+
			`<p class="gl-text-secondary">GitLab Community Edition 19.2.4</p></div></body></html>`)
		return true
	case "/-/health", "/-/liveness", "/-/readiness":
		// GitLab's own spelling. An uptime monitor pointed at this host does
		// not reach /-/health by accident, so this cannot report a plain
		// monitor to AbuseIPDB — the same call made for LiteLLM's
		// /health/liveliness and Metabase's /api/health.
		markAttack(info, "gitlab-scan")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"401 Unauthorized"}`)
		return true
	}
	return false
}
