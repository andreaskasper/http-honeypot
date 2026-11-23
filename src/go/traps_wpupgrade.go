package main

import (
	"fmt"
	"net/http"
	"strings"
)

// wpUpgradeTrap covers CVE-2026-119977, the WordPress core "upgrade window"
// race (CVSS 8.1). During a full-package core update WordPress 4.7 through
// 7.1.3 unpacks the new release into a predictable, web-reachable folder
// under /wp-content/upgrade/ (named after the package and version), and for
// the few seconds the folder exists its wp-admin/setup-config.php can be run
// without WordPress loading: an attacker points it at a database of their own
// and gets code execution. Fixed in 7.1.4 on 2026-10-28 (random suffix on the
// folder name plus a config guard), backported to every branch down to 4.7.
// Wordfence deployed a rule at 20:30 UTC that day and saw the first match nine
// minutes later; more than 18,500 requests in the first 21 hours and more than
// 240,000 blocked by 2026-11-05 (peak above 74,000 on 2026-10-30). CISA KEV
// 2026-11-03, public PoC 2026-11-04.
//
// The scanners do not know when a site updates, so they poll: they cycle
// version-named folders (/wp-content/upgrade/wordpress-6.9.11/...) and ask
// for the installer again and again. Write-ups disagree on whether the
// unpacked tree has an extra wordpress/ level, so the installer file name is
// matched at any depth below /wp-content/upgrade/.
//
// Three tags:
//
//   - wp-upgrade-setup-config — setup-config.php anywhere below
//     /wp-content/upgrade/. A GET gets the installer's first screen; the PoC's
//     POST with ?step=2 gets the "database connection worked" screen, so the
//     race looks won.
//
//   - wp-upgrade-install — install.php anywhere below /wp-content/upgrade/, the
//     follow-up step after a hijacked setup-config.php; answered with the
//     "Welcome" form.
//
//   - wp-upgrade-scan — everything else under /wp-content/upgrade/, including
//     the bare directory (scanners look for a listing that names the folder).
//     Answered 404, like a site that is not mid-update.
//
// Ordering: the prefix block at the end of handleRoutes tags all of
// /wp-content as wordpress-scan, so this trap has to be dispatched before it;
// the edge-appliance chain is. Nothing above claims /wp-content/upgrade/.
//
// The body is never read, nothing is written and no connection is made; every
// response is fabricated.
func wpUpgradeTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	if p != "/wp-content/upgrade" && !strings.HasPrefix(p, "/wp-content/upgrade/") {
		return false
	}

	switch {
	case strings.HasSuffix(p, "/setup-config.php"):
		markAttack(info, "wp-upgrade-setup-config")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodPost && r.URL.Query().Get("step") == "2" {
			fmt.Fprint(w, wpSetupPage("Setup Configuration File",
				`<h1 class="screen-reader-text">Successful database connection</h1>`+
					`<p>All right, sparky! You&#8217;ve made it through this part of the installation. `+
					`WordPress can now communicate with your database. If you are ready, time now to&hellip;</p>`+
					`<p class="step"><a href="../wp-admin/install.php?language=en_US" class="button button-large">Run the installation</a></p>`))
			return true
		}
		fmt.Fprint(w, wpSetupPage("Setup Configuration File",
			`<h1 class="screen-reader-text">Before getting started</h1>`+
				`<p>Welcome to WordPress. Before getting started, you will need to know the following items.</p>`+
				`<ol><li>Database name</li><li>Database username</li><li>Database password</li>`+
				`<li>Database host</li><li>Table prefix (if you want to run more than one WordPress in a single database)</li></ol>`+
				`<p class="step"><a href="setup-config.php?step=1" class="button button-large">Let&#8217;s go!</a></p>`))
		return true

	case strings.HasSuffix(p, "/install.php"):
		markAttack(info, "wp-upgrade-install")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, wpSetupPage("Installation",
			`<h1>Welcome</h1>`+
				`<p>Welcome to the famous five-minute WordPress installation process! `+
				`Just fill in the information below and you&#8217;ll be on your way.</p>`+
				`<h2>Information needed</h2>`+
				`<form id="setup" method="post" action="install.php?step=2" novalidate="novalidate">`+
				`<table class="form-table" role="presentation">`+
				`<tr><th scope="row"><label for="weblog_title">Site Title</label></th><td><input name="weblog_title" type="text" id="weblog_title" size="25" value="" /></td></tr>`+
				`<tr><th scope="row"><label for="user_login">Username</label></th><td><input name="user_name" type="text" id="user_login" size="25" value="" /></td></tr>`+
				`<tr><th scope="row"><label for="pass1">Password</label></th><td><input type="password" name="admin_password" id="pass1" class="regular-text" autocomplete="new-password" /></td></tr>`+
				`<tr><th scope="row"><label for="admin_email">Your Email</label></th><td><input name="admin_email" type="email" id="admin_email" size="25" value="" /></td></tr>`+
				`</table>`+
				`<p class="step"><input type="submit" name="Submit" id="submit" class="button button-large" value="Install WordPress" /></p>`+
				`</form>`))
		return true
	}

	markAttack(info, "wp-upgrade-scan")
	http.Error(w, "Not Found", http.StatusNotFound)
	return true
}

// wpSetupPage wraps body in the bare layout wp-admin/setup-config.php and
// wp-admin/install.php print before WordPress itself is loaded.
func wpSetupPage(title, body string) string {
	return `<!DOCTYPE html>` + "\n" +
		`<html lang="en-US">` + "\n" +
		`<head>` + "\n" +
		`<meta name="viewport" content="width=device-width" />` + "\n" +
		`<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />` + "\n" +
		`<meta name="robots" content="noindex,nofollow" />` + "\n" +
		`<title>WordPress &rsaquo; ` + title + `</title>` + "\n" +
		`<link rel="stylesheet" id="install-css" href="../wp-admin/css/install.min.css?ver=7.1.3" media="all" />` + "\n" +
		`</head>` + "\n" +
		`<body class="wp-core-ui">` + "\n" +
		`<p id="logo">WordPress</p>` + "\n" +
		body + "\n" +
		`</body>` + "\n" +
		`</html>` + "\n"
}
