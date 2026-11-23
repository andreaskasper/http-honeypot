package main

import (
	"fmt"
	"net/http"
	"strings"
)

// rollerTrap covers CVE-2026-129448 (and its narrower predecessor
// CVE-2026-82384), a pre-authentication deserialization RCE in the XML-RPC
// servlet of Apache Roller, the Java blog server. The servlet runs Apache
// ws-xmlrpc with extensions enabled, so an <ex:serializable> parameter
// (base64 Java serialization) is deserialized while the request is parsed,
// before any method or credential check; the methodName does not matter.
// Fix merged 2026-09-05, Roller 6.1.6 around 2026-09-24, PoC public
// 2026-09-28, 6.1.7 on 2026-11-11. CVE-2026-129448 was published on
// 2026-11-17 with Apache stating it is actively exploited and widening the
// range to 4.0.0 through 6.1.4; CISA KEV 2026-11-20.
//
// Request shape: POST /roller-services/xmlrpc (or
// /roller/roller-services/xmlrpc when Roller is not the root context),
// Content-Type text/xml.
//
// Two tags:
//
//   - roller-xmlrpc-rce — a POST to the XML-RPC servlet. The reply is the
//     ws-xmlrpc fault an unpatched server returns after it has deserialized the
//     payload ("Failed to load class for result object"), which is what the
//     public scanners treat as "vulnerable".
//
//   - roller-scan — any other method on the servlet path (the real servlet
//     answers 405), anything else under /roller-services/, and Roller's own UI
//     prefix /roller-ui/ (login.rol is the usual fingerprint), with or without
//     the /roller context. Answered like a stock install would.
//
// Deliberately not claimed: a bare /roller or /roller/ (an ordinary blog
// path) and /xmlrpc.php, which belongs to WordPress and keeps its own tag.
//
// Nothing reads the body, deserializes or runs anything; every response is
// fabricated.
func rollerTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	if strings.HasPrefix(p, "/roller/") {
		p = strings.TrimPrefix(p, "/roller")
	}
	p = strings.TrimSuffix(p, "/")

	switch {
	case p == "/roller-services/xmlrpc":
		if r.Method != http.MethodPost {
			markAttack(info, "roller-scan")
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title></head>`+
				`<body><h1>HTTP Status 405 – Method Not Allowed</h1></body></html>`)
			return true
		}
		markAttack(info, "roller-xmlrpc-rce")
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`+
			`<methodResponse xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions">`+
			`<fault><value><struct>`+
			`<member><name>faultCode</name><value><i4>0</i4></value></member>`+
			`<member><name>faultString</name><value>Failed to load class for result object: java.lang.ClassCastException</value></member>`+
			`</struct></value></fault></methodResponse>`)
		return true

	case strings.HasPrefix(p, "/roller-services/"):
		markAttack(info, "roller-scan")
		http.Error(w, "Not Found", http.StatusNotFound)
		return true

	case p == "/roller-ui" || strings.HasPrefix(p, "/roller-ui/"):
		markAttack(info, "roller-scan")
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Front Page: Welcome to Roller</title>`+
			`<meta name="generator" content="Apache Roller 6.1.5" /></head><body>`+
			`<h2>Welcome to Roller</h2>`+
			`<form method="post" id="loginForm" action="/roller_j_security_check">`+
			`<p><label for="j_username">Username:</label> <input type="text" name="j_username" id="j_username" size="25" /></p>`+
			`<p><label for="j_password">Password:</label> <input type="password" name="j_password" id="j_password" size="20" /></p>`+
			`<p><input type="submit" name="login" id="login" value="Login" /></p>`+
			`</form></body></html>`)
		return true
	}
	return false
}
