package main

import (
	"fmt"
	"net/http"
	"strings"
)

// wso2Trap covers WSO2 API Manager and the products built on it (API Control
// Plane, Traffic Manager, Universal Gateway) — the gateway that fronts an
// organisation's APIs and holds the consumer keys, secrets and backend
// credentials for every one of them.
//
// CVE-2026-5430 — CVSS 10.0 — is a JWT authentication bypass by algorithm
// confusion: the gateway accepts tokens signed with an algorithm other than
// the one it is configured for, so an attacker can forge an administrator
// token. WSO2 shipped the fix in May 2026; watchTowr's honeypots caught forged
// administrator tokens arriving on 2026-09-13, and CISA added the CVE to the
// KEV catalog on 2026-09-24 with a federal deadline of 2026-09-27.
//
// The forged token travels as "Authorization: Bearer", so the request that
// matters is any call to a protected API path. The product-specific ones are:
//
//   - wso2-apim-dcr — /client-registration/. Dynamic client registration, the
//     call that mints a consumer key and secret. The secret in the reply is an
//     IP-specific honeytoken.
//   - wso2-apim-api — /api/am/, the publisher, admin and devportal REST APIs.
//     The API list carries a backend endpoint-security password, which is the
//     credential an attacker came for; that field is a honeytoken.
//   - wso2-carbon-login — /carbon/, the management console login that a
//     scanner reads to confirm the product and its version.
//
// Deliberately not claimed: /oauth2/token, /services/, /admin/, /publisher/
// and /devportal/ on their own. Other identity servers and gateways serve the
// same names, and a mislabelled AbuseIPDB report is worse than a missed one.
//
// Ordering: nothing above claims /carbon/, /api/am/ or /client-registration/.
// restAPITrap only matches /api/v<N>/(users|accounts|admin|customers|
// employees)/<digits>, and /api/am/ does not start with that shape.
//
// No token is parsed or verified and no gateway exists; every response is
// fabricated.
func wso2Trap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)

	switch {
	case strings.HasPrefix(p, "/client-registration/"):
		markAttack(info, "wso2-apim-dcr")
		token := honeytoken(info.ip, "wso2-apim-dcr")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"clientId":"Zk8wP2dJc0t1YmxpY2F0aW9u","clientName":"admin_rest_api_client",`+
				`"callBackURL":"","clientSecret":%q,"isSaasApplication":true}`, token)
		return true

	case strings.HasPrefix(p, "/api/am/"):
		markAttack(info, "wso2-apim-api")
		token := honeytoken(info.ip, "wso2-apim-api")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w,
			`{"count":1,"list":[{"id":"6f3a1c9e-0000-4000-8000-0000000000c1","name":"PaymentsAPI",`+
				`"context":"/payments/1.0.0","version":"1.0.0","provider":"admin","lifeCycleStatus":"PUBLISHED",`+
				`"endpointConfig":{"endpoint_type":"http","production_endpoints":{"url":"https://payments.internal:8443"},`+
				`"endpoint_security":{"production":{"enabled":true,"type":"BASIC","username":"svc-gateway","password":%q}}}}],`+
				`"pagination":{"offset":0,"limit":25,"total":1}}`, token)
		return true

	case strings.HasPrefix(p, "/carbon/"), p == "/carbon":
		markAttack(info, "wso2-carbon-login")
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>WSO2 Management Console</title></head>`+
			`<body><div id="login"><h1>WSO2 API Manager</h1>`+
			`<form action="../admin/login_action.jsp" method="post">`+
			`<input type="text" name="username" id="txtUserName"/>`+
			`<input type="password" name="password" id="txtPassword"/>`+
			`<input type="submit" value="Sign-in"/></form>`+
			`<p class="version">WSO2 API Manager 4.5.0</p></div></body></html>`)
		return true
	}
	return false
}
