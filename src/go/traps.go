package main

import (
	"fmt"
	"net/http"
	"regexp"
)

// restAPITrap catches IDOR-style scanners probing /api/v*/users/{id} etc.
// The fake response embeds an IP-specific honeytoken as the api_key field.
func restAPITrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	apiRe := regexp.MustCompile(`^/api/v\d+/(users|accounts|admin|customers|employees)/(\d+)`)
	m := apiRe.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return false
	}
	resource := m[1]
	id := m[2]
	markAttack(info, "rest-api-idor-"+resource)
	token := honeytoken(info.ip, "rest-api-idor-"+resource)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w,
		`{"id":%s,"email":"user%s@contoso.internal","role":"user",`+
			`"password_hash":"$2b$12$FakeHashForHoneypotXXXXXXXXXXXXXXX",`+
			`"api_key":%q,"created_at":"2024-01-15T10:30:00Z"}`,
		id, id, token)
	return true
}
