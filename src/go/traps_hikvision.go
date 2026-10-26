package main

import (
	"fmt"
	"net/http"
	"strings"
)

// hikvisionTrap covers the Hikvision web server's /SDK/webLanguage endpoint,
// the target of CVE-2021-36260 — a command injection in the <language> element
// of the XML body, reachable without authentication on unpatched IP cameras
// and DVRs. It is five years old and still one of the most reliably scanned
// IoT paths; GreyNoise reported a fresh wave against DVRs between
// 2026-09-21 and 2026-10-01. The exploit is a PUT with an XML body, but
// scanners probe it with whatever method their template uses, so any method
// is answered.
//
// One tag:
//
//   - hikvision-weblanguage — /SDK/webLanguage. The reply is the ISAPI
//     ResponseStatus document a camera returns, so the probe looks like it
//     landed.
//
// Only the exact path is claimed (case-insensitive, optional trailing slash).
//
// Ordering: vCenterTrap claims everything under /sdk/ (the SOAP endpoint), so
// this trap has to run before it in the dispatch chain. It claims nothing else
// under /sdk/, which still reaches vCenter.
//
// The body is never read and no command is executed; every response is
// fabricated.
func hikvisionTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.TrimSuffix(strings.ToLower(r.URL.Path), "/")
	if p != "/sdk/weblanguage" {
		return false
	}
	markAttack(info, "hikvision-weblanguage")
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
		`<ResponseStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">`+"\n"+
		`<requestURL>/SDK/webLanguage</requestURL>`+"\n"+
		`<statusCode>1</statusCode>`+"\n"+
		`<statusString>OK</statusString>`+"\n"+
		`<subStatusCode>ok</subStatusCode>`+"\n"+
		`</ResponseStatus>`+"\n")
	return true
}
