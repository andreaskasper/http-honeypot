package main

import (
	"fmt"
	"net/http"
	"strings"
)

// plexTrap covers "Plex2Shell", the chain of CVE-2026-96652, -96654, -96655 and
// -96656 against Plex Media Server up to 1.43.3.10828 (fixed in 1.43.3.10861,
// released 2026-08-04). The first link is an unauthenticated SSRF in the
// player-companion endpoint /player/timeline, taking a "protocol" parameter
// that makes the server send a POST wherever the attacker points it; the later
// links reach the owner token and finally a code-loading primitive in the
// transcoder settings. Full technical details were published on 2026-10-16, a
// public PoC followed within days, exploitation started against honeypots on
// 2026-10-17 (cryptominers), and CISA warned on 2026-10-21.
//
// Two tags:
//
//   - plex-timeline-ssrf — /player/timeline and everything below it
//     (/player/timeline/poll, /player/timeline/subscribe), the SSRF entry. The
//     reply is the empty Response document the companion API returns, so the
//     request looks accepted.
//
//   - plex-scan — the other Plex player-companion endpoints
//     (/player/playback/, /player/navigation/, /player/application/,
//     /player/mirror/) and /system/agents, which the chain's follow-up stage and
//     scanners both touch. Answered 401 Unauthorized like a real server would
//     for an anonymous request.
//
// Deliberately not claimed: /identity and /library/sections (other products
// serve those names too, and a mislabelled AbuseIPDB report is worse than a
// missed one), and a bare /player/ (an ordinary name for a video page).
//
// Nothing makes an outbound request or reads a body; every response is
// fabricated.
func plexTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.TrimSuffix(strings.ToLower(r.URL.Path), "/")

	switch {
	case p == "/player/timeline" || strings.HasPrefix(p, "/player/timeline/"):
		markAttack(info, "plex-timeline-ssrf")
		w.Header().Set("Content-Type", "text/xml;charset=utf-8")
		w.Header().Set("X-Plex-Protocol", "1.0")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
			`<Response code="200" status="OK" />`+"\n")
		return true

	case p == "/system/agents",
		strings.HasPrefix(p, "/player/playback/"), strings.HasPrefix(p, "/player/navigation/"),
		strings.HasPrefix(p, "/player/application/"), strings.HasPrefix(p, "/player/mirror/"):
		markAttack(info, "plex-scan")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `<html><head><title>Unauthorized</title></head>`+
			`<body><h1>401 Unauthorized</h1></body></html>`)
		return true
	}
	return false
}
