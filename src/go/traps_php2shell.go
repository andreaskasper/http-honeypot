package main

import (
	"fmt"
	"net/http"
	"strings"
)

// "PHP2Shell": CVE-2026-109618 and CVE-2026-109619, two flaws in PHP core
// itself (an out-of-memory miscalculation on multipart MIME uploads and a
// double free on a second request that reads leftover request state), which
// chain to unauthenticated remote code execution on any site running an
// affected PHP 8 build. Patches shipped on 2026-10-22, CISA added both CVEs to
// the KEV catalog on 2026-10-26, and GreyNoise counted 509 attacker IPs and
// over 245,000 sessions by 2026-11-01. Sessions that succeeded hit "/" with GET
// and POST, some also POSTed to /upload.php.
//
// The exploit needs no particular path, so there is no path to trap. Two cheap
// and honest signals exist instead:
//
//   - php2shell-scan — the first scanner GreyNoise saw identifies itself in the
//     User-Agent header as "php2shell-scan/<number>". Matched by prefix; the
//     request is tagged and then routed as usual (a hit on "/" still gets the
//     default page), so any path-specific trap below keeps its answer but this
//     tag, set first, names the request.
//
//   - php-multipart-upload — a multipart POST to /upload.php, the second path
//     the successful sessions used and the stock name of upload handlers that
//     webshell droppers look for. Answered with a small JSON acknowledgement.
//
// Deliberately not claimed: multipart POSTs to any other path (ordinary
// forms), and a bare GET of /upload.php.
//
// Nothing parses a body or touches a file; every response is fabricated.

// php2ShellScanner tags requests from the php2shell-scan User-Agent. It never
// answers; the caller keeps routing.
func php2ShellScanner(r *http.Request, info *HoneypotRequest) {
	if strings.HasPrefix(strings.ToLower(r.UserAgent()), "php2shell-scan") {
		markAttack(info, "php2shell-scan")
	}
}

func phpUploadTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	if r.Method != http.MethodPost || strings.ToLower(r.URL.Path) != "/upload.php" ||
		!strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/") {
		return false
	}
	markAttack(info, "php-multipart-upload")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok","message":"File uploaded successfully"}`)
	return true
}
