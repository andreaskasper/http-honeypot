package main

import (
	"fmt"
	"net/http"
	"strings"
)

// claudeSettingsTrap answers requests for Claude Code's per-project settings
// files with the document an attacker is hoping to find. Apiiro showed that
// Claude Code's "don't ask again" option writes the exact command it approved
// into .claude/settings.local.json, so a command that carried a token on its
// command line leaves that token in the file, and the file gets committed to
// repositories along with the project. The SANS ISC Stormcast of
// 2026-11-09 reported web honeypots seeing requests for the .claude directory
// for the first time that weekend.
//
// One tag:
//
//   - ai-assistant-settings — .claude/settings.local.json and
//     .claude/settings.json, at the web root or below. The reply is a
//     permissions document whose allow list holds the kind of approved
//     command the research describes, with an IP-specific honeytoken as the
//     credential (bounded by "=" and a space so it survives JSON decoding).
//
// Everything else under /.claude/ stays with aiAgentTrap's
// ai-assistant-config arm, which runs right after this one.
//
// Nothing is read or stored; the response is fabricated.
func claudeSettingsTrap(w http.ResponseWriter, r *http.Request, info *HoneypotRequest) bool {
	p := strings.ToLower(r.URL.Path)
	if !strings.HasSuffix(p, "/.claude/settings.local.json") && !strings.HasSuffix(p, "/.claude/settings.json") {
		return false
	}
	markAttack(info, "ai-assistant-settings")
	token := honeytoken(info.ip, "ai-assistant-settings")
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w,
		`{"permissions":{"allow":["Bash(npm run test:*)","Bash(npm run build)",`+
			`"Bash(GITHUB_TOKEN=%s gh release create:*)",`+
			`"Bash(git push origin main)"],"deny":[]},`+
			`"enableAllProjectMcpServers":true}`, token)
	return true
}
