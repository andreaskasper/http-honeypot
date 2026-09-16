---
title: Edge Appliances & VPN
parent: Attack Traps
nav_order: 4
---

# Edge Appliance & VPN Traps
{: .no_toc }

VPN and remote-access appliances are a top initial-access vector. Nation-state actors and ransomware groups routinely scan for known-vulnerable VPN endpoints before major campaigns. The same is true of the consoles that manage those appliances, which is why a firewall management centre now sits on this page too.

---

## Fortinet FortiGate

**Path:** `/remote/fgt_lang*`  
**Tag:** `fortinet-fgt`

Returns the characteristic `-72:LF` response that FortiOS returns when the `lang` parameter is probed. This pattern is used to fingerprint internet-facing FortiGate devices and is associated with scanning prior to exploitation of **CVE-2022-40684** (authentication bypass) and **CVE-2023-27997** (heap overflow in SSL-VPN).

---

## SonicWall SSL-VPN

**Paths:** `/remote/login`, `/remote/logincheck`  
**Tag:** `sonicwall-vpn`

Returns a minimal SonicWall SSL-VPN 10.2 login page. SonicWall appliances have been targeted by multiple critical CVEs including **CVE-2021-20038** (unauthenticated stack overflow).

---

## Ivanti Connect Secure (Pulse Secure)

**Path:** `/dana-na/auth/url_default/welcome.cgi`  
**Tag:** `pulse-secure`

The canonical path for Ivanti Connect Secure (formerly Pulse Secure). Returns a fake welcome portal page. **CVE-2019-11510** (unauthenticated arbitrary file read) and **CVE-2021-22893** were exploited by nation-state actors including APT29.

---

## Cisco ASA SSL VPN

**Path:** `/+CSCOE+/logon.html`  
**Tag:** `cisco-asa-vpn`

The login path for Cisco Adaptive Security Appliance SSL VPN. Returns a fake Cisco ASA page. Associated with scanning for **CVE-2023-20269** (unauthenticated remote access VPN brute-force).

---

## Citrix NetScaler ADC / Gateway 🍯

**Paths:** `/p/u/doAuthentication.do`, `/nf/auth/doAuthentication.do`, `/vpn/index.html`, `/vpn/tmindex.html`, `/cgi/login`, `/logon/LogonPoint/*`, and the `/vpn/`, `/vpns/`, `/nsconfig/`, `/citrix/`, `/logon/` prefixes  
**Tags:** `citrix-netscaler-bleed`, `citrix-netscaler-logon`, `citrix-netscaler-scan`

Citrix NetScaler is one of the most heavily scanned edge appliances on the internet.

The `doAuthentication.do` arm answers the **CitrixBleed 2** probe (**CVE-2025-5777**). On a real appliance, sending the `login` parameter without a value leaves a variable uninitialised and the device echoes back leftover stack memory inside an `<InitialValue>` XML tag — which is how attackers harvest session tokens. The honeypot returns an `<InitialValue>` filled with **fabricated** memory-looking content that carries an IP-specific [honeytoken](../honeytokens), so a scanner that "leaks" a session token from this host and later tries to reuse it lights up a `honeytoken_used` event.

The prefixes also cover the older **CVE-2019-19781** path-traversal probes (`/vpn/../vpns/cfg/smb.conf`) and generic Gateway fingerprinting.

---

## Palo Alto Networks PAN-OS GlobalProtect 🍯

**Paths:** `/global-protect/login.esp`, `/global-protect/portal/login.esp`, `/global-protect/prelogin.esp`, `/global-protect/getconfig.esp`, and the same set under `/ssl-vpn/`  
**Tags:** `panos-globalprotect-login`, `panos-globalprotect-prelogin`, `panos-globalprotect-config`, `panos-globalprotect-scan`

`/global-protect/login.esp` is the single most-probed VPN login surface GreyNoise tracks — millions of sessions, dominated by credential-stuffing infrastructure. Probing typically starts with `prelogin.esp` (which a real portal answers unauthenticated, making it an ideal fingerprint) before moving on to login attempts.

The `getconfig.esp` arm returns a fake portal configuration whose `<portal-userauthcookie>` is an IP-specific [honeytoken](../honeytokens) — the field an attacker exploiting an authentication bypass such as **CVE-2026-0257** would go looking for.

---

## Cisco Secure Firewall Management Center 🍯

**Paths:** `/api/fmc_platform/v1/auth/generatetoken`, `/sajaxintf.cgi`, `/pjb.cgi`, `/ui/login`, `/help/about.cgi`, and the `/platinum/`, `/api/fmc_platform/`, `/api/fmc_config/`, `/api/fmc_troubleshoot/` prefixes  
**Tags:** `cisco-fmc-token`, `cisco-fmc-authbypass`, `cisco-fmc-login`, `cisco-fmc-scan`

FMC is not a VPN — it is the console that manages an estate of Cisco firewalls, which means one compromised console reaches every policy standing in front of the network. That is why it gets swept as hard as the appliances it manages.

[CVE-2026-20079](https://nvd.nist.gov/vuln/detail/CVE-2026-20079) is a **CVSS 10.0** authentication bypass (CWE-288, alternate path or channel), added to the CISA KEV catalog on **2026-09-09** with a remediation deadline three days later. A process created at boot leaves a session for an internal machine account reachable over HTTP; a crafted request rides that session into the management UI, and from there into command execution as root. Cisco PSIRT confirmed exploitation from August 2026, by both state-sponsored and ransomware actors. Censys counts roughly 300 internet-facing instances and FOFA 600–700 — a small enough population that all of it gets found.

### `/api/fmc_platform/v1/auth/generatetoken` 🍯

**Tag:** `cisco-fmc-token`

The documented REST token endpoint, and the arm that matters. A real FMC answers it with a **204 No Content** and puts the credential in the response *headers* — `X-auth-access-token` and `X-auth-refresh-token` — so that is where the honeytokens go. This is the first carrier in the honeypot that lives in a header rather than a body, and it gets **two distinct tokens**, so a replayed access token can be told apart from a replayed refresh token in the `honeytoken_used` event.

### `/sajaxintf.cgi`, `/pjb.cgi`

**Tag:** `cisco-fmc-authbypass`

The two CGI scripts the published chain abuses: `sajaxintf.cgi` for the arbitrary write and the Perl `Storable` deserialisation, `pjb.cgi` for the privileged bulk call that executes the result. Reaching either of these unauthenticated *is* the exploit, not recon — which is why they get their own tag rather than falling into the scan arm.

### `/ui/login`

**Tag:** `cisco-fmc-login`

The page an unauthenticated caller is bounced to, and the one a scanner reads to confirm the product and its version.

### `/help/about.cgi`, `/platinum/*`, `/api/fmc_config/*`, `/api/fmc_troubleshoot/*`

**Tag:** `cisco-fmc-scan`

Answered the way a real appliance answers them: a `302` back to `/ui/login` with the original target preserved for the CGI paths, and FMC's own error envelope (`{"error":{"category":"FRAMEWORK",...}}`) for the API subtrees.

{: .note }
> The bare `/login.cgi` is **deliberately not claimed**, even though it appears in the published chain. Routers, NAS boxes and DVRs serve `/login.cgi` too, and a probe of one of those should not be reported to AbuseIPDB as a Cisco FMC attack. The same call was made for LoadMaster's `/progs/` paths and Metabase's `/api/health`: cover less rather than guess.
