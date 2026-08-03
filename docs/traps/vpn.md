---
title: VPN Appliances
parent: Attack Traps
nav_order: 4
---

# VPN Appliance Traps
{: .no_toc }

VPN and remote-access appliances are a top initial-access vector. Nation-state actors and ransomware groups routinely scan for known-vulnerable VPN endpoints before major campaigns.

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
