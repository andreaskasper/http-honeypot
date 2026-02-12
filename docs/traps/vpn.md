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
