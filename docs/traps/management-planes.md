---
title: Management Planes & API Gateways
parent: Attack Traps
nav_order: 14
---

# Management Planes & API Gateways
{: .no_toc }

Two September 2026 KEV listings with the same shape: a CVSS 9.8–10.0 authentication bypass on the console that controls everything behind it. A compromised SD-WAN manager reaches every branch router; a compromised API gateway holds the consumer keys and backend credentials of every API it fronts.

1. TOC
{:toc}

---

## Cisco Catalyst SD-WAN Manager

**CVE-2026-76504** — CVSS 9.8, CWE-177. Improper handling of URI encoding lets a request for the authentication endpoint slip past the rule that protects it: an encoded character in the name, such as `/%6a_security_check` (`%6a` is `j`), yields API access as the admin user. Cisco published the advisory on 2026-09-29, Rapid7 and Qualys reported exploitation in the wild immediately, and CISA added it to the KEV catalog on 2026-09-30 with a deadline of 2026-10-03. There is no workaround.

Go decodes the request path before a handler sees it, so the plain and every encoded spelling of `/j_security_check` arrive as the same path and one comparison covers them all.

### `/j_security_check` (plain or encoded)

**Tag:** `cisco-sdwan-authbypass` 🍯

Reaching this endpoint with a mangled name *is* the exploit, so the bypass appears to succeed: the reply sets a `JSESSIONID` cookie whose value is an IP-specific honeytoken — the credential the attacker would carry into the next request.

### `/dataservice/client/token`

**Tag:** `cisco-sdwan-token` 🍯

The CSRF-token endpoint every authenticated API session fetches first. The real one returns a bare string, so the body is the honeytoken.

### `/dataservice/*`

**Tag:** `cisco-sdwan-api`

The REST API the bypass opens up. Answered **200** with a device inventory rather than a `401`: getting this far unauthenticated is the bypass working, and an inventory keeps the scanner talking.

{: .note }
> **Deliberately not claimed:** `/login` and `/`. Far too many products serve them to report a probe as an SD-WAN attack.

---

## WSO2 API Manager

**CVE-2026-5430** — CVSS 10.0, JWT authentication bypass by algorithm confusion: the gateway accepts tokens signed with an algorithm other than the one it is configured for, so an attacker can forge an administrator token. WSO2 shipped the fix in May 2026; watchTowr's honeypots caught forged administrator tokens on 2026-09-13, and CISA added the CVE to the KEV catalog on 2026-09-24. The forged token travels as `Authorization: Bearer`, so what a honeypot sees is the walk across the product-specific API paths that follows.

### `/client-registration/*`

**Tag:** `wso2-apim-dcr` 🍯

Dynamic client registration — the call that mints a consumer key and secret. The `clientSecret` in the reply is a honeytoken.

### `/api/am/*`

**Tag:** `wso2-apim-api` 🍯

The publisher, admin and devportal REST APIs. The API list carries a backend `endpoint_security` password, the credential an attacker is after; that field is a honeytoken.

### `/carbon/*`

**Tag:** `wso2-carbon-login`

The management console login a scanner reads to confirm the product and version.

{: .note }
> **Deliberately not claimed:** `/oauth2/token`, `/services/`, `/admin/`, `/publisher/` and `/devportal/` on their own. Other identity servers and gateways use the same names, and a mislabelled AbuseIPDB report is worse than a missed one.
>
> **Ordering:** `restAPITrap` only matches `/api/v<N>/(users|accounts|admin|customers|employees)/<digits>`, so `/api/am/` never collides with it.

No token is parsed or verified, no session exists and no inventory exists; every response is fabricated.
