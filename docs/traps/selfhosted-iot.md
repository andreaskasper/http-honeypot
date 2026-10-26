---
title: Self-hosted Apps & IoT
parent: Attack Traps
nav_order: 17
---

# Self-hosted Apps & IoT
{: .no_toc }

Software that people install on their own server or plug into their own network and then forget to update: a document editor bolted onto a file-sync server, an IP camera with a web interface. Neither is a big-vendor product, which is exactly why scanners find so many unpatched copies.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Nextcloud Collabora CODE 🍯

**Paths:** `/apps/richdocumentscode/…` and `/apps/richdocumentscode_arm64/…`
**Tags:** `nextcloud-code-proxy-rce`, `nextcloud-code-webshell`, `nextcloud-code-scan`

CVE-2026-110447 (CVSS 9.2) is an unauthenticated OS command injection in `proxy.php` of the "built-in CODE server" app, the small PHP proxy that lets Nextcloud run its own Collabora document editor. It was fixed in release 26.4.303 on 2026-09-11, attacks appear in access logs from 2026-09-10, and the advisory followed on 2026-10-14. The shell command rides in the request path itself, not in the query string; the follow-up is a one-line PHP webshell named `shx<random>.php` dropped next to `proxy.php`, used to look for password databases, password-manager files and wallets.

| Request | Tag | Response |
|---|---|---|
| `…/richdocumentscode/proxy.php` (any path or query after it) | `nextcloud-code-proxy-rce` | The small JSON status document the real proxy returns, so the injection looks like it worked |
| `…/richdocumentscode/shx*.php` | `nextcloud-code-webshell` | A fabricated `id` output; with `c=` naming a `config.php`, a fabricated Nextcloud config whose `dbpassword`, `secret` and `passwordsalt` are IP-specific [honeytokens](../honeytokens) |
| Anything else under the app directory | `nextcloud-code-scan` | 404, reported as a scanner (category 14+21) |

Only paths under the two app directories are claimed. A bare `/proxy.php` or any other Nextcloud app is left alone, because other software uses those names. No command is executed and no file is read; every response is fabricated.

## Hikvision `/SDK/webLanguage`

**Path:** `/SDK/webLanguage` (case-insensitive, optional trailing slash)
**Tag:** `hikvision-weblanguage`

CVE-2021-36260 is a command injection in the `<language>` element of the XML body sent to this endpoint, reachable without authentication on unpatched Hikvision cameras and DVRs. It is five years old and still one of the most reliably scanned IoT paths; GreyNoise reported a fresh wave against DVRs between 2026-09-21 and 2026-10-01. The exploit is a `PUT`, but scanners use whatever method their template carries, so every method is answered with the ISAPI `ResponseStatus` document a camera returns.

This trap runs before the VMware vCenter trap, which owns the rest of `/sdk/`. Only the exact path above is taken; `/sdk`, `/sdk/vimServiceVersions.xml` and everything else under `/sdk/` still go to vCenter, and the camera's `/ISAPI/` tree is deliberately not claimed.
