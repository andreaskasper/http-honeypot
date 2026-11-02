---
title: PHP Platforms
parent: Attack Traps
nav_order: 18
---

# PHP Platforms
{: .no_toc }

Two October 2026 additions with a PHP angle: a file-upload bug in the most widely deployed PHP shop system, and a flaw in PHP itself that needs no particular path at all.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Adobe Commerce / Magento "PolyShell"

**Paths:** `/rest/[<store>/]V1/guest-carts…` and `/pub/media/custom_options/…`
**Tags:** `magento-polyshell-upload`, `magento-polyshell-scan`

CVE-2026-48356 is an unrestricted file upload in Adobe Commerce and Magento Open Source. A guest cart accepts an item with a file-type custom option, Magento writes the base64 data below `pub/media/custom_options/quote/` without checking the extension, and the only guard is an image-header check that a GIF/PNG-with-PHP polyglot passes. Sansec saw mass scanning from 2026-03-19, Adobe published APSB26-73 on 2026-07-14, and CISA added the CVE to the KEV catalog on 2026-10-27. The request shape is the public REST API, so the paths are the documented guest-cart routes.

| Request | Tag | Response |
|---|---|---|
| `POST /rest/V1/guest-carts` | `magento-polyshell-upload` | A quoted 32-character cart id |
| Any other `/rest/[<store>/]V1/guest-carts…` path | `magento-polyshell-upload` | A cart-item document carrying that cart id as `quote_id`, so the upload looks like it landed |
| Anything under `/pub/media/custom_options/` | `magento-polyshell-scan` | A bare `GIF89a` header, the first bytes of a polyglot; reported as a scanner (category 14+21) |

The rest of `/rest/` (every Magento shop serves its catalogue there) and the rest of `/pub/media/` are deliberately not claimed. Request bodies are never read and nothing is stored; every response is fabricated.

## PHP2Shell

**Signals:** the `php2shell-scan` User-Agent prefix, and a multipart `POST` to `/upload.php`
**Tags:** `php2shell-scan`, `php-multipart-upload`

CVE-2026-109618 and CVE-2026-109619 are two flaws in PHP core (a memory miscalculation on multipart MIME uploads and a double free on a second request) that chain to unauthenticated remote code execution on affected PHP 8 builds. Patches shipped on 2026-10-22, CISA added both CVEs to the KEV catalog on 2026-10-26, and GreyNoise counted 509 attacker IPs and more than 245,000 sessions by 2026-11-01. Successful sessions hit `/` with `GET` and `POST`; some also posted to `/upload.php`.

The exploit needs no particular path, so there is none to trap. Two narrow signals are used instead:

| Request | Tag | Response |
|---|---|---|
| Any request whose `User-Agent` starts with `php2shell-scan` (the first scanner GreyNoise saw) | `php2shell-scan` | Whatever the path would normally get; the tag is set first and routing carries on, so a hit on `/` still sees the default page. Reported as a scanner (category 14+21) |
| `POST /upload.php` with a `multipart/…` content type | `php-multipart-upload` | `{"status":"ok","message":"File uploaded successfully"}` |

A multipart `POST` to any other path, a non-multipart `POST` to `/upload.php` and a bare `GET /upload.php` are not claimed. The User-Agent is trivial to change, so `php2shell-scan` catches the first wave only; the upload trap is the part that survives a rename. Nothing parses a body or touches a file.
