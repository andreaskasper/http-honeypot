---
title: File & Print Servers
parent: Attack Traps
nav_order: 15
---

# File & Print Servers
{: .no_toc }

Two small servers that people put on the internet and then forget about: a file-sharing server and a print-management console. Both have had authentication bypasses that turn into code execution on the host, and both were being probed within days of public write-ups in October 2026.

1. TOC
{:toc}

---

## Rejetto HFS 3

**CVE-2026-61500** — CVSS 9.3. HFS 3.0.0 through 3.2.0 derives its session-cookie signing key from `Math.random()`, which is not a cryptographic generator. Anyone can request a handful of unauthenticated login responses, reconstruct the generator state, recover the signing key and forge an administrator session cookie. The admin API then accepts a `server_code` setting that runs as server-side JavaScript. Fixed in 3.2.1 (July 2026). Horizon3 published a write-up and a public proof of concept on 2026-09-30, and VulnCheck's canaries saw the first probing on 2026-10-01 — small-scale reconnaissance from a single address so far.

Everything HFS 3 serves beyond the shared files lives under the reserved `/~/` prefix, which makes the product recognisable from the path alone.

### `/~/api/loginSrp1`

**Tag:** `hfs-session-forge` 🍯

The first step of the SRP login. It needs no credentials, which is exactly why the exploit repeats it to harvest session cookies. The reply sets a session cookie whose value is an IP-specific honeytoken.

### `/~/api/get_config`, `/~/api/set_config`

**Tag:** `hfs-admin-config` 🍯

What a forged administrator session is used for. `get_config` returns a configuration object carrying an `upload_token` honeytoken; `set_config` is acknowledged with an empty object.

### Everything else under `/~/`

**Tag:** `hfs-scan`

The admin UI, frontend assets and other API calls, answered with a small JSON object so a scanner keeps talking. Reported to AbuseIPDB as category 14 + 21.

{: .note }
> **Source caveat:** the write-ups I could read name the `loginSrp1`, `get_config` and `set_config` handlers but not their URLs. The `/~/api/<handler>` shape is HFS 3's documented convention for its API, not something taken from an exploit. If scanners use a different path the trap stays quiet; no other trap changes owner.
>
> **Deliberately not claimed:** Apache-style home directories (`/~alice/`) do not start with `/~/` and are untouched.

---

## PaperCut NG / MF

A repeat target: authentication-bypass and pre-auth RCE chains in 2023, and again in 2026 (CVE-2026-81578, CVE-2026-82077, CVE-2026-82078, with a series of patch bypasses tracked by watchTowr as WT-2026-0141 to 0144). watchTowr's honeypots captured exploitation of the earlier 26.0.3 chain.

The whole console is one Apache Tapestry servlet at `/app`, and every page is selected by a `service` query parameter. That is the fingerprint: `/app` alone is a name other products use, but `/app` with `service=page/...` or `service=direct/...` is PaperCut and nothing else.

### `/app?service=…setup…`

**Tag:** `papercut-setup-bypass` 🍯

The first-run wizard (`page/SetupCompleted`, `direct/1/Home/SetupAdmin/$Form`, `SetupOrgType`, `SetupUserSource`, `SetupVerify`). Reaching it on an installed system without authenticating is the bypass, so the reply "accepts" it with a password page and sets a `JSESSIONID` cookie whose value is an IP-specific honeytoken.

### `/app?service=…` (any other Tapestry service)

**Tag:** `papercut-scan`

Answered with a login page naming the product and version so a scanner can confirm what it found. Reported to AbuseIPDB as category 14 + 21.

{: .note }
> **Deliberately not claimed:** `/app` without a Tapestry `service` parameter, and the bare `/user` and `/admin` names. Other products serve the same names, and a mislabelled AbuseIPDB report is worse than a missed one. PaperCut normally listens on 9191/9192; the trap matches the path on whichever port the honeypot is exposed.

Nothing here signs or verifies a cookie, parses a form, creates an account or executes anything; every response is fabricated.
