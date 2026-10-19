---
title: Collaboration Platforms
parent: Attack Traps
nav_order: 16
---

# Collaboration Platforms
{: .no_toc }

The issue tracker, the wiki and the source host: the systems an organisation uses to talk to itself, and therefore the ones that hold its tickets, design documents and code. The Atlassian Data Center products share one web-resource handler, and in October 2026 a flaw in it turned into a mass file-read sweep within a day of the patch.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Atlassian Data Center (CVE-2026-21589) 🍯

Jira, Confluence, Bitbucket, Bamboo, Crowd and Fisheye/Crucible, Data Center editions. CVE-2026-21589 (CVSS 9.3) is a pre-authentication arbitrary file read: the web-resource handler converts `..::` into `../`, so a static-resource URL can be walked out of its directory and into `WEB-INF`. Atlassian shipped the fix on 2026-10-05, honeypots at the SANS Internet Storm Center saw the first attempts on 2026-10-06, and CISA added the CVE to the KEV catalog on 2026-10-15.

The exploit needs the exact file name, so scanners sweep a short list of well-known files. The request shape, taken from those honeypot captures:

```
/download/resources/jira.webresources:color-picker-popup/images/..::..::..::WEB-INF::web.xml
/s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/..::..::WEB-INF::web.xml
```

### `/download/resources/…/..::…/<file>` 🍯

**Tag:** `atlassian-webinf-read`

A traversal that ends in a file the trap can fake: `web.xml` and `urlrewrite.xml` (what a scanner fingerprints with) and `crowd.properties`, which is what the exploit is after. `crowd.properties` carries an IP-specific honeytoken as `application.password`.

### Any other `..::` traversal under `/download/resources/`

**Tag:** `atlassian-traversal-scan`

Answered `404`, the way a real server answers a file that does not exist. Reported as category 14 + 21 because the tag contains `scan`.

{: .note }
> **Deliberately not claimed:** a plain `/download/resources/` request without the `..::` marker. Every Atlassian page requests those, and on a host that is not Atlassian it is simply a 404; the marker is the exploit.
>
> **Ordering:** `atlassianTrap` is the last helper in the edge-appliance dispatch line. It needs both `/download/resources/` and `..::` in the path, which nothing above claims; the one other `/download/` prefix in the chain, `/download/current/`, keeps its own tag.
>
> **Honeytoken carrier:** unlike most carriers this one is not behind an authentication bypass: the file read itself is the vulnerability. The token is replayed only if the attacker tries the Crowd credentials against a real Crowd server.

---

## Related

- [Supply Chain & AI Gateways](supply-chain) — GitLab, Artifactory, LiteLLM and Kestra
- [Honeytokens](../honeytokens) — how the `hp_live_*` tokens work and what happens on reuse
- [AbuseIPDB](../abuseipdb) — why `*-scan` tags report as category 14 + 21
