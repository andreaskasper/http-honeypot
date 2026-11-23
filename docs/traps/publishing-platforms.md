---
title: Publishing Platforms
parent: Attack Traps
nav_order: 20
---

# Publishing Platforms
{: .no_toc }

Two November 2026 additions from the blog world: a race in WordPress core that only exists while a site updates itself, and a pre-auth deserialization bug in the XML-RPC servlet of Apache Roller.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## WordPress core upgrade window

**Tags:** `wp-upgrade-setup-config`, `wp-upgrade-install`, `wp-upgrade-scan`

[CVE-2026-119977](https://nvd.nist.gov/vuln/detail/CVE-2026-119977), **CVSS 8.1**, CISA KEV **2026-11-03**. During a full-package core update, WordPress 4.7 through 7.1.3 unpacks the new release into a predictable, web-reachable folder under `/wp-content/upgrade/`, named after the package and version. For the few seconds that folder exists, its `wp-admin/setup-config.php` runs without WordPress being loaded: an attacker who hits it in time points the installer at a database of their own and gets code execution.

Fixed in **7.1.4** on 2026-10-28 (random suffix on the folder name plus a config guard) and backported to every branch down to 4.7; 7.1.5 followed on 2026-11-18. Wordfence deployed a firewall rule at 20:30 UTC on release day and saw the first match nine minutes later: more than 18,500 requests in the first 21 hours, more than 240,000 blocked by 2026-11-05, with a peak above 74,000 on 2026-10-30. A public PoC appeared on 2026-11-04. Sources: [Rescana](https://www.rescana.com/post/wordpress-core-7-1-4-upgrade-staging-race-rce), [Inception Security](https://www.inceptionsecurity.com/post/wordpress-cve-2026-119977-exploited-hunt-upgrade-race), [ThreatDefence](https://threatdefence.com/article/wordpress-7-1-4-upgrade-window-rce-hunting).

Scanners cannot know when a site updates, so they poll: they cycle version-named folders such as `/wp-content/upgrade/wordpress-6.9.11/` and ask for the installer again and again. Because the request goes straight to a PHP file, a WordPress-level security plugin never sees it; only the web server log does. Write-ups disagree on whether the unpacked tree has an extra `wordpress/` level, so the trap matches the installer file name at any depth below `/wp-content/upgrade/`.

### `setup-config.php` below `/wp-content/upgrade/`

**Tag:** `wp-upgrade-setup-config`

A `GET` gets the installer's first screen ("Before getting started"). The PoC's `POST` with `?step=2` gets the "Successful database connection" screen with its "Run the installation" link, so the race looks won. The body is never read.

### `install.php` below `/wp-content/upgrade/`

**Tag:** `wp-upgrade-install`

The follow-up step after a hijacked installer. Answered with the "Welcome" form of the five-minute install.

### Anything else under `/wp-content/upgrade/`

**Tag:** `wp-upgrade-scan`

Including the bare directory, which scanners request in the hope of a listing that names the staging folder. Answered `404`, like a site that is not in the middle of an update.

{: .note }
> **Deliberately not claimed:** `/wp-admin/setup-config.php` at its normal place (that is an unconfigured-install probe, not this race) and look-alike prefixes such as `/wp-content/upgrader/`. The rest of `/wp-content/` keeps `wordpress-scan`.
>
> **Ordering:** `wpUpgradeTrap` closes the edge-appliance dispatch line and therefore runs before the prefix block that tags all of `/wp-content` as `wordpress-scan`.

---

## Apache Roller XML-RPC

**Tags:** `roller-xmlrpc-rce`, `roller-scan`

[CVE-2026-129448](https://nvd.nist.gov/vuln/detail/CVE-2026-129448) (and its narrower predecessor CVE-2026-82384), **CVSS 9.8**, CISA KEV **2026-11-20**. Apache Roller's XML-RPC servlet runs Apache ws-xmlrpc with extensions enabled, so an `<ex:serializable>` parameter (base64 Java serialization) is deserialized while the request is parsed, before any method or credential check. The `methodName` does not matter.

The fix was merged on 2026-09-05 and shipped in 6.1.6; a PoC followed on 2026-09-28 and 6.1.7 on 2026-11-11. CVE-2026-129448 was published on 2026-11-17 with Apache stating it is actively exploited and widening the affected range to 4.0.0 through 6.1.4. Sources: [The Hacker News](https://thehackernews.com/2026/11/critical-apache-roller-rce-flaw-under.html), [Corgea](https://corgea.com/research/cve-2026-129448-82384-apache-roller-xml-rpc-deserialization-exploited-november-2026), [Phoenix Security](https://phoenix.security/apache-roller-xml-rpc-deserialization-cve-2026-129448-rce/).

### `POST /roller-services/xmlrpc`

**Tag:** `roller-xmlrpc-rce`

Also with the `/roller` context prefix (`/roller/roller-services/xmlrpc`). The reply is the ws-xmlrpc fault an unpatched server returns once it has deserialized the payload, `Failed to load class for result object`, which is what public scanners read as "vulnerable". Nothing is parsed or deserialized.

### Other Roller paths

**Tag:** `roller-scan`

Any other method on the servlet path (answered `405`, like the real servlet), the rest of `/roller-services/` (`404`), and Roller's UI prefix `/roller-ui/`, where `login.rol` is the usual fingerprint (answered with a Roller login page).

{: .note }
> **Deliberately not claimed:** a bare `/roller` or `/roller/` (an ordinary blog path) and `/xmlrpc.php`, which belongs to WordPress and keeps its `xmlrpc` tag.

No response on this page carries a credential, so neither trap embeds a honeytoken.

---

## Related

- [CMS](cms) — the rest of the WordPress, Joomla and phpMyAdmin traps
- [PHP Platforms](php-platforms) — Magento PolyShell and PHP2Shell
- [AbuseIPDB](../abuseipdb) — why `*-scan` tags report as category 14 + 21
