---
title: Microsoft Exchange
parent: Attack Traps
nav_order: 3
---

# Microsoft Exchange Traps
{: .no_toc }

Microsoft Exchange is one of the most heavily targeted enterprise products. The ProxyLogon vulnerability chain (CVE-2021-26855 + CVE-2021-27065) was exploited at massive scale in early 2021 and scanning for these paths continued for years afterward.

---

## /owa/ and /owa/auth/logon.aspx

**Tag:** `owa-login`

Serves a convincing fake Outlook Web Access login page (`assets/owa_logon_aspx.html`). `/owa/` redirects to the logon page, exactly as real Exchange does.

---

## /ews/exchange.asmx

**Tag:** `exchange-ews`

Exchange Web Services endpoint. Returns a minimal HTML response: `Exchange Web Services are working.` — the exact message a real Exchange EWS endpoint returns when accessed via GET.

---

## /autodiscover/autodiscover.json

**Tag:** `exchange-proxylogon`

This is the path probed by tools exploiting **CVE-2021-26855** (ProxyLogon). Returns a fake Autodiscover JSON response. Any hit here is a strong indicator of a targeted Exchange attack.

```json
{
  "Protocol": "Autodiscoverv1",
  "Url": "https://autodiscover.contoso.com/autodiscover/autodiscover.xml"
}
```

---

## /ecp/

**Tag:** `exchange-ecp`

The Exchange Control Panel — targeted by **CVE-2021-27065** (the second stage of ProxyLogon). Returns 401 Unauthorized with a `WWW-Authenticate: Basic realm="Exchange Control Panel"` header.
