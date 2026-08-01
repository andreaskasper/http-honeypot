---
title: Other Services
parent: Attack Traps
nav_order: 9
---

# Other Service Traps
{: .no_toc }

## Microsoft SharePoint ("ToolShell")

**Paths:** `/_layouts/15/ToolPane.aspx`, `/_layouts/16/ToolPane.aspx`  
**Tag:** `sharepoint-toolpane`

The ToolShell exploit chain against on-premises SharePoint Server — **CVE-2025-53770** and the 2026 follow-ups (**CVE-2026-56164**, **CVE-2026-58644**), all on the CISA KEV catalog. Attackers POST to `ToolPane.aspx` with `DisplayMode=Edit` and a `Referer` spoofed to `/_layouts/SignOut.aspx`. The honeypot answers with an inert Web Part maintenance page and the `MicrosoftSharePointTeamServices` header a real server would send.

**Paths:** `/_vti_bin/*`, `/_api/web*`, other `/_layouts/*`  
**Tag:** `sharepoint-scan`

The broad reconnaissance sweep that precedes and follows the exploit. Returns a fake `401` `UnauthorizedAccessException` in SharePoint's OData error format.

---

## Adobe ColdFusion

**Path prefix:** `/CFIDE/administrator*`  
**Tag:** `coldfusion-admin`

Serves a fake ColdFusion Administrator login form. **CVE-2023-26360** and the **CVE-2026-48282** path traversal (CVSS 10.0, added to CISA KEV in July 2026 days after the patch) both make this one of the most-probed admin panels on the internet.

**Paths:** `/CFIDE/*`, `/cf_scripts/*`, `*.cfm`, `*.cfc`  
**Tag:** `coldfusion-scan`

Returns ColdFusion's characteristic "Error Occurred While Processing Request" page including a version banner.

---

## Langflow / AI agent platforms 🍯

**Path:** `/api/v1/validate/code`  
**Tag:** `langflow-rce`

**CVE-2025-3248** — unauthenticated code execution in Langflow's code validation endpoint, still actively scanned by botnets. Returns a fake "no errors" validation result.

**Paths:** `/api/v1/api_key`, `/api/v1/variables`  
**Tag:** `langflow-apikey`

Returns a fake API key listing containing an **IP-specific honeytoken** (`hp_live_*`). If that key ever comes back to the honeypot, you get a `honeytoken_used` event.

**Paths:** `/api/v1/flows*`, `/api/v1/store*`, `/api/v1/version`  
**Tag:** `langflow-scan`

Fingerprinting and the cross-tenant IDOR **CVE-2026-55255** — the first AI agent platform vulnerability ever added to CISA KEV.

---

## Apache Solr

**Path prefix:** `/solr/*`  
**Tag:** `apache-solr`

Returns a fake Solr 9.4.0 JSON response. Apache Solr has had multiple critical RCE vulnerabilities (CVE-2019-0192, CVE-2021-27905) and is regularly mass-scanned.

---

## Jenkins

### /script
**Tag:** `jenkins-script`

Serves a fake Groovy Script Console. An unauthenticated Jenkins Script Console provides direct code execution on the server and is one of the most critical Jenkins misconfigurations.

### /computer/(master)/api/json
**Tag:** `jenkins-api`

Returns a fake Hudson/Jenkins API response including version number.

---

## H2 / JBoss Console

**Paths:** `/console`, `/h2-console`  
**Tag:** `h2-console`

Serves a fake H2 Database Console login form. Exposed H2 consoles allow arbitrary SQL execution and are a known initial access vector.

---

## Grafana

**Paths:** `/grafana/*`, `/api/snapshots`, `/api/ds/query`  
**Tag:** `grafana`

Returns 401 Unauthorized with a JSON body matching Grafana's format. Grafana has had critical vulnerabilities including **CVE-2021-43798** (path traversal to read arbitrary files) which was widely exploited.

---

## Confluence

**Paths:** `**/pages/createpage*`, `**/rest/tinymce/*`  
**Tag:** `confluence-rce`

Paths associated with **CVE-2023-22527** (OGNL injection, CVSS 10.0). Returns a fake success response.

---

## Liferay

**Path prefix:** `/api/jsonws*`  
**Tag:** `liferay-rce`

**CVE-2020-7961** — unauthenticated RCE via OGNL injection in the JSON Web Services API. Returns a fake `PrincipalException` response.

---

## phpunit RCE

**Path pattern:** `*phpunit*eval-stdin*`  
**Tag:** `phpunit-rce`

**CVE-2017-9841** — a phpunit development file accidentally deployed to production allows arbitrary PHP execution via `eval-stdin.php`. Returns a fake PHP fatal error.

---

## phpinfo

**Paths:** `**phpinfo.php`, `**info.php`  
**Tag:** `phpinfo`

Returns a stripped-down fake `phpinfo()` page with a PHP version and document root. A real one leaks the full server configuration.

---

## Apache server-status

**Path:** `/server-status`  
**Tag:** `apache-server-status`

Returns a fake Apache mod_status page. A real exposed server-status page reveals all active connections, request URIs, and server version.

---

## FritzBox

**Path:** `/login_sid.lua`  
**Tag:** `fritzbox`

The AVM FritzBox router login endpoint. Returns a fake `SessionInfo` XML response with a challenge token.

---

## Legacy admin paths

**Paths:** `/admin/config.php`, `/bag2`, `/config/getuser`  
**Tags:** `admin-config`, `bag2`, `config-getuser`

Long-tail paths that old scanner kits still probe. `/config/getuser` returns a fake shadow-style hash.

---

## CGI scanning

**Path prefix:** `/cgi-bin/`  
**Tag:** `cgi-scan`

Returns `CGI script not found`. Any probe under `/cgi-bin/` is logged — Shellshock (CVE-2014-6271) scanners still actively probe this path.

---

## Swagger / OpenAPI

**Paths:** `**swagger.json`, `**swagger.yaml`, `**openapi.json`  
**Tag:** `swagger`

Serves a fake Swagger/OpenAPI definition (`assets/swagger.json`). Exposed API specs reveal all endpoints and parameter names, providing a roadmap for further attacks.
