---
title: Other Services
parent: Attack Traps
nav_order: 9
---

# Other Service Traps
{: .no_toc }

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

## CGI scanning

**Path prefix:** `/cgi-bin/`  
**Tag:** `cgi-scan`

Returns `CGI script not found`. Any probe under `/cgi-bin/` is logged — Shellshock (CVE-2014-6271) scanners still actively probe this path.

---

## Swagger / OpenAPI

**Paths:** `**swagger.json`, `**swagger.yaml`, `**openapi.json`  
**Tag:** `swagger`

Serves a fake Swagger/OpenAPI definition (`assets/swagger.json`). Exposed API specs reveal all endpoints and parameter names, providing a roadmap for further attacks.
