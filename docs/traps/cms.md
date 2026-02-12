---
title: CMS (WordPress, Joomla)
parent: Attack Traps
nav_order: 2
---

# CMS Traps
{: .no_toc }

WordPress powers roughly 40% of the web, making it the single most targeted CMS. Cloudflare's Q4 2024 DDoS report found `/wp-admin/` targeted in **98% of HTTP DDoS attacks**.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## WordPress

### /wp-login.php
**Tag:** `wp-login`

Serves a pixel-perfect fake WordPress login form — same HTML structure, same field names (`log`, `pwd`, `redirect_to`, `testcookie`). Credential-stuffing bots will submit username/password pairs which are captured in the JSON log and POST body.

### /wp-admin/
**Tag:** `wp-admin`

302 redirect to `/wp-login.php?redirect_to=%2Fwp-admin%2F` — identical to WordPress behaviour.

### /xmlrpc.php
**Tag:** `xmlrpc`

Returns a valid XML-RPC fault response. Brute-force tools that use `system.multicall` to test thousands of passwords in a single request will find this endpoint.

### /wp-includes/wlwmanifest.xml
**Tag:** `wp-wlwmanifest`

The Windows Live Writer manifest — a classic passive fingerprinting path.

### /wp-content/*, /wp-json/*
**Tag:** `wordpress-scan`

Returns 404 — still logged and tagged so you can see which plugins attackers probe.

---

## Joomla

### /administrator/
**Tag:** `joomla-admin`

Serves a minimal fake Joomla administration login form.

---

## phpMyAdmin

### /(pma|phpmyadmin|myadmin)/index.php
**Tag:** `phpmyadmin-index`

Serves the fake phpMyAdmin login page (from `assets/phpmyadmin_index.html`).

### /(pma|phpmyadmin|myadmin)/scripts/setup.php
**Tag:** `phpmyadmin-setup`

Serves the fake phpMyAdmin setup page. The setup script has historically had multiple critical vulnerabilities and is aggressively scanned.
