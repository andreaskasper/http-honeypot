---
title: Credential & File Leaks
parent: Attack Traps
nav_order: 7
---

# Credential & File Leak Traps
{: .no_toc }

Scanners routinely probe for accidentally exposed configuration and credential files. These traps return convincing fake data.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## .env files

**Path:** `**/.env` or `/.env`  
**Tag:** `env-file`

One of the most commonly misconfigured files. Returns a fake `.env` with realistic-looking secrets:

```
APP_ENV=production
DB_HOST=prod-db.internal
DB_PASSWORD=Sup3rS3cr3t!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_examplekey123456
```

---

## .env variants 🍯

**Paths:** `**/.env.local`, `**/.env.production`, `**/.env.old`, `**/.env.bak`, `**/.env.swp`, `**/.env~` — anything matching `**/.env.*`  
**Tag:** `env-file-variant`

Four of the ten most-requested paths in the GreyNoise credential-sweep report of 2026-08-28 were `.env` **variants** rather than the bare file, and until now they fell through to a plain 404. A leftover `.env.old` or an editor swap file is usually the same secrets as the live one, which is why scanners ask for all of them in a single pass.

Returns a fuller fake environment file with an **IP-specific honeytoken** as `STRIPE_SECRET_KEY`.

---

## .htpasswd

**Path:** `**/.htpasswd`  
**Tag:** `htpasswd`

Returns a fake Apache htpasswd entry with an MD5-hashed password.

---

## SSH private keys

**Paths:** `**/id_rsa`, `**/id_ecdsa`  
**Tag:** `ssh-key`

Serves a fake SSH private key file (from `assets/fake_id_rsa`). Automated credential harvesters will attempt to use the key and fail silently.

---

## Git repository leaks

**Paths:** `**/.git/config`, `**/.git/HEAD`  
**Tags:** `git-config`, `git-head`

Exposed `.git` directories are a critical misconfiguration. `.git/config` includes a fake remote URL pointing to a fake internal repository.

```ini
[remote "origin"]
    url = https://github.com/contoso/internal-api.git
```

Tools like [GitDumper](https://github.com/internetwache/GitTools) specifically probe `/.git/HEAD` first to confirm a dumping attack is viable.

---

## Git credential store 🍯

**Path:** `**/.git-credentials`  
**Tag:** `git-credentials`

Different file, different problem: `.git config` leaks *where* the repository lives, `.git-credentials` leaks the plaintext token that clones it. Returns a single line with an **IP-specific honeytoken** as the password:

```
https://svc-ci:hp_live_...@github.com
```

---

## Password stores 🍯

**Paths:** `**/.netrc`, `**/_netrc`, `**/.pgpass`  
**Tag:** `password-store-leak`

The plaintext credential files that `curl`, `git`, `ftp` and `psql` read without being asked. Returns a fake `.netrc` machine entry whose password is an **IP-specific honeytoken**.

---

## Registry & cloud tokens 🍯

**Paths:** `**/.npmrc`, `**/.pypirc`, `**/.s3cfg`, `**/.docker/config.json`  
**Tag:** `registry-token-leak`

Package-registry and container-registry credentials — the ones a build container leaves behind and an attacker uses to publish a poisoned package. `.docker/config.json` gets a JSON `auths` document with the honeytoken in `identitytoken`; the rest get an `.npmrc`-shaped `_authToken` line.

---

## AWS credentials

**Paths:** `**/.aws/credentials`, `**/.aws/config`  
**Tag:** `aws-credentials`

Fake AWS credentials file:
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = eu-west-1
```

---

## Vite arbitrary file read 🍯

**Path prefixes:** `/@fs/*`, `/@id/*`  
**Tag:** `vite-file-read`

**CVE-2025-30208** — a Vite dev server exposed to the network serves any file on disk through `/@fs/` when the request carries a crafted `?raw??` or `?import&raw??` suffix. GreyNoise saw probes for it on the same client fingerprint as the forged-crawler credential sweep, so it travels with that campaign rather than on its own.

Returns a fake Vite environment file with an **IP-specific honeytoken**.

{: .note }
> `/@fs/etc/passwd` and `/@fs/**/.env` are matched by the path-traversal and `.env` traps earlier in the chain and keep *their* tags. Both still answer with fake data, so nothing is lost — only the label differs.

---

## Database dumps & backups

**Paths:** `**.sql`, `**/backup.zip`, `**/backup.tar.gz`  
**Tag:** `backup-file`

Returns a minimal but valid fake MySQL dump header with a `users` table definition.

---

## Spring Boot config

**Paths:** `**/application.yml`, `**/application.yaml`, `**/application.properties`  
**Tag:** `spring-config-leak`

Returns a fake Spring datasource config with a password.

---

## Docker Compose files

**Paths:** `**/docker-compose.yml`, `**/docker-compose.yaml`  
**Tag:** `docker-compose-leak`

Fake compose file with a PostgreSQL password in plaintext — a common developer mistake.

---

## phpinfo

**Paths:** `**/phpinfo.php`, `**/info.php`  
**Tag:** `phpinfo`

Fake PHP version and configuration table. phpinfo files are left behind accidentally and reveal hosting environment details.

---

## Path traversal

**Patterns:** `**/etc/passwd`, `**/../etc/passwd`  
**Tag:** `path-traversal-passwd`

Returns a fake `/etc/passwd` with three entries including a `deploy` user. Automated LFI/path-traversal scanners confirm vulnerability by parsing the output — the fake data lets you see exactly what they're looking for.

---

## Web shells

**Paths:** `**shell.php`, `**cmd.php`, `**c99.php`, `**r57.php`, `**webshell.php`  
**Tag:** `webshell`

Serves a fake web shell form. Attackers who already think they've uploaded a shell will try to interact with it, generating additional log entries.

---

## A note on forged AI-crawler traffic

On 2026-08-28 GreyNoise reported scanners on **824 addresses across 795 separate /24 networks** forging the user-agent strings of 13 AI crawlers from eight companies — the impostor `ClaudeBot` string matched Anthropic's character for character — while requesting environment files, cloud keys, private keys and password stores in the millions of requests. Not one source address fell inside any vendor's published crawler range, and not one of them ever fetched `/robots.txt`.

The honeypot **does not** use the user agent as an attack signal. A genuine crawler sends the identical string, and mislabelling it would mean reporting it to AbuseIPDB. Identification stays on the requested path, which is the part an impostor cannot fake: real crawlers read pages, and these ask for `.env`.

If you want the crawler-name angle in your own analysis, the `user_agent` field is in every JSON log line and webhook payload — join it against the vendors' published IP range files rather than trusting it on its own.
