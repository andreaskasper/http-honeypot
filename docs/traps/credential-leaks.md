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
