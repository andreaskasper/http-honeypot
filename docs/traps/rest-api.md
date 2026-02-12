---
title: REST API IDOR
parent: Attack Traps
nav_order: 8
---

# REST API IDOR Trap
{: .no_toc }

**Insecure Direct Object Reference (IDOR)** is one of the OWASP Top 10. Automated scanners probe common REST API patterns looking for unauthenticated access to user records.

---

## How it works

The honeypot matches any path of the form:

```
/api/v{n}/{resource}/{id}
```

where `resource` is one of: `users`, `accounts`, `admin`, `customers`, `employees`.

**Examples:**
- `GET /api/v1/users/1`
- `GET /api/v2/accounts/42`
- `GET /api/v3/admin/1`

**Tag:** `rest-api-idor-{resource}` (e.g. `rest-api-idor-users`)

---

## Response

The honeypot returns a convincing fake user object:

```json
{
  "id": 1,
  "email": "user1@contoso.internal",
  "role": "user",
  "password_hash": "$2b$12$FakeHashForHoneypotXXXXXXXXXXXXXXX",
  "api_key": "sk_live_honeypot1",
  "created_at": "2024-01-15T10:30:00Z"
}
```

The fake response includes a `password_hash` and an `api_key`, which automated scrapers will record. Since the key follows the pattern `sk_live_honeypot{id}`, you can instantly identify any downstream attempt to use the leaked key.

---

## What this catches

- API fuzzing tools that enumerate `/api/v1/users/1` through `/api/v1/users/1000`
- OWASP ZAP and Burp Suite automated scans
- Custom scrapers looking for unauthenticated API access
- Bug bounty automation that probes common REST patterns
