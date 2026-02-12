---
title: Spring Boot Actuator
parent: Attack Traps
nav_order: 1
---

# Spring Boot Actuator Traps
{: .no_toc }

Spring Boot's Actuator endpoints are a favourite target for attackers. When exposed publicly, they leak environment variables (including AWS keys and database passwords), allow heap dumps containing secrets, and can even shut down the application.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## /actuator/env

**Tag:** `spring-actuator-env`  
**Risk:** Critical — leaks all environment variables including secrets

The honeypot returns a convincing JSON response containing fake but realistic-looking secrets:

```json
{
  "activeProfiles": ["prod"],
  "propertySources": [{
    "name": "systemEnvironment",
    "properties": {
      "DB_PASSWORD": { "value": "prod_db_pass_2024!" },
      "AWS_SECRET_ACCESS_KEY": { "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
      "SPRING_DATASOURCE_URL": { "value": "jdbc:postgresql://prod-db.internal:5432/appdb" }
    }
  }]
}
```

Scanners that automate credential harvesting will record these fake keys — useful for tracking attacker tooling.

---

## /actuator/heapdump

**Tag:** `spring-actuator-heapdump`  
**Risk:** Critical — a real heapdump contains all in-memory secrets

Returns a fake Java heap dump file header (`JAVA PROFILE 1.0.2`). Automated tools that download and parse heapdumps looking for secrets will waste time on this fake file.

---

## /actuator/shutdown

**Tag:** `spring-actuator-shutdown`  
**Risk:** High — allows graceful application shutdown

Returns:
```json
{"message": "Shutting down, bye..."}
```

---

## /actuator/health

**Tag:** `spring-actuator-health`  
**Risk:** Low (but signals Spring Boot presence)

```json
{"status": "UP", "groups": ["liveness", "readiness"]}
```

---

## Other actuator endpoints

`/actuator/beans`, `/actuator/mappings`, `/actuator/trace`, `/actuator/httptrace` all return minimal valid JSON and are tagged `spring-actuator`.

---

## Real-world context

The Shadowserver Foundation regularly reports thousands of internet-exposed Spring Boot Actuator endpoints. The `/actuator/env` endpoint in particular is automated by tools like [SpringBootExploit](https://github.com/SummerSec/SpringBootExploit) and is included in bulk scanning payloads from Shodan-based attack frameworks.
