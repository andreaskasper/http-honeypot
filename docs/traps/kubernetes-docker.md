---
title: Kubernetes & Docker
parent: Attack Traps
nav_order: 5
---

# Kubernetes & Docker API Traps
{: .no_toc }

Exposed Kubernetes API servers and Docker daemons are extremely high-value targets — they provide direct code execution on cluster infrastructure.

---

## Kubernetes API

### /api/v1/pods

**Tag:** `k8s-pods`

Returns a fake `PodList` response. A real unauthenticated Kubernetes API server at this path leaks all running workloads.

```json
{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"12345"},"items":[{"metadata":{"name":"app-deployment-abc12","namespace":"default"}}]}
```

### /api/v1/secrets

**Tag:** `k8s-secrets`

Returns a fake `SecretList` including a base64-encoded fake database password. This is a critical misconfiguration in real clusters — Kubernetes Secrets are base64-encoded, **not encrypted**, by default.

```json
{"kind":"SecretList","apiVersion":"v1","items":[{"metadata":{"name":"db-credentials"},"data":{"password":"cHJvZF9wYXNzd29yZDEyMw=="}}]}
```

Hits here almost certainly indicate automated Kubernetes attack tooling.

---

## Docker API

**Path pattern:** `/v1.*/containers/*`  
**Tag:** `docker-api`

The Docker remote API (port 2375/2376 on Docker daemons, sometimes exposed on 80 via a proxy). Returns a fake container listing:

```json
[{"Id":"abc123","Names":["/webapp"],"Image":"nginx:latest","Status":"running","Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]
```

An exposed Docker API gives complete host access. Tools like [Doki](https://www.intezer.com/blog/cloud-security/doki-infecting-docker-servers-in-the-cloud/) specifically target this.
