---
title: Cloud Metadata
parent: Attack Traps
nav_order: 6
---

# Cloud Metadata Service Traps
{: .no_toc }

Server-Side Request Forgery (SSRF) vulnerabilities are commonly exploited to reach cloud metadata endpoints from within a compromised application. These traps catch scanners that probe for SSRF or for direct metadata service exposure.

---

## AWS EC2 Instance Metadata Service

**Path prefix:** `/latest/meta-data/`  
**Tag:** `aws-metadata`

Mimics the AWS IMDSv1 endpoint (`http://169.254.169.254/latest/meta-data/`). Returns a list of available metadata keys:

```
ami-id
ami-launch-index
hostname
instance-id
instance-type
local-ipv4
public-ipv4
```

AWS has deprecated IMDSv1 in favour of IMDSv2 (which requires a token), but many older EC2 instances still have it enabled. A successful SSRF to this endpoint leaks the instance's IAM role credentials via `/latest/meta-data/iam/security-credentials/`.

---

## Google Cloud Platform Metadata

**Path prefix:** `/computeMetadata/v1/`  
**Tag:** `gcp-metadata`

Mimics the GCP metadata server (`http://metadata.google.internal/computeMetadata/v1/`). Returns fake instance data including the service account email.

---

## DigitalOcean Metadata

**Path prefix:** `/metadata/v1/`  
**Tag:** `do-metadata`

Mimics the DigitalOcean droplet metadata endpoint. Returns fake droplet ID, hostname, and region.
