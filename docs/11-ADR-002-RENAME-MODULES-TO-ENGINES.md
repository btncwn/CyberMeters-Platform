# CyberMeters Architecture Decision Record

## ADR-002 — Rename Modules to Intelligence Engines

**Status:** Accepted
**Date:** 27 June 2026

---

# Decision

The official CyberMeters architecture replaces the concept of **Modules** with **Intelligence Engines**.

Technical checks such as DNS, SSL, DKIM, DMARC, headers, certificates and subdomain discovery are no longer considered standalone modules.

They are detectors inside Intelligence Engines.

---

# Official Architecture

```text
engines
├── attack-surface
│   ├── dns
│   ├── ssl
│   ├── headers
│   ├── certificates
│   ├── subdomains
│   ├── takeover
│   ├── assets
│   └── cloud
│
├── business-email
│   ├── spf
│   ├── dkim
│   ├── dmarc
│   ├── mta-sts
│   ├── tls-rpt
│   └── mx
│
├── identity
│   ├── microsoft-365
│   ├── google-workspace
│   ├── entra-id
│   └── oauth
│
├── brand
│   ├── typosquatting
│   ├── homoglyphs
│   ├── certificate-abuse
│   └── lookalike-domains
│
└── executive
    ├── scoring
    ├── trends
    ├── narratives
    └── recommendations
```

---

# Engine Responsibilities

## Attack Surface Intelligence

Owns:

- DNS
- SSL/TLS
- HTTPS
- HTTP Security Headers
- Certificates
- Subdomains
- Subdomain Takeover
- Asset Inventory
- Cloud Exposure
- Admin Interfaces
- SaaS Exposure
- Third-Party Assets

---

## Business Email Intelligence

Owns:

- SPF
- DKIM
- DMARC
- MTA-STS
- TLS-RPT
- MX Intelligence
- Email Provider Intelligence

---

## Identity Intelligence

Owns:

- Microsoft 365
- Google Workspace
- Entra ID
- OAuth
- MFA Posture
- SSO Exposure

---

## Brand Intelligence

Owns:

- Typosquatting
- Homoglyph Detection
- Lookalike Domains
- Certificate Abuse
- Brand Monitoring

---

## Executive Intelligence

Owns:

- Cyber Metrics Score
- Executive Summary
- Historical Trends
- Risk Narratives
- Prioritized Remediation
- Recommendations

---

# Naming Rules

Preferred terminology:

- Intelligence Engine
- Engine
- Detector
- Signal
- Evidence
- Finding
- Observation
- Recommendation

Avoid introducing:

- Module
- Scanner Module
- Plugin
- Tool

---

# Migration Strategy

## Phase 1

Immediately update:

- Documentation
- Product language
- Reports
- Dashboard labels
- Roadmaps
- AI prompts

No risky code changes.

---

## Phase 2

After Public Beta:

Gradually refactor internal folder names, namespaces and APIs to align with the Intelligence Engine architecture.

---

# Engineering Rule

Every new capability must answer:

1. Which Intelligence Engine owns it?
2. Is it a detector, signal, finding or recommendation?
3. Does it affect scoring?
4. Does it appear in Executive Intelligence?
5. Does it improve customer trust?

---

# Final Principle

A detector produces evidence.

An Intelligence Engine transforms evidence into intelligence.

Executive Intelligence transforms intelligence into business decisions.

This architecture will guide CyberMeters' evolution for future releases.
