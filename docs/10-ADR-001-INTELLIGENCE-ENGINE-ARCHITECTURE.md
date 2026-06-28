# CyberMeters Architecture Decision Record

## ADR-001 — Intelligence Engine Architecture

**Status:** Accepted
**Date:** 27 June 2026

---

# Decision

CyberMeters will no longer be architected or presented as a collection of independent scanning modules.

Instead, every capability belongs to an **Intelligence Engine**.

The Intelligence Engine becomes the primary architectural boundary across:

- Product
- Backend
- Frontend
- Reporting
- Documentation
- API
- Marketing
- Future roadmap

Individual detectors are implementation details.

Customers purchase intelligence—not scanners.

---

# Why

Traditional security scanners expose dozens of disconnected features.

Examples:

- DNS Scanner
- SSL Scanner
- SPF Checker
- DMARC Checker
- Certificate Scanner
- Header Scanner
- Subdomain Scanner

While technically accurate, this creates several problems:

- Difficult for customers to understand
- Inconsistent product messaging
- Feature-centric instead of outcome-centric
- Harder to extend without redesigning the product

CyberMeters instead delivers intelligence.

Every scan contributes evidence.

Evidence becomes intelligence.

Intelligence becomes executive insight.

---

# Intelligence Model

Evidence

↓

Detection

↓

Correlation

↓

Intelligence

↓

Executive Insight

↓

Recommended Action

---

# Intelligence Engines

## Attack Surface Intelligence

Purpose:

Discover and explain an organization's externally exposed assets and services.

Current capabilities:

- DNS Intelligence
- SSL/TLS Intelligence
- Certificate Intelligence
- Security Header Intelligence
- HTTP Exposure
- HTTPS Validation
- Redirect Analysis
- Asset Discovery
- Asset Inventory
- Subdomain Discovery
- Wildcard Detection
- Subdomain Takeover Detection
- Cloud Asset Discovery
- Admin Surface Discovery
- SaaS Exposure Discovery
- Third-Party Asset Discovery

Future capabilities:

- Internet-wide asset correlation
- IPv6 exposure analysis
- Network fingerprinting
- CDN intelligence
- External technology fingerprinting

Outputs:

- Attack Surface Score
- Findings
- Timeline

---

## Business Email Intelligence

Purpose:

Assess an organization's email security posture and business email exposure.

Current capabilities:

- SPF
- DKIM
- DMARC
- MTA-STS
- TLS-RPT
- MX Intelligence
- Email Provider Identification
- Email Security Recommendations

Future capabilities:

- Business Email Exposure Score
- Mail infrastructure health
- Executive impersonation indicators
- Mail reputation signals

Outputs:

- Business Email Score
- Findings
- Recommendations

---

## Identity Intelligence (Future)

Purpose:

Assess externally observable identity-related risks.

Capabilities:

- Microsoft 365
- Google Workspace
- Entra ID
- OAuth Applications
- MFA posture
- SSO exposure

Outputs:

- Identity Exposure Score
- Findings
- Recommendations

---

## Brand Intelligence

Purpose:

Identify abuse or misuse of an organization's public brand.

Capabilities:

- Typosquatting
- Homoglyph Detection
- Lookalike Domains
- Certificate Abuse
- Brand Monitoring

Outputs:

- Brand Exposure Score
- Findings
- Timeline

---

## Executive Intelligence

Purpose:

Translate technical evidence into business decisions.

Capabilities:

- Cyber Metrics Score
- Historical Trends
- Risk Narratives
- Verified Findings
- Observations
- Prioritized Remediation
- Executive Summary

Outputs:

- Executive Report
- Risk Summary
- Business Recommendations

---

# Design Principles

Every detector belongs to exactly one Intelligence Engine.

Each Intelligence Engine owns:

- Evidence
- Findings
- Observations
- Scoring
- Recommendations
- Historical trends

No feature should exist independently.

---

# Engineering Rule

Every new capability must answer:

1. Which Intelligence Engine owns it?
2. What intelligence does it produce?
3. How does it affect scoring?
4. What recommendations does it generate?
5. How will it appear in the Executive Report?

If these questions cannot be answered, the feature should not be implemented.

---

# Product Philosophy

CyberMeters is not a collection of security scanners.

CyberMeters is an **External Exposure Intelligence Platform**.

Customers buy intelligence that helps them understand, prioritize and reduce external cyber risk.
