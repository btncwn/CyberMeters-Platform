# CyberMeters Confidence Scoring v1

**Sprint 8 — Trust & Methodology**
**Date:** June 2026
**Status:** Internal Reference — Not Customer-Facing

---

## Overview

This document describes how CyberMeters assigns confidence levels to findings and how evidence quality is validated. All behaviour documented here reflects actual code in `workers/scan-api/src/index.js`.

---

## 1. Confidence Levels

CyberMeters uses four confidence levels across findings:

| Level | Meaning |
|---|---|
| `confirmed` | Multiple independent signals corroborate the finding (e.g., page title + hostname pattern + server header all match) |
| `high` | Strong single signal or two corroborating signals |
| `medium` | One reliable signal; outcome is probable but not verified |
| `low` | Indirect inference; detection heuristic only |

These values are stored on each finding object and surfaced in the API response. The confidence level does not gate score deduction — score impact is fixed per finding type regardless of confidence.

---

## 2. Per-Module Confidence Assignment

### 2.1 DNS Module

All DNS findings use fixed confidence:

- `dns_no_resolution` → `high` (resolver returns NXDOMAIN or empty set)
- `dns_resolver_disagreement` → `medium` (two resolvers disagree; may be legitimate GeoDNS)
- `dnssec_not_enabled` → `high` (absence of DNSKEY is deterministic)
- `dnssec_misconfigured` → `medium` (validation failure may be transient)

### 2.2 SSL Module

- `ssl_not_available` → `high` (TLS handshake failed on both port 443 and 8443)
- `ssl_no_http_redirect` (score-impacting) → `high` (redirect chain validated, no enterprise CDN exception)
- `ssl_no_http_redirect` (zero-impact) → `low` (enterprise CDN contradiction detected; redirect may exist at edge layer)
- `canonical_url_uncertain` → `medium`

### 2.3 Security Headers

Headers are deterministic: the HTTP response either contains the header or it does not.

- Missing header findings → `high`
- `header_weak_hsts` → `high` (value parsed and compared against thresholds)
- `csp_weak_policy` → `high` (value parsed for `unsafe-inline`, `unsafe-eval`, `*`)
- `header_malformed_{name}` → `high` (value fails format regex)

### 2.4 Email Security

SPF, DMARC, and DKIM queries are direct DNS lookups:

- `email_missing_dmarc` → `high`
- `email_dmarc_policy_none` → `high`
- `email_missing_spf` → `high`
- `email_dkim_not_detected` → `low` (only common selectors probed: google, default, mail, k1, selector1, selector2; absence of these does not confirm DKIM is absent)

### 2.5 Subdomains

- `subdomain_sensitive_{sub}` → `medium` (subdomain was discovered via CT log or DNS brute-force; hostname matches a sensitive label, but reachability is not verified at finding time)
- `subdomains_large_attack_surface` → `medium`

### 2.6 Subdomain Takeover

- `subdomain_takeover` → `high` (CNAME confirmed to point to unclaimed service; body pattern fingerprint matched)

Body fingerprint match is required alongside CNAME suffix match. A CNAME suffix match alone does not produce a takeover finding.

### 2.7 Asset Exposure

Asset exposure confidence is assigned by `runExposureModule` based on how many signals match (title, hostname, server header):

| Signal Combination | Confidence |
|---|---|
| title + (hostname OR server) | `confirmed` |
| title only | `high` |
| hostname + server | `high` |
| hostname only | `medium` |

The `computeScore()` function maps these to finding severity:
- `confirmed` or `high` with critical/high risk_level → `asset_exposure_sensitive_tool` (score: −10)
- `confirmed` or `high` with medium risk_level → `asset_exposure_admin_interface` (score: −8)
- `medium` confidence assets → `asset_exposure_dev_env` (score: −5)

### 2.8 Admin Surface Detection

`runAdminSurfaceModule` uses the same three-signal system as asset exposure (title_re, host_re, server_re):

| Signal Match | Confidence |
|---|---|
| title + (host OR server) | `confirmed` |
| title only | `high` |
| host + server | `high` |
| host only | `medium` |

Admin surface findings have score_impact: 0. Confidence affects only the posture score (Admin Exposure category).

### 2.9 Cloud Storage Discovery

| Condition | Confidence |
|---|---|
| CNAME confirmed, bucket unclaimed | `high` |
| Bucket responds with listing | `high` |
| Bucket accessible, response score ≥ 80 | `medium` |
| Bucket accessible, response score < 80 | `low` (surfaced as `info` severity) |

### 2.10 Identity Discovery

Provider detection confidence:

| Matching Signals | Confidence |
|---|---|
| 2 or more signal sources match | `high` |
| 1 signal source matches | `medium` |

Portal detection (hostname patterns): always `medium` — hostname prefix is observed but reachability and service identity are unverified.

### 2.11 Brand Monitoring (Typosquat)

Brand monitoring candidates are generated algorithmically at scan time. DNS confirmation is deferred to the `/brand-monitoring/refresh` endpoint. Therefore:

- At scan time: no confidence is assigned; candidates are unvalidated
- After DNS refresh: `dns_resolved = true/false` is stored in `workspace_brand_assets`

The Business Risk Score and Security Posture use only DNS-confirmed brand risks (`status = 'active'` in `workspace_brand_assets`).

---

## 3. Evidence Quality Validation

Every finding passes through `validateFindingEvidence()`. This is a mandatory quality gate that checks the `evidence` object on each finding.

### 3.1 Required Fields

| Field | Required When | Description |
|---|---|---|
| `evidence.source` | Always | Module or probe that produced the observation |
| `evidence.probe_target` or `.target` or `.queried_hostname` or `.requested_url` | Always | The asset that was probed |
| `evidence.observed_value` or `.headers_observed` or `.returned_records` | Always | What was actually observed |
| `evidence.expected_value` | `score_impact != 0` | The expected secure state |
| `evidence.manual_verification_command` | Always | curl/dig/nmap command to reproduce |
| `evidence.checked_at` | Always | ISO timestamp of the probe |

### 3.2 Quality Levels

| Level | Warning Count | Meaning |
|---|---|---|
| `excellent` | 0 | All required fields present; finding is fully auditable |
| `good` | 1–2 | Minor gaps; finding is usable |
| `partial` | 3+ | Significant gaps; finding should not be customer-reported without remediation |
| `missing` | n/a | No `evidence` object at all; finding must not be scored |

### 3.3 Current Coverage

Score-impacting findings in `computeScore()` are constructed with evidence objects. Intelligence findings from `buildEmailIntelFindings()` also carry evidence. However, not all modules produce full evidence objects meeting the `excellent` standard. The false-positive audit (`false-positive-audit-v1.md`) identifies specific gaps.

---

## 4. Known Confidence Weaknesses

### 4.1 DKIM Low Confidence

`email_dkim_not_detected` is always assigned `low` confidence because only 6 common selectors are probed. An organization using a non-standard selector (e.g., `dkim2024`, `proofpoint`) will receive this finding despite having DKIM configured. This is the highest-volume false positive in the email module.

### 4.2 Sensitive Subdomain Medium Confidence

`subdomain_sensitive_*` findings fire on hostname pattern alone. A subdomain named `staging.example.com` that actually serves a public marketing page will receive the same finding as a genuine staging environment. Reachability is not confirmed at finding time.

### 4.3 HTTP Redirect Low Confidence Cases

When the enterprise CDN exception fires (`ssl_no_http_redirect` at `low` confidence, score_impact: 0), the system correctly suppresses the score deduction but still surfaces the finding. This creates an information-only finding that may confuse customers who verify and observe a redirect at the browser layer.

### 4.4 Brand Monitoring Unvalidated Candidates

At scan time, all typosquat candidates are unvalidated. Risk_level is assigned algorithmically (keyword scoring + variant type scoring) with no DNS confirmation. A `high` risk-level candidate may not resolve at all. Customers must trigger `/brand-monitoring/refresh` to obtain confirmed results.
