# CyberMeters Risk Methodology v1

**Sprint 8 — Trust & Methodology**
**Date:** June 2026
**Status:** Internal Reference — Not Customer-Facing

---

## Overview

CyberMeters produces three distinct risk scores. Each serves a different audience and uses a different calculation model:

1. **Security Score** — technical scan outcome, single domain, 0–100
2. **Business Risk Score** — executive-facing, five weighted categories, 0–100
3. **Security Posture Score** — workspace-level, five weighted categories, 0–100

All three are calculated from the same scan module outputs. This document describes the risk model for each.

---

## 1. Security Score

### 1.1 Model

Start at 100. Apply deductions from `computeScore()` based on findings detected during the scan. Clamp result to [0, 100].

The score is domain-scoped and scan-scoped. It reflects the current technical state of a single domain at the time of the last scan.

### 1.2 Maximum Deductions by Module

| Module | Maximum Deduction | Notes |
|---|---|---|
| DNS | −30 | `dns_no_resolution` alone |
| SSL | −30 | `ssl_not_available` (−25) + `ssl_no_http_redirect` (−5) |
| Security Headers | −14 | All 6 headers missing (HSTS −5, CSP −3, XFO −2, XCTO −2, RP −1, PP −1) |
| Email Security | −30 | `email_missing_dmarc` (−15) + `email_missing_spf` (−10) + `email_dmarc_policy_none` (−5) |
| Subdomains | −23 | `subdomain_sensitive_*` capped at 4 × −5 = −20, plus `subdomains_large_attack_surface` (−3) |
| Subdomain Takeover | −25 | Multiple takeovers (−25); single (−15) |
| Asset Exposure | −23 | `asset_exposure_sensitive_tool` (−10) + `asset_exposure_admin_interface` (−8) + `asset_exposure_dev_env` (−5) |

A domain with all categories failing would reach approximately 0 before clamping.

### 1.3 Score Bands

| Score | Interpretation |
|---|---|
| 90–100 | Good — minor issues only |
| 75–89 | Fair — addressable gaps |
| 50–74 | Poor — significant exposure |
| < 50 | Critical — urgent remediation required |

### 1.4 What the Score Does Not Cover

The Security Score does not reflect:

- Brand monitoring risk (typosquat domains are fed to Business Risk and Posture, not the Security Score)
- Third-party/vendor risk
- Identity provider exposure
- Admin surface exposure (score_impact: 0 in Phase 1)
- Historical trend (score is point-in-time)

---

## 2. Business Risk Score

### 2.1 Model

Computed by `computeBusinessRiskScore()`. Five weighted categories, each scored 0–100, then combined using fixed percentage weights. The output is a single 0–100 Business Risk Score (inverse: 100 = lowest risk).

### 2.2 Categories and Weights

| Category | Weight | Data Sources |
|---|---|---|
| Email Trust | 25% | SPF, DMARC (policy + presence), DKIM |
| Website Trust | 20% | HTTPS availability, HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| Operational Continuity | 20% | DNS resolution, SSL certificate expiry, HTTPS availability |
| Attack Surface Exposure | 20% | Subdomain takeovers, asset exposures, vendor risk score, identity exposure, supply chain signal |
| Brand / Reputation | 15% | DNS-confirmed typosquat domains by risk level |

### 2.3 Deduction Tables

**Email Trust (base: 100)**

| Condition | Deduction |
|---|---|
| SPF missing | −30 |
| DMARC missing | −30 |
| DMARC p=none | −15 |
| DKIM not detected | −15 |

**Website Trust (base: 100)**

| Condition | Deduction |
|---|---|
| No HTTPS / SSL | −35 |
| HSTS missing | −20 |
| HSTS present but weak | −8 |
| CSP missing | −15 |
| CSP present but weak | −5 |
| X-Frame-Options missing | −8 |
| X-Content-Type-Options missing | −8 |

**Operational Continuity (base: 100)**

| Condition | Deduction |
|---|---|
| DNS no resolution | −50 |
| SSL certificate expired | −35 |
| SSL certificate expiring within 7 days | −25 |
| SSL certificate expiring within 30 days | −15 |
| No SSL / HTTPS at all | −25 |

**Attack Surface Exposure (base: 100)**

| Condition | Deduction |
|---|---|
| Subdomain takeover risks | Up to −30 |
| Asset exposures (sensitive tools, admin interfaces) | Up to −15 |
| High-risk vendor score | Scaled deduction |
| Identity exposure (high_risk_count × 7, capped at −20) | Up to −20 |
| Supply chain signal (payment/identity vendors in CSP, capped at −10) | Up to −10 |

**Brand / Reputation (base: 100)**

| Condition | Deduction |
|---|---|
| Per high-risk brand domain (DNS-confirmed) | −20 each |
| Per medium-risk brand domain (DNS-confirmed) | −10 each |
| Per low-risk brand domain (DNS-confirmed) | −4 each |
| Maximum total deduction | −70 |

### 2.4 Composition

Final Business Risk Score = (EmailTrust × 0.25) + (WebsiteTrust × 0.20) + (OpContinuity × 0.20) + (AttackSurface × 0.20) + (Brand × 0.15)

All inputs are clamped to [0, 100] before weighting. The combined score is also clamped.

---

## 3. Security Posture Score

### 3.1 Model

Computed by `computeSecurityPosture()`. Five weighted categories defined in `POSTURE_WEIGHTS`. Operates at the workspace level using the most recent scan data per domain.

### 3.2 Categories and Weights

| Category Key | Label | Weight |
|---|---|---|
| `email_security` | Email Security | 20% |
| `ssl_certificates` | SSL & Certificates | 20% |
| `attack_surface` | Attack Surface | 25% |
| `third_party_risk` | Third-Party Risk | 15% |
| `admin_exposure` | Admin Exposure | 20% |

### 3.3 Per-Category Deductions

**Email Security (base: 100)**

| Condition | Deduction |
|---|---|
| SPF missing | −25 |
| DMARC missing | −30 |
| DMARC p=none | −10 |
| DKIM not detected | −10 |

**SSL & Certificates (base: 100)**

| Condition | Deduction |
|---|---|
| HTTPS not available | −40 |
| HTTP does not redirect to HTTPS | −15 |
| Certificate expired | −35 |
| Certificate expires < 7 days | −25 |
| Certificate expires < 30 days | −15 |
| Certificate risk level: critical | −20 |
| Certificate risk level: high | −10 |

**Attack Surface (base: 100)**

| Condition | Deduction |
|---|---|
| Per high-risk confirmed brand domain | −12 each, capped at −35 |
| Per medium-risk brand domain | −5 each, capped at −15 |
| Per new asset in last 30 days | −4 each, capped at −20 |
| Cloud storage assets exposed | −10 |

**Third-Party Risk (base: 100)**

| Condition | Deduction |
|---|---|
| Per high-risk vendor | −15 each, capped at −40 |
| Per medium-risk vendor | −5 each, capped at −20 |
| Per third-party asset | −3 each, capped at −15 |
| Per SaaS exposure | −3 each, capped at −15 |

**Admin Exposure (base: 100)**

| Condition | Deduction |
|---|---|
| Per critical admin surface | −20 each, capped at −60 |
| Per high-risk admin surface | −12 each, capped at −30 |
| Per other (medium) admin surface | −6 each, capped at −20 |

### 3.4 Composition

Final Security Posture = (EmailSecurity × 0.20) + (SSL × 0.20) + (AttackSurface × 0.25) + (ThirdPartyRisk × 0.15) + (AdminExposure × 0.20)

Each category score and the final score are clamped to [0, 100].

---

## 4. Workspace Supply Chain Score

Computed by `computeWorkspaceSupplyChainRisk()` for workspace-level supply chain view. Five sub-drivers:

| Driver | Weight | Source |
|---|---|---|
| Vendor Risk | derived | `vendor_risk.workspace_vendor_risk_score` + concentration deduction |
| Security Findings | derived | Aggregated from scan findings |
| Asset Exposure | derived | Admin surface + sensitive asset counts |
| Brand Exposure | derived | Active brand risks |
| Supply Chain Concentration | up to −10 | Dominant vendor category concentration |

This feeds the `/ws/supply-chain` page and is not exposed in the main Security Score.

---

## 5. Score Relationships

```
Scan Output (modules)
        │
        ├─► computeScore()              → Security Score (domain, 0–100)
        │
        ├─► computeBusinessRiskScore()  → Business Risk Score (domain, 0–100)
        │
        └─► computeSecurityPosture()    → Security Posture Score (workspace, 0–100)
                │
                └─► computeWorkspaceSupplyChainRisk() → Supply Chain Score (workspace)
```

All four scores are derived from the same scan module data. The Security Score is the most granular (finding-level deductions). The Business Risk and Posture scores aggregate across categories and add workspace-level intelligence not captured in the Security Score (vendor risk, brand intelligence, admin surfaces).

---

## 6. Risk Model Gaps

### 6.1 No Exploit Likelihood Weighting

Severity is fixed per finding type. The model does not adjust for exploitability (e.g., a `subdomain_takeover` for a low-traffic staging subdomain scores identically to one on a primary production subdomain).

### 6.2 Brand Monitoring Requires Manual Refresh

Brand risk inputs to Business Risk and Posture Scores rely on DNS-confirmed candidates in `workspace_brand_assets`. These are only populated after a manual `/brand-monitoring/refresh` API call. A workspace that has never refreshed will have `brand_risks = { high: 0, medium: 0, low: 0 }` regardless of actual exposure.

### 6.3 Admin Surface Score Impact Is Zero

Admin surface detection (`runAdminSurfaceModule`) is operational but currently has `score_impact: 0` in `computeScore()`. Critical admin surfaces (Jenkins, Kibana, VMware vCenter) do not reduce the Security Score. They only affect the Security Posture Admin Exposure category. This is documented as "Phase 1" in the code comments.

### 6.4 Vendor Risk Requires Workspace Context

Vendor risk (third-party and supply chain) is computed at the workspace level from accumulated scan data. A single domain scan does not produce vendor risk scores — the workspace must have processed at least one scan and populated `workspace_vendors`.
