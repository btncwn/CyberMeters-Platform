# CyberMeters Scoring Methodology v1

**Sprint 8 — Trust & Methodology**
**Date:** June 2026
**Status:** Internal Reference — Not Customer-Facing

---

## Overview

This document provides a precise, auditable description of every arithmetic operation in the CyberMeters scoring engine. It is intended for internal engineering and product review, not customer distribution.

All values and formulas are sourced directly from `workers/scan-api/src/index.js`.

---

## 1. Security Score

### 1.1 Algorithm

```
score = 100

For each finding in computeScore():
    score += finding.score_impact   // score_impact is always 0 or negative

score = clamp(score, 0, 100)
```

`clamp(v, 0, 100)` = `Math.min(100, Math.max(0, v))`

### 1.2 Finding Deductions (ordered by module execution)

| Finding | Condition | Deduction |
|---|---|---|
| `dns_no_resolution` | DNS returns no A/AAAA records | −30 |
| `ssl_not_available` | HTTPS probe fails | −25 |
| `ssl_no_http_redirect` | HTTP→HTTPS redirect absent, chain validated, no CDN exception | −5 |
| `header_missing_strict_transport_security` | HSTS header absent | −5 |
| `header_missing_content_security_policy` | CSP header absent | −3 |
| `header_missing_x_frame_options` | XFO header absent | −2 |
| `header_missing_x_content_type_options` | XCTO header absent | −2 |
| `header_missing_referrer_policy` | RP header absent | −1 |
| `header_missing_permissions_policy` | PP header absent | −1 |
| `email_missing_dmarc` | No DMARC TXT record | −15 |
| `email_dmarc_policy_none` | DMARC present but `p=none` | −5 |
| `email_missing_spf` | No SPF TXT record | −10 |
| `subdomain_sensitive_{n}` | Sensitive-label subdomain discovered | −5 each, max 4 findings = −20 |
| `subdomains_large_attack_surface` | Subdomain count exceeds threshold | −3 |
| `subdomain_takeover` | Single confirmed takeover | −15 |
| `subdomain_takeover` | Multiple confirmed takeovers | −25 |
| `asset_exposure_sensitive_tool` | High-confidence critical/high-risk asset exposed | −10 |
| `asset_exposure_admin_interface` | High-confidence medium-risk admin panel exposed | −8 |
| `asset_exposure_dev_env` | Medium-confidence dev/staging environment exposed | −5 |

**Theoretical minimum:** All deductions applied simultaneously yields approximately −145 before clamping, resulting in a final score of 0.

**Note:** `email_dmarc_policy_none` (−5) and `email_missing_dmarc` (−15) are mutually exclusive — they cannot both fire for the same domain.

### 1.3 What Does Not Affect the Security Score

- DKIM not detected (info finding, score_impact: 0)
- All DNS resolver, DNSSEC, and canonical URL findings (score_impact: 0)
- Admin surface detection findings (score_impact: 0 — Phase 1)
- Brand monitoring / typosquat candidates
- Cloud storage discovery findings
- WHOIS intelligence findings
- Email intelligence findings (`email_intel_*`)
- Identity discovery findings
- Vendor risk / SaaS exposure findings

---

## 2. Business Risk Score

### 2.1 Algorithm

```
emailScore      = computeEmailTrustScore()      // returns 0–100
websiteScore    = computeWebsiteTrustScore()    // returns 0–100
opScore         = computeOpContinuityScore()    // returns 0–100
attackScore     = computeAttackSurfaceScore()   // returns 0–100
brandScore      = computeBrandReputationScore() // returns 0–100

businessRisk = (emailScore   * 0.25)
             + (websiteScore * 0.20)
             + (opScore      * 0.20)
             + (attackScore  * 0.20)
             + (brandScore   * 0.15)

businessRisk = clamp(businessRisk, 0, 100)
```

### 2.2 Email Trust Component

```
score = 100
if !spf.present:    score -= 30
if !dmarc.present:  score -= 30
elif dmarc.policy == 'none': score -= 15
if !dkim.present:   score -= 15
score = clamp(score, 0, 100)
```

Minimum: 25 (SPF absent, DMARC absent, DKIM absent)

### 2.3 Website Trust Component

```
score = 100
if !ssl.https_available:                      score -= 35
if hsts missing:                              score -= 20
elif hsts.max_age < 31536000 (weak):          score -= 8
if csp missing:                               score -= 15
elif csp has unsafe-inline/unsafe-eval/*:     score -= 5
if x_frame_options missing:                   score -= 8
if x_content_type_options missing:            score -= 8
score = clamp(score, 0, 100)
```

Minimum: 6 (no HTTPS, no HSTS, no CSP, no XFO, no XCTO)

### 2.4 Operational Continuity Component

```
score = 100
if !dns.resolves:                   score -= 50
if ssl.certificate_expired:         score -= 35
elif ssl.certificate_expires < 7d:  score -= 25
elif ssl.certificate_expires < 30d: score -= 15
if !ssl.https_available:            score -= 25
score = clamp(score, 0, 100)
```

Minimum: 0 (DNS down, certificate expired, no HTTPS)

### 2.5 Attack Surface Exposure Component

```
score = 100
score -= min(takeover_deduction, 30)
score -= min(asset_exposure_deduction, 15)
if vendor_risk.workspace_score > threshold:
    score -= vendor_scaled_deduction
score -= min(identityHighRiskCount * 7, 20)
score -= min(supplyChainSignalDeduction, 10)
score = clamp(score, 0, 100)
```

### 2.6 Brand / Reputation Component

```
score = 100
deduction = (brandHighRisk * 20) + (brandMedRisk * 10) + (brandLowRisk * 4)
deduction = min(deduction, 70)
score -= deduction
score = clamp(score, 0, 100)
```

Uses only DNS-confirmed brand risks (`status = 'active'` in `workspace_brand_assets`).

---

## 3. Security Posture Score

### 3.1 Algorithm

```
emailScore   = computePostureEmailScore()   // returns 0–100 or null
sslScore     = computePostureSslScore()     // returns 0–100 or null
attackScore  = computePostureAttackScore()  // returns 0–100
tpScore      = computePostureThirdParty()   // returns 0–100
admScore     = computePostureAdminScore()   // returns 0–100

// Null categories are excluded from weighting; remaining weights re-normalise
postureScore = weighted_average(
    [emailScore,  0.20],
    [sslScore,    0.20],
    [attackScore, 0.25],
    [tpScore,     0.15],
    [admScore,    0.20],
    exclude_nulls=true
)

postureScore = clamp(postureScore, 0, 100)
```

### 3.2 Email Security Component

```
score = 100
if !spf.present:         score -= 25
if !dmarc.present:       score -= 30
elif dmarc.policy='none': score -= 10
if !dkim.present:        score -= 10
score = clamp(score, 0, 100)
```

Returns `null` if no email security module data is available for the workspace.

### 3.3 SSL & Certificates Component

```
score = 100
if !ssl.https_available:              score -= 40
if !ssl.http_redirects_to_https
   AND redirect_validated
   AND !enterprise_contradiction:     score -= 15
if days_until_expiry < 0:            score -= 35
elif days_until_expiry < 7:          score -= 25
elif days_until_expiry < 30:         score -= 15
if cert_risk_level == 'critical':    score -= 20
elif cert_risk_level == 'high':      score -= 10
score = clamp(score, 0, 100)
```

Returns `null` if neither SSL module data nor certificate risk data is available.

### 3.4 Attack Surface Component

```
score = 100
score -= min(brandHigh * 12, 35)
score -= min(brandMed  *  5, 15)
score -= min(newAssets30d * 4, 20)
if cloudStorageAssets > 0: score -= 10
score = clamp(score, 0, 100)
```

### 3.5 Third-Party Risk Component

```
score = 100
score -= min(vendorHigh *  15, 40)
score -= min(vendorMed  *   5, 20)
score -= min(thirdPartyAssets * 3, 15)
score -= min(saasExposures    * 3, 15)
score = clamp(score, 0, 100)
```

### 3.6 Admin Exposure Component

```
score = 100
score -= min(admCritical * 20, 60)
score -= min(admHigh     * 12, 30)
score -= min(admOther    *  6, 20)
score = clamp(score, 0, 100)
```

`admOther` = `adm.total - admCritical - admHigh`

---

## 4. Score Aggregation at Portfolio Level

The portfolio score is computed by `computePortfolioScore()` using workspace Security Score aggregates. The calculation is:

```
portfolioScore = weighted_average of workspace scores,
                 where weight = domain_count per workspace (or 1 if 0 domains)

// Penalty for high-risk workspaces
portfolioScore -= highRiskWorkspaceCount * HIGH_RISK_PENALTY
portfolioScore = clamp(portfolioScore, 0, 100)
```

Portfolio score is stored in `portfolio_scores` table with `calculated_at` timestamp.

---

## 5. Score Persistence

| Score | Table | Frequency |
|---|---|---|
| Security Score | `scans.score` | Per scan |
| Business Risk Score | `scans.business_risk_score` | Per scan |
| Security Posture | Not directly stored in `scans`; computed from latest scan data per workspace on demand | On API request |
| Portfolio Score | `portfolio_scores` | On demand (recalculated when workspace scores change) |

Historical tracking: Security Score history is queryable via `/api/domains/:id/history` using `scans` table. Business Risk Score trend requires `scans.business_risk_score` column (present as of migration ~040+).

---

## 6. Precision Notes

All scores use JavaScript `number` (IEEE 754 double) arithmetic. Clamping is applied at every stage. No rounding is performed within sub-components — the final score is returned as a float and rounded at the API response layer (typically `Math.round()` before JSON serialisation).

Category null handling in Security Posture: if a category returns `null` (no data), its weight is excluded and the remaining weights are re-normalised to sum to 1.0. This means a workspace with no email scanning history can still receive a full Posture score from the other four categories.
