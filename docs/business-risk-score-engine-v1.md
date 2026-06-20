# Business Risk Score Engine v1

Version: June 2026
Sprint: BRS v2 upgrade (tasks 244–248)

---

## Overview

The Business Risk Score (BRS) is a composite executive-facing metric that translates technical scan findings into a single business-readable score (0–100) with a risk band label. It is designed for non-technical stakeholders: boards, CISOs, and procurement teams.

BRS is computed at two levels:

- **Scan-level** — per individual scan, using only findings and module signals from that scan's R2 report.
- **Workspace-level** — per workspace, using the latest scan findings plus workspace-wide signals (brand monitoring, vendor risk, subdomain takeover count, exposed asset count).

---

## Score Model

### Formula

```
BRS = sum of weighted category scores
```

| Category | Weight |
|---|---|
| Email Trust | 25% |
| Website Trust | 20% |
| Operational Continuity | 20% |
| Attack Surface Exposure | 20% |
| Brand / Reputation Risk | 15% |

Each category starts at 100 and has deductions applied for detected findings. A category score cannot go below 0.

### Risk Bands

| Score Range | Band |
|---|---|
| 90–100 | Low Business Risk |
| 70–89 | Moderate Business Risk |
| 40–69 | High Business Risk |
| 0–39 | Critical Business Risk |

---

## Category Model

### Email Trust (25%)

Measures whether the organisation's email infrastructure protects against phishing and spoofing.

| Finding | Deduction |
|---|---|
| No SPF record | −30 |
| No DMARC record | −30 |
| DMARC policy = none | −15 |
| DKIM not detected | −15 |

### Website Trust (20%)

Measures whether the website is secure and trustworthy for visitors and customers.

| Finding | Deduction |
|---|---|
| No HTTPS redirect OR no SSL certificate | −35 |
| Missing HSTS | −20 |
| Weak HSTS configuration | −8 |
| Missing CSP | −15 |
| Weak CSP policy | −5 |
| Missing both X-Frame-Options and X-Content-Type-Options | −8 |

### Operational Continuity (20%)

Measures whether the organisation's internet-facing infrastructure is reliably reachable and maintained.

| Finding | Deduction |
|---|---|
| Domain DNS not resolving | −50 |
| SSL certificate expired | −35 |
| SSL certificate expiring within 30 days | −15 |
| No SSL certificate | −25 |

### Attack Surface Exposure (20%)

Measures the breadth and risk of the organisation's exposed digital attack surface.

| Signal | Deduction |
|---|---|
| Each subdomain takeover risk | −15 (max −30) |
| Each reachable exposed asset | −5 (max −15) |
| High-risk vendor per vendor | −12 (max −30 combined with medium) |
| Medium-risk vendor per vendor | −5 (max −30 combined with high) |
| No vendors detected (clean) | +10 bonus |

### Brand / Reputation Risk (15%)

Measures brand exposure via lookalike domains, typosquatting, and third-party brand monitoring signals.

| Signal | Deduction |
|---|---|
| High-risk brand finding | −20 per finding (max −70 total) |
| Medium-risk brand finding | −10 per finding (max −70 total) |
| Low-risk brand finding | −4 per finding (max −70 total) |

At scan-level, brand signals default to 0 (not available per-scan). Full brand scoring is only available at the workspace level.

---

## Finding-to-Business-Impact Mapping

The BRS engine maps 13 canonical finding IDs to business impact language. Each entry includes a human-readable title, business impact description, and recommended action.

| Finding ID | Business Title |
|---|---|
| `email_missing_spf` | No email sender protection (SPF) |
| `email_missing_dmarc` | No email anti-fraud policy (DMARC) |
| `email_dmarc_policy_none` | Email fraud protection is not enforced |
| `email_dkim_not_detected` | Email signatures not configured (DKIM) |
| `ssl_certificate_expired` | SSL certificate has expired |
| `ssl_certificate_expiring_soon` | SSL certificate expiring soon |
| `ssl_no_certificate` | No SSL/TLS certificate |
| `no_https_redirect` | Website does not enforce HTTPS |
| `header_missing_strict_transport_security` | HSTS not configured |
| `header_weak_hsts` | HSTS configuration is weak |
| `header_missing_content_security_policy` | No Content Security Policy (CSP) |
| `csp_weak_policy` | Content Security Policy is too permissive |
| `dns_no_resolution` | Domain is unreachable |

---

## API Response

### Scan Report (`GET /api/scans/:id/report`)

The `business_risk` block is added to the standard scan report response:

```json
{
  "business_risk": {
    "score": 72,
    "band": "Moderate Business Risk",
    "summary": "Your organisation has moderate business risk exposure...",
    "categories": {
      "email_trust":             { "score": 40, "label": "Email Trust",            "issues": [...] },
      "website_trust":           { "score": 85, "label": "Website Trust",          "issues": [] },
      "operational_continuity":  { "score": 100,"label": "Operational Continuity", "issues": [] },
      "attack_surface_exposure": { "score": 70, "label": "Attack Surface Exposure","issues": [...] },
      "brand_reputation_risk":   { "score": 100,"label": "Brand / Reputation Risk","issues": [] }
    },
    "top_business_risks": [
      {
        "id": "email_missing_dmarc",
        "title": "No email anti-fraud policy (DMARC)",
        "impact": "Attackers may impersonate your organisation by sending emails from your domain...",
        "recommendation": "Publish a DMARC record at p=reject...",
        "severity": "high"
      }
    ],
    "generated_at": "2026-06-20T09:00:00.000Z"
  }
}
```

### Workspace BRS (`GET /api/workspaces/:id/business-risk`)

Returns the same structure with additional workspace context and trend data. Also includes backward-compat aliases: `brs`, `grade`, `grade_label`, `narrative`, `top_concerns`.

---

## Backward Compatibility

The `computeBusinessRiskScore` function returns both the v2 format and backward-compat aliases:

| Alias | Maps to |
|---|---|
| `brs` | `score` |
| `grade` | Letter grade (A/B/C/D/F) derived from score |
| `grade_label` | `band` |
| `narrative` | `summary` |
| `top_concerns` | `top_business_risks` (remapped to legacy shape) |

The alias `brs.brs` is consumed by `historical_scores.brs_score` persistence at scan completion — this must not be removed.

---

## Limitations

- At scan level, brand and vendor signals are not available (they are workspace-aggregate signals). Brand/vendor deductions default to 0 for scan-level BRS.
- The attack surface category at scan level uses subdomain takeover and reachable asset counts from that scan's R2 report only, not workspace history.
- BRS does not account for asset age, remediation velocity, or SLA compliance. These are planned for v2.
- Category issues arrays contain human-readable strings derived from matched IMPACT_MAP entries; they do not include finding IDs (to avoid leaking internal codes to the UI layer).

---

## Future Improvements

- **Asset age weighting** — penalise findings that have been open for more than 30/60/90 days.
- **Remediation velocity bonus** — reward workspaces that consistently fix high-severity findings quickly.
- **Peer benchmarking** — compare BRS to industry vertical average.
- **Trend-aware summary** — detect improving vs declining trajectories and reflect in narrative.
- **Portfolio-level BRS** — aggregate BRS across all workspaces for an MSP-level composite.
- **Supply chain expansion** — include more vendor risk signals (CVEs, breach history, SLA tier).
- **Scan-level brand signals** — when brand monitoring is per-domain rather than per-workspace, surface these in the scan-level BRS.
