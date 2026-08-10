# Cyber Essentials Readiness

CyberMeters provides Cyber Essentials readiness guidance for UK SMB customers.
It does not certify Cyber Essentials, replace an assessor, or prove compliance.

## Evidence boundary (canonical)

Two rules govern every customer-facing statement about Cyber Essentials. Both are
enforced in code and in CI (`scripts/validate-ce-lifecycle.js`,
`scripts/validate-ce-data-integrity.js`).

**1. Readiness is computed from externally observable evidence only.** The
questionnaire is *not* an input. `buildCyberEssentialsReadiness()` never reads
`cyber_essentials_answers` — a customer's self-attestation cannot move the
readiness score, and no answer is treated as security truth. The questionnaire is
a separate surface with its own completeness status; the two must not be conflated.

**2. Three of the five controls cannot be observed externally at all.** `access_control`
(User Access Control), `malware_protection` (Malware Protection) and
`patch_management_readiness` (Security Update Management) carry `external_coverage: none`
in `shared/cyber-essentials-questions.js`, the authoritative source for this metadata
(it is re-exported through `workers/scan-api/src/lib/cyber-essentials.js`). Their readiness
categories publish no external number, are labelled not externally assessable, and never
alert; no withdrawn proxy signal is used in their place. The remaining two
(`boundary_protection`, `secure_configuration`) are `external_coverage: partial` — partial,
not complete.

It follows that CyberMeters **cannot** predict a certification outcome. Never claim,
in product or in marketing, that a customer "would pass" or "would fail" Cyber
Essentials, that a report is one an auditor can rely on, that the platform replaces a
consultant's gap assessment, that all five controls are continuously checked, or that
a customer is "compliant". Readiness is guidance for preparing for certification —
nothing more. See `docs/alerts-eight-domain-coverage.md` for the alerting boundary.

The v1 assessment is intentionally lightweight. It uses only data CyberMeters
already collects through external attack surface monitoring and workspace
intelligence. It does not introduce new probes, evidence uploads, policy
generation, audit packs, or a generic compliance framework.

## Scoring Model

The readiness score is calculated dynamically from five equally weighted
categories. Each category starts at 100 and receives deductions for observable
gaps. The final score is the weighted average.

| Category | Weight | Signals Used |
| --- | ---: | --- |
| Firewalls & Boundary Protection | split evenly across the assessable areas | HTTPS availability, browser security headers, critical findings, exposed admin surfaces, subdomain takeover risks |
| Secure Configuration | split evenly across the assessable areas | HSTS, Content Security Policy, HTTP to HTTPS redirect, TLS availability, certificate intelligence |
| User Access Control | 0% | None — not externally assessable, self-attestation only |
| Malware Protection | 0% | None — not externally assessable, self-attestation only |
| Security Update Management | 0% | None — not externally assessable, self-attestation only |

The three `external_coverage: none` areas carry weight 0 and cannot move the external
readiness indicator. The indicator is the mean of the externally assessable areas only, and
it states its own denominator (currently 2 of 5). An earlier revision gave all five a fixed
weight of 20%, which let control areas the product cannot observe carry 40% of the number;
that arithmetic was withdrawn.

## Grades

| Grade | Score Range | Meaning |
| --- | ---: | --- |
| A | 90-100 | Likely ready from available external signals |
| B | 75-89 | Likely ready with minor gaps |
| C | 55-74 | Partially ready |
| D | 35-54 | Not ready |
| F | 0-34 | Not ready, major gaps detected |

API status values:

- `likely_ready`
- `partially_ready`
- `not_ready`

## Data Sources

Cyber Essentials Readiness v1 reuses:

- Latest completed scan metadata
- R2 scan report modules
- DNS and SSL/TLS scan results
- Security header observations
- SPF, DMARC, and DKIM findings
- Workspace asset inventory
- Admin surface detection
- SaaS exposure detection
- Subdomain takeover detection
- Certificate intelligence
- Latest scan findings and remediation backlog

No historical readiness table is created in v1. Scores are calculated at request
time so the feature can be validated commercially before adding stored snapshots.

## Relationship to Business Risk Score

Business Risk Score (BRS) measures business impact and executive risk.

Cyber Essentials Readiness measures estimated preparedness for Cyber Essentials
controls.

The scores serve different purposes and should not be compared directly.

## Future Historical Tracking

Cyber Essentials Readiness v1 is calculated dynamically.

Future versions may store readiness snapshots alongside existing
`historical_scores` records.

If implemented, readiness scores should be added as an additive column to
`historical_scores` rather than creating a dedicated readiness table.

## Limitations

CyberMeters does not certify Cyber Essentials.

CyberMeters provides readiness guidance only. It can estimate likely readiness
from externally observable technical signals, but it cannot fully assess:

- Endpoint malware protection configuration
- Internal device build standards
- Internal patch management tooling
- User account lifecycle controls
- MFA coverage across every internal system
- Firewall rules that are not externally observable
- Policies, procedures, or staff attestations

Malware Protection was once estimated from email authentication, domain security posture
and external findings. Those proxies were withdrawn and no replacement was introduced: the
category is now labelled not externally assessable and publishes no external number. It must
never be presented as proof that endpoint malware protection is installed or correctly
configured.

## Product Boundary

Cyber Essentials Readiness is a focused CyberMeters feature, not a generic GRC
engine. Do not expand this implementation into ISO 27001, SOC 2, audit evidence
collection, policy generation, or certification workflows without a separate
approved product sprint.
