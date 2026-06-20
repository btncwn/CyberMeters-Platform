# Cyber Essentials Readiness

CyberMeters provides Cyber Essentials readiness guidance for UK SMB customers.
It does not certify Cyber Essentials, replace an assessor, or prove compliance.

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
| Boundary Protection | 20% | HTTPS availability, browser security headers, critical findings, exposed admin surfaces, subdomain takeover risks |
| Secure Configuration | 20% | HSTS, Content Security Policy, HTTP to HTTPS redirect, TLS availability, certificate intelligence |
| Access Control | 20% | SPF, DMARC, DKIM, exposed admin surfaces, externally reachable SaaS portals |
| Phishing & Malware Exposure | 20% | Email authentication strength and high-impact external findings as proxy indicators only |
| Patch Management Readiness | 20% | Certificate expiry health, certificate risk, critical/high finding backlog, recent asset change visibility |

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

The Phishing & Malware Exposure category is explicitly a proxy estimate based on
email authentication, domain security posture, and external findings. It must
not be presented as proof that endpoint malware protection is installed or
correctly configured.

## Product Boundary

Cyber Essentials Readiness is a focused CyberMeters feature, not a generic GRC
engine. Do not expand this implementation into ISO 27001, SOC 2, audit evidence
collection, policy generation, or certification workflows without a separate
approved product sprint.
