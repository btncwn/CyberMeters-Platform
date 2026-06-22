# CyberMeters — Finding-to-Academy Mapping v1

**Sprint 11 — Academy Foundation**
**Date:** June 2026
**Status:** v1 — 12 cornerstone articles mapped

---

## Purpose

This document maps Worker finding type IDs to Academy article slugs. In Sprint 11A, the ScanDetail.jsx finding row will render a "Learn More →" link that navigates to `/academy/:slug` when a matching article exists.

The mapping is bidirectional:
- **findingIds** array on each article in `academy.js` — used to query from article to finding
- **This table** — used to query from finding ID to article slug at render time

---

## Mapping Table

| Finding ID | Academy Slug | Article Title |
|------------|--------------|---------------|
| `email_missing_spf` | `spf-explained` | SPF Explained |
| `email_spf_softfail` | `spf-explained` | SPF Explained |
| `email_spf_neutral` | `spf-explained` | SPF Explained |
| `email_spf_permerror` | `spf-explained` | SPF Explained |
| `email_missing_dmarc` | `dmarc-explained` | DMARC Explained |
| `email_dmarc_policy_none` | `dmarc-explained` | DMARC Explained |
| `email_dmarc_no_reporting` | `dmarc-explained` | DMARC Explained |
| `email_missing_dkim` | `dkim-explained` | DKIM Explained |
| `email_dkim_weak_key` | `dkim-explained` | DKIM Explained |
| `email_dkim_unknown_selector` | `dkim-explained` | DKIM Explained |
| `dns_dnssec_not_enabled` | `dnssec-explained` | DNSSEC Explained |
| `dns_dnssec_chain_broken` | `dnssec-explained` | DNSSEC Explained |
| `header_missing_hsts` | `hsts-explained` | HSTS Explained |
| `header_weak_hsts` | `hsts-explained` | HSTS Explained |
| `header_hsts_no_subdomains` | `hsts-explained` | HSTS Explained |
| `header_missing_csp` | `csp-explained` | Content Security Policy Explained |
| `header_csp_unsafe_inline` | `csp-explained` | Content Security Policy Explained |
| `header_csp_weak_policy` | `csp-explained` | Content Security Policy Explained |
| `subdomain_takeover_detected` | `what-is-subdomain-takeover` | What is Subdomain Takeover? |
| `dangling_cname_github` | `what-is-subdomain-takeover` | What is Subdomain Takeover? |
| `dangling_cname_azure` | `what-is-subdomain-takeover` | What is Subdomain Takeover? |
| `dangling_cname_heroku` | `what-is-subdomain-takeover` | What is Subdomain Takeover? |
| `subdomain_discovered` | `what-is-attack-surface-management` | What is Attack Surface Management? |
| `exposed_admin_panel` | `what-is-attack-surface-management` | What is Attack Surface Management? |
| `dangling_dns_record` | `what-is-attack-surface-management` | What is Attack Surface Management? |
| `cloud_storage_public_bucket` | `public-cloud-storage-risks` | Public Cloud Storage Risks |
| `cloud_storage_bucket_listing` | `public-cloud-storage-risks` | Public Cloud Storage Risks |
| `s3_public_read` | `public-cloud-storage-risks` | Public Cloud Storage Risks |
| `identity_microsoft_365_detected` | `microsoft-365-exposure-risks` | Microsoft 365 Exposure Risks |
| `identity_legacy_auth_exposed` | `microsoft-365-exposure-risks` | Microsoft 365 Exposure Risks |
| `identity_autodiscover_exposed` | `microsoft-365-exposure-risks` | Microsoft 365 Exposure Risks |
| `vendor_risk_detected` | `vendor-risk-explained` | Vendor Risk Explained |
| `third_party_service_detected` | `vendor-risk-explained` | Vendor Risk Explained |
| `saas_exposure_detected` | `vendor-risk-explained` | Vendor Risk Explained |
| `supply_chain_vendor_detected` | `supply-chain-attacks-explained` | Supply Chain Attacks Explained |
| `third_party_js_detected` | `supply-chain-attacks-explained` | Supply Chain Attacks Explained |
| `known_vulnerable_component` | `supply-chain-attacks-explained` | Supply Chain Attacks Explained |

---

## Sprint 11A Implementation Notes

### Frontend integration point

In `ScanDetail.jsx`, the finding row component currently renders:

```jsx
<div className="finding-row">
  <span>{finding.title}</span>
  <SeverityBadge severity={finding.severity} />
</div>
```

In Sprint 11A, add:

```jsx
import { FINDING_TO_ACADEMY } from '../data/academy'

// In the finding row:
const academySlug = FINDING_TO_ACADEMY[finding.finding_id]
{academySlug && (
  <Link to={`/academy/${academySlug}`} className="text-xs text-brand-600 hover:underline">
    Learn more →
  </Link>
)}
```

### academy.js export to add in Sprint 11A

```js
// Derived mapping: finding_id → article slug
export const FINDING_TO_ACADEMY = Object.fromEntries(
  ARTICLES.flatMap(a =>
    (a.findingIds || []).map(id => [id, a.slug])
  )
)
```

This is computed at module load time from the existing `findingIds` arrays on each article — no duplication required.

---

## Coverage Status

| Category | Finding IDs mapped | Articles covering |
|----------|--------------------|-------------------|
| Email Security | 10 | SPF, DMARC, DKIM |
| DNS Security | 2 | DNSSEC |
| Security Headers | 6 | HSTS, CSP |
| Subdomain Takeover | 4 | Subdomain Takeover |
| ASM | 3 | ASM overview |
| Cloud Storage | 3 | Cloud Storage Risks |
| Identity | 3 | M365 Exposure |
| Vendor / Supply Chain | 6 | Vendor Risk, Supply Chain |
| **Total** | **37** | **12 articles** |

---

## Gap Analysis — Finding IDs Without Academy Articles (v1)

The following finding types exist in the Worker but do not yet have Academy articles. These are candidates for Sprint 11A content additions:

- SSL/TLS findings: `ssl_expired`, `ssl_self_signed`, `ssl_weak_cipher`, `ssl_expiry_warning`
- Additional headers: `header_missing_x_frame_options`, `header_missing_referrer_policy`, `header_missing_permissions_policy`
- DNS hygiene: `dns_no_mx_record`, `dns_missing_caa_record`
- Brand monitoring: `brand_lookalike_domain`, `brand_typosquat_detected`
- Subdomain exposure: `subdomain_takeover_candidate`, `open_port_detected`, `sensitive_path_exposed`

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | 37 finding IDs mapped across 12 cornerstone articles |
