# CyberMeters — Finding-to-Academy Integration Audit v1

**Sprint 11A — Finding-to-Academy Integration**
**Date:** June 2026
**Status:** Audit complete — implementation follows

---

## Overview

This audit identifies every finding ID emitted by the Worker scanner, the field used to carry the finding identifier in `ScanDetail.jsx`, and the Academy article mapping coverage. It is the input for the `getAcademyArticleForFinding()` helper implementation.

---

## Finding ID Field in ScanDetail.jsx

Findings are consumed in `FindingRow({ f })` via the report JSON shape:

```js
f.id          — finding identifier string (primary lookup key)
f.module      — module name string (fallback lookup key)
f.severity    — 'critical' | 'high' | 'medium' | 'low' | 'info'
f.title       — display title
f.description — short description
f.confidence  — numeric 0–100
f.evidence    — array of evidence objects
```

The `f.id` field carries the finding type ID set by the Worker at scan time. This is the primary key for Academy article lookup.

---

## Complete Finding ID Inventory (Worker audit)

### Email Security (`module: "email_security"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `email_missing_spf` | high | No SPF record found |
| `email_missing_dmarc` | high | No DMARC record found |
| `email_dkim_not_detected` | medium | No DKIM record on standard selectors |
| `email_dmarc_policy_none` | medium | DMARC present but p=none (no enforcement) |
| `email_weak_dmarc` | medium | DMARC partially configured |
| `email_not_applicable` | info | Domain has no MX record |

### Email Security Intelligence (`module: "email_security_intelligence"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `email_intel_spf_missing` | high | SPF record absent |
| `email_intel_spf_permissive` | medium | SPF uses ~all or ?all |
| `email_intel_dmarc_missing` | high | DMARC record absent |
| `email_intel_dmarc_reporting_only` | medium | DMARC p=none |
| `email_intel_dkim_not_found` | medium | DKIM not detected |
| `email_intel_mta_sts_missing` | low | MTA-STS policy absent |
| `email_intel_tls_rpt_missing` | low | TLS-RPT reporting absent |

### Security Headers (`module: "headers"`)

Dynamic ID pattern: `header_missing_${header_name.replace(/-/g, "_")}`

| Finding ID | Severity | Header |
|-----------|---------|--------|
| `header_missing_strict_transport_security` | high | HSTS |
| `header_missing_content_security_policy` | medium | CSP |
| `header_missing_x_frame_options` | medium | X-Frame-Options |
| `header_missing_x_content_type_options` | low | X-Content-Type-Options |
| `header_missing_referrer_policy` | low | Referrer-Policy |
| `header_missing_permissions_policy` | low | Permissions-Policy |
| `header_weak_hsts` | medium | HSTS max-age too short |
| `csp_weak_policy` | medium | CSP uses unsafe-inline or wildcard |
| `header_malformed_*` | low | Header present but malformed |
| `canonical_url_uncertain` | info | Header validation inconclusive |

### DNS (`module: "dns"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `dns_no_resolution` | critical | Domain does not resolve |
| `dns_resolver_disagreement` | medium | Inconsistent resolver responses |
| `dnssec_not_enabled` | medium | DNSSEC not configured |
| `dnssec_misconfigured` | high | DNSSEC chain broken or expired |

### SSL/TLS (`module: "ssl"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `ssl_not_available` | critical | No HTTPS endpoint |
| `ssl_no_certificate` | critical | No valid certificate |
| `ssl_no_http_redirect` | medium | HTTP not redirecting to HTTPS |
| `ssl_no_redirect` | medium | Redirect misconfigured |
| `ssl_certificate_expired` | critical | Certificate expired |
| `ssl_certificate_expiring_soon` | high | Certificate expires within threshold |

### Subdomain Takeover (`module: "subdomain_takeover"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `subdomain_takeover` | critical | Active takeover vulnerability detected |
| `subdomain_takeover_risk` | high | Dangling DNS pointing to unclaimed resource |
| `subdomain_sensitive_*` | varies | Sensitive subdomain detected (dynamic prefix) |
| `subdomains_large_attack_surface` | medium | Excessive number of subdomains discovered |

### Cloud Storage (`module: "cloud_storage_discovery"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `cloud_storage_exposure_observed` | critical | Public bucket confirmed readable |
| `cloud_storage_public_listing` | critical | Bucket listing enabled |
| `cloud_storage_takeover_risk` | high | Unclaimed bucket URL in DNS |
| `cloud_storage_detected` | info | Cloud storage association identified |

### Asset Exposure / Admin Surfaces (`module: "admin_surface_detection"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `admin_surface_critical` | critical | Admin panel exposed to internet |
| `admin_surface_high` | high | High-risk management surface exposed |
| `admin_surface_medium` | medium | Management interface detected |
| `asset_exposure_admin_interface` | high | Admin interface exposed |
| `asset_exposure_dev_env` | high | Development environment exposed |
| `asset_exposure_sensitive_tool` | medium | Sensitive tool exposed |

### Domain Security Enrichment (`module: "domain_security_enrichment"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `dse_missing_caa` | low | No CAA record |
| `dse_caa_no_issuers` | medium | CAA record allows no CAs |
| `dse_hsts_short_maxage` | medium | HSTS max-age below 1 year |
| `dse_hsts_not_preload_eligible` | low | HSTS missing preload criteria |
| `dse_cookie_no_secure` | medium | Cookie missing Secure flag |
| `dse_cookie_no_httponly` | medium | Cookie missing HttpOnly flag |
| `dse_cookie_no_samesite` | low | Cookie missing SameSite attribute |

### WHOIS Intelligence (`module: "whois_intelligence"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `whois_domain_expired` | critical | Domain registration expired |
| `whois_expiry_critical` | critical | Domain expires within 30 days |
| `whois_expiry_warning` | high | Domain expires within 90 days |
| `whois_new_domain` | info | Recently registered domain |
| `whois_registrar_info` | info | Registrar details flagged |

### Technology Detection (`module: "technology_detection"`)

| Finding ID | Severity | Description |
|-----------|---------|-------------|
| `tech_server_version_disclosure` | low | Server version exposed in headers |
| `tech_xpoweredby_version_disclosure` | low | X-Powered-By version exposed |
| `cve_high_severity_detected` | critical | Technology matched to high-severity CVE |
| `kev_active_exploitation` | critical | Technology in CISA KEV list |

---

## Academy Coverage Analysis

### Mapped (finding ID → article slug)

| Finding ID | Mapped To | Coverage Method |
|------------|-----------|----------------|
| `email_missing_spf` | `spf-explained` | exact |
| `email_intel_spf_missing` | `spf-explained` | exact |
| `email_intel_spf_permissive` | `spf-explained` | prefix (`email_intel_spf`) |
| `email_missing_dmarc` | `dmarc-explained` | exact |
| `email_intel_dmarc_missing` | `dmarc-explained` | exact |
| `email_intel_dmarc_reporting_only` | `dmarc-explained` | prefix (`email_intel_dmarc`) |
| `email_dmarc_policy_none` | `dmarc-explained` | exact |
| `email_dkim_not_detected` | `dkim-explained` | exact |
| `email_intel_dkim_not_found` | `dkim-explained` | exact |
| `email_weak_dmarc` | `dmarc-explained` | prefix (`email_weak_dmarc` → DMARC) |
| `dnssec_not_enabled` | `dnssec-explained` | exact |
| `dnssec_misconfigured` | `dnssec-explained` | prefix (`dnssec`) |
| `header_missing_strict_transport_security` | `hsts-explained` | exact |
| `header_weak_hsts` | `hsts-explained` | exact |
| `dse_hsts_short_maxage` | `hsts-explained` | prefix (`dse_hsts`) |
| `dse_hsts_not_preload_eligible` | `hsts-explained` | prefix (`dse_hsts`) |
| `header_missing_content_security_policy` | `csp-explained` | exact |
| `csp_weak_policy` | `csp-explained` | exact |
| `subdomain_takeover` | `what-is-subdomain-takeover` | exact |
| `subdomain_takeover_risk` | `what-is-subdomain-takeover` | prefix (`subdomain_takeover`) |
| `cloud_storage_exposure_observed` | `public-cloud-storage-risks` | prefix (`cloud_storage`) |
| `cloud_storage_public_listing` | `public-cloud-storage-risks` | prefix (`cloud_storage`) |
| `cloud_storage_takeover_risk` | `public-cloud-storage-risks` | prefix (`cloud_storage`) |
| `admin_surface_critical` | `what-is-attack-surface-management` | module fallback (`admin_surface_detection`) |
| `admin_surface_high` | `what-is-attack-surface-management` | module fallback |
| `admin_surface_medium` | `what-is-attack-surface-management` | module fallback |

### Not Mapped (no Academy article yet — v1 gap)

| Finding ID | Category | Priority for v2 |
|------------|----------|----------------|
| `ssl_not_available` | SSL/TLS | High |
| `ssl_no_certificate` | SSL/TLS | High |
| `ssl_certificate_expired` | SSL/TLS | High |
| `ssl_certificate_expiring_soon` | SSL/TLS | High |
| `ssl_no_http_redirect` | SSL/TLS | Medium |
| `dns_no_resolution` | DNS | Medium |
| `dns_resolver_disagreement` | DNS | Low |
| `dse_missing_caa` | DNS | Low |
| `whois_domain_expired` | WHOIS | Medium |
| `whois_expiry_critical` | WHOIS | Medium |
| `cve_high_severity_detected` | CVE | High |
| `kev_active_exploitation` | CVE | High |
| `tech_server_version_disclosure` | Tech | Low |
| `email_intel_mta_sts_missing` | Email | Low |
| `email_intel_tls_rpt_missing` | Email | Low |
| `dse_cookie_no_secure` | Headers | Low |
| `dse_cookie_no_httponly` | Headers | Low |

---

## Lookup Strategy (for `getAcademyArticleForFinding`)

Three-tier lookup, first match wins:

**Tier 1 — Exact match:** `FINDING_TO_ACADEMY[finding.id]`

**Tier 2 — Prefix match:** Test prefixes from most-specific to least-specific:
- e.g., `email_intel_spf_permissive` → try `email_intel_spf`, `email_intel`, `email` → return first article found

**Tier 3 — Module fallback:** `MODULE_TO_ACADEMY[finding.module]`

**Tier 4 — No match:** Return `null`, render no link.

---

## Module Fallback Mapping

| Module | Fallback Article |
|--------|-----------------|
| `email_security` | `spf-explained` (most common email finding) |
| `email_security_intelligence` | `dmarc-explained` |
| `headers` | `hsts-explained` |
| `dns` | `dnssec-explained` |
| `subdomain_takeover` | `what-is-subdomain-takeover` |
| `cloud_storage_discovery` | `public-cloud-storage-risks` |
| `admin_surface_detection` | `what-is-attack-surface-management` |
| `technology_detection` | `what-is-attack-surface-management` |

SSL, WHOIS, and DSE modules have no module fallback in v1 — no article covers these categories yet.

---

## ScanDetail.jsx Integration Point

The `FindingRow` component in `ScanDetail.jsx` (line 222) renders each finding. The `Learn More` link will be placed inside the trust badges row (line 257) alongside the confidence badge, after score_impact but before the evidence toggle:

```jsx
{/* Academy Learn More link */}
{academySlug && (
  <Link
    to={`/academy/${academySlug}`}
    className="flex items-center gap-1 text-[10px] font-semibold text-brand-600 hover:text-brand-800 transition-colors"
  >
    <GraduationCap className="w-3 h-3" />
    Learn more
  </Link>
)}
```

No changes to: scanner modules, scoring, confidence calculation, evidence logic, PDF generation.

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Full finding ID inventory — 55 IDs across 10 modules, coverage analysis for 12 Academy articles |
