# CyberMeters Confidence Engine Audit v1

**Sprint 9B — Confidence Engine**
**Date:** June 2026
**Status:** Pre-implementation audit — required before code changes

---

## Overview

This document audits all 47 active scan finding IDs, their evidence source, current confidence state, and assigned numeric confidence score for Sprint 9B.

Confidence scale:

| Score | Label | Meaning |
|---|---|---|
| 95 | Verified observation | Direct probe, deterministic result |
| 90 | Multiple confirmations | Strong single source or corroborating signals |
| 80 | Strong evidence | Single validated probe, no ambiguity |
| 70 | Probable | Heuristic with reasonable signal quality |
| 60 | Weak signal | Indirect inference or common-pattern heuristic |
| 40 | Unvalidated candidate | Generated algorithmically, no probe validation |

---

## Current State of Confidence Values

`computeScore()` findings already carry string confidence values (`"high"`, `"medium"`, `"low"`). Sprint 9B normalizes all values to numeric per this conversion table:

| String | Numeric |
|---|---|
| `"confirmed"` | 95 |
| `"high"` | 90 |
| `"medium"` | 70 |
| `"low"` | 60 |

Findings that currently have `confidence: null` are assigned numeric values from the `FINDING_CONFIDENCE_SCORES` map below.

---

## Finding Confidence Assignments

### DNS Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `dns_no_resolution` | Direct DNS query via Cloudflare/Google/Quad9 DOH resolvers | `"high"` string | **90** (converted) | Three resolver cross-check. String "high" converts to 90. |
| `dns_resolver_disagreement` | Two independent DNS resolvers return different A records | `"medium"` string | **70** (converted) | Real signal but legitimate GeoDNS can cause this. String "medium" converts to 70. |
| `dnssec_not_enabled` | DNS lookup for DS, DNSKEY, RRSIG all absent | `"high"` string | **90** (converted) | Deterministic absence check with three record types. |
| `dnssec_misconfigured` | Partial DS/DNSKEY presence detected | `"medium"` string | **70** (converted) | Partial evidence; DNS propagation delay possible. |

### SSL Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `ssl_not_available` | HTTPS probe (Workers fetch on port 443) | `"high"` string | **90** (converted) | TLS handshake confirmed failed. |
| `ssl_no_http_redirect` (medium/confirmed) | HTTP probe completed, no 3xx to HTTPS observed | `"high"` string | **90** (converted) | Redirect chain validated. |
| `ssl_no_http_redirect` (info/uncertain) | HTTP probe blocked or CDN contradiction | `"low"` string | **60** (converted) | Enterprise CDN interference; cannot confirm. |
| `canonical_url_uncertain` | HTTP/HTTPS redirect chain analysis | `"medium"` string | **70** (converted) | Inferred from redirect chain; no direct validation. |

### Security Headers Module

Dynamic finding IDs: `header_missing_{name}` and `header_malformed_{name}` for 6 headers.

| Finding ID Pattern | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `header_missing_*` (score-impacting) | HTTP response header observation | `"high"` string | **90** (converted) | Header directly observed in HTTP response. |
| `header_missing_*` (info/uncertain) | Response uncertain (bot protection) | `"medium"` or `"low"` string | **70** or **60** (converted) | Probe may have been answered by edge layer. |
| `header_weak_hsts` | HSTS header parsed, max-age evaluated | `"high"` string | **90** (converted) | Value present and parsed deterministically. |
| `csp_weak_policy` | CSP header parsed, directives evaluated | `"high"` string | **90** (converted) | Value present and parsed deterministically. |
| `header_malformed_*` | Response header parsed, format validation failed | `"high"` string | **90** (converted) | Malformed value is directly observed. |

Specific header IDs (all follow same confidence as pattern above):
- `header_missing_strict_transport_security`
- `header_missing_content_security_policy`
- `header_missing_x_frame_options`
- `header_missing_x_content_type_options`
- `header_missing_referrer_policy`
- `header_missing_permissions_policy`

### Email Security Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `email_not_applicable` | MX record DNS lookup — no records found | `"high"` string | **90** (converted) | DNS lookup is deterministic. |
| `email_missing_dmarc` | DNS TXT lookup at `_dmarc.{domain}` | `"high"` string | **90** (converted) | Direct DNS query. |
| `email_dmarc_policy_none` | DMARC TXT record parsed, `p=none` detected | `"high"` string | **90** (converted) | Value directly parsed from DNS record. |
| `email_missing_spf` | DNS TXT lookup at `{domain}` for `v=spf1` | `"high"` string | **90** (converted) | Direct DNS query. |
| `email_dkim_not_detected` | DNS TXT lookup at 6 common selectors only | `"low"` string | **60** (converted) | Selector heuristic; non-standard selectors not probed. |

### Subdomains Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `subdomain_sensitive_{sub}` | Subdomain discovered via CT log; hostname matches keyword list | `null` | **70** | Keyword pattern match. Subdomain exists in CT log but reachability unverified. |
| `subdomains_large_attack_surface` | Subdomain count from CT discovery | `null` | **80** | Count directly measured from CT log results. |

### Subdomain Takeover Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `subdomain_takeover` | CNAME target suffix matched + HTTP body fingerprint matched | `"high"` string | **90** (converted) | Dual-signal match (CNAME + body). High confidence but body patterns can false-positive. |

### Asset Exposure Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `asset_exposure_sensitive_tool` | HTTP probe: title or tech stack matches management tool pattern | `"high"` string | **90** (converted) | Title/tech match confirmed from HTTP response. |
| `asset_exposure_admin_interface` | HTTP probe: hostname or title matches admin interface pattern | `"medium"` string | **70** (converted) | Pattern match on hostname or title; not fingerprint-verified. |
| `asset_exposure_dev_env` | HTTP probe: hostname matches dev/staging keyword | `"medium"` string | **70** (converted) | Hostname keyword match only; service type not verified. |

### WHOIS Intelligence Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `whois_domain_expired` | RDAP expiry date in the past | `null` | **95** | Expiry date from RDAP is deterministic. |
| `whois_expiry_critical` | RDAP expiry date within 30 days | `null` | **95** | Expiry date from RDAP is deterministic. |
| `whois_expiry_warning` | RDAP expiry date within 90 days | `null` | **90** | Expiry date deterministic; 90-day threshold is a policy choice. |
| `whois_new_domain` | RDAP registration date < 180 days ago | `null` | **90** | Registration date is deterministic; 180-day threshold is heuristic. |
| `whois_registrar_info` | RDAP entity data present | `null` | **95** | Directly reported by RDAP registry. |

### Email Security Intelligence Module

These findings live in `modules.email_security_intelligence.findings`, not the top-level `findings[]`. Included here for completeness and future sprint compatibility.

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `email_intel_dmarc_missing` | DNS TXT at `_dmarc.{domain}` — absent | `null` | **95** | Same DNS probe as `email_missing_dmarc`. |
| `email_intel_dmarc_reporting_only` | DMARC record parsed, `p=none` | `null` | **95** | Deterministic parse of DNS record value. |
| `email_intel_spf_missing` | DNS TXT at `{domain}` — `v=spf1` absent | `null` | **95** | Deterministic DNS lookup. |
| `email_intel_spf_permissive` | SPF record parsed, `+all` detected | `null` | **95** | Value directly parsed from DNS record. |
| `email_intel_dkim_not_found` | Common DKIM selectors probed — absent | `null` | **60** | Same limitation as `email_dkim_not_detected`. |
| `email_intel_mta_sts_missing` | HTTP probe to `https://mta-sts.{domain}/.well-known/mta-sts.txt` | `null` | **90** | Direct HTTP probe; resource either present or absent. |
| `email_intel_tls_rpt_missing` | DNS TXT at `_smtp._tls.{domain}` — absent | `null` | **90** | Direct DNS lookup. |

### Cloud Storage Discovery Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `cloud_storage_takeover_risk` | CNAME to unclaimed provider + provider validation response | `"high"` or `"medium"` string | **90** or **70** (converted) | String converted. Provider existence check confirms non-existence. |
| `cloud_storage_public_listing` | HTTP probe: bucket returns directory listing body | `"high"` string | **90** (converted) | Listing confirmed from HTTP response body. |
| `cloud_storage_exposure_observed` | HTTP probe: provider headers present on accessible endpoint | `"high"` or `"medium"` string | **90** or **70** (converted) | String converted. Reachability confirmed but content not verified. |

### Admin Surface Detection Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `admin_surface_critical` | Hostname/title/server header fingerprint match for critical-risk services | `null` | **70** | Multi-signal fingerprint match; authentication status not verified. One of the signals may be title text matching a CDN error page. |
| `admin_surface_high` | Hostname/title/server fingerprint match for high-risk services | `null` | **70** | Same as above. |
| `admin_surface_medium` | Hostname fingerprint only for medium-risk services (GitLab, Jira, Confluence) | `null` | **60** | Hostname pattern alone; often legitimate public instances with auth enforced. |

### Domain Security Enrichment Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `dse_missing_caa` | DNS CAA lookup at `{domain}` — absent | `null` | **95** | Direct DNS query; absence is deterministic. |
| `dse_caa_no_issuers` | CAA record present but no `issue` tags | `null` | **95** | Record parsed and evaluated deterministically. |
| `dse_hsts_short_maxage` | HSTS header present, `max-age` parsed and below threshold | `null` | **95** | Value directly observed and parsed. |
| `dse_hsts_not_preload_eligible` | HSTS header parsed, preload eligibility criteria evaluated | `null` | **90** | Directly observed but preload eligibility involves multiple criteria. |
| `dse_cookie_no_secure` | Set-Cookie response headers observed, `Secure` flag absent | `null` | **90** | Header directly observed; cookies from one response may not represent all cookies. |
| `dse_cookie_no_httponly` | Set-Cookie response headers observed, `HttpOnly` flag absent | `null` | **90** | Same limitation as above. |
| `dse_cookie_no_samesite` | Set-Cookie response headers observed, `SameSite` attribute absent | `null` | **90** | Same limitation as above. |

### Technology Detection Module

| Finding ID | Evidence Source | Current State | Assigned Score | Rationale |
|---|---|---|---|---|
| `tech_xpoweredby_version_disclosure` | `X-Powered-By` response header contains version string | `null` | **90** | Header directly observed with version pattern. |
| `tech_server_version_disclosure` | `Server` response header contains version string | `null` | **90** | Header directly observed with version pattern. |

---

## Implementation Plan

**Approach:** Two-step normalization inside `normalizeFindingSchema()`:

1. **String → Numeric conversion** (handles all `computeScore()` findings which already carry string values):
   ```
   "confirmed" → 95
   "high"      → 90
   "medium"    → 70
   "low"       → 60
   ```

2. **Null → Numeric assignment** (handles WHOIS, admin surface, DSE, tech detection, email intel):
   - Direct ID lookup in `FINDING_CONFIDENCE_SCORES` map
   - Pattern-based fallback for dynamic IDs (`subdomain_sensitive_*`, `header_missing_*`, etc.)
   - Default: 70

**No changes to:** finding counts, severity, score_impact, any module logic, any API response shape (except `confidence` changes from string/null to integer).

---

## Full Confidence Reference Table

| Finding ID | Confidence Score |
|---|---|
| `dns_no_resolution` | 90 (was "high") |
| `dns_resolver_disagreement` | 70 (was "medium") |
| `dnssec_not_enabled` | 90 (was "high") |
| `dnssec_misconfigured` | 70 (was "medium") |
| `ssl_not_available` | 90 (was "high") |
| `ssl_no_http_redirect` (confirmed) | 90 (was "high") |
| `ssl_no_http_redirect` (uncertain) | 60 (was "low") |
| `canonical_url_uncertain` | 70 (was "medium") |
| `header_missing_*` (confirmed) | 90 (was "high") |
| `header_missing_*` (uncertain) | 70 or 60 (was "medium"/"low") |
| `header_weak_hsts` | 90 (was "high") |
| `csp_weak_policy` | 90 (was "high") |
| `header_malformed_*` | 90 (was "high") |
| `email_not_applicable` | 90 (was "high") |
| `email_missing_dmarc` | 90 (was "high") |
| `email_dmarc_policy_none` | 90 (was "high") |
| `email_missing_spf` | 90 (was "high") |
| `email_dkim_not_detected` | 60 (was "low") |
| `subdomain_sensitive_{sub}` | 70 (was null) |
| `subdomains_large_attack_surface` | 80 (was null) |
| `subdomain_takeover` | 90 (was "high") |
| `asset_exposure_sensitive_tool` | 90 (was "high") |
| `asset_exposure_admin_interface` | 70 (was "medium") |
| `asset_exposure_dev_env` | 70 (was "medium") |
| `whois_domain_expired` | 95 (was null) |
| `whois_expiry_critical` | 95 (was null) |
| `whois_expiry_warning` | 90 (was null) |
| `whois_new_domain` | 90 (was null) |
| `whois_registrar_info` | 95 (was null) |
| `email_intel_dmarc_missing` | 95 (was null) |
| `email_intel_dmarc_reporting_only` | 95 (was null) |
| `email_intel_spf_missing` | 95 (was null) |
| `email_intel_spf_permissive` | 95 (was null) |
| `email_intel_dkim_not_found` | 60 (was null) |
| `email_intel_mta_sts_missing` | 90 (was null) |
| `email_intel_tls_rpt_missing` | 90 (was null) |
| `cloud_storage_takeover_risk` | 90 or 70 (converted from "high"/"medium") |
| `cloud_storage_public_listing` | 90 (was "high") |
| `cloud_storage_exposure_observed` | 90 or 70 (converted from "high"/"medium") |
| `admin_surface_critical` | 70 (was null) |
| `admin_surface_high` | 70 (was null) |
| `admin_surface_medium` | 60 (was null) |
| `dse_missing_caa` | 95 (was null) |
| `dse_caa_no_issuers` | 95 (was null) |
| `dse_hsts_short_maxage` | 95 (was null) |
| `dse_hsts_not_preload_eligible` | 90 (was null) |
| `dse_cookie_no_secure` | 90 (was null) |
| `dse_cookie_no_httponly` | 90 (was null) |
| `dse_cookie_no_samesite` | 90 (was null) |
| `tech_xpoweredby_version_disclosure` | 90 (was null) |
| `tech_server_version_disclosure` | 90 (was null) |
