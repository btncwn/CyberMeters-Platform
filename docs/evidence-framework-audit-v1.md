# CyberMeters Evidence Framework Audit v1

**Sprint 9C — Evidence Framework**
**Date:** June 2026
**Status:** Pre-implementation audit — required before code changes

---

## Overview

This document audits the `evidence` field state for every active finding across all 7 creation sites. It determines what raw data is available per finding and proposes the structured evidence array for Sprint 9C.

Target evidence format:

```json
[{ "type": "...", "label": "...", "value": "...", "source": "..." }]
```

Sprint 9C constraint: Do not invent evidence. Every evidence entry must reference data already present in the scan result or the finding object itself.

---

## Implementation Strategy

Sprint 9A adopted a single `normalizeFindingSchema()` normalizer applied at the report boundary. Sprint 9C extends this normalizer with a `buildEvidenceArray()` function.

Three cases handled:

| Case | Condition | Action |
|---|---|---|
| A | `evidence` is already a non-empty array | Return as-is — no modification |
| B | `evidence` is a non-null, non-array object (rich evidence) | Normalize to array format, preserving all fields |
| C | `evidence` is `null`, `undefined`, or `[]` | Generate from finding fields (`id`, `module`, `description`) |

Case B applies to all `computeScore()` findings and cloud storage findings, which already carry rich `evidence: {...}` objects. These are wrapped into arrays without data loss.

Case C applies to all inline site findings (admin surface, DSE), WHOIS, and tech detection findings, where no evidence was set at creation time. Evidence is derived from finding fields — primarily `description`, which was written to contain the observed values.

---

## Evidence State by Module

### DNS Module — computeScore() Site 1

All DNS findings carry rich evidence objects set at creation time.

| Finding ID | Evidence State | Evidence Type | Proposed Action |
|---|---|---|---|
| `dns_no_resolution` | Rich object ✅ | `dns_lookup` | Case B — wrap in array |
| `dns_resolver_disagreement` | Rich object ✅ | `dns_cross_check` | Case B — wrap in array |
| `dnssec_not_enabled` | Rich object ✅ | `dnssec_lookup` | Case B — wrap in array |
| `dnssec_misconfigured` | Rich object ✅ | `dnssec_lookup` | Case B — wrap in array |

Available fields in existing objects: `evidence_type`, `probe_target`, `observed_value`, `expected_value`, `source`, `checked_at`, `manual_verification_command`, `resolver_agreement_score`, `cross_checked_at`, `per_type_scores`, `resolver_results`, `ds`, `dnskey`, `rrsig`.

---

### SSL Module — computeScore() Site 1

All SSL findings carry rich evidence objects.

| Finding ID | Evidence State | Evidence Type | Proposed Action |
|---|---|---|---|
| `ssl_not_available` | Rich object ✅ | `https_probe` | Case B — wrap in array |
| `ssl_no_http_redirect` (info/uncertain) | Rich object ✅ | `http_redirect_probe` | Case B — wrap in array |
| `ssl_no_http_redirect` (medium/confirmed) | Rich object ✅ | `http_redirect_probe` | Case B — wrap in array |
| `canonical_url_uncertain` | Rich object ✅ | `canonical_url_probe` | Case B — wrap in array |

---

### Security Headers Module — computeScore() Site 1

All header findings carry rich evidence objects built from a shared `headerBaseEvidence` template. The `observed_value` field varies per condition.

| Finding ID Pattern | Evidence State | Evidence Type | Proposed Action |
|---|---|---|---|
| `header_missing_*` (observed elsewhere) | Rich object ✅ | `http_header_probe` | Case B — wrap in array |
| `header_missing_*` (low quality response) | Rich object ✅ | `http_header_probe` | Case B — wrap in array |
| `header_missing_*` (confirmed absent) | Rich object ✅ | `http_header_probe` | Case B — wrap in array |
| `header_weak_hsts` | Rich object ✅ | `http_header_probe` | Case B — wrap in array |
| `csp_weak_policy` | Rich object ✅ | `http_header_probe` | Case B — wrap in array |
| `header_malformed_*` | Rich object ✅ | `http_header_probe` | Case B — wrap in array |

Available fields include: `probe_target`, `redirect_chain`, `headers_observed`, `checked_paths`, `missing_header`, `observed_value`, `manual_verification_command`.

---

### Email Security Module — computeScore() Site 1

All email security findings carry rich evidence objects.

| Finding ID | Evidence State | Evidence Type | Proposed Action |
|---|---|---|---|
| `email_not_applicable` | Rich object ✅ | `dns_mx_lookup` | Case B — wrap in array |
| `email_missing_dmarc` | Rich object ✅ | `dns_txt_lookup` | Case B — wrap in array |
| `email_dmarc_policy_none` | Rich object ✅ | `dns_txt_lookup` | Case B — wrap in array |
| `email_missing_spf` | Rich object ✅ | `dns_txt_lookup` | Case B — wrap in array |
| `email_dkim_not_detected` | Rich object ✅ | `dns_txt_lookup` | Case B — wrap in array |

Available fields include: `probe_target`, `observed_value`, `expected_value`, `resolver_agreement_score`, `resolver_disagreement`, `manual_verification_command`.

---

### Subdomains Module — computeScore() Site 1

These findings have NO evidence set at creation time. The subdomain name and count are available from the finding `id` and `description`.

| Finding ID | Evidence State | Available Data | Proposed Evidence |
|---|---|---|---|
| `subdomain_sensitive_{sub}` | None ❌ | Subdomain name extractable from ID by removing prefix and replacing `_` with `.` | `[{ "type": "certificate_transparency", "label": "Subdomain discovered in CT logs", "value": "<subdomain>", "source": "certificate_transparency_log" }]` |
| `subdomains_large_attack_surface` | None ❌ | Count and domain name in `description` | `[{ "type": "certificate_transparency", "label": "Subdomain count from CT logs", "value": "<description>", "source": "certificate_transparency_log" }]` |

For `subdomain_sensitive_{sub}`: The subdomain is reconstructed as `id.replace("subdomain_sensitive_", "").replace(/_/g, ".")`. This is the CT log-discovered hostname — factual and non-invented.

---

### Subdomain Takeover Module — computeScore() Site 1

No evidence set at creation. The finding description lists all affected hosts and their CNAME targets.

| Finding ID | Evidence State | Available Data | Proposed Evidence |
|---|---|---|---|
| `subdomain_takeover` | None ❌ | Host list and CNAME targets in `description` | `[{ "type": "dns_cname", "label": "Dangling CNAME detected", "value": "<description>", "source": "dns_lookup" }]` |

---

### Asset Exposure Module — computeScore() Site 1

No evidence set at creation. The finding description lists all affected hostnames.

| Finding ID | Evidence State | Available Data | Proposed Evidence |
|---|---|---|---|
| `asset_exposure_sensitive_tool` | None ❌ | Host names and tool names in `description` | `[{ "type": "http_probe", "label": "Reachable asset detected", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |
| `asset_exposure_admin_interface` | None ❌ | Host names in `description` | `[{ "type": "http_probe", "label": "Reachable admin interface detected", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |
| `asset_exposure_dev_env` | None ❌ | Host names in `description` | `[{ "type": "http_probe", "label": "Reachable dev environment detected", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |

---

### WHOIS Intelligence Module — Site 2

No evidence set at creation. Expiry dates, domain age, and registrar name are embedded in `description`.

| Finding ID | Evidence State | Available Data | Proposed Evidence |
|---|---|---|---|
| `whois_domain_expired` | None ❌ | Expiry date and days in `description` | `[{ "type": "rdap_lookup", "label": "Domain expiry from RDAP registry", "value": "<description>", "source": "rdap" }]` |
| `whois_expiry_critical` | None ❌ | Days until expiry in `description` | `[{ "type": "rdap_lookup", "label": "Domain expiry from RDAP registry", "value": "<description>", "source": "rdap" }]` |
| `whois_expiry_warning` | None ❌ | Days until expiry in `description` | `[{ "type": "rdap_lookup", "label": "Domain expiry from RDAP registry", "value": "<description>", "source": "rdap" }]` |
| `whois_new_domain` | None ❌ | Domain age in days in `description` | `[{ "type": "rdap_lookup", "label": "Domain registration date from RDAP registry", "value": "<description>", "source": "rdap" }]` |
| `whois_registrar_info` | None ❌ | Registrar name and status in `description` | `[{ "type": "rdap_lookup", "label": "Registrar identification from RDAP", "value": "<description>", "source": "rdap" }]` |

---

### Email Security Intelligence Module — Site 3

**Out of scope for this sprint.** These findings live in `modules.email_security_intelligence.findings`, not the top-level scan `findings[]`. The `normalizeFindingSchema()` normalizer runs on the top-level array only and never processes these findings. Evidence for email intel findings will be addressed in a future sprint if these findings are elevated to the top-level array.

---

### Cloud Storage Discovery Module — Site 4

Cloud storage findings carry rich `evidence: {...}` objects set at creation time in `runCloudStorageModule()`. These are Case B.

| Finding ID | Evidence State | Evidence Type | Proposed Action |
|---|---|---|---|
| `cloud_storage_takeover_risk` | Rich object ✅ | custom object | Case B — wrap in array |
| `cloud_storage_public_listing` | Rich object ✅ | custom object | Case B — wrap in array |
| `cloud_storage_exposure_observed` | Rich object ✅ | custom object | Case B — wrap in array |

Available fields include: `provider`, `bucket_or_container`, `source_hostname`, `discovery_source`, `validation_method`, `status_code`, `provider_headers_present`, `confidence`, `observed_value`, `expected_value`, `listing_enabled`, `object_count_observed`, `checked_at`, `manual_verification_command`.

Note: Cloud storage findings also carry an `evidence_quality: "good"` field (not from `validateFindingEvidence()`) — this is preserved as-is.

---

### Admin Surface Detection Module — Site 5

No evidence set at creation. Hostname and product lists are embedded in `description`.

| Finding ID | Evidence State | Available Data | Proposed Evidence |
|---|---|---|---|
| `admin_surface_critical` | None ❌ | Hostname/product list in `description` | `[{ "type": "http_probe", "label": "Admin service fingerprint match", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |
| `admin_surface_high` | None ❌ | Hostname/product list in `description` | `[{ "type": "http_probe", "label": "Admin service fingerprint match", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |
| `admin_surface_medium` | None ❌ | Hostname/product list in `description` | `[{ "type": "http_probe", "label": "Service fingerprint match", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |

---

### Domain Security Enrichment Module — Site 6

No evidence set at creation. Observed values (CAA records, HSTS max-age, cookie counts, missing criteria) are embedded in `description`.

| Finding ID | Evidence State | Available Data | Source Type | Proposed Action |
|---|---|---|---|---|
| `dse_missing_caa` | None ❌ | Description states absence | `dns_lookup` | Generate from `description` |
| `dse_caa_no_issuers` | None ❌ | Record presence in `description` | `dns_lookup` | Generate from `description` |
| `dse_hsts_short_maxage` | None ❌ | `max-age` value in `description` | `http_header_probe` | Generate from `description` |
| `dse_hsts_not_preload_eligible` | None ❌ | Missing criteria list in `description` | `http_header_probe` | Generate from `description` |
| `dse_cookie_no_secure` | None ❌ | Cookie counts in `description` | `http_header_probe` | Generate from `description` |
| `dse_cookie_no_httponly` | None ❌ | Cookie counts in `description` | `http_header_probe` | Generate from `description` |
| `dse_cookie_no_samesite` | None ❌ | Cookie counts in `description` | `http_header_probe` | Generate from `description` |

Source type routing: CAA findings → `dns_lookup`; HSTS and cookie findings → `http_header_probe`.

---

### Technology Detection Module — Site 7

No evidence set at creation. The actual version string is embedded in `description`.

| Finding ID | Evidence State | Available Data | Proposed Evidence |
|---|---|---|---|
| `tech_xpoweredby_version_disclosure` | None ❌ | Version string in `description` | `[{ "type": "http_header_probe", "label": "Version disclosure in HTTP response header", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |
| `tech_server_version_disclosure` | None ❌ | Version string in `description` | `[{ "type": "http_header_probe", "label": "Version disclosure in HTTP response header", "value": "<description>", "source": "cloudflare_workers_fetch" }]` |

---

## Evidence State Summary

| Module | Findings with evidence | Findings without evidence |
|---|---|---|
| dns | 4 | 0 |
| ssl | 4 | 0 |
| headers | 9+ | 0 |
| email_security | 5 | 0 |
| subdomains | 0 | 2 |
| subdomain_takeover | 0 | 1 |
| asset_exposure | 0 | 3 |
| whois_intelligence | 0 | 5 |
| cloud_storage_discovery | 3 | 0 |
| admin_surface_detection | 0 | 3 |
| domain_security_enrichment | 0 | 7 |
| technology_detection | 0 | 2 |
| email_security_intelligence | — | — (out of scope) |
| **Total** | **~25** | **~23** |

---

## Implementation Plan

### Function: `buildEvidenceArray(finding)`

Added inside `normalizeFindingSchema()` in `workers/scan-api/src/index.js`.

**Case A** — already an array: return as-is.

**Case B** — rich object: extract `evidence_type → type`, `probe_target → label`, `observed_value → value`, `source → source`. Spread all remaining fields to preserve richness.

**Case C** — null/undefined/empty: call `buildEvidenceFromFields(finding)` which routes by `id` prefix/exact match:

| ID pattern | `type` | `label` | `source` |
|---|---|---|---|
| `subdomain_sensitive_*` | `certificate_transparency` | `Subdomain discovered in CT logs` | `certificate_transparency_log` |
| `subdomains_large_attack_surface` | `certificate_transparency` | `Subdomain count from CT logs` | `certificate_transparency_log` |
| `subdomain_takeover` | `dns_cname` | `Dangling CNAME detected` | `dns_lookup` |
| `asset_exposure_*` | `http_probe` | `Reachable asset detected` | `cloudflare_workers_fetch` |
| `whois_*` | `rdap_lookup` | `RDAP registry query result` | `rdap` |
| `admin_surface_*` | `http_probe` | `Admin service fingerprint match` | `cloudflare_workers_fetch` |
| `dse_missing_caa` / `dse_caa_*` | `dns_lookup` | `DNS CAA record query` | `cloudflare_doh` |
| `dse_hsts_*` / `dse_cookie_*` | `http_header_probe` | `HTTP response header observation` | `cloudflare_workers_fetch` |
| `tech_*` | `http_header_probe` | `Version disclosure in HTTP response header` | `cloudflare_workers_fetch` |
| fallback | `scanner_detection` | `Detection basis` | `CyberMeters/<module>` |

**Value field:** All Case C entries use `finding.description` as `value`. This is non-invented — the description was written to contain the observed values (version strings, hostnames, counts, days, registrar names).

**Subdomain sensitive special case:** Value is reconstructed from `id` as `id.replace("subdomain_sensitive_", "").replace(/_/g, ".")` — the actual subdomain hostname.

### No changes to:
- Score calculations
- Severity assignments
- Confidence values
- Any module logic
- API response structure (except `evidence` changes from `null`/`{}` to `[...]`)
- Frontend
- Database
