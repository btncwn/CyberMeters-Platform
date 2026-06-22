# CyberMeters Finding Schema Audit v1

**Sprint 9A — Finding Schema Upgrade**
**Date:** June 2026
**Status:** Pre-implementation audit — required before any code changes

---

## Objective

Document every finding creation path in `workers/scan-api/src/index.js`, cataloguing which fields each site currently produces and which are missing from the target v2 schema.

---

## Target Schema (v2)

```json
{
  "id":                "finding_id",
  "title":             "Human-readable title",
  "severity":          "critical | high | medium | low | info",
  "score_impact":      -5,
  "module":            "module_name",
  "confidence":        null,
  "validation_quality": null,
  "evidence":          [],
  "remediation_owner": null
}
```

---

## Finding Creation Sites

### Site 1 — `computeScore()` (lines ~5911–6700)

**Function:** `computeScore(modules, domain)`
**Returns via:** `finding()` helper which calls `findings.push()` and subtracts from score, then `applyEvidenceQuality()` is called before return.

| Field | Present? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All findings |
| `module` | ✅ | All findings have explicit `module` field |
| `confidence` | ✅ | All findings (actual values: "high", "medium", "low") |
| `validation_quality` | ❌ | Missing — needs `null` |
| `evidence` | ✅ | Rich evidence objects (not arrays) |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `dns_no_resolution` | dns | critical | −30 |
| `dns_resolver_disagreement` | dns | info | 0 |
| `dnssec_not_enabled` | dns | info | 0 |
| `dnssec_misconfigured` | dns | info | 0 |
| `ssl_not_available` | ssl | critical | −25 |
| `ssl_no_http_redirect` (uncertain) | ssl | info | 0 |
| `ssl_no_http_redirect` (confirmed) | ssl | medium | −5 |
| `canonical_url_uncertain` | ssl | info | 0 |
| `header_missing_{name}` (uncertain) | headers | info | 0 |
| `header_missing_{name}` (confirmed) | headers | high/medium/low/info | varies |
| `header_weak_hsts` | headers | info | 0 |
| `csp_weak_policy` | headers | medium | 0 |
| `header_malformed_{name}` | headers | medium | 0 |
| `email_not_applicable` | email_security | info | 0 |
| `email_missing_dmarc` | email_security | high | −15 |
| `email_dmarc_policy_none` | email_security | medium | −5 |
| `email_missing_spf` | email_security | high | −10 |
| `email_dkim_not_detected` | email_security | info | 0 |
| `subdomain_sensitive_{sub}` | subdomains | medium | −5 each |
| `subdomains_large_attack_surface` | subdomains | low | −3 |
| `subdomain_takeover` | subdomain_takeover | high | −15 or −25 |
| `asset_exposure_sensitive_tool` | asset_exposure | high | −10 |
| `asset_exposure_admin_interface` | asset_exposure | medium | −8 |
| `asset_exposure_dev_env` | asset_exposure | medium | −5 |

**Gap:** `validation_quality`, `remediation_owner`

---

### Site 2 — `runWhoisIntelligenceModule()` (lines ~2180–2260)

**Function:** `runWhoisIntelligenceModule(domain, env)`
**Returns via:** `findings.push()` into a local array; returned as `result.findings`

| Field | Present? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All 0 |
| `module` | ✅ | All set to `"whois_intelligence"` |
| `confidence` | ❌ | Missing — needs `null` |
| `validation_quality` | ❌ | Missing — needs `null` |
| `evidence` | ❌ | Missing — needs `[]` |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `whois_domain_expired` | whois_intelligence | high | 0 |
| `whois_expiry_critical` | whois_intelligence | high | 0 |
| `whois_expiry_warning` | whois_intelligence | medium | 0 |
| `whois_new_domain` | whois_intelligence | low | 0 |
| `whois_registrar_info` | whois_intelligence | informational | 0 |

**Gap:** `confidence`, `validation_quality`, `evidence`, `remediation_owner`

---

### Site 3 — `buildEmailIntelFindings()` (lines ~5730–5826)

**Function:** `buildEmailIntelFindings(spf, dmarc, dkim, mtaSts, tlsRpt)`
**Returns via:** local `findings.push()`, returned from `runEmailIntelModule()`; included in `modules.email_security_intelligence`
**Note:** These findings are NOT currently included in the top-level scan `findings[]`. They are in `modules.email_security_intelligence.findings`. Included here for completeness.

| Field | Present? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All 0 |
| `module` | ✅ | All set to `"email_security_intelligence"` |
| `confidence` | ❌ | Missing — needs `null` |
| `validation_quality` | ❌ | Missing — needs `null` |
| `evidence` | ❌ | Missing — needs `[]` |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `email_intel_dmarc_missing` | email_security_intelligence | high | 0 |
| `email_intel_dmarc_reporting_only` | email_security_intelligence | medium | 0 |
| `email_intel_spf_missing` | email_security_intelligence | high | 0 |
| `email_intel_spf_permissive` | email_security_intelligence | high | 0 |
| `email_intel_dkim_not_found` | email_security_intelligence | medium | 0 |
| `email_intel_mta_sts_missing` | email_security_intelligence | low | 0 |
| `email_intel_tls_rpt_missing` | email_security_intelligence | low | 0 |

**Gap:** `confidence`, `validation_quality`, `evidence`, `remediation_owner`

---

### Site 4 — `runCloudStorageModule()` (lines ~3147–3200)

**Function:** `runCloudStorageModule(domain, modules)`
**Returns via:** `findings.push()` into local array, then pushed to main `findings[]` at line 8065

| Field | Present? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All 0 |
| `module` | ✅ | Set to `"cloud_storage_discovery"` |
| `confidence` | ✅ | Set to `"high"` or `"medium"` |
| `validation_quality` | ❌ | Missing — needs `null` (has `evidence_quality` instead) |
| `evidence` | ✅ | Rich evidence object |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `cloud_storage_takeover_risk` | cloud_storage_discovery | high or medium | 0 |
| `cloud_storage_public_listing` | cloud_storage_discovery | high | 0 |
| `cloud_storage_exposure_observed` | cloud_storage_discovery | medium or info | 0 |

**Gap:** `validation_quality`, `remediation_owner`

---

### Site 5 — Admin Surface Detection (lines ~7862–7900)

**Location:** Inline in scan handler, after `computeScore()` returns
**Returns via:** Direct `findings.push()` into the main `findings[]`

| Field | Present? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All 0 |
| `module` | ✅ | Set to `"admin_surface_detection"` |
| `confidence` | ❌ | Missing — needs `null` |
| `validation_quality` | ❌ | Missing — needs `null` |
| `evidence` | ❌ | Missing — needs `[]` |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `admin_surface_critical` | admin_surface_detection | critical | 0 |
| `admin_surface_high` | admin_surface_detection | high | 0 |
| `admin_surface_medium` | admin_surface_detection | medium | 0 |

**Gap:** `confidence`, `validation_quality`, `evidence`, `remediation_owner`

---

### Site 6 — Domain Security Enrichment (lines ~7909–7990)

**Location:** Inline in scan handler, after `computeScore()` returns
**Returns via:** Direct `findings.push()` into the main `findings[]`

| Field | Present? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All 0 |
| `module` | ✅ | Set to `"domain_security_enrichment"` |
| `confidence` | ❌ | Missing — needs `null` |
| `validation_quality` | ❌ | Missing — needs `null` |
| `evidence` | ❌ | Missing — needs `[]` |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `dse_missing_caa` | domain_security_enrichment | medium | 0 |
| `dse_caa_no_issuers` | domain_security_enrichment | low | 0 |
| `dse_hsts_short_maxage` | domain_security_enrichment | low | 0 |
| `dse_hsts_not_preload_eligible` | domain_security_enrichment | low | 0 |
| `dse_cookie_no_secure` | domain_security_enrichment | high | 0 |
| `dse_cookie_no_httponly` | domain_security_enrichment | medium | 0 |
| `dse_cookie_no_samesite` | domain_security_enrichment | low | 0 |

**Gap:** `confidence`, `validation_quality`, `evidence`, `remediation_owner`

---

### Site 7 — Technology Detection info_findings (lines ~1900–1935)

**Function:** `runTechModule()` — returns `info_findings[]` array
**Returns via:** Merged into main `findings[]` at line 7853 via: `findings.push({ module: "technology_detection", ...f })`
**Note:** `module` is injected at push time, not at creation time.

| Field | Present at source? | Notes |
|---|---|---|
| `id` | ✅ | All findings |
| `title` | ✅ | All findings |
| `severity` | ✅ | All findings |
| `score_impact` | ✅ | All 0 |
| `module` | ❌ (added at push) | Added as `"technology_detection"` at merge point |
| `confidence` | ❌ | Missing — needs `null` |
| `validation_quality` | ❌ | Missing — needs `null` |
| `evidence` | ❌ | Missing — needs `[]` |
| `remediation_owner` | ❌ | Missing — needs `null` |

**Findings produced:**

| Finding ID | Module | Severity | Score Impact |
|---|---|---|---|
| `tech_xpoweredby_version_disclosure` | technology_detection | low | 0 |
| `tech_server_version_disclosure` | technology_detection | low | 0 |

**Gap:** `confidence`, `validation_quality`, `evidence`, `remediation_owner`

---

## Schema Gap Summary

| Site | `module` | `confidence` | `validation_quality` | `evidence` | `remediation_owner` |
|---|---|---|---|---|---|
| computeScore() | ✅ | ✅ | ❌ | ✅ (object) | ❌ |
| runWhoisIntelligenceModule() | ✅ | ❌ | ❌ | ❌ | ❌ |
| buildEmailIntelFindings() | ✅ | ❌ | ❌ | ❌ | ❌ |
| runCloudStorageModule() | ✅ | ✅ | ❌ | ✅ (object) | ❌ |
| Admin surface (inline) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Domain security enrichment (inline) | ✅ | ❌ | ❌ | ❌ | ❌ |
| runTechModule() info_findings | added at push | ❌ | ❌ | ❌ | ❌ |

---

## Total Finding Types

| Module | Finding Count |
|---|---|
| dns | 4 |
| ssl | 3 |
| headers | 9 (6 missing + 3 quality) |
| email_security | 5 |
| subdomains | 2 |
| subdomain_takeover | 1 |
| asset_exposure | 3 |
| whois_intelligence | 5 |
| email_security_intelligence | 7 (in module, not top-level findings) |
| cloud_storage_discovery | 3 |
| admin_surface_detection | 3 |
| domain_security_enrichment | 7 |
| technology_detection | 2 |
| **Total distinct IDs** | **~54** |

---

## Implementation Decision

**Approach: Single normalization pass at report assembly boundary.**

Rather than patching each of the 7 creation sites individually (risking missed sites), a `normalizeFindingSchema()` utility will be applied to the final `findings[]` array immediately before the scan report is assembled.

Benefits:
- One code change, zero risk of missing a creation site
- All future finding creation sites automatically covered
- Fully additive — existing fields are spread first, defaults only fill gaps
- Backward compatible — no existing field is removed or renamed

```js
function normalizeFindingSchema(finding) {
  return {
    ...finding,
    module:             finding.module             ?? null,
    confidence:         finding.confidence         ?? null,
    validation_quality: finding.validation_quality ?? null,
    evidence:           finding.evidence           ?? [],
    remediation_owner:  finding.remediation_owner  ?? null,
  };
}
```

Applied at scan report boundary:
```js
// Sprint 9A: Normalize findings to v2 schema before report assembly
const normalizedFindings = findings.map(normalizeFindingSchema);
const report = { ..., findings: normalizedFindings, ... };
```

**Note on `evidence` field:** Existing findings in `computeScore()` and `runCloudStorageModule()` carry rich `evidence` objects (not arrays). These are preserved as-is — the `?? []` default only fires when `evidence` is `undefined` or `null`. Normalizing `evidence` to an array format is deferred to Sprint 9C.

**Note on `buildEmailIntelFindings()` scope:** These findings live in `modules.email_security_intelligence.findings`, not in the top-level scan `findings[]`. The normalizer runs on the top-level array only. Email intel module findings will be normalized in Sprint 9B when that module's output is elevated to top-level.
