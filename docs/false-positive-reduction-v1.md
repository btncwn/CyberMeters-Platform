# CyberMeters False Positive Reduction v1

**Sprint 9D — False Positive Reduction**
**Date:** June 2026
**Status:** Pre-implementation audit — required before code changes

---

## Overview

This document implements the highest-value recommendations from `docs/false-positive-audit-v1.md`. The goal is to replace heuristic certainty with evidence-based confidence tiers and explicit `validation_quality` values across the five noisiest finding categories.

**Constraint:** No score changes. No severity changes. No new findings. No UI changes. No database changes.

---

## Validation Quality Scale

All affected findings and module objects receive a `validation_quality` field with one of these values:

| Value | Meaning |
|---|---|
| `excellent` | Multiple independent signals or direct HTTP verification confirming the finding |
| `good` | Single strong signal with HTTP validation or multi-source corroboration |
| `partial` | Heuristic match that may be incorrect; data is suggestive but not confirmatory |
| `weak` | Algorithmic generation only; no probe validation performed |

---

## Priority 1 — Sensitive Subdomains

### Current State

Finding ID: `subdomain_sensitive_{sub}` (in `computeScore()`)
Current: `confidence: "medium"` → resolves to 70 via Sprint 9B. No `validation_quality`.

Root cause of false positives (from audit): Subdomains come from Certificate Transparency logs. A decommissioned CT entry that no longer resolves still generates a finding with `-5` score impact.

### Available Data at Creation Time

`computeScore()` receives the full `modules` object, which includes:

- `modules.asset_exposure.assets[]` — each item has `host`, `reachable` (boolean), `status` (HTTP status code). The asset_exposure module probes all discovered subdomains for HTTP/HTTPS reachability.
- `modules.dns_bruteforce.items[]` — array of hostnames that resolved via DNS brute-force probing (wordlist-based A-record lookups).

### Evidence Tiers

| Tier | Condition | Confidence | Validation Quality |
|---|---|---|---|
| HTTP confirmed | `asset_exposure.assets` has entry with `reachable: true` | 80 | `good` |
| DNS confirmed (brute-force only) | Hostname in `dns_bruteforce.items` but not HTTP-reachable | 70 | `partial` |
| CT log only | Not in asset_exposure (reachable) or dns_bruteforce | 60 | `weak` |

### Implementation Site

`computeScore()` function, subdomain sensitive loop (before the `for` loop over `cappedSensitive`).

Build lookup sets once:
```js
const reachableHosts = new Set(
  (modules.asset_exposure?.assets || [])
    .filter(a => a.reachable)
    .map(a => a.host)
);
const bruteDnsHosts = new Set(modules.dns_bruteforce?.items || []);
```

Per-subdomain tier resolution:
```js
let subConf, subVQ;
if (reachableHosts.has(sub)) {
  subConf = 80; subVQ = "good";
} else if (bruteDnsHosts.has(sub)) {
  subConf = 70; subVQ = "partial";
} else {
  subConf = 60; subVQ = "weak";
}
```

---

## Priority 2 — Brand Monitoring Candidates

### Current State

`generateTyposquatCandidates()` returns candidates with: `candidate_domain`, `variant_type`, `risk_level`, `risk_reasons`. No `confidence` or `validation_quality` fields.

The `/brand-monitoring/refresh` endpoint validates candidates via DNS A-record lookup and sets `dns_resolves: true/false`. The Business Risk Score already only counts DNS-confirmed candidates (`dns_resolves = 1`), so scoring is correct. The issue is the candidate objects themselves carry no certainty signal.

Root cause: An unvalidated candidate with `risk_level: "high"` looks identical to a DNS-confirmed threat in the raw module output.

### Implementation

**`generateTyposquatCandidates()`** — add to each returned candidate:
```js
confidence: 40, validation_quality: "weak"
```

**`/brand-monitoring/refresh` endpoint** — enrich `validationResults` entries:
```js
confidence: dnsResolves ? 80 : 40,
validation_quality: dnsResolves ? "good" : "weak",
```

No database columns changed. These fields are in-memory enrichment on response objects only.

### Evidence Tiers

| Tier | Condition | Confidence | Validation Quality |
|---|---|---|---|
| DNS verified | `dns_resolves === true` (from /refresh endpoint) | 80 | `good` |
| Unvalidated | Generated algorithmically, not yet DNS-probed | 40 | `weak` |

---

## Priority 3 — Identity Discovery

### Current State

`runIdentityDiscoveryModule()` sets string confidence on two asset types:

- **Provider** (signal-based): `confidence: matched.length >= 2 ? "high" : "medium"`. No `validation_quality`.
- **Portal** (hostname pattern): `confidence: "medium"`. No `validation_quality`.

Root cause: Both provider detection (CNAME/SPF/MX/CSP fingerprint matching) and hostname pattern matching use the same "medium" confidence label despite having very different signal quality.

### Evidence Tiers

| Tier | Condition | Confidence | Validation Quality |
|---|---|---|---|
| Known IdP fingerprint | Provider matched via IDENTITY_PROVIDER_SIGS (CNAME/SPF/MX/CSP signals) | 90 | `excellent` |
| Hostname heuristic | Portal matched via IDENTITY_HOSTNAME_PATTERNS (prefix pattern only) | 60 | `partial` |

Provider detection matches against 12+ known IdP CNAME/SPF/MX/CSP patterns. A single-signal match already constitutes verified fingerprint evidence — the source is a real DNS or HTTP signal, not an algorithmic guess.

Hostname pattern matching (`sso.*`, `vpn.*`, `auth.*`, etc.) is pure heuristic with no DNS/HTTP confirmation.

### Implementation Site

`runIdentityDiscoveryModule()` function:

Provider push:
```js
confidence:        90,
validation_quality: "excellent",
```

Portal push:
```js
confidence:        60,
validation_quality: "partial",
```

---

## Priority 4 — Cloud Storage Discovery

### Current State

`runCloudStorageModule()` sets `confidence: enriched.confidence >= 80 ? "high" : "medium"` — based on the candidate detection score, not on HTTP validation outcome. `evidence_quality: "good"` is hardcoded on all findings regardless of validation result.

Root cause: All three cloud storage finding types (takeover risk, public listing, exposure observed) receive the same static confidence assignment. But these findings represent very different evidence levels — a confirmed public listing is far more certain than a CNAME-only candidate.

### Evidence Tiers

| Finding ID | Condition | Confidence | Validation Quality |
|---|---|---|---|
| `cloud_storage_public_listing` | HTTP GET confirmed public listing (`listing_enabled: true`) | 95 | `excellent` |
| `cloud_storage_exposure_observed` | Resource exists + provider headers confirmed via HTTP | 90 | `good` |
| `cloud_storage_takeover_risk` | HTTP validated resource non-existence (`resource_exists: false`) | 80 | `good` |
| Fallback | Any unvalidated candidate | 60 | `weak` |

Note: `cloud_storage_takeover_risk` requires HTTP validation to confirm non-existence. CNAME match alone (without HTTP confirmation) results in `candidate.confidence < 50` and exits early with `null` — no finding is generated. So all `cloud_storage_takeover_risk` findings that reach the push block have been HTTP-validated.

### Implementation Site

`runCloudStorageModule()`, the `findings.push()` block. Replace the static confidence line and add `validation_quality` using `findingBase.id`:

```js
const { conf: cloudConf, vq: cloudVQ } = cloudStorageConfidenceVQ(findingBase.id);
// ...
confidence:        cloudConf,
validation_quality: cloudVQ,
```

Where:
```js
function cloudStorageConfidenceVQ(findingId) {
  if (findingId === "cloud_storage_public_listing")    return { conf: 95, vq: "excellent" };
  if (findingId === "cloud_storage_exposure_observed") return { conf: 90, vq: "good" };
  if (findingId === "cloud_storage_takeover_risk")     return { conf: 80, vq: "good" };
  return { conf: 60, vq: "weak" };
}
```

---

## Priority 5 — DKIM Detection

### Current State

Two DKIM absence findings:

1. **`email_dkim_not_detected`** (in `computeScore()`): `confidence: "low"` → resolves to 60. No `validation_quality`. Description already explains the selector heuristic limitation.

2. **`email_intel_dkim_not_found`** (in `buildEmailIntelFindings()`): No `confidence` set (gets 60 from FINDING_CONFIDENCE_SCORES map). No `validation_quality`.

Root cause: Absence of DKIM via common-selector probing is presented with the same weight as confirmed absences. Enterprise domains routinely use non-standard selectors (Proofpoint, Mimecast, Barracuda) and will always fail common-selector probes.

### Implementation

Both findings get `confidence: 60, validation_quality: "partial"` set explicitly at creation time.

"Partial" accurately conveys: the probe ran, common selectors were checked, no record was found — but non-standard selectors were not probed. The finding is honest about its limitations.

The "verified DKIM → confidence 95/excellent" case has no finding, because when DKIM is detected there is no `email_dkim_not_detected` finding to emit.

### Implementation Sites

**`computeScore()`** DKIM block: change `confidence: "low"` to `confidence: 60` and add `validation_quality: "partial"`.

**`buildEmailIntelFindings()`** DKIM block: add `confidence: 60, validation_quality: "partial"`.

---

## Change Summary

| Priority | Finding / Object | Current | After |
|---|---|---|---|
| P1 | `subdomain_sensitive_*` | confidence 70, no vq | 60/70/80 + weak/partial/good |
| P2 | Brand candidates (scan) | no confidence, no vq | 40 + weak |
| P2 | Brand candidates (refresh, validated) | no confidence, no vq | 80 + good |
| P3 | Identity provider assets | confidence "high"/"medium", no vq | 90 + excellent |
| P3 | Identity portal assets | confidence "medium", no vq | 60 + partial |
| P4 | `cloud_storage_public_listing` | confidence "high"/"medium", no vq | 95 + excellent |
| P4 | `cloud_storage_exposure_observed` | confidence "high"/"medium", no vq | 90 + good |
| P4 | `cloud_storage_takeover_risk` | confidence "high"/"medium", no vq | 80 + good |
| P5 | `email_dkim_not_detected` | confidence "low", no vq | 60 + partial |
| P5 | `email_intel_dkim_not_found` | no confidence, no vq | 60 + partial |

### No changes to:
- Score calculations (computeScore, BRS, posture)
- Severity assignments
- Finding counts
- UI
- Database schema
- API response shape (except new `validation_quality` field appearing on targeted findings/objects)
