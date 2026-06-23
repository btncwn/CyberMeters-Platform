# Finding Noise Reduction & Observation Consolidation — Design v1

**Date:** June 2026  
**Status:** Design only — awaiting implementation approval  
**Scope:** Presentation and finding structure only. No score changes. No scanner changes.

---

## 1 — Header Observation Consolidation

### Current State

For blackbullbarbers.co.uk (HTTPS 200, response quality OK), the scanner currently emits four separate Branch C findings:

| Finding ID | Title | Score Impact | Confidence |
|---|---|---|---|
| `header_missing_x_frame_options` | Missing X-Frame-Options Header (Unverified) | 0 | 70 |
| `header_missing_x_content_type_options` | Missing X-Content-Type-Options Header (Unverified) | 0 | 70 |
| `header_missing_referrer_policy` | Missing Referrer-Policy Header (Unverified) | 0 | 70 |
| `header_missing_permissions_policy` | Missing Permissions-Policy Header (Unverified) | 0 | 70 |

Four cards. Identical observation. Four "Needs Verification" banners (after the P2 threshold fix). Four academy links all pointing to the same article. One finding-count reduction each delivers zero customer value.

### Proposed Model

Replace all four with a single aggregated observation:

```
Finding ID:    security_headers_not_observed
Title:         Security Headers Not Fully Observed
Severity:      info
Score impact:  0
Confidence:    70 (medium — same as existing Branch C)
```

**Description:** The following security headers were not detected in the scanner response from `[domain]`: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. These headers are frequently delivered by CDN layers, framework middleware, or applied per-path and may not be present on the root path scanned. Verify on the canonical origin before treating as a defect.

**Evidence:** Single evidence object with:
- `observed_value`: list of absent headers
- `manual_verification_command`: multi-header curl check

### What Is Explicitly Preserved

**BRS calculations:** The Business Risk Score deducts based on `header_missing_x_frame_options` and `header_missing_x_content_type_options`. After consolidation, the Worker stores an internal `_headers_absent` array on the finding. The BRS function reads from this array, not from finding IDs. Score deductions are identical to current behaviour.

**Evidence:** The consolidated finding includes a combined evidence object listing all absent headers and all checked paths. The verify command covers all headers in one `curl` invocation.

**Remediation guidance:** A single consolidated remediation card covers all four headers, with per-header recommendations listed. Academy link points to a new `security-headers-explained` article (or falls back to `hsts-explained` if the article does not exist).

**Individual finding IDs in the evidence:** The `_consolidated_ids` array on the finding preserves the individual IDs for any downstream consumer that needs to reference specific headers.

### What Changes

| Before | After |
|---|---|
| 4 finding cards | 1 finding card |
| 4 "Needs Verification" banners | 1 banner |
| Finding ID: `header_missing_x_frame_options` etc. | Finding ID: `security_headers_not_observed` |
| `ACADEMY_LINK_MAP` points to `hsts-explained` for all | New entry: `security_headers_not_observed → security-headers-explained` |

### Scope Boundary

Branch A (header present on alternate path) and Branch B (response quality failed) are **not consolidated** — they each carry diagnostic information about why the header was not observed. Only Branch C is consolidated.

HSTS is **not included** — it has its own scored path (Branch D) and should remain a distinct finding.

### Files to Change

| File | Change |
|---|---|
| `workers/scan-api/src/index.js` | Branch C loop → collect + emit consolidated finding |
| `workers/scan-api/src/index.js` | BRS table update — read from `_headers_absent` list |
| `workers/scan-api/src/index.js` | `ACADEMY_LINK_MAP` — add `security_headers_not_observed` entry |
| `workers/scan-api/src/index.js` | `REMEDIATION_INTEL` — add consolidated remediation card |

No frontend changes required for the consolidation itself.

---

## 2 — Observation Classification Model

### The Two-Category Proposal

All findings in the scanner fall into one of two categories based on what the customer is expected to do with them:

**Category A — Security Findings**
Direct evidence of a configuration gap that the customer controls and can fix. Score-impacting or confirmed by direct probe with high confidence. Action expected.

**Category B — Security Observations**
Scanner noted something that may or may not require action. Not score-impacting (or very low impact). Confidence is limited by probe constraints. Customer should be aware, but no immediate action is implied.

### Full Classification — All Current Finding IDs

**Category A: Security Findings**

| Finding ID | Why Category A |
|---|---|
| `dns_no_resolution` | Domain doesn't resolve — confirmed, severe, customer controls DNS |
| `ssl_not_available` | TLS not responding — confirmed, scored, directly fixable |
| `ssl_no_http_redirect` (scored variant) | HTTP serves plaintext — confirmed, scored, -5 |
| `email_missing_spf` | SPF absent — direct DNS TXT lookup, deterministic, scored |
| `email_missing_dmarc` | DMARC absent — direct DNS TXT lookup, deterministic, scored |
| `email_dmarc_policy_none` | DMARC configured but non-enforcing — deterministic, scored |
| `email_weak_dmarc` | DMARC configured with weak policy — deterministic, scored |
| `header_missing_strict_transport_security` (Branch D) | HSTS absent — confirmed on HTTPS 200, scored |
| `header_weak_hsts` | HSTS present but configuration inadequate — confirmed |
| `subdomain_takeover` | CNAME → unclaimed service — confirmed via fingerprint, scored |
| `subdomain_takeover_risk` | Potential takeover indicator — medium confidence, scored |
| `dse_missing_caa` | CAA record absent — direct DNS lookup, deterministic |
| `dse_hsts_short_maxage` | HSTS max-age inadequate — direct header observation |
| `whois_domain_expired` | Domain expiry confirmed — direct RDAP lookup |
| `whois_domain_expiring_soon` | Domain expiry within 30/60 days — direct RDAP lookup |
| `email_intel_spf_permissive` | SPF too permissive (`+all`) — direct DNS analysis |
| `email_intel_dmarc_reporting_only` | DMARC reporting-only mode confirmed |
| `csp_weak_policy` | CSP present but insufficient — confirmed via header analysis |
| Admin surface findings (medium/high severity) | External exposure confirmed by probe |
| Cloud storage exposure (medium confidence) | Storage endpoint confirmed reachable |

**Category B: Security Observations**

| Finding ID | Why Category B |
|---|---|
| `dnssec_not_enabled` | Infrastructure observation — 90% confidence, but 95%+ of SMBs have no DNSSEC |
| `dnssec_misconfigured` | Partial DNSSEC — technical, low customer action expected |
| `email_dkim_not_detected` | Selector heuristic — 60% confidence, provider-specific selectors likely missed |
| `ssl_no_http_redirect` (uncertain variant) | Probe blocked — scanner cannot determine HTTP state |
| `canonical_url_uncertain` | Cannot determine canonical URL — probe limitation |
| `dns_resolver_disagreement` | DNS resolver inconsistency — technical, may be transient |
| `header_missing_x_frame_options` (Branch C) | CDN injection likely — observation only |
| `header_missing_x_content_type_options` (Branch C) | CDN injection likely — observation only |
| `header_missing_referrer_policy` (Branch C) | Framework injection likely — observation only |
| `header_missing_permissions_policy` (Branch C) | Framework injection likely — observation only |
| `security_headers_not_observed` (consolidated) | Same as above — consolidated observation |
| `header_missing_*` (Branch A — present elsewhere) | Present on alt path, contradictory signal |
| `header_missing_*` (Branch B — response quality failed) | Scanner got a bad response, cannot conclude |
| `header_weak_hsts` (when confidence < 90) | HSTS present but configuration detail uncertain |
| `email_not_applicable` | No MX records — informational note, no action needed |
| Admin surface findings (info severity, confidence ≤ 70) | Candidate detected, not confirmed |

### Classification Criteria

A finding is Category A if **all** of the following are true:
1. Score impact ≠ 0, OR severity is high/medium
2. Confidence ≥ 80
3. The scanner has a direct probe result (DNS lookup, TLS handshake, HTTP 200 response)
4. The customer can reasonably be expected to fix it

A finding is Category B if **any** of the following are true:
1. Score impact = 0 AND confidence < 80
2. The finding is explicitly labelled "Unverified" or "Uncertain"
3. The probe result was ambiguous or blocked
4. The finding describes an observation about infrastructure rather than a directly fixable gap

---

## 3 — Finding Count Integrity

### The Current Problem

The dashboard currently shows a single "Findings" count that includes both Category A and Category B items. For blackbullbarbers.co.uk:

- Total: 7 findings
- Category A (actionable): 2–3 (DMARC p=none, header HSTS if scored)
- Category B (observations): 4–5 (DNSSEC, DKIM, headers × 4)

A customer sees "7 Findings" on a 95/100 domain and loses confidence in the platform, or worse, begins to doubt that the score is meaningful.

### Three Display Options

**Option 1 — Single count, exclude observations**
Display only Category A findings in the headline count. Observations exist in the finding list but are visually separated and not counted.

- `3 Findings` instead of `7 Findings`
- Observations shown below in an "Observations" section
- Pro: clearest headline signal
- Con: customers may feel information is being hidden

**Option 2 — Split count**
Display two numbers:

`3 Findings  •  4 Observations`

- Pro: transparent — nothing hidden
- Con: adds UI complexity; customers may not understand the distinction immediately

**Option 3 — Single count with observation footnote**
Keep the finding count as-is but add context:

`7 Findings (4 are unverified observations)`

- Pro: no UI redesign needed
- Con: "unverified observations" is awkward phrasing; still shows 7

### Recommendation

**Option 1** for authenticated workspace scans where customers have context. The Scan Detail page title `7 Findings` becomes `3 Findings` with an "Observations" section below the main finding list. The finding count in dashboard/portfolio APIs (`findings_count`, `critical_count`, `high_count`, etc.) should only count Category A.

**Option 2** for external/FreeScan results where the two-category split may be new to the user. Two numbers side by side with brief inline labels.

### What Changes in the Data Layer

The Worker needs to emit `finding_type: "finding"` or `finding_type: "observation"` on each generated finding. The API should then:

- `findings_count` = count where `finding_type === "finding"`
- `observation_count` = count where `finding_type === "observation"`

Frontend uses whichever count is appropriate per context. No database schema change is required — this is a computed field in the report JSON.

---

## 4 — Remaining Terminology Inconsistencies

### Confirmed Issues

**A — `IntelligencePage.jsx` line 254: `label: 'Risk Level'`**

Context: SummaryBar stat card showing `risk?.overall_risk_level`. This is a score-derived posture rating (excellent/good/moderate/poor/critical), not a finding severity. The label should be "Security Rating".

File: `frontend/src/pages/IntelligencePage.jsx`  
Change: `label: 'Risk Level'` → `label: 'Security Rating'`  
Also: line 258 `sub: 'Overall'` → `sub: 'Posture Rating'` for additional clarity

**B — `PortfolioPage.jsx` line 176: `<th>Risk Rating</th>` + `RiskBadge` for posture**

The Portfolio page shows workspace risk ratings in a table with the column header "Risk Rating" (should be "Security Rating"), and renders the value with `<RiskBadge level={(ws.risk_rating || '').toLowerCase()} />`. `RiskBadge` handles critical/high/medium/low but the posture values (excellent/good/moderate) fall through to unexpected classes.

File: `frontend/src/pages/PortfolioPage.jsx`  
Change 1: `<th>Risk Rating</th>` → `<th>Security Rating</th>`  
Change 2: `<RiskBadge level={...} />` → `<RatingBadge rating={...} />` (import/define RatingBadge same as WorkspaceScorecard.jsx)

**C — `ScanDetail.jsx` line 41: comment `// ── Risk level config`**

Non-customer-facing (code comment only). Low priority. Can be updated to `// ── Security Rating config` for internal consistency.

### Items Confirmed NOT Issues

| Location | Display text | Classification | Verdict |
|---|---|---|---|
| `AssetsPage.jsx` line 149 | "Risk" label for asset risk level | Asset/finding severity (System B) | Correct — assets use risk level |
| `BrandMonitoringPage.jsx` line 21 | `RiskBadge level={v.risk_level}` | Asset/squatting domain risk (System B) | Correct — this is finding severity |
| `WorkspaceSupplyChainPage.jsx` line 97 | `RiskBadge level={v.risk_level}` | Vendor risk level (System B) | Correct — vendor risk is System B |
| `ThirdPartyPage.jsx` line 28 | `RiskBadge level={asset.risk_level}` | Asset risk level (System B) | Correct |
| `FirstResultsGuide.jsx` line 56 | "assessed for risk level" | Description text, refers to vendor risk | Acceptable — lowercase generic usage |
| `WorkspaceExecutiveDashboard.jsx` line 348 | `Rating: Good` | Already fixed (Sprint A Fix 4) | Correct |
| `WorkspaceDashboard.jsx` | `securityRatingLabel()` | Already fixed (Sprint A Fix 5) | Correct |
| `ScanDetail.jsx` line 1186 | `label="Security Rating"` | Already fixed (Sprint A Fix 3) | Correct |
| `Dashboard.jsx` | `RISK_LABEL` with correct values | Already fixed (Sprint A Fix 6) | Correct |
| `WorkspaceScorecard.jsx` | `RatingBadge` component | Already fixed (Sprint A Fix 2) | Correct |

### Summary of Remaining Fixes Required

| File | Line | Current | Correct | Priority |
|---|---|---|---|---|
| `IntelligencePage.jsx` | 254 | `label: 'Risk Level'` | `label: 'Security Rating'` | High |
| `PortfolioPage.jsx` | 176 | `<th>Risk Rating</th>` | `<th>Security Rating</th>` | High |
| `PortfolioPage.jsx` | 197 | `<RiskBadge level={...}>` | `<RatingBadge rating={...}>` | High |
| `ScanDetail.jsx` | 41 | `// ── Risk level config` | `// ── Security Rating config` | Low |

---

## 5 — Evidence Badge Root Cause

### Investigation Result

The P4 change (Tier 1 Trust Fixes sprint) **correctly removed** the Evidence quality badge from `ScanDetail.jsx`. The Phase 3 JSX block (lines 394–397) was replaced with a comment explaining the removal. Verified: no `evidence_quality` rendering exists in `FindingCard`, `FreeScanPage.jsx`, or any other finding-display component in the codebase.

### Root Cause of Continued Appearance

The "Evidence: Excellent" badge the user observes is **not the evidence_quality badge** — it is the **Validation quality badge (Phase 2)**, which was intentionally retained. This badge displays:

```
Validation: Excellent
```

when `f.validation_quality === "excellent"`. The label prefix "Validation:" can be misread as "Evidence:" especially at small font size (10px).

**Evidence:** The Phase 2 badge (line 388–392 of ScanDetail.jsx) remains:
```jsx
{f.validation_quality && (
  <span>Validation: {qualityLabel(f.validation_quality)}</span>
)}
```

`qualityLabel("excellent")` returns `"Excellent"`. The badge renders as `Validation: Excellent` in green. Visually similar to the removed `Evidence: Excellent` badge.

### Fix Options

**Option A — Rename "Validation:" prefix to something more distinct**

Change `Validation: Excellent` → `Probe Quality: Excellent` or `Source: Verified`

This makes it clear the badge refers to the probe source quality, not a general "evidence" assessment.

**Option B — Remove the Validation quality badge (same logic as P4)**

`validation_quality` is a different measure from `evidence_quality` but suffers the same conceptual problem: it's an internal engineering metric that customers cannot interpret without a legend. Remove it for the same reasons P4 removed the evidence badge.

If removed, the only remaining trust signal on a finding card would be the confidence badge (numeric + color).

**Option C — Keep as-is, acknowledge it's misidentified**

No customer harm — the Validation badge is green "Excellent" for well-evidenced findings. The confusion is cosmetic. Lowest-effort resolution.

**Recommendation: Option B.** The `validation_quality` badge has the same structural-vs-substantive conflation problem as `evidence_quality`. Removing it produces a cleaner finding card: confidence badge only for trust signalling, full evidence panel for detail. This is consistent with the evidence framework direction from the audit.

### Fix Location

File: `frontend/src/pages/ScanDetail.jsx` lines 387–392

Remove:
```jsx
{/* Phase 2 — Validation quality badge */}
{f.validation_quality && (
  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${QUALITY_STYLE[f.validation_quality] || QUALITY_STYLE.weak}`}>
    Validation: {qualityLabel(f.validation_quality)}
  </span>
)}
```

---

## 6 — Implementation Plan

### Phase 1 — Terminology Fixes (immediate, no design risk)

Changes are additive label updates. Two files. No logic changes.

| Task | File | Effort |
|---|---|---|
| Fix `label: 'Risk Level'` → `label: 'Security Rating'` | `IntelligencePage.jsx` | < 5 min |
| Fix `<th>Risk Rating</th>` → `<th>Security Rating</th>` | `PortfolioPage.jsx` | < 5 min |
| Replace `RiskBadge` with `RatingBadge` for posture | `PortfolioPage.jsx` | ~15 min |
| Remove Validation quality badge | `ScanDetail.jsx` | < 5 min |

**Commit:** `fix(ux): align Security Rating terminology — IntelligencePage, PortfolioPage, ScanDetail`

---

### Phase 2 — Header Consolidation (Worker change, medium effort)

Requires Worker changes and BRS compatibility update. Deploy together in one Worker release.

| Task | File | Effort |
|---|---|---|
| Collect Branch C headers, emit `security_headers_not_observed` | `index.js` | ~1 hour |
| Update BRS to read `_headers_absent` from consolidated finding | `index.js` | ~30 min |
| Add `ACADEMY_LINK_MAP` entry for `security_headers_not_observed` | `index.js` | 5 min |
| Add `REMEDIATION_INTEL` card for consolidated finding | `index.js` | 15 min |
| Syntax check and validate | — | 10 min |

**Commit:** `feat(findings): consolidate Branch C header observations into single finding`

**Expected impact:** 4–5 fewer finding cards per scan on typical CDN-hosted domains. Headline finding count reduced from ~7 to ~4 for blackbullbarbers.co.uk equivalent.

---

### Phase 3 — Observation Model & Finding Count (larger scope, requires approval)

This phase introduces `finding_type` as a first-class field and requires both Worker and frontend changes.

| Task | Scope | Effort |
|---|---|---|
| Add `finding_type: "finding" | "observation"` to all findings in Worker | `index.js` | ~2 hours |
| Update API count fields to separate findings from observations | `index.js` | ~1 hour |
| Frontend: separate Observations section in ScanDetail | `ScanDetail.jsx` | ~3 hours |
| Frontend: update dashboard/portfolio count display | Multiple pages | ~2 hours |

**Pre-condition:** Requires explicit approval on Option 1/2/3 from section 3 above.

**Suggested commit:** `feat(findings): introduce finding_type field and split Finding/Observation display`

---

### Phase 4 — DKIM Provider Detection (per P6 design spike)

Deferred. Reference: `docs/tier1-design-spikes-v1.md`, P6 section. Implement after Phase 2 is validated.

---

### Priority Order

```
Phase 1 (terminology) → now
Phase 2 (header consolidation) → after Phase 1 is merged
Phase 3 (observation model) → after design approval
Phase 4 (DKIM) → after Phase 2 is stable
```

---

## Appendix — blackbullbarbers.co.uk Finding Count Projection

| Sprint | Finding count | Notes |
|---|---|---|
| Pre-Tier-1 | 8 | Original state |
| Post-Tier-1 (P1–P4 applied) | 7 | HTTP redirect finding suppressed (P1) |
| Post-Phase-2 (header consolidation) | 4 | 4 header findings → 1 |
| Post-Phase-3 (observation model) | 3 Findings + 1 Observation | DMARC p=none, DNSSEC, DKIM classified separately |

Score: 95/100 throughout. No score changes at any phase.

---

*Finding Noise Reduction & Observation Consolidation — Design v1 — June 2026*
