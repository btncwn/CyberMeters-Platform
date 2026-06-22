# CyberMeters Trust Layer UI Audit v1

**Sprint 9E — Trust Layer UI Audit**
**Date:** June 2026
**Status:** Audit complete — no code changes in this sprint

---

## Overview

Sprint 9A–9D introduced a finding schema v2 with three new trust fields:

| Field | Type | Source |
|---|---|---|
| `confidence` | `number` (0–100) | Sprint 9B — `resolveConfidence()` |
| `validation_quality` | `string` (`excellent`/`good`/`partial`/`weak`) | Sprint 9D — set at finding creation |
| `evidence` | `array` of `{type, label, value, source, ...}` | Sprint 9C — `buildEvidenceArray()` |

This audit identifies every location where findings are rendered across the platform, documents what fields each location currently uses, and recommends where and how to surface the new trust indicators.

**Constraint:** No code changes in this sprint. Audit and recommendations only.

---

## Locations Audited

1. ScanDetail.jsx — scan-level finding detail view
2. Dashboard.jsx — workspace overview
3. WorkspaceExecutiveDashboard.jsx — executive summary view
4. WorkspaceScorecard.jsx — security posture scorecard
5. WorkspaceReportsPage.jsx — report archive view
6. IntelligencePage.jsx — risk intelligence, email intel, tech detection panels
7. PortfolioPage.jsx / PortfolioRiskPage.jsx — portfolio-level views
8. Executive PDF (buildExecutivePdf in Worker) — exported PDF report

---

## 1. ScanDetail.jsx

**Primary location for individual finding display.** The `FindingsPanel` renders a list of finding objects via `FindingRow` and `EvidencePanel`.

### Current fields displayed

| Component | Fields rendered |
|---|---|
| `FindingRow` | `f.title`, `f.description`, `f.severity` (badge), `f.score_impact` (if non-zero), evidence toggle |
| `EvidencePanel` | `evidence.evidence_type`, `evidence.probe_target`, `evidence.observed_value`, `evidence.expected_value`, `evidence.source`, `evidence.checked_at`, `evidence.status_code`, `evidence.missing_header`, `evidence.manual_verification_command` |
| `EvidencePanel` header | `f.confidence` (rendered as string badge using `CONFIDENCE_STYLE`) |

### Available fields after Sprint 9A–9D

All of: `title`, `description`, `severity`, `score_impact`, `module`, `confidence` (numeric), `validation_quality`, `evidence` (array), `remediation_owner`.

### Recommended trust indicators

- `confidence` → numeric tier badge in `FindingRow` metadata row (e.g., "80 — Good")
- `validation_quality` → inline badge in `FindingRow` metadata row
- `evidence` → `EvidencePanel` rendered from array (each array item as a row)
- `remediation_owner` → below description (future)

### Compatibility breaks from Sprint 9B/9C — BUGS, NOT FEATURES

These are existing rendering failures that the UI sprint must fix before adding new indicators:

**Break 1 — Confidence badge always gray (Sprint 9B)**

`CONFIDENCE_STYLE` at line 124 maps string keys `"high"`, `"medium"`, `"low"` to CSS classes. After Sprint 9B, `f.confidence` is numeric (e.g., 90, 70, 60). `CONFIDENCE_STYLE[90]` is `undefined`, so every finding falls back to `CONFIDENCE_STYLE.low` (gray). The confidence badge is always gray regardless of actual confidence.

The `confidence === 'low'` string check at line 171 (EvidencePanel warning) also never matches numeric values. The "needs manual verification" callout never renders.

Fix: replace `CONFIDENCE_STYLE` string keys with a numeric tier mapping function (e.g., `>= 80 → green`, `>= 70 → amber`, `< 70 → gray`).

**Break 2 — EvidencePanel renders empty (Sprint 9C)**

`EvidencePanel` is called at line 222 with `evidence={{ ...f.evidence, evidence_quality: evidenceQuality }}`. After Sprint 9C, `f.evidence` is always an array (e.g., `[{type, label, value, source}]`). Spreading an array produces `{ 0: {...} }` — not the object field names `EvidencePanel` expects. All row checks (`evidence.evidence_type`, `evidence.probe_target`, etc.) evaluate to `undefined`. The panel renders with zero rows.

Fix: `EvidencePanel` must accept the new array format and render each item as a labeled row.

**Break 3 — Evidence toggle always shown (Sprint 9C)**

`hasEvidence = !!f.evidence` at line 192. After Sprint 9C, `f.evidence` is always a non-empty array. The evidence toggle now renders on every finding, including those where evidence was previously absent (Case C findings). This is functionally acceptable since evidence is always present, but the toggle label may feel misleading on low-information findings where evidence is purely derived from the description field.

**Break 4 — `validateFindingEvidence()` produces wrong evidence_quality (Sprint 9C)**

The legacy `validateFindingEvidence()` function (line ~680) checks evidence as an object: `evidence.source`, `evidence.probe_target`, `evidence.observed_value`, etc. After Sprint 9C, `f.evidence` is an array. All object-field checks return `undefined`. The function accumulates 4–6 warnings per finding and returns `evidence_quality: "partial"` for every finding — including those with excellent direct-probe evidence. The `evidenceQuality` variable read in `FindingRow` is wrong for all findings.

Fix: `validateFindingEvidence()` must be updated to check the first element of the array (`f.evidence[0]`) rather than `f.evidence` directly.

---

## 2. Dashboard.jsx

**Overview dashboard — findings used for counts and a top-findings surface.**

### Current fields displayed

- Severity counts: `f.severity === 'critical'`, `f.severity === 'high'`, etc. (filter/count only)
- Top findings list: `f.title`, `f.severity` (mapped to a risk label)

### Available fields after Sprint 9A–9D

All v2 fields, but findings here are summary objects from the workspace scorecard, not normalized scan finding objects. They may not carry `confidence` or `validation_quality` depending on how they are sourced.

### Recommended trust indicators

None recommended for this view. The Dashboard is a high-level overview; adding confidence badges to aggregated counts would be misleading (the counts already represent confirmed findings at the scan level). Trust indicators belong in the detail view.

---

## 3. WorkspaceExecutiveDashboard.jsx

**Executive-facing summary — top risks table and findings distribution chart.**

### Current fields displayed

- `TopRisksTable`: `r.title`, `r.severity` (badge), `r.domain`, `r.detected_at`
- `FindingsDistributionChart`: aggregate severity counts only (no individual fields)

### Available fields after Sprint 9A–9D

The `top_risks` data is sourced from the workspace scorecard (`collectPdfData()`) which pulls `title`, `severity`, `recommendation`, `domain`, `date` from historical scan records. It does not include `confidence` or `validation_quality` — these would need to be added to the `collectPdfData()` query if desired.

### Recommended trust indicators

Not recommended in v1. The Executive Dashboard is designed for non-technical stakeholders. Confidence and validation quality are investigative signals, not executive metrics. If added, they should appear as a filter ("hide low-confidence findings") rather than per-row badges.

---

## 4. WorkspaceScorecard.jsx

**Security posture scorecard — section-level status, not individual findings.**

### Current fields displayed

`sec.title`, `sec.status`, `sec.summary` — these are report SECTIONS (e.g., "Email Security", "SSL & Certificates"), not individual finding objects. The recommendations surface shows `r.title`, `r.description`.

### Available fields after Sprint 9A–9D

The scorecard renders aggregated section-level data. Individual finding trust fields are not applicable here.

### Recommended trust indicators

None. The scorecard communicates security posture at the category level. Trust indicators are per-finding concepts and do not map to this surface.

---

## 5. WorkspaceReportsPage.jsx

**Report archive — sections and top recommendations, not individual findings.**

### Current fields displayed

- Section rows: `sec.title`, `sec.status`, `sec.summary`
- Recommendations: `r.priority`, `r.title`, `r.description`

### Available fields after Sprint 9A–9D

Not applicable — this view renders pre-aggregated report structure, not finding objects.

### Recommended trust indicators

None in v1. Recommendations could eventually show a confidence range ("based on 3 high-confidence findings"), but this requires data that doesn't exist yet.

---

## 6. IntelligencePage.jsx

**Risk intelligence, email security intelligence, and tech detection panels.**

### Current fields displayed

| Section | Fields rendered |
|---|---|
| `RiskIntelligenceSection` — category findings | `f.severity` (dot + badge), `f.title` |
| `EmailIntelSection` — email findings | `f.severity` (dot + badge), `f.title`, `f.description` |
| Tech version disclosure (`info_findings`) | `f.title`, `f.description` |

### Available fields after Sprint 9A–9D

Risk intelligence findings from `modules.risk_intelligence` and email intel findings from `modules.email_security_intelligence` carry full v2 schemas. `f.confidence`, `f.validation_quality`, and `f.evidence` are present but unused.

Note: Email intel findings (`modules.email_security_intelligence.findings`) are explicitly marked out of scope in the evidence framework audit (Sprint 9C doc, section 3). They are not processed by `normalizeFindingSchema()`. They carry `validation_quality` from Sprint 9D but evidence is not guaranteed to be in array format.

### Recommended trust indicators

`validation_quality` as a small inline badge next to the severity badge in the RiskIntelligenceSection and EmailIntelSection finding rows. This view is used by security analysts — they benefit from seeing "partial" or "weak" signals flagged inline without expanding to evidence detail.

`confidence` as a tooltip or secondary label is a lower-priority addition.

Evidence detail is not recommended for this panel — the panel is designed for scanning, not investigating.

---

## 7. PortfolioPage.jsx / PortfolioRiskPage.jsx

**Portfolio-level workspace aggregation views.**

### Current fields displayed

- `PortfolioRiskPage`: `AlertSeverityBar` with `a.severity` — aggregate alert objects, not scan findings
- `PortfolioPage`: workspace-level score cards, counts — no individual finding fields

### Available fields after Sprint 9A–9D

These views operate on workspace-level aggregates, not individual finding objects. Trust fields are not present.

### Recommended trust indicators

None. Portfolio views communicate risk across workspaces at a score/count level. Individual finding trust signals are not meaningful at this aggregation level.

---

## 8. Executive PDF (buildExecutivePdf in Worker)

**Generated PDF report — up to 10 pages, US-Letter format.**

### Current fields rendered

| PDF section | Fields used |
|---|---|
| Cover page | `findings_summary.critical`, `.high`, `.medium`, `.low` (counts only) |
| Executive Summary page | `es.strengths[]`, `es.weaknesses[]`, `es.priority_actions[]` (text strings) |
| Top Risks section | `r.title`, `r.severity`, `r.recommendation`, `r.domain`, `r.date` |
| Security Posture section | Posture category scores and statuses (not findings) |
| Business Risk section | BRS score, risk band, supply chain score, CE grade |

### Available fields after Sprint 9A–9D

The `collectPdfData()` function sources `top_risks` from workspace scorecard records. These records carry `title` and `severity` but the `confidence` and `validation_quality` fields from scan findings are not currently persisted or passed through to the PDF data payload.

### Recommended trust indicators

A confidence tier column in the Top Risks table is the highest-value PDF addition, but requires a backend change to include confidence in the `top_risks` array from `collectPdfData()`. Not recommended for v1 of the UI sprint.

In the longer term, a "Findings Quality" note in the executive summary (e.g., "X of Y findings are high-confidence based on direct verification") would be appropriate for an executive audience.

---

## Summary Table

| Location | Individual findings? | Currently shows trust fields? | Recommended in v1? |
|---|---|---|---|
| ScanDetail.jsx | Yes — full detail | Partially (broken) | Yes — primary target |
| IntelligencePage.jsx | Yes — compact list | No | Yes — `validation_quality` badge only |
| Dashboard.jsx | Yes — top findings (title + severity) | No | No |
| WorkspaceExecutiveDashboard.jsx | Yes — top risks table | No | No |
| WorkspaceScorecard.jsx | No — section aggregates | No | No |
| WorkspaceReportsPage.jsx | No — section aggregates | No | No |
| PortfolioPage.jsx | No — workspace aggregates | No | No |
| PortfolioRiskPage.jsx | No — alert aggregates | No | No |
| Executive PDF | Partial — top risks list | No | No (needs backend change first) |

---

## Final Recommendations

### (1) Best place to show confidence

**ScanDetail.jsx `FindingRow`** — the metadata row below the finding title already shows `score_impact`. A confidence tier label belongs here as a second item: e.g., `80 — Good evidence`. This is where analysts investigate findings and decide remediation priority. No other view is appropriate for per-finding confidence.

Numeric → tier label mapping:

| Range | Label | Display color |
|---|---|---|
| 90–100 | Verified | Green |
| 80–89 | Strong evidence | Green |
| 70–79 | Probable | Amber |
| 60–69 | Weak signal | Gray |
| < 60 | Unvalidated | Gray |

### (2) Best place to show evidence

**ScanDetail.jsx `EvidencePanel`** — already exists. Must be updated to render the new array format (`evidence[0]`, `evidence[1]`, ...). Each array item has `type`, `label`, `value`, `source`. These map directly to the existing row structure; only the data access pattern changes from `evidence.probe_target` to `evidence[0].label`.

Evidence is too verbose for any other surface. It is an investigative tool for analysts, not a summary element.

### (3) Best place to show validation_quality

**ScanDetail.jsx `FindingRow`** (primary) and **IntelligencePage.jsx finding rows** (secondary).

In ScanDetail, `validation_quality` belongs in the metadata row alongside confidence. It conveys the verification method quality in a single word that analysts can scan quickly: "excellent", "good", "partial", "weak".

In IntelligencePage, a `validation_quality` badge next to severity is the only practical trust indicator for that compact list format.

### (4) Risks of information overload

Adding trust fields to the wrong surfaces creates noise that erodes trust in the platform:

- **Aggregate views (Dashboard, Portfolio, Scorecard)** — confidence and evidence are per-finding concepts. Showing them at summary level would require averaging or filtering logic that doesn't exist and would mislead non-technical users.
- **Executive PDF** — executives interpret confidence as a quality assurance signal for the report itself, not for individual findings. Showing "60 — weak signal" in an executive report risks undermining the report's authority. Only aggregate quality statements belong in executive outputs.
- **All surfaces at once** — rolling out to every location simultaneously would make it impossible to validate user response. ScanDetail is the correct first scope.
- **EvidencePanel always open** — after Sprint 9C the evidence toggle renders on every finding. If the panel is also expanded by default, the ScanDetail page becomes very long. Keep evidence collapsed by default.

### (5) Recommended rollout order

**Phase 1 — Fix existing breaks (prerequisite, not a feature)**

These are bugs introduced by Sprints 9B and 9C that must be fixed regardless of trust layer work:

1. Fix `CONFIDENCE_STYLE` — replace string key lookup with numeric tier function
2. Fix `EvidencePanel` — accept `evidence` as array; render `evidence[0]` fields (or all items if multiple)
3. Fix `validateFindingEvidence()` in Worker — check `finding.evidence[0]` not `finding.evidence` (object checks)
4. Fix `confidence === 'low'` string check — replace with `confidence < 70` numeric check

**Phase 2 — Confidence + validation_quality in FindingRow (ScanDetail only)**

5. Add confidence tier label to `FindingRow` metadata row
6. Add `validation_quality` badge to `FindingRow` metadata row
7. Update EvidencePanel confidence display to use the numeric tier mapping

**Phase 3 — validation_quality in IntelligencePage**

8. Add `validation_quality` badge to RiskIntelligenceSection and EmailIntelSection finding rows
9. Consider whether "weak" findings should be visually de-emphasized (reduced opacity)

**Phase 4 — Executive PDF (requires backend work)**

10. Add `confidence` to `top_risks` array in `collectPdfData()`
11. Add confidence tier column to Top Risks table in `buildExecutivePdf()`
12. Add findings quality summary line to Executive Summary page

---

## Notes for UI Sprint

- Do not change `normalizeFindingSchema()`, `buildEvidenceArray()`, or any Worker logic in the UI sprint.
- The `CONFIDENCE_STYLE` fix and `EvidencePanel` array fix are the minimum viable changes to unblock any trust layer display at all.
- The `validateFindingEvidence()` Worker fix is a prerequisite for correct `evidence_quality` values. The Worker change is small (one line: `finding.evidence[0]` instead of `finding.evidence`) but requires a syntax check and deploy.
- `remediation_owner` is available in the finding schema but has no recommended display location in v1. It is a future addition for ticket-creation integrations.
