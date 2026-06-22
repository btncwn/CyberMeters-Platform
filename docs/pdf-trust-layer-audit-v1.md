# CyberMeters PDF Trust Layer Audit v1

**Sprint 9F — PDF Trust Layer Audit**
**Date:** June 2026
**Status:** Audit complete — implementation to follow

---

## Overview

Sprint 9A–9D introduced a finding schema v2 with three trust fields (`confidence`, `validation_quality`, `evidence`). Sprint 9E.2 surfaced these fields in `ScanDetail.jsx`. This audit documents where findings enter the PDF pipeline, which trust fields are available at each stage, and what changes Sprint 9F must make.

**Constraint:** No database schema changes. No scan engine changes. No API contract changes (except adding fields to `top_risks` array, which is an additive, non-breaking extension).

---

## Pipeline Overview

```
D1 findings table           R2 scan report JSON
     │                             │
     │ (title, severity,           │ (normalizedFindings:
     │  recommendation,            │  all v2 trust fields)
     │  domain, created_at)        │
     └──────────┬──────────────────┘
                │
         collectPdfData()
                │
         pdfData object
                │
         buildExecutivePdf()
                │
         PDF bytes → R2 + response
```

---

## Stage 1: D1 `findings` Table

**Schema** (from `database/schema.sql` lines 30–38):

```sql
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    recommendation TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

**Trust fields in D1:** None. `confidence`, `validation_quality`, `evidence_quality`, and `evidence` are NOT stored in the `findings` table. They are computed at scan time by `normalizeFindingSchema()` and written only to the R2 scan report JSON.

---

## Stage 2: R2 Scan Report JSON

Each completed scan stores a full JSON report at `reports/${scanId}.json` with:

```json
{
  "status": "completed",
  "findings": [
    {
      "id": "...",
      "title": "...",
      "severity": "...",
      "score_impact": ...,
      "module": "...",
      "confidence": 90,
      "validation_quality": "good",
      "evidence_quality": "excellent",
      "evidence": [{ "type": "...", "label": "...", "value": "...", "source": "...", "checked_at": "...", "manual_verification_command": "..." }],
      "remediation_owner": "..."
    }
  ],
  "modules": { ... }
}
```

**Trust fields in R2:** All trust fields are present in `report.findings` after `normalizeFindingSchema()` is applied. This is the authoritative source for per-finding trust data.

---

## Stage 3: `collectPdfData()` — lines 15063–15513

`collectPdfData(wsId, env)` assembles the PDF data object from D1 + R2.

### `top_risks` — lines 15215–15235

SQL query (line 15075):
```sql
SELECT f.title, f.severity, f.recommendation, s.domain, s.created_at
FROM findings f
JOIN scans s ON s.id = f.scan_id
JOIN domains d ON d.id = s.domain_id
JOIN workspace_domains wd ON wd.domain_id = d.id
WHERE wd.workspace_id = ?
ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ...
LIMIT 200
```

Output per entry:
```js
{
  title:          r.title          ?? '',
  severity:       r.severity       ?? 'medium',
  recommendation: r.recommendation ?? '',
  domain:         r.domain         ?? null,
  date:           r.created_at.slice(0, 10),
}
```

**Trust fields discarded here:** The SQL query does not select `confidence`, `validation_quality`, `evidence_quality`, or `evidence` — because the `findings` table does not store them. Trust enrichment must come from R2.

### `findings_summary` — lines 15237–15246

Counts only: `{ critical, high, medium, low, info, total }`. No individual finding objects.

### R2 access in `collectPdfData()`

`collectPdfData()` calls `buildScorecardData(wsId, env)` which fetches **one** R2 report (the latest scan in the workspace, line 12290). This is used for module-level data (saas_exposure, admin_surface_detection, etc.) only — not for finding trust fields.

---

## Stage 4: `buildExecutivePdf(pdfData)` — lines 14225–15058

Pure function. Renders 10-page US-Letter PDF from `pdfData`.

### `topR` — line 14371

```js
const topR = pdfData.top_risks ?? [];
```

**Finding:** `topR` is declared but **never rendered** in any of the 10 PDF pages. The variable is unused. Top risks are present in the data payload but produce no PDF output.

### Current finding-related rendering

| Page | What renders | Fields used |
|------|-------------|-------------|
| Page 1 (Cover) | Findings Snapshot boxes | `fs.critical`, `fs.high`, `fs.medium`, `fs.low` (counts only) |
| Page 2 (Executive Summary) | Findings Summary section | `fs.critical`, `fs.high`, `fs.medium`, `fs.low`, `fs.info`, `fs.total` (counts only) |
| Pages 3–10 | No findings | — |

Trust fields (`confidence`, `validation_quality`, `evidence_quality`, `evidence`) are rendered in **zero** PDF pages.

---

## Breaking Compatibility Issues

None — the `top_risks` array currently has no trust fields, so adding them is purely additive. `buildExecutivePdf()` ignores unknown fields on `top_risks` entries. The PDF API response (`/scorecard/pdf`) is bytes, not JSON, so no contract break.

The `/scorecard/pdf-data` JSON endpoint exposes `pdfData` directly. Adding fields to `top_risks` entries is an additive, non-breaking change.

---

## Sprint 9F Implementation Plan

### Phase 2 — Enrich `top_risks` in `collectPdfData()`

After `top_risks` is built (line 15235), add:

1. Extract unique domains from `top_risks`
2. For each domain, query D1 for the latest completed `scan_id`
3. Fetch `reports/${scanId}.json` from R2 in parallel (`Promise.allSettled`)
4. Build lookup: `Map<domain, Map<title_lowercase, {confidence, validation_quality, evidence_quality, evidence}>>` from `report.findings`
5. Merge trust fields onto each `top_risks` entry by `domain` + `title.toLowerCase()` match
6. Tolerate failures gracefully — trust fields are `null` if R2 is unavailable

**R2 subrequests added:** At most 1 per unique domain in `top_risks` (typically 1–5 domains). Each subrequest is in parallel. No serial chains.

### Phase 3–7 — Add "Top Security Findings" page to PDF

Add a new page (Page 5, shifting Attack Surface to Page 6, ..., Methodology to Page 11). Update `NP` from `10` to `11`.

Per finding row renders:
- **Phase 3 — Trust badges:** Severity pill | Confidence tier (e.g., "90 Verified") | Validation Quality | Evidence Quality
- **Phase 4 — Evidence summary:** Up to 3 items from `finding.evidence`, rendered as `type: label` lines
- **Phase 5 — Verification command:** First `evidence[i].manual_verification_command`, monospace block
- **Phase 6 — Low confidence warning:** "Needs Verification" amber banner when `confidence < 70`

Add trust quality overview to Page 2 (Executive Summary):
- **Phase 7:** "X findings verified (≥90) / Y strong evidence (80–89) / Z needs review (<70)"

### Phase 8 — No duplicate PDF generators

`buildExecutivePdf()` is the only PDF renderer in the codebase. `generateWorkspaceExecutiveReport()` calls `collectPdfData()` → `buildExecutivePdf()`. Workspace and executive reports both use the same pipeline. No duplicate implementation needed.

---

## Summary

| Stage | Trust fields available? | Notes |
|-------|------------------------|-------|
| D1 `findings` table | No | Schema has no trust columns |
| R2 scan report JSON | Yes — all fields | `report.findings` after `normalizeFindingSchema()` |
| `collectPdfData()` top_risks | No (Sprint 9F adds them) | Requires R2 enrichment step |
| `buildExecutivePdf()` topR | Never rendered (Sprint 9F adds rendering) | `topR` declared but unused |
| PDF output | None currently | Sprint 9F adds page 5 + executive summary section |

---

## Files to Change in Sprint 9F

| File | Change |
|------|--------|
| `workers/scan-api/src/index.js` | `collectPdfData()`: R2 trust enrichment after top_risks build |
| `workers/scan-api/src/index.js` | `buildExecutivePdf()`: NP 10→11, new page 5, trust overview on page 2 |
| `docs/pdf-trust-layer-audit-v1.md` | This file |

No frontend changes. No database changes. No scan engine changes.
