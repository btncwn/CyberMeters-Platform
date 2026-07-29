# Phase-5 Historical Customer-Read Inventory

Audit date: 2026-07-29
Implementation base: `9f2014994ecd3e57c6ec2cf64da2cbac4dec904a`

## Boundary and shared design

This inventory covers customer reads that can expose the frozen Cyber Metrics
Score, rating/risk band, or an unqualified clean risk narrative from a D1 scan
row, an R2 scan report, or an immutable M5.c snapshot.

Storage remains immutable. `resolvePhase5HistoricalCustomerProjection()` is the
single customer-assessment decision. It reuses
`resolvePhase5CustomerAssessment()` and the canonical
`isPublishableModuleEvidence()` contract. The R2/D1 adapters load the stored
Phase-5 module evidence, project missing modules as explicit unavailable
placeholders, and withhold only the customer conclusion when any required
evidence is not publishable. Observed findings and trustworthy sibling evidence
are retained.

The shared D1-to-R2 adapter deduplicates scan IDs, permits at most 100 stored
evidence reads per invocation, and runs at most eight reads concurrently. A
read failure, missing object, missing scan ID, unavailable binding, or identity
beyond the fixed bound is projected as incomplete with null score/rating.
Responses expose `phase5_evidence_coverage`; aggregate resolvers additionally
withhold the aggregate when all candidate rows cannot be assessed honestly.

The M5.c snapshot reader now exposes two views:

- `snapshot`: parsed immutable bytes, still checksum-gated and used by the
  verbatim endpoint;
- `customerSnapshot`: a separately derived presentation object used by customer
  report renderers.

## Customer-consumer inventory

| Customer surface / consumer | Stored source | Incomplete Phase-5 reachable before correction | Customer correction | Proof |
| --- | --- | --- | --- | --- |
| `GET /api/scans` and Dashboard recent scans/trend | D1 `scans.score/rating`, with R2 report available by scan ID | Yes; a complete-quality historical D1 row could show `100` / `excellent` | Project every completed row through stored Phase-5 evidence; incomplete rows carry null score/rating and partial/degraded assessment | Historical route fixture; Dashboard consumes the projected list contract |
| `GET /api/scans/:id` | D1 scan row | Yes | Same D1-row projection | Historical route fixture |
| `GET /api/scans/domain/:domain/history` | D1 scan rows | Yes | Same D1-row projection | Shared route adapter plus regression gate |
| `GET /api/scans/:id/report` and `ScanDetail` | Immutable snapshot plus R2 report modules | Yes; snapshot score/band and R2 `risk_intelligence` Low/clean narrative remained publishable | Use `customerSnapshot`; project module flags/placeholders; null Low/clean narrative when the shared contract is incomplete | Historical, missing, completed-zero and positive route fixtures |
| `IntelligencePage` | Scan-list D1 row plus projected report | Yes; it selected stale list score/rating and missing modules/counts failed open | Report is assessment authority; frontend accepts only `evidence_publishable === true`; missing counts render `—` | Route-to-UI test and pinned mutants M1, M4, M5 |
| Executive scan report v2 | Immutable snapshot | Yes | Read `customerSnapshot` | Historical executive-route fixture and mutant M7 |
| Per-scan PDF | Immutable snapshot | Yes | Read `customerSnapshot`; show existing incomplete disclosure and retain findings | Historical PDF text fixture |
| Workspace Executive PDF | Latest immutable snapshots | Yes | Replace only each renderer view with `customerSnapshot` | Historical workspace-PDF text fixture |
| Workspace scorecard PDF-data API | Latest immutable snapshots | Yes | Return customer snapshots; integrity metadata explicitly states that the checksum scopes the immutable snapshot | M5.d route contract plus checksum/customer-projection fixture |
| `current-posture.js` and all headline consumers | D1 candidate plus R2 report | Yes; `scan_quality='complete'` alone could establish a healthy posture | A candidate becomes authoritative only when Phase-5 evidence is publishable | Incomplete and completed-zero posture controls |
| `scorecard.js` / Workspace Scorecard | D1 candidate plus R2 report | Yes; score and “No critical or high-severity findings” could be published | Reuse historical projection for the score and gate the clean summary | Historical scorecard fixture |
| Executive Dashboard headline, score trend and delta | Current-posture projection plus `historical_scores` D1 rows | Yes | Headline delegates to current posture; trend/delta rows are Phase-5 projected by `scan_id` | Historical dashboard route fixture |
| Workspace detail stats and domain rows | D1 `scans` rows | Yes | Project latest-per-domain average, latest scan, and per-domain latest score/rating | Shared adapter; canonical-presentation and historical route governance |
| Workspace insights summary | D1 latest-complete rows | Yes | Project rows before averaging | Shared adapter and regression gate |
| Attack Surface rolling risk trend | D1 completed scan rows | Yes | Project each period before averaging | Shared adapter and exposure-honesty/regression gates |
| Portfolio overview | D1 latest-per-domain rows | Yes | Project individual candidates before averaging | Shared adapter and portfolio validators |
| Portfolio customers and executive summary | D1 latest-per-domain rows | Yes | Project individual rows before customer average/rating | Portfolio and read-purity validators |
| Portfolio score trends | D1 completed scan rows | Yes | Project individual rows before daily aggregate/min/max | M5.e and portfolio validators |
| `GET /api/portfolio/domains` | D1 latest scan row plus R2 evidence | Yes | Project scan row before `overall_score` / `overall_rating`; expose bounded-read coverage | Authenticated historical incomplete and completed-zero list fixture |
| `GET /api/portfolio/domains/:workspaceId/:domainId` | D1 latest scan row plus R2 evidence | Yes; the detail call omitted `{ env }` while the list supplied it | Use the exact list projection call; retain workspace authorization and non-enumerating 404 behavior | Authenticated list/detail parity fixture and pinned mutant M8 |
| Portfolio risk / BRS current and historical comparison | Persisted BRS plus basis/latest D1 scan rows and R2 reports | Yes; stored BRS could retain a healthy basis whose Phase-5 evidence is incomplete | Existing BRS projection now receives Phase-5-projected basis/latest rows; oldest comparison point is also gated | BRS honesty and portfolio-risk validators |
| Business-risk trend read | Persisted BRS plus basis/latest D1 scan rows | Yes | Same shared scan-row projection before `resolveWorkspaceBrsProjection()` | BRS partial-scan fixture |
| Historical scan comparison | Previous D1 score plus R2 report | Yes; false score could become a delta baseline | Historical projection must approve the prior score before comparison | Missing-legacy historical fixture |

## Intentionally excluded stored/internal surfaces

| Surface | Reason |
| --- | --- |
| R2 `reports/:scanId.json` objects | Immutable scan-time evidence. No object is rewritten. Customer routes project it at read time. |
| D1 `scans.score/rating`, `historical_scores`, findings and lifecycle rows | Historical/audit storage. No row is rewritten or reclassified. |
| `GET /api/scans/:id/snapshot` | The checksum-gated M5.c verbatim contract. It returns `read.snapshot`, never `customerSnapshot`. |
| `readScanReportSnapshot().raw` and `.snapshot` | Internal immutable/checksum view retained for audit and tamper evidence. Customer renderers use the separate projection. |
| Non-assessment risk fields (finding severity, asset/vendor/brand/certificate risk) | These describe observed sibling evidence, not the Phase-5 whole-assessment score/rating/clean conclusion. Suppressing them would hide trustworthy evidence. |
| Public free-scan preview | It executes a separate bounded coverage contract and already nulls score/risk unless all of its required modules complete. It does not read the historical Phase-5 objects in scope. |

## Production attribution procedure

`scripts/extract-phase5-historical-attribution.js` is the exact committed
extraction procedure. Its fixed read-only D1 query selects at most 57
partial/degraded completed scans with frozen `excellent` or score `>= 90`;
`LIMIT 58` makes cohort growth fail instead of truncating silently. It reads
only the corresponding immutable R2 objects, sequentially, deletes raw
temporary files, refuses to write inside the repository, and emits no scan,
workspace, tenant, domain or report identifier. Its recorded invocation is:

```sh
node scripts/extract-phase5-historical-attribution.js \
  --remote --expected=57 \
  --output=/tmp/phase5-candidate-evidence.json
```

`scripts/analyze-phase5-historical-attribution.js` then accepts only that
sanitised evidence-only local extraction and emits aggregate counts. The
recorded bounded cohort is checked by
`scripts/fixtures/phase5-historical-attribution-aggregate.json`:

- Phase-5 deadline exceeded: 16 — **PROVEN** by stored module outcome;
- incomplete/unexecuted without deadline outcome: 29 — **PROVEN** by stored
  module state, but no deadline/provider cause is claimed;
- fully completed: 12 — **PROVEN** by the canonical publishability contract;
- unattributable from historical contract: 0 in this bounded cohort.

It is **NOT PROVEN** that all 57 reports were caused by the Phase-5 deadline.
Only 16 carry that stored outcome. The analyser performs no network request.
The extractor performs only the bounded D1/R2 reads described above and
contains no production write command; neither step reclassifies tenants or
mutates reports.
