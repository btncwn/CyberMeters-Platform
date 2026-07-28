# Business Risk Score partial-scan reconciliation

Status: founder-gated. This runbook authorises no production write, backfill,
scan or deployment by itself.

## Why reconciliation is required

Before the partial-scan honesty corrective, every terminal `completed` scan could
replace `workspace_brs_scores` and append `workspace_brs_score_history`, including
a scan whose canonical `scan_quality` was not `complete`. The legacy payload named a
`latest_scan`, but did not carry the new `complete_scan/v1` basis contract.

The corrected read projection masks every legacy row whose complete basis cannot be
proven. It does not delete or rewrite historical data.

## Read-only production inventory

Inventory captured on 28 July 2026 from the production `cybermeters-db` remote D1
database. The Wrangler result reported `changes: 0`, `rows_written: 0` and
`changed_db: false`.

| Classification | Rows |
| --- | ---: |
| Persisted workspace BRS rows | 5 |
| Legacy basis quality provably complete | 0 |
| Legacy basis provably not complete | 4 |
| Legacy basis unprovable (missing/unmatched reference) | 1 |
| Rows whose latest terminal assessment is incomplete | 4 |
| Rows already carrying `complete_scan/v1` | 0 |

The four provably non-complete rows are the confirmed affected population. The
remaining row is not safe to publish either: its complete basis cannot be proven.
All five therefore remain masked until a new complete, founder-approved assessment
establishes the new basis contract.

The mask also propagates to direct BRS-derived consumers. While a workspace BRS is
unavailable, ASM maturity and the authoritative Supply Chain Score are incomplete
and non-numeric, and BRS-dependent compliance families are incomplete rather than
`low`. Independently observed vendor, concentration, asset, scan-cadence and
operational-resilience evidence remains visible. Legacy numeric supply-chain rows
may remain inert in D1 because migration 035 requires a non-null score; customer
reads recompute the completeness projection and portfolio reads require both an
assessed BRS and an assessed supply-chain payload before publishing that number.

Re-run the inventory read-only:

```sql
WITH brs AS (
  SELECT
    b.workspace_id,
    b.payload_json,
    CASE WHEN json_valid(b.payload_json)
      THEN json_extract(b.payload_json, '$.latest_scan.scan_id')
    END AS legacy_basis_scan_id
  FROM workspace_brs_scores b
),
classified AS (
  SELECT
    brs.*,
    s.id AS matched_scan_id,
    s.status AS basis_status,
    s.scan_quality AS basis_quality
  FROM brs
  LEFT JOIN scans s
    ON s.id = brs.legacy_basis_scan_id
   AND s.workspace_id = brs.workspace_id
),
latest AS (
  SELECT workspace_id, id AS latest_scan_id, status AS latest_status,
         scan_quality AS latest_quality
  FROM (
    SELECT workspace_id, id, status, scan_quality,
           ROW_NUMBER() OVER (
             PARTITION BY workspace_id
             ORDER BY created_at DESC, id DESC
           ) AS rn
    FROM scans
    WHERE status IN ('completed', 'failed')
  )
  WHERE rn = 1
)
SELECT
  COUNT(*) AS persisted_brs_rows,
  SUM(CASE
    WHEN legacy_basis_scan_id IS NOT NULL
     AND matched_scan_id IS NOT NULL
     AND basis_status = 'completed'
     AND basis_quality = 'complete'
    THEN 1 ELSE 0 END
  ) AS legacy_basis_quality_provably_complete,
  SUM(CASE
    WHEN legacy_basis_scan_id IS NOT NULL
     AND matched_scan_id IS NOT NULL
     AND (
       basis_status <> 'completed'
       OR COALESCE(basis_quality, 'unknown') <> 'complete'
     )
    THEN 1 ELSE 0 END
  ) AS legacy_basis_provably_not_complete,
  SUM(CASE
    WHEN legacy_basis_scan_id IS NULL OR matched_scan_id IS NULL
    THEN 1 ELSE 0 END
  ) AS legacy_basis_unprovable,
  SUM(CASE
    WHEN latest_status = 'failed'
      OR (
        latest_status = 'completed'
        AND COALESCE(latest_quality, 'unknown') <> 'complete'
      )
    THEN 1 ELSE 0 END
  ) AS rows_with_latest_incomplete_assessment,
  SUM(CASE
    WHEN json_valid(payload_json)
     AND json_extract(payload_json, '$.basis_contract') = 'complete_scan/v1'
    THEN 1 ELSE 0 END
  ) AS rows_on_new_basis_contract
FROM classified c
LEFT JOIN latest l ON l.workspace_id = c.workspace_id;
```

## Founder-gated reconciliation sequence

1. Deploy the reviewed corrective before any reconciliation. Its read projection is
   the safe mask: legacy/unproven stored numbers become unavailable without a
   destructive D1 update.
2. Re-run the query above and record the counts. Stop if the population differs from
   the approved reconciliation scope.
3. Do not copy an old score forward and do not recompute an old scan against current
   vendors/assets. That would create a mixed-time assessment.
4. For each founder-approved workspace, run one normal bounded assessment only when
   the complete scan prerequisites are expected to be available.
5. If the new scan is partial, leave the row masked and do not retry blindly.
6. If the new scan is complete, verify:
   - `workspace_brs_scores.payload_json.basis_contract = 'complete_scan/v1'`;
   - `basis_scan.scan_id` is the exact new scan;
   - that scan is terminal `completed` with `scan_quality = 'complete'`;
   - exactly one new `workspace_brs_score_history` row exists;
   - the customer API reports `state = 'assessed'` and the same basis scan.
7. Re-run the inventory. A reconciled row moves to
   `rows_on_new_basis_contract`; no direct backfill is needed.

## Rollback

The corrective is code-only. A Worker rollback restores the previous code but would
also restore the false-healthy read behavior, so rollback is appropriate only for a
more severe incident. No schema rollback exists or is required. This runbook performs
no direct production mutation.
