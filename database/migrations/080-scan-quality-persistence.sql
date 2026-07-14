-- ── 080-scan-quality-persistence.sql ─────────────────────────────────────────
-- Persist assessment coverage quality to D1 so authoritative-current-posture and
-- trend selection can be completeness-aware without re-reading R2 (partial-scan
-- honesty). scan_quality ∈ complete | partial | degraded | unknown. Additive only —
-- no DROP, no rewrite. **NULL means unknown** (legacy compatibility); NULL is NEVER
-- treated as complete anywhere in code. Backfill is a separate one-time auditable
-- deployment script (scripts/backfill-scan-quality.js) that reads canonical R2
-- reports — never inferred from status/score/rating/findings.
ALTER TABLE scans             ADD COLUMN scan_quality TEXT;
ALTER TABLE historical_scores ADD COLUMN scan_quality TEXT;
