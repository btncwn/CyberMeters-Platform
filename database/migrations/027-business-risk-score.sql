-- ── 027-business-risk-score.sql ─────────────────────────────────────────────
-- Adds BRS (Business Risk Score) column to historical_scores for trend tracking.
-- BRS is an executive-facing risk score separate from the ASM technical score.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/027-business-risk-score.sql
--
-- Rollback: D1 (SQLite) does not support DROP COLUMN.
--   To roll back, leave the column in place; the application will stop writing to it.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE historical_scores ADD COLUMN brs_score INTEGER;
