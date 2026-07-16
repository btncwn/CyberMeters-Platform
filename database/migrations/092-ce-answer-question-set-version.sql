-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 092: persist the question-set version an answer was given under
-- ─────────────────────────────────────────────────────────────────────────────
--
-- CE Questionnaire Hygiene increment. Additive only: one nullable column plus a backfill.
--
-- WHY THIS IS NEEDED (the schema was genuinely insufficient).
-- `cyber_essentials_answers` records WHAT the customer answered but not WHICH QUESTION they
-- were asked. The wording is not frozen — this very migration ships alongside a reworded set
-- (`2026-07` → `2026-07-16`), where for example the urgent-patch question moved from the
-- unanswerable "applied quickly when flagged as important?" to the actual Cyber Essentials
-- expectation, "applied within 14 days of release?".
--
-- Those are different questions. A stored "yes" to the old one is NOT a "yes" to the new one,
-- and without a version column there is no way to tell them apart — the product would silently
-- reinterpret an old answer as an answer to a question the customer never saw. That is the
-- same class as every other evidence-honesty defect this platform has closed: presenting
-- something as evidence for a claim it does not support.
--
-- HISTORICAL INTEGRITY. Existing answers KEEP their original version. They are backfilled to
-- '2026-07' — the version that was live when they were written — and are never rewritten to
-- the current one. An answer is evidence about the question that was actually asked.
--
-- NOT NULL is deliberately NOT used: D1/SQLite cannot add a NOT NULL column without a default
-- to an existing table, and a DEFAULT of the CURRENT version would silently stamp future
-- inserts with whatever the default said at migration time rather than what the writer meant.
-- The writer sets it explicitly (routes/workspace-analytics.js); a NULL therefore means
-- "written before 092", which the backfill below resolves to '2026-07'.
--
-- Rollback:
--   Leave the column in place; roll back APPLICATION CODE only. The column is nullable and
--   nothing reads it as a precondition, so an older Worker simply stops writing it.
--   (D1/SQLite has no DROP COLUMN path, and none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/092-ce-answer-question-set-version.sql

ALTER TABLE cyber_essentials_answers ADD COLUMN question_set_version TEXT;

-- Backfill: every row that exists today was answered under the set that was live before this
-- migration. Scoped to NULL so re-running the migration cannot overwrite a version a newer
-- writer has already set.
UPDATE cyber_essentials_answers
   SET question_set_version = '2026-07'
 WHERE question_set_version IS NULL;
