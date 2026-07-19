-- 097 — Stripe webhook idempotency STATE (Q3 closure).
--
-- The webhook recorded a processed-event marker (069) BEFORE running the event's
-- side effects. A side-effect failure mid-handler returned 500 for Stripe to retry,
-- but the retry hit the already-present marker and was short-circuited to
-- 200 { deduped } WITHOUT re-running the side effects — permanently suppressing the
-- retry and leaving entitlement state drifted (e.g. a cancellation whose audit write
-- succeeded but whose subscription downgrade failed).
--
-- This adds a lifecycle status so the marker is a CLAIM, not a completion:
--   'processing' — claimed; side effects in flight (or a crashed attempt).
--   'completed'  — all side effects succeeded; a duplicate delivery is safely skipped.
--   'failed'     — side effects failed; the next Stripe retry re-claims and re-runs.
-- processed_at doubles as the claim/transition timestamp so a stale 'processing' row
-- (a crashed attempt) can be re-claimed by a later retry after a lease interval.
--
-- Additive and backward-compatible. Existing rows default to 'completed' — under the
-- old code every recorded marker meant "already handled", so preserving that as the
-- historical semantic keeps replay protection intact for pre-migration events.
-- Applied BEFORE the dependent Worker deploy.

ALTER TABLE stripe_processed_events
  ADD COLUMN status TEXT NOT NULL DEFAULT 'completed';

-- Retry scans look up by (id) [PK, already indexed]; no additional index needed.
