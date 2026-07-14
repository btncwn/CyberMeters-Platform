-- ── 084-shadow-it-monitoring.sql ──────────────────────────────────────────
-- Shadow IT inventory: derived ownership status + the monitoring evaluator's
-- persisted output. Additive only; nullable columns. Ownership status is DERIVED
-- (server-side) from business/technical owners — it is NOT a customer
-- classification. Monitoring fields are the deterministic evaluator's snapshot.

-- Derived ownership status (known | partial | missing) — separate from the
-- customer `classification`.
ALTER TABLE shadow_it_inventory ADD COLUMN ownership_status TEXT;

-- Monitoring evaluator snapshot.
ALTER TABLE shadow_it_inventory ADD COLUMN monitoring_reason TEXT;
ALTER TABLE shadow_it_inventory ADD COLUMN evidence_age_days INTEGER;
ALTER TABLE shadow_it_inventory ADD COLUMN material_change INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shadow_it_inventory ADD COLUMN recurrence_type TEXT;
ALTER TABLE shadow_it_inventory ADD COLUMN required_case_action TEXT;
ALTER TABLE shadow_it_inventory ADD COLUMN evaluated_at TEXT;

-- Removal verification state: a customer `removal_status = 'removed'` is an
-- assertion; if the technology is still observed the assertion is CONTRADICTED
-- (never silently overwritten). null | verified | contradicted | unverified.
ALTER TABLE shadow_it_inventory ADD COLUMN removal_verified TEXT;
