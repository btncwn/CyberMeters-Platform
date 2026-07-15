-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 088: Email Protection lifecycle events + sender monitoring state
-- ─────────────────────────────────────────────────────────────────────────────
--
-- PR-B3. Additive only. Email Protection is the FIRST alerting domain that had
-- no managed lifecycle at all: B1 and B2 wired alerts onto lifecycles that
-- already existed (certificate_lifecycle, identity_exposure, managed_cases).
-- Email had none, so this migration creates the append-only occurrence source
-- the canonical pipeline requires, and the minimum sender state a transition
-- guard needs.
--
-- WHY A DEDICATED TABLE (founder decision, 15 July 2026): audit_events must
-- NEVER become an occurrence adapter. It is retained as audit history only. An
-- occurrence identity has to be a row whose id and created_at are stable
-- forever; audit_events is a general-purpose log with different retention,
-- different write rules and no guarantee that one row means one transition.
--
-- WHY ONE TABLE FOR TWO RECORD FAMILIES: this is FORCED, not a preference.
-- LIFECYCLE_EVENT_SOURCES (alert-occurrence.js) maps one domain_key to exactly
-- one {table, fk, type_column}. Hosted DMARC records and DMARC sender sources
-- are both domain_key 'email_protection'. Two tables is not expressible — one
-- family would silently resolve no occurrence forever, which is precisely the
-- production defect PR-B1 found in Brand Protection and Attack Surface.
--
-- Honest scope: these rows record what CyberMeters OBSERVED and what state it
-- moved a record to. They are not proof a customer read anything, and not proof
-- that mail was delivered, blocked or spoofed.
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer,
--   email_protection_events simply stops receiving rows and the four new
--   email_sender_sources columns stay NULL — behaviour identical to
--   pre-migration. (D1/SQLite has no DROP COLUMN path here, and none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/088-email-protection-lifecycle.sql

-- ── email_protection_events — the append-only occurrence source ──────────────
--
-- One row per observed transition. Append-only: never updated, never deleted
-- except by workspace purge. The row id IS the occurrence identity and its
-- created_at IS when the condition began — which is why nothing here may ever
-- be rewritten.
--
-- NO FOREIGN KEY TO EITHER PARENT RECORD, deliberately, for two independent
-- reasons:
--   1. hosted-dmarc.js HARD-DELETES its row on completed removal
--      (DELETE FROM hosted_dns_entries). A real FK would either block that
--      delete or cascade this history away. Historical integrity requires the
--      events outlive the record they describe.
--   2. The fk column must hold ids from BOTH families, so it cannot reference
--      one table. certificate_lifecycle_events (mig 085) already sets this
--      precedent: it FKs workspaces only, never certificate_lifecycle.
CREATE TABLE IF NOT EXISTS email_protection_events (
    id            TEXT PRIMARY KEY,          -- epe-<hex>; THE occurrence identity
    -- The record this transition belongs to. Generic by necessity (see above):
    -- hosted_dns_entries.id ('hd-…') or email_sender_sources.id ('esender_…').
    -- Those two id namespaces MUST NOT collide or one family could resolve the
    -- other's occurrence. The namespaces are disjoint by construction and CI
    -- asserts it — the database cannot.
    record_id     TEXT NOT NULL,
    -- Which family this row describes: hosted_dns_entry | email_sender_source.
    -- Diagnostics, purging and human reading only. It is deliberately NOT part
    -- of the occurrence lookup: findConditionOccurrence's SQL does not know this
    -- column exists, and record_id is already unique across families.
    record_type   TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    actor_type    TEXT NOT NULL,             -- system|customer
    actor_id      TEXT,
    -- baseline_established|monitoring_changed|hosted_record_reconnected|
    -- hosted_policy_changed|hosted_rolled_back_manual|sender_failures_recovered|
    -- sender_manual_classification
    --
    -- Only `monitoring_changed` carrying a non-null detail.to_recurrence_type is
    -- an OCCURRENCE. Every other value is history: the resolver cannot match it,
    -- so it is structurally incapable of raising an alert. That is how the
    -- founder-mandated non-alertable transitions are enforced — by construction,
    -- not by remembering to skip a call.
    event_type    TEXT NOT NULL,
    detail_json   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- The occurrence lookup: (workspace_id, record_id, event_type) + newest-first.
CREATE INDEX IF NOT EXISTS idx_email_protection_events_rec
    ON email_protection_events (workspace_id, record_id, created_at);

-- Per-family history and the baseline count at activation.
CREATE INDEX IF NOT EXISTS idx_email_protection_events_type
    ON email_protection_events (workspace_id, record_type, created_at);

-- ── email_sender_sources: the minimum lifecycle state a guard needs ──────────
--
-- Four nullable columns, mirroring the shipped lifecycle shape
-- (certificate_lifecycle / identity_exposure / shadow_it_inventory). All
-- nullable so every pre-088 row stays valid and un-evaluated rows read as
-- "no state yet" rather than a fabricated one.
--
-- Deliberately ABSENT: any stored window volume, any recurrence_detected_at, any
-- occurrence counter. The append-only events table already owns "when did this
-- begin" and "which occurrence is this"; a second copy of either would
-- eventually disagree with it. Window volumes are COMPUTED from
-- dmarc_aggregate_records at evaluation time — storing them would create a
-- second source of truth that drifts from the receiver-reported evidence.

-- baseline | observed | recovered. The transition guard's first dimension.
ALTER TABLE email_sender_sources ADD COLUMN monitoring_status TEXT;

-- The graded condition, or NULL for none. What findConditionOccurrence matches.
ALTER TABLE email_sender_sources ADD COLUMN recurrence_type TEXT;

-- The severity band derived from classification by one pure function
-- (senderAlertBand). This is isMonitoringTransition's THIRD dimension (PR-B2):
-- a sender worsening suspicious→unauthorised keeps the same recurrence_type but
-- must escalate medium→high. Without the band no transition is seen, no event is
-- appended, the occurrence id is unchanged, the dedupe key is unchanged, and the
-- customer is never told it got worse.
ALTER TABLE email_sender_sources ADD COLUMN recurrence_band TEXT;

-- Last evaluation pass. DIAGNOSTIC ONLY — it is refreshed by every pass, so it
-- must never be read as a condition-start or passed as observed_at. Doing so
-- would drift the watermark forward on every run and re-alert the same unchanged
-- condition forever (alert-occurrence.js:18-23).
ALTER TABLE email_sender_sources ADD COLUMN evaluated_at TEXT;

-- Sender evaluation sweeps rows for one (workspace, domain) and needs the
-- current condition to compare against.
CREATE INDEX IF NOT EXISTS idx_email_sender_sources_monitoring
    ON email_sender_sources (workspace_id, domain, monitoring_status);
