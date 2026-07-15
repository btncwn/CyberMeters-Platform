-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 090: Cyber Essentials external-evidence lifecycle
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Corrective Alerts phase. Additive only. Cyber Essentials is the EIGHTH and last
-- canonical alerting domain.
--
-- ── WHAT CE ALERTS ON, AND WHAT IT MUST NOT (founder ownership decision) ─────
-- CE detects NOTHING of its own: cyber-mot-domains.js gives it `modules: []` and
-- `match: () => false`, so no scan finding is ever attributed to it. Every control it
-- grades is a RE-INTERPRETATION of evidence another domain already owns and already
-- alerts on — DMARC belongs to Email Protection, HSTS/CSP to Website Security,
-- certificate expiry to Certificates & Trust, exposed admin surfaces to Attack
-- Surface.
--
-- So CE must never raise a second "we found X" alert. It owns exactly one claim no
-- other domain makes: a CONTROL THEME's externally evidenced readiness has changed.
-- "Your Secure Configuration theme is no longer externally evidenced as ready" is a
-- different question from "your HSTS header is missing", and it is the question a
-- customer preparing for certification is actually asking.
--
-- Never: certified / compliant / audit passed / formal status / an attack occurred /
-- the customer changed an answer.
--
-- ── ONLY EXTERNALLY SUPPORTABLE CONTROLS MAY ALERT ──────────────────────────
-- lib/cyber-essentials.js already carries the repo's own honesty metadata:
--   boundary_protection         external_coverage: "partial"   → may alert
--   secure_configuration        external_coverage: "partial"   → may alert
--   patch_management_readiness  external_coverage: "partial"   → may alert
--   access_control              external_coverage: "none"      → MUST NOT alert
--   malware_protection          external_coverage: "none"      → MUST NOT alert
--
-- The last two are scored from email-auth proxies (SPF/DMARC), which measure
-- anti-spoofing, not user access control or endpoint malware protection. The repo
-- says their external coverage is none and it is right: MFA, admin separation,
-- joiner/leaver and endpoint AV are not observable from outside. They stay VISIBLE in
-- the readiness product and are persisted here as `not_externally_assessable`, but
-- they can never contribute a canonical alert occurrence. Inventing a proxy claim is
-- exactly what this episode exists to stop.
--
-- ── THE QUESTIONNAIRE IS NOT SECURITY TRUTH, AND IS NOT READ HERE ───────────
-- buildCyberEssentialsReadiness never reads cyber_essentials_answers — every control
-- comes from ssl/headers/email_security/cert evidence. The questionnaire gates only
-- DISPLAY, inside getCyberEssentialsSnapshot. The lifecycle evaluator therefore calls
-- buildCyberEssentialsReadiness DIRECTLY. Routing it through the snapshot would let a
-- customer flipping one answer to "unknown" flip `complete` to false, `status` to
-- null, and mint a security occurrence from a form edit.
--
-- ── EVIDENCE FINGERPRINT, NOT SCORE ────────────────────────────────────────
-- A readiness percentage moving is not an event: the score is a recomputation, and
-- 72→68 says nothing about which evidence changed. The state is derived from the SET
-- of canonical remediation ids currently failing for the control. That set is stable
-- against count churn ("1 critical finding" → "2 critical findings" is the same
-- ce.backlog.remediate ref) and against scoring-weight changes, and it moves only
-- when a genuinely different control gap appears or clears.
--
-- Honest scope (permanent): CyberMeters does not certify Cyber Essentials. These rows
-- record externally observable readiness signals only. Endpoint protection, internal
-- device configuration and user access policies cannot be assessed from outside.
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer both
--   tables stop receiving rows — behaviour identical to pre-migration.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/090-cyber-essentials-lifecycle.sql

-- ── cyber_essentials_control_records — the durable per-control record ────────
--
-- Exactly one row per (workspace, control_key). Workspace-level, not domain-level:
-- buildCyberEssentialsReadiness is workspace-scoped (readiness is a property of the
-- organisation, assembled from its scanned domains), so a domain_id here would be a
-- fabrication. control_key is one of the five stable CE_QUESTIONS keys.
CREATE TABLE IF NOT EXISTS cyber_essentials_control_records (
    id             TEXT PRIMARY KEY,          -- cec-<hex>
    workspace_id   TEXT NOT NULL,
    -- boundary_protection|secure_configuration|access_control|
    -- malware_protection|patch_management_readiness
    control_key    TEXT NOT NULL,
    control_label  TEXT,
    -- partial|none — copied from lib/cyber-essentials.js at evaluation time so the
    -- record shows WHY a control never alerts, rather than leaving it a mystery.
    external_coverage TEXT NOT NULL DEFAULT 'none',

    -- ready                     — externally evidenced, no failing gap
    -- not_ready                 — externally evidenced, one or more failing gaps
    -- unknown                   — the underlying evidence was not collected
    -- not_externally_assessable — external_coverage = none. Never alerts, ever.
    readiness_state TEXT NOT NULL DEFAULT 'unknown',
    readiness_reason TEXT,

    -- The SET of canonical remediation ids currently failing, sorted + joined.
    -- This is the evidence identity: it changes only when a genuinely different gap
    -- appears or clears, never when a count or a score moves.
    evidence_fingerprint TEXT,
    -- The named external evidence behind the current state (JSON array of
    -- {remediation_id, reason}) — so a notification can say WHICH evidence moved
    -- rather than asserting a verdict with nothing behind it.
    evidence_json    TEXT,
    -- The signals CyberMeters could not observe for this control this pass.
    unknown_json     TEXT,

    -- Provenance: the exact assessment this state was established from.
    last_scan_id     TEXT,
    last_assessed_at TEXT,

    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    last_changed_at TEXT,

    monitoring_status TEXT NOT NULL DEFAULT 'observed',   -- observed|baseline
    recurrence_type   TEXT,
    recurrence_band   TEXT,

    lifecycle_state TEXT NOT NULL DEFAULT 'observed',
    linked_case_id  TEXT,                     -- managed_cases.id (cyber_essentials_case)

    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    -- Diagnostic ONLY — never a condition-start (it drifts every pass).
    evaluated_at TEXT,

    UNIQUE (workspace_id, control_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_ce_control_records_ws
  ON cyber_essentials_control_records (workspace_id, readiness_state);

-- ── cyber_essentials_events — the append-only occurrence source ──────────────
--
-- One row per observed transition. Append-only; the row id IS the occurrence
-- identity and its created_at IS when the condition began.
--
-- NO FOREIGN KEY to the records table — the precedent of 085/086/088/089: history
-- must be able to outlive the record it describes.
--
-- ONLY `monitoring_changed` with a non-null detail.to_recurrence_type is an
-- OCCURRENCE. The rest is history the resolver cannot match:
--   workspace_baseline_established — THE FLOOD GUARD. Written once per workspace on
--       the first evaluation, record_id = workspace_id. Its ABSENCE marks the seeding
--       pass. Written even when that pass finds every control ready, so a workspace
--       that starts healthy is still baselined and its first real deterioration
--       correctly alerts instead of being re-seeded.
--   baseline_established           — this control was already not-ready when we
--       started watching. Never alerts.
--   control_recovered              — external evidence now supports readiness again.
--       Good news requiring no action: history, not an alert.
--   control_evidence_unknown       — the evidence was not collected. NOT a recovery.
--   case_linked
CREATE TABLE IF NOT EXISTS cyber_essentials_events (
    id            TEXT PRIMARY KEY,          -- cee-<hex>; THE occurrence identity
    -- cyber_essentials_control_records.id ('cec-…'), except for
    -- workspace_baseline_established where it is the workspace_id. Disjoint by the
    -- 'cec-' prefix, and the marker is not a monitoring_changed row in any case.
    record_id     TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    actor_type    TEXT NOT NULL,             -- system|customer
    actor_id      TEXT,
    event_type    TEXT NOT NULL,
    detail_json   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_ce_events_occurrence
  ON cyber_essentials_events (workspace_id, record_id, created_at);
