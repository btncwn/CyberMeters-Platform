-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 089: Website Security managed lifecycle (conditions + append-only events)
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Corrective Alerts phase. Additive only. Website Security is the SEVENTH alerting
-- domain and the second (after Email Protection, mig 088) that had no managed
-- lifecycle at all.
--
-- WHY A DEDICATED PAIR — the evidence exists, the CONTINUITY does not.
-- Website Security is not short of evidence: headers-scan.js, ssl-scan.js and
-- tech-scan.js collect it every scan; scoring.js turns it into findings with STABLE
-- canonical ids (`header_missing_strict_transport_security`, `ssl_not_available`,
-- `header_malformed_*`); and the full module output plus those ids are persisted
-- immutably in the R2 report at reports/<scan_id>.json, one object per scan, never
-- rewritten. Nine canonical remediations already key on those exact ids.
--
-- What is missing is CONTINUITY. The D1 `findings` INSERT (scan-engine.js) binds
-- createId("finding") and DROPS the canonical slug, so the same condition carries a
-- different random id on every scan and D1 cannot answer "is HSTS still missing, and
-- since when?". No row anywhere records when a website condition began. That is the
-- whole gap, and it is what these two tables close. The evaluator reads the canonical
-- id from the in-memory findings at scan time (as createManagedAsmCasesForScan
-- already does), so this does not require touching the findings INSERT.
--
-- WHY NOT workspace_assets: it is UNIQUE(workspace_id, hostname) — one row per HOST.
-- A website condition is (host × condition), many per host. Smuggling them into
-- metadata_json would fabricate a second, unindexed, un-evented source of truth
-- inside a row Attack Surface owns.
--
-- ── ENTITY GRANULARITY — domain-scoped, and that is an HONESTY decision ──────
-- The identity is (workspace_id, domain_id, condition_key), NOT per-hostname and NOT
-- per-path. Every Website Security finding scoring.js emits is domain-level: none
-- carries `affected_hosts`, a hostname, a url or a path — contrast dse-findings.js,
-- which sets affected_hosts explicitly. The per-path evidence that DOES exist
-- (headers.checked_paths for "/", the canonical URL and the www variant) is consumed
-- by scoring.js only as a boolean — "was this header seen on ANY checked path?" — and
-- no finding records which path it was.
--
-- So a per-hostname key would have to INVENT the attribution, and the obvious source
-- for it (evidence.final_url) is the redirect target, which moves when a customer
-- changes their canonical redirect: the record would "resolve" on one host and
-- "appear" on another, alerting twice because the customer improved their site.
-- The entity is scoped to exactly the granularity the evidence supports. Hostname
-- travels in the event detail as observed context, never in the identity.
--
-- If a future scan change attributes a host to a website finding, THAT is when a
-- host column earns its place — added additively, with the evidence to fill it.
--
-- Honest scope (permanent): these rows record what CyberMeters observed from
-- OUTSIDE, passively, over HTTP(S). They are not proof of the server's internal
-- configuration, not an authenticated or intrusive test, and a condition being
-- absent is evidence of a fix ONLY when the module that detects it provably ran to
-- completion (migration 089 ships after the probe-honesty fix that makes that
-- knowable at all — before it, a timed-out probe reported `complete`).
--
-- Rollback:
--   Leave the schema in place; roll back APPLICATION CODE only. With no writer both
--   tables simply stop receiving rows — behaviour identical to pre-migration.
--   (D1/SQLite has no DROP COLUMN path, and none is needed.)
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/089-website-security-lifecycle.sql

-- ── website_security_conditions — the durable per-condition record ───────────
--
-- Exactly one row per (workspace, domain, condition_key). condition_key is the
-- CANONICAL FINDING ID from scoring.js — the same stable slug the remediation
-- registry keys `finding_types` on and the eight-domain resolver matches. It is
-- deterministic across scans by construction, which is the entire reason this domain
-- can have an identity at all.
CREATE TABLE IF NOT EXISTS website_security_conditions (
    id             TEXT PRIMARY KEY,          -- wsc-<hex>
    workspace_id   TEXT NOT NULL,
    domain_id      TEXT NOT NULL,
    domain         TEXT NOT NULL,             -- hostname text: display/entity naming only

    -- The canonical finding id, e.g. 'header_missing_strict_transport_security'.
    condition_key  TEXT NOT NULL,

    -- What the platform's own scoring engine graded this condition as, verbatim.
    -- Severity provenance is the FINDING; the lifecycle must never invent a grade
    -- the scan did not assign. Carried into the alert as record_severity (INHERIT).
    observed_severity TEXT,                   -- critical|high|medium (material only)
    observed_title    TEXT,
    -- Which module must have RUN for absence to mean "fixed". headers|ssl|
    -- technology_detection. Fed to moduleCompletionGate.canVerify().
    detecting_module  TEXT,

    -- Provenance: the exact scan this state was last established from.
    last_scan_id      TEXT,
    last_scan_quality TEXT,                   -- complete|partial|degraded|unknown

    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    last_changed_at TEXT,                     -- last MATERIAL change

    -- observed           — present in the latest assessed evidence
    -- baseline           — present, but it predates our watching. Never alerts, and
    --                      STAYS baseline until the CONDITION itself changes (the
    --                      PR-B3 pass-two trap: flipping baseline→observed while the
    --                      condition is identical reads as a transition and releases
    --                      the whole backlog one pass later).
    -- no_longer_observed — absent AND the detecting module provably ran: a real fix
    -- unknown            — absent or downgraded to a non-material grade, and we
    --                      cannot show it is gone. NOT recovery.
    monitoring_status TEXT NOT NULL DEFAULT 'observed',
    monitoring_reason TEXT,
    -- module_not_assessed|scan_partial|evidence_uncertain
    unknown_reason    TEXT,

    -- The alertable condition class, and the band that makes "it got worse" a
    -- transition in its own right (the PR-B2 pattern: same recurrence_type, higher
    -- severity, still a real escalation the customer must hear about).
    recurrence_type TEXT,
    recurrence_band TEXT,

    lifecycle_state TEXT NOT NULL DEFAULT 'observed',
    linked_case_id  TEXT,                     -- managed_cases.id (website_case)

    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    -- Diagnostic ONLY. Refreshed by every evaluation pass, so reading it as a
    -- condition-start would drift the watermark forward and re-alert the same
    -- unchanged condition forever. alert-occurrence.js never reads it.
    evaluated_at TEXT,

    -- Exactly one managed record per condition per domain per tenant: this is what
    -- makes a repeat scan an UPDATE rather than a second identity.
    UNIQUE (workspace_id, domain_id, condition_key),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE INDEX IF NOT EXISTS idx_website_security_conditions_ws
  ON website_security_conditions (workspace_id, domain_id);
CREATE INDEX IF NOT EXISTS idx_website_security_conditions_monitoring
  ON website_security_conditions (workspace_id, monitoring_status);
CREATE INDEX IF NOT EXISTS idx_website_security_conditions_seen
  ON website_security_conditions (workspace_id, last_seen_at);

-- ── website_security_events — the append-only occurrence source ──────────────
--
-- One row per observed transition. Append-only: never updated, never deleted except
-- by workspace purge. The row id IS the occurrence identity and its created_at IS
-- when the condition began — which is why nothing here may ever be rewritten.
--
-- NO FOREIGN KEY TO website_security_conditions, deliberately — the precedent set by
-- certificate_lifecycle_events (085), identity_exposure_events (086) and
-- email_protection_events (088). History must be able to outlive the record it
-- describes.
--
-- ONLY `monitoring_changed` carrying a non-null detail.to_recurrence_type is an
-- OCCURRENCE. Every other event_type is history the resolver is STRUCTURALLY
-- incapable of matching — which is how baseline, recovery and unknown stay
-- non-alertable by construction rather than by remembering to skip a call:
--
--   domain_baseline_established — THE FLOOD GUARD. Written once per (workspace,
--       domain) on the first evaluation, with record_id = domain_id (a synthetic
--       key; it names no condition row). Its ABSENCE is what marks a pass as the
--       seeding pass. It is written even when that pass finds zero conditions, so a
--       domain whose first scan is clean is still baselined and the first condition
--       to appear afterwards is correctly treated as NEW rather than re-seeded.
--   baseline_established        — this condition predates our watching: it existed on
--       the seeding pass. Can never alert.
--   condition_resolved          — absent AND the detecting module provably ran. A
--       real recovery, recorded as history: no customer action is required, so there
--       is nothing to alert.
--   evidence_unknown            — the module did not assess, or the grade fell below
--       material and we cannot show the condition is gone. NOT a recovery.
--   case_linked                 — a managed case was opened/linked for this condition.
CREATE TABLE IF NOT EXISTS website_security_events (
    id            TEXT PRIMARY KEY,          -- wse-<hex>; THE occurrence identity
    -- website_security_conditions.id — EXCEPT for domain_baseline_established, where
    -- it is the domain_id. The two namespaces cannot collide: condition ids are
    -- minted 'wsc-<hex>' by this engine and domain ids are not.
    record_id     TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    actor_type    TEXT NOT NULL,             -- system|customer
    actor_id      TEXT,
    -- monitoring_changed|domain_baseline_established|baseline_established|
    -- condition_resolved|evidence_unknown|case_linked
    event_type    TEXT NOT NULL,
    detail_json   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- The occurrence lookup's exact predicate + order (alert-occurrence.js):
-- WHERE workspace_id = ? AND record_id = ? AND event_type = ?
-- ORDER BY created_at DESC, rowid DESC. workspace_id leads because the resolver is
-- tenant-scoped by construction.
CREATE INDEX IF NOT EXISTS idx_website_security_events_occurrence
  ON website_security_events (workspace_id, record_id, created_at);
