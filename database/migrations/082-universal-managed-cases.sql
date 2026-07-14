-- ── 082-universal-managed-cases.sql ───────────────────────────────────────
-- Universal Managed-Case Model: extend the existing managed_cases table in place
-- (no parallel table) to the universal 8-domain case contract. Additive only —
-- new columns are nullable; enums stay application-owned (no CHECK constraints);
-- the existing managed_case_events table remains the append-only history/audit
-- log. Existing asm_exposure / brand_abuse rows keep their status values and are
-- back-filled with their canonical domain_key.

-- Canonical Cyber MOT domain the case belongs to (one of the eight keys).
ALTER TABLE managed_cases ADD COLUMN domain_key TEXT;

-- Source finding + scan provenance (finding_id already stores the case-identity
-- key; source_finding_type is the canonical finding type used for remediation
-- resolution, source_scan_id ties the case to the scan that opened/updated it).
ALTER TABLE managed_cases ADD COLUMN source_finding_type TEXT;
ALTER TABLE managed_cases ADD COLUMN source_scan_id TEXT;

-- Canonical remediation linkage (the registry remediation_id, when one exists).
ALTER TABLE managed_cases ADD COLUMN remediation_id TEXT;

-- Human-facing case framing.
ALTER TABLE managed_cases ADD COLUMN title TEXT;
ALTER TABLE managed_cases ADD COLUMN summary TEXT;
ALTER TABLE managed_cases ADD COLUMN priority TEXT;

-- Ownership (assigned_user_id complements the existing owner_type/owner_ref;
-- business_owner / technical_owner name the accountable parties).
ALTER TABLE managed_cases ADD COLUMN assigned_user_id TEXT;
ALTER TABLE managed_cases ADD COLUMN business_owner TEXT;
ALTER TABLE managed_cases ADD COLUMN technical_owner TEXT;

-- Canonical-lifecycle phase timestamps. (created_at / updated_at / due_at /
-- resolved_at / last_verified_at / risk_accepted_until already exist and are
-- reused; status_reason maps to the existing `reason` column.)
ALTER TABLE managed_cases ADD COLUMN accepted_at TEXT;
ALTER TABLE managed_cases ADD COLUMN approved_at TEXT;
ALTER TABLE managed_cases ADD COLUMN action_started_at TEXT;
ALTER TABLE managed_cases ADD COLUMN awaiting_verification_at TEXT;
ALTER TABLE managed_cases ADD COLUMN verified_at TEXT;
ALTER TABLE managed_cases ADD COLUMN monitoring_started_at TEXT;
ALTER TABLE managed_cases ADD COLUMN reopened_at TEXT;
ALTER TABLE managed_cases ADD COLUMN closed_at TEXT;

-- Back-fill domain_key for the two existing case types so every current case is
-- addressable by the universal cross-domain queue. Idempotent (guarded on NULL).
UPDATE managed_cases SET domain_key = 'attack_surface'  WHERE case_type = 'asm_exposure' AND domain_key IS NULL;
UPDATE managed_cases SET domain_key = 'brand_protection' WHERE case_type = 'brand_abuse'  AND domain_key IS NULL;

-- Cross-domain queue index (workspace + domain_key + status).
CREATE INDEX IF NOT EXISTS idx_managed_cases_domain_key
  ON managed_cases (workspace_id, domain_key, status);
