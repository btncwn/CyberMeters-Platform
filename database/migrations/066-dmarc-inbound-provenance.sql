-- ── 066-dmarc-inbound-provenance.sql ─────────────────────────────────────────
-- Inbound RUA sender provenance (red-team hardening).
--
-- The inbound aggregate-report email handler only enforced enforceDomainMatch
-- (policy_published.domain must equal the endpoint's domain). Because the opaque
-- RUA address is embedded in the customer's PUBLIC DMARC TXT record, an attacker
-- can discover it and email a forged-but-well-formed report whose XML sets the
-- domain to match — passing enforceDomainMatch and poisoning sender-intelligence
-- / DMARC dashboard data. Cloudflare Email Routing already rejects inbound mail
-- that fails the sender's DMARC policy, so a legitimate reporter (google.com,
-- outlook.com, …) cannot be spoofed — but an attacker CAN send a well-formed
-- report from a domain they themselves control.
--
-- This migration records who really sent each inbound report (envelope sender,
-- authenticated header-From reporter domain, and a trust verdict) so that:
--   1. reports from a recognised major reporter are marked 'verified';
--   2. reports from any other source are still ingested (never dropped — many
--      legitimate smaller reporters exist) but marked 'unverified';
--   3. if poisoning is ever detected, the offending rows are identifiable by
--      envelope_from / reporter_domain / auth_verdict and can be purged.
--
-- Additive only. No existing column is altered or dropped, no existing API
-- response changes, and the source-agnostic DMARC dedupe UNIQUE index is
-- untouched. Manual-paste and signed-upload rows leave these columns NULL
-- (those paths are already authenticated / interactive).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/066-dmarc-inbound-provenance.sql
--
-- Rollback:
--   DROP INDEX IF EXISTS idx_dmarc_reports_auth_verdict;
--   -- envelope_from / reporter_domain / auth_verdict / auth_evidence are
--   -- harmless to leave in place (all NULL on legacy rows).
--
-- Idempotency note: SQLite/D1 ALTER TABLE ADD COLUMN is NOT idempotent — it
-- errors if the column already exists. This matches migrations 055 and 056 in
-- this project. Re-running requires removing the ADD COLUMN lines that already
-- applied. The CREATE INDEX line IS idempotent (IF NOT EXISTS).

-- Envelope MAIL FROM (Cloudflare SPF-checks this). The attacker's real deliverable
-- sending address in a poisoning attempt — the primary forensic / purge key.
ALTER TABLE dmarc_aggregate_reports ADD COLUMN envelope_from TEXT;

-- The classified reporter identity: the single, unambiguous RFC5322 header-From
-- domain (or envelope-from fallback). Cloudflare's inbound DMARC enforcement binds
-- the header-From domain, so this cannot be spoofed for an enforcing reporter.
ALTER TABLE dmarc_aggregate_reports ADD COLUMN reporter_domain TEXT;

-- 'verified'  — header-From is a recognised major DMARC reporter (Cloudflare
--               DMARC-enforced ⇒ trustworthy identity).
-- 'unverified'— any other inbound source (ingested, but flagged for forensics).
-- NULL        — non-inbound sources (manual_paste / signed_upload).
ALTER TABLE dmarc_aggregate_reports ADD COLUMN auth_verdict TEXT;

-- Compact JSON of the (partly self-asserted, hence untrusted) auth signals kept
-- for forensics: header_from, envelope_from, dkim/spf/dmarc tokens, match basis.
ALTER TABLE dmarc_aggregate_reports ADD COLUMN auth_evidence TEXT;

-- Fast lookup of unverified inbound rows for a workspace+domain (audit / purge).
CREATE INDEX IF NOT EXISTS idx_dmarc_reports_auth_verdict
    ON dmarc_aggregate_reports (workspace_id, domain, auth_verdict);
