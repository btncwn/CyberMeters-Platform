-- ── 079-workspace-domain-verification.sql ────────────────────────────────────
-- Move domain-ownership verification authority from the (user_id, domain) `domains`
-- row to the PER-WORKSPACE `workspace_domains` link, so proof-of-control is
-- workspace-scoped and can gate scan-start. A domain verified in one workspace must
-- NOT authorize scanning in another. Additive only — no DROP, no rewrite. The legacy
-- domains.verification_* columns are left intact as read-only compatibility data
-- (never used for scan authorization anymore).

ALTER TABLE workspace_domains ADD COLUMN verification_status       TEXT DEFAULT 'unverified';
ALTER TABLE workspace_domains ADD COLUMN verification_method       TEXT;
ALTER TABLE workspace_domains ADD COLUMN verification_token        TEXT;
ALTER TABLE workspace_domains ADD COLUMN verification_initiated_at TEXT;
ALTER TABLE workspace_domains ADD COLUMN verified_at               TEXT;
ALTER TABLE workspace_domains ADD COLUMN verification_metadata     TEXT;

-- Backfill: promote ONLY links whose exact linked domain record is already verified,
-- copying the existing evidence so current valid relationships stay valid. Links to
-- unverified/missing domain records keep the column default 'unverified'. This does
-- NOT create global inheritance going forward — new links default to 'unverified'
-- and each workspace must independently prove control.
UPDATE workspace_domains
SET verification_status       = 'verified',
    verification_method       = (SELECT d.verification_method       FROM domains d WHERE d.id = workspace_domains.domain_id),
    verification_token        = (SELECT d.verification_token        FROM domains d WHERE d.id = workspace_domains.domain_id),
    verification_initiated_at = (SELECT d.verification_initiated_at FROM domains d WHERE d.id = workspace_domains.domain_id),
    verified_at               = (SELECT d.verified_at               FROM domains d WHERE d.id = workspace_domains.domain_id)
WHERE domain_id IN (SELECT id FROM domains WHERE verification_status = 'verified');
