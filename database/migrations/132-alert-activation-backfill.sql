-- Migration 132: every live workspace starts alert monitoring now, for all
-- eight domains.
--
-- The alert watermark (alert_activation, migration 087) used to be written
-- lazily, at a domain's first alert ATTEMPT. A workspace that already had
-- history for that domain then had its first real alert suppressed as
-- "baseline": a silent monitoring loss, once per domain, for every customer.
-- The Worker now writes the watermarks when monitoring starts (the first scan
-- of a workspace); this backfills the same "now" watermark for workspaces that
-- already exist. Anything observed before this instant stays history; every
-- new condition after it alerts.
--
-- INSERT OR IGNORE against UNIQUE (workspace_id, domain_key): an existing
-- watermark is never moved. Additive only; soft-deleted workspaces are skipped.
--
-- Apply (before the Worker deploy):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/132-alert-activation-backfill.sql
--
-- Rollback:
--   Roll the Worker back first. The rows can stay: they only make a workspace
--   that already had history alert on new conditions, which is the intent.
--   To undo exactly, delete the rows whose id starts with 'aa_bf132_'.

INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, baseline_count, created_at)
SELECT 'aa_bf132_' || lower(hex(randomblob(16))), w.id, d.domain_key, datetime('now'), 0, datetime('now')
  FROM workspaces w
  CROSS JOIN (
    SELECT 'certificates_trust' AS domain_key
    UNION ALL SELECT 'identity_exposure'
    UNION ALL SELECT 'shadow_it_unmanaged_technology'
    UNION ALL SELECT 'brand_protection'
    UNION ALL SELECT 'attack_surface'
    UNION ALL SELECT 'email_protection'
    UNION ALL SELECT 'website_security'
    UNION ALL SELECT 'cyber_essentials_readiness'
  ) d
 WHERE w.deleted_at IS NULL;
