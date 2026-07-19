-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 096: Report Branding v2 — per-workspace co-brand logos, MSP branding
--                profiles, and frozen historical branding. Additive + idempotent.
-- ─────────────────────────────────────────────────────────────────────────────
--
-- ── WHY THE EXISTING MODEL CANNOT BE EXTENDED ────────────────────────────────
-- Migration 070 put branding on customer_profiles, keyed by owner_user_id — one
-- brand for EVERY workspace an account owns, and a single report_white_label flag
-- that conflates "show my logo" (co-branding) with "lead with my brand and reduce
-- CyberMeters attribution" (full white-label). That model cannot represent:
--   • a per-WORKSPACE customer logo (all plans, co-branded, CyberMeters attribution
--     retained) — the canonical contract requires this for every plan;
--   • an MSP whose child-client workspaces each carry their OWN logo — one
--     owner_user_id fans out to many workspaces, so per-owner branding cannot
--     distinguish them;
--   • branding that is FROZEN into a report so a later logo change never rewrites
--     historical PDFs.
-- 070 is left intact as a backward-compatible fallback; nothing here overwrites it.
--
-- ── TENANT + DETERMINISM CONTRACT ────────────────────────────────────────────
--   • workspace_branding is keyed by workspace_id (the tenant boundary); logos
--     live in R2 under a tenant-prefixed, content-addressed key
--     (branding/logos/{workspace_id}/{sha256}.{ext}) and are IMMUTABLE — a new
--     logo is a new object, never an overwrite, so a frozen historical reference
--     never breaks or silently changes.
--   • msp_branding_profiles is owned by the MSP account (owner_user_id); a profile
--     is usable only for workspaces in that MSP's own portfolio (enforced in code,
--     never from the request body).
--   • scan_report_snapshots.branding_json freezes the effective branding descriptor
--     resolved at snapshot-build time. Report renderers read the frozen descriptor,
--     so changing or deleting a logo affects FUTURE scans' reports only. Snapshots
--     built before this migration have NULL branding_json and fall back to live
--     resolution (unchanged behaviour).

-- 1. Per-workspace co-brand logo (ALL plans). One row per workspace.
CREATE TABLE IF NOT EXISTS workspace_branding (
  workspace_id   TEXT PRIMARY KEY,                 -- tenant boundary; one branding per workspace
  logo_r2_key    TEXT,                             -- branding/logos/{workspace_id}/{sha256}.{ext}; NULL → no logo
  logo_mime      TEXT,                             -- image/png | image/jpeg | image/webp
  logo_sha256    TEXT,                             -- content hash (integrity, immutability, dedupe)
  logo_width     INTEGER,
  logo_height    INTEGER,
  logo_bytes     INTEGER,
  display_name   TEXT,                             -- workspace/customer name shown on the report
  updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by     TEXT,                             -- users.id who last set it (audit)
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

-- 2. MSP-owned branding profiles (white-label). Owned by the MSP account; selectable
--    for the MSP's own child-client workspaces. mode distinguishes co-brand from
--    full white-label (reduced attribution) — the latter also requires the plan's
--    white_label feature entitlement, enforced server-side.
CREATE TABLE IF NOT EXISTS msp_branding_profiles (
  id             TEXT PRIMARY KEY,                 -- mbp-<hex>
  owner_user_id  TEXT NOT NULL,                    -- MSP account (tenant boundary for the profile)
  name           TEXT NOT NULL,
  logo_r2_key    TEXT,
  logo_mime      TEXT,
  logo_sha256    TEXT,
  accent         TEXT,                             -- #RRGGBB
  mode           TEXT NOT NULL DEFAULT 'co_brand', -- co_brand | white_label
  is_default     INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (owner_user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_msp_branding_profiles_owner
  ON msp_branding_profiles (owner_user_id);

-- 3. Frozen branding descriptor captured at snapshot build (JSON):
--    { mode, source, logo_r2_key, logo_sha256, display_name, accent, renderer_identity }.
--    NULL for pre-096 snapshots (→ live resolution, unchanged).
ALTER TABLE scan_report_snapshots ADD COLUMN branding_json TEXT;
