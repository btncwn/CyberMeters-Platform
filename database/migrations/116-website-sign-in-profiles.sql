-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 116: Website Security signed-in scanning — sign-in profiles
-- ─────────────────────────────────────────────────────────────────────────────
--
-- Additive only. A workspace owner/admin may give CyberMeters a TEST account for
-- one of the workspace's VERIFIED domains so scans can check pages behind its
-- sign-in (engines/website-sign-in.js). One profile per (workspace, domain).
--
-- SECRETS (permanent):
--   • the username/password, header or cookie is stored ONLY as AES-256-GCM
--     ciphertext under the dedicated WEBSITE_AUTH_KEY ring
--     (lib/website-auth-secrets.js), bound to workspace, domain, profile and
--     method; nothing secret is ever stored in clear or returned by any API;
--   • `credential_hint` is a masked display value ("j•••@acme.com",
--     "Authorization header") — never the secret itself;
--   • deleting a profile DELETES the row (the ciphertext is destroyed, not
--     soft-deleted); the attempt history and the audit event remain.
--
-- Attempts are append-only and hold codes, counts, names and flags only — never
-- cookie or header values, never page content.
--
-- Rollback: leave the schema; roll back application code (no reader/writer =
-- inert). Purge: both tables are workspace-scoped and in WORKSPACE_PURGE_TABLES.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/116-website-sign-in-profiles.sql

CREATE TABLE IF NOT EXISTS website_sign_in_profiles (
    id                         TEXT PRIMARY KEY,      -- wsip_<hex> (deterministic per workspace+domain)
    workspace_id               TEXT NOT NULL,
    domain_id                  TEXT NOT NULL,
    method                     TEXT NOT NULL CHECK (method IN ('form', 'header', 'cookie')),
    login_url                  TEXT,                  -- form only; https on the verified site
    start_url                  TEXT,                  -- a page that needs sign-in (required for header/cookie)
    signed_in_text             TEXT,                  -- optional text shown only when signed in
    username_field             TEXT,                  -- optional form-field override
    password_field             TEXT,                  -- optional form-field override
    credential_hint            TEXT NOT NULL,         -- masked display value, never the secret
    secret_ciphertext          TEXT NOT NULL,         -- {"v":1,"kid","iv","ct"} AES-256-GCM envelope
    credential_revision        TEXT NOT NULL,         -- changes on every save of the secret
    status                     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
    paused_reason              TEXT,                  -- e.g. repeated_sign_in_failures
    authorization_attested_by  TEXT NOT NULL,         -- user who confirmed they may let us sign in
    authorization_attested_at  TEXT NOT NULL,
    created_by                 TEXT NOT NULL,
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL,
    last_attempt_at            TEXT,
    last_attempt_source        TEXT,                  -- 'test' | 'scan'
    last_outcome               TEXT,
    last_signed_in_at          TEXT,
    consecutive_failures       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (workspace_id, domain_id)
);

CREATE INDEX IF NOT EXISTS idx_website_sign_in_profiles_domain
    ON website_sign_in_profiles(domain_id);

CREATE TABLE IF NOT EXISTS website_sign_in_attempts (
    id                    TEXT PRIMARY KEY,           -- wsia_<uuid>
    workspace_id          TEXT NOT NULL,
    domain_id             TEXT NOT NULL,
    profile_id            TEXT NOT NULL,              -- the profile at the time (row may be deleted later)
    credential_revision   TEXT,
    source                TEXT NOT NULL CHECK (source IN ('test', 'scan')),
    scan_id               TEXT,                       -- scan attempts only
    outcome               TEXT NOT NULL,
    detail_json           TEXT NOT NULL DEFAULT '{}', -- codes, counts, names, flags only
    coverage              TEXT,                       -- signed-in page checks (scan attempts): complete|partial|not_run
    summary_json          TEXT,                       -- signed-in page check counts (scan attempts)
    actor_user_id         TEXT,                       -- test attempts only
    created_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_website_sign_in_attempts_ws_domain
    ON website_sign_in_attempts(workspace_id, domain_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_website_sign_in_attempts_scan
    ON website_sign_in_attempts(workspace_id, scan_id) WHERE scan_id IS NOT NULL;
