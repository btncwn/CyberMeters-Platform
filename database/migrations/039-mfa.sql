-- ── 039-mfa.sql ──────────────────────────────────────────────────────────────
-- Adds TOTP-based multi-factor authentication support to the users table
-- and creates the mfa_challenges table for the pre-session challenge flow.
--
-- Design decisions:
--   - totp_secret is encrypted (AES-256-GCM via env.MFA_ENCRYPTION_KEY).
--     Raw secret is never persisted in plaintext.
--   - mfa_recovery_codes_hash_json stores a JSON array of PBKDF2 hashes.
--     Raw recovery codes are shown to the user once and never stored.
--   - mfa_enabled is stored as INTEGER (0/1) for D1/SQLite boolean compat.
--   - mfa_challenges is ephemeral — entries expire in 10 minutes.
--     Entries are kept for audit purposes (used_at is set, not deleted).
--
-- Backward-compatible:
--   - All new users columns are nullable / have safe defaults.
--   - Existing users get mfa_enabled = 0 (MFA off) and NULL secrets.
--   - Login flow is unchanged for non-MFA users.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/039-mfa.sql
--
-- Rollback:
--   ALTER TABLE users DROP COLUMN totp_secret;
--   ALTER TABLE users DROP COLUMN mfa_enabled;
--   ALTER TABLE users DROP COLUMN mfa_enabled_at;
--   ALTER TABLE users DROP COLUMN mfa_recovery_codes_hash_json;
--   ALTER TABLE users DROP COLUMN mfa_last_verified_at;
--   DROP TABLE IF EXISTS mfa_challenges;

-- ── MFA columns on users ──────────────────────────────────────────────────────

-- Encrypted TOTP secret (AES-256-GCM; stored as JSON {iv, ct} hex strings).
-- NULL = no secret generated yet. Present even before mfa_enabled = 1
-- (during setup/verify flow, secret is stored but not yet enabled).
ALTER TABLE users ADD COLUMN totp_secret TEXT;

-- 0 = MFA disabled (default), 1 = MFA active and enforced at login.
ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;

-- Timestamp when MFA was last enabled.
ALTER TABLE users ADD COLUMN mfa_enabled_at TEXT;

-- JSON array of PBKDF2-hashed recovery codes.
-- Format: ["pbkdf2:sha256:100000:...:...", ...]  (8 codes on setup).
-- NULL = no recovery codes (set when MFA is disabled).
ALTER TABLE users ADD COLUMN mfa_recovery_codes_hash_json TEXT;

-- Timestamp of last successful MFA verification (useful for auditing / policy).
ALTER TABLE users ADD COLUMN mfa_last_verified_at TEXT;

-- ── MFA challenge tokens ──────────────────────────────────────────────────────
-- Issued after correct password, before TOTP code is submitted.
-- Allows the two-step login (password → MFA) without exposing a session token
-- before the second factor is verified.

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    challenge_hash TEXT NOT NULL UNIQUE,     -- SHA-256 of raw cmfa_ token
    expires_at     TEXT NOT NULL,            -- 10 minutes from issue
    used_at        TEXT,                     -- set when challenge is consumed
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_hash
  ON mfa_challenges (challenge_hash);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id
  ON mfa_challenges (user_id);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at
  ON mfa_challenges (expires_at);
