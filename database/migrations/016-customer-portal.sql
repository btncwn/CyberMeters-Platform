-- ── 016-customer-portal.sql ────────────────────────────────────────────────
-- Customer Portal Foundation v1.
-- Adds account-owned company profile and manual subscription foundation tables.
-- No payment processor, checkout flow, or external billing provider is added.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/016-customer-portal.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS subscription_accounts;
--   DROP TABLE IF EXISTS customer_profiles;

-- ── Company / Customer Profile ───────────────────────────────────────────────
-- One profile per account owner. Workspaces remain separate; this table captures
-- company metadata for the customer portal only.

CREATE TABLE IF NOT EXISTS customer_profiles (
    id             TEXT PRIMARY KEY,
    owner_user_id  TEXT NOT NULL UNIQUE,
    company_name   TEXT NOT NULL,
    website        TEXT,
    industry       TEXT,
    company_size   TEXT,
    contact_email  TEXT,
    contact_name   TEXT,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT,
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_customer_profiles_owner
  ON customer_profiles (owner_user_id);

-- ── Subscription Foundation ─────────────────────────────────────────────────
-- Manual v1 subscription record per account owner.
-- billing_provider is intentionally "manual"; Stripe/payment providers are out
-- of scope for this sprint.

CREATE TABLE IF NOT EXISTS subscription_accounts (
    id                 TEXT PRIMARY KEY,
    owner_user_id      TEXT NOT NULL UNIQUE,
    plan               TEXT NOT NULL DEFAULT 'free',
    status             TEXT NOT NULL DEFAULT 'active',
    billing_provider   TEXT NOT NULL DEFAULT 'manual',
    billing_email      TEXT,
    trial_ends_at      TEXT,
    current_period_end TEXT,
    created_at         TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at         TEXT,
    FOREIGN KEY (owner_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_subscription_accounts_owner
  ON subscription_accounts (owner_user_id);

CREATE INDEX IF NOT EXISTS idx_subscription_accounts_plan_status
  ON subscription_accounts (plan, status);
