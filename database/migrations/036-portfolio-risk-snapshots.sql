-- Migration 036: MSP Portfolio Risk Snapshots
-- Append-only history of portfolio-level risk calculations.
-- One row per computePortfolioRisk() run (typically post-scan or on-demand).
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/036-portfolio-risk-snapshots.sql
--
-- Rollback:
--   DROP TABLE IF EXISTS portfolio_risk_snapshots;

CREATE TABLE IF NOT EXISTS portfolio_risk_snapshots (
  id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  owner_id         TEXT NOT NULL,          -- users.id of the account owner
  portfolio_score  INTEGER NOT NULL,       -- 0-100 (higher = healthier portfolio)
  workspace_count  INTEGER NOT NULL,
  high_risk_count  INTEGER NOT NULL DEFAULT 0,
  critical_count   INTEGER NOT NULL DEFAULT 0,
  calculated_at    TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_portfolio_risk_snapshots_owner_date
  ON portfolio_risk_snapshots (owner_id, calculated_at DESC);
