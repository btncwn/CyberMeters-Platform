-- Migration 035: Supply Chain Intelligence
-- Creates tables for supply chain risk scores and historical trend tracking.
-- Part of Sprint: Supply Chain, Resilience & Third-Party Risk Engine v1
--
-- Tables:
--   workspace_supply_chain_scores   — latest computed supply chain intelligence per workspace
--   workspace_supply_chain_history  — historical snapshots for trend analysis
--
-- Rollback:
--   DROP TABLE IF EXISTS workspace_supply_chain_history;
--   DROP TABLE IF EXISTS workspace_supply_chain_scores;

-- Latest supply chain intelligence per workspace (one row per workspace)
CREATE TABLE IF NOT EXISTS workspace_supply_chain_scores (
  id                     TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workspace_id           TEXT NOT NULL UNIQUE,
  supply_chain_score     INTEGER NOT NULL DEFAULT 0,   -- 0-100 overall supply chain health
  resilience_score       INTEGER NOT NULL DEFAULT 0,   -- 0-100 operational resilience
  concentration_level    TEXT NOT NULL DEFAULT 'unknown', -- low | medium | high | critical
  critical_vendor_count  INTEGER NOT NULL DEFAULT 0,
  tier1_count            INTEGER NOT NULL DEFAULT 0,   -- direct critical vendors
  tier2_count            INTEGER NOT NULL DEFAULT 0,   -- indirect / secondary vendors
  tier3_count            INTEGER NOT NULL DEFAULT 0,   -- tertiary / unknown-tier vendors
  spof_count             INTEGER NOT NULL DEFAULT 0,   -- single points of failure
  payload_json           TEXT NOT NULL DEFAULT '{}',   -- full intelligence payload
  calculated_at          TEXT NOT NULL DEFAULT (datetime('now')),
  created_at             TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at             TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_wsc_scores_workspace
  ON workspace_supply_chain_scores (workspace_id);

-- Historical snapshots — one row per scan per workspace
CREATE TABLE IF NOT EXISTS workspace_supply_chain_history (
  id                     TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  workspace_id           TEXT NOT NULL,
  supply_chain_score     INTEGER NOT NULL DEFAULT 0,
  resilience_score       INTEGER NOT NULL DEFAULT 0,
  concentration_level    TEXT NOT NULL DEFAULT 'unknown',
  critical_vendor_count  INTEGER NOT NULL DEFAULT 0,
  spof_count             INTEGER NOT NULL DEFAULT 0,
  calculated_at          TEXT NOT NULL DEFAULT (datetime('now')),
  created_at             TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_wsc_history_workspace_date
  ON workspace_supply_chain_history (workspace_id, calculated_at DESC);
