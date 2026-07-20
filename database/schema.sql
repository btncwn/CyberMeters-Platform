-- CyberMeters Platform Database Schema
-- Cloudflare D1 / SQLite compatible
--
-- ⚠ HISTORICAL BASELINE — NOT the authoritative production schema on its own.
-- The canonical schema is THIS FILE plus every migration in database/migrations/
-- applied in numeric order (production is tracked in CHANGELOG.md, e.g.
-- "latest applied migration"). Never apply this file alone to production, and
-- never treat a table shape here as current without checking the migrations
-- that alter it. CI validators build their test databases the same way:
-- schema.sql first, then all migrations in order.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    plan TEXT DEFAULT 'free',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    score INTEGER,
    rating TEXT,
    status TEXT DEFAULT 'completed',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    recommendation TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS hidden_assets (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    risk_level TEXT,
    risk_reason TEXT,
    source TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS kev_matches (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    required_action TEXT,
    due_date TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS remediation_items (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    priority TEXT NOT NULL,
    title TEXT NOT NULL,
    reason TEXT,
    action TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    json_r2_key TEXT,
    pdf_r2_key TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    frequency TEXT NOT NULL DEFAULT 'daily',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    next_run_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
