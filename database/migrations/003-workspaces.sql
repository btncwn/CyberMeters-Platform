CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workspace_domains (
    workspace_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    PRIMARY KEY (workspace_id, domain_id)
);
