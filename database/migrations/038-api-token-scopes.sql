-- ── 038-api-token-scopes.sql ─────────────────────────────────────────────────
-- Adds workspace binding and permission scopes to API tokens.
--
-- scope        — what the token can do: 'read' | 'write' | 'admin'
-- workspace_id — optional workspace binding; if set, token can only access
--                that one workspace (null = user-level, no workspace restriction)
--
-- Existing tokens receive scope = 'read' (DEFAULT) and workspace_id = NULL
-- (no workspace restriction) — backward-compatible with any previously issued tokens.
--
-- Apply:
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/038-api-token-scopes.sql
--
-- Rollback:
--   ALTER TABLE api_tokens DROP COLUMN scope;
--   ALTER TABLE api_tokens DROP COLUMN workspace_id;
--   DROP INDEX IF EXISTS idx_api_tokens_workspace_id;

ALTER TABLE api_tokens ADD COLUMN scope        TEXT NOT NULL DEFAULT 'read';
ALTER TABLE api_tokens ADD COLUMN workspace_id TEXT REFERENCES workspaces(id);

CREATE INDEX IF NOT EXISTS idx_api_tokens_workspace_id
  ON api_tokens (workspace_id)
  WHERE workspace_id IS NOT NULL;
