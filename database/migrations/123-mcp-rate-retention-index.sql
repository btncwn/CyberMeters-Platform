-- Keep the daily MCP-only rate-counter sweep bounded as the shared API grows.
-- All MCP windows currently last at most one hour; the cleanup waits two days.
CREATE INDEX IF NOT EXISTS idx_api_rate_limits_mcp_retention
  ON api_rate_limits (window_start)
  WHERE action GLOB 'mcp_*';
