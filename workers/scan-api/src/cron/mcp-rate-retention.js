// OAuth/Customer MCP rate counters share the API D1. Only counters whose
// action starts with the literal `mcp_` prefix are eligible for this sweep.
export const MCP_RATE_RETENTION_BATCH_SIZE = 250;
export const MCP_RATE_RETENTION_MAX_BATCHES = 20;
const TWO_DAYS_MS = 2 * 24 * 60 * 60 * 1000;

const DELETE_SQL = `
  DELETE FROM api_rate_limits WHERE rowid IN (
    SELECT rowid FROM api_rate_limits
     WHERE action GLOB 'mcp_*' AND window_seconds BETWEEN 1 AND 86400
       AND window_start < ?
     ORDER BY window_start, rowid LIMIT ?
  )`;
const EXISTS_SQL = `
  SELECT 1 AS pending FROM api_rate_limits
   WHERE action GLOB 'mcp_*' AND window_seconds BETWEEN 1 AND 86400
     AND window_start < ? LIMIT 1`;

export async function cleanupExpiredMcpRateLimits(env, nowIso, options = {}) {
  const nowMs = Date.parse(nowIso);
  if (!Number.isFinite(nowMs) || new Date(nowMs).toISOString() !== nowIso) {
    throw new TypeError("Invalid MCP rate retention time");
  }
  if (!env?.cybermeters_db) throw new Error("MCP rate database unavailable");
  const batchSize = options.batchSize ?? MCP_RATE_RETENTION_BATCH_SIZE;
  const maxBatches = options.maxBatches ?? MCP_RATE_RETENTION_MAX_BATCHES;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MCP_RATE_RETENTION_BATCH_SIZE ||
      !Number.isInteger(maxBatches) || maxBatches < 1 || maxBatches > MCP_RATE_RETENTION_MAX_BATCHES) {
    throw new TypeError("Invalid MCP rate retention batch bound");
  }
  const cutoff = new Date(nowMs - TWO_DAYS_MS).toISOString();
  let deleted = 0;
  for (let batch = 0; batch < maxBatches; batch++) {
    const result = await env.cybermeters_db.prepare(DELETE_SQL).bind(cutoff, batchSize).run();
    const changes = Number(result?.meta?.changes ?? result?.changes);
    if (!Number.isInteger(changes) || changes < 0 || changes > batchSize) {
      throw new Error("MCP rate retention did not confirm its delete count");
    }
    deleted += changes;
    if (changes < batchSize) return { deleted, pending: false };
  }
  const pending = Boolean(await env.cybermeters_db.prepare(EXISTS_SQL).bind(cutoff).first());
  if (pending) console.warn("[mcp-rate-retention-backlog]", JSON.stringify({ deleted }));
  return { deleted, pending };
}
