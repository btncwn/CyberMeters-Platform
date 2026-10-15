// The Privacy Notice and DPA retain audit events for 12 calendar months.
// Audit rows remain append-only until expiry; each daily sweep deletes a
// bounded number of expired rows and preserves malformed/unknown timestamps.
export const AUDIT_RETENTION_BATCH_SIZE = 250;
export const AUDIT_RETENTION_MAX_BATCHES = 20;

const EXPIRED_AUDIT_DELETE_SQL = `
  DELETE FROM audit_events
   WHERE rowid IN (
     SELECT rowid FROM audit_events
      WHERE unixepoch(created_at) < unixepoch(?, '-12 months')
      ORDER BY unixepoch(created_at), rowid
      LIMIT ?
   )`;

const EXPIRED_AUDIT_EXISTS_SQL = `
  SELECT 1 AS pending FROM audit_events
   WHERE unixepoch(created_at) < unixepoch(?, '-12 months')
   LIMIT 1`;

export async function cleanupExpiredAuditEvents(env, nowIso, options = {}) {
  const nowMs = Date.parse(nowIso);
  if (!Number.isFinite(nowMs) || new Date(nowMs).toISOString() !== nowIso) {
    throw new TypeError("Invalid audit retention time");
  }
  if (!env?.cybermeters_db) throw new Error("Audit database unavailable");

  // Test-only batch overrides keep the bound verifiable with a small fixture.
  // Cron calls this function without overrides.
  const batchSize = options.batchSize ?? AUDIT_RETENTION_BATCH_SIZE;
  const maxBatches = options.maxBatches ?? AUDIT_RETENTION_MAX_BATCHES;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > AUDIT_RETENTION_BATCH_SIZE ||
      !Number.isInteger(maxBatches) || maxBatches < 1 || maxBatches > AUDIT_RETENTION_MAX_BATCHES) {
    throw new TypeError("Invalid audit retention batch bound");
  }

  let deleted = 0;
  let fullBatches = 0;
  for (let batch = 0; batch < maxBatches; batch++) {
    const result = await env.cybermeters_db.prepare(EXPIRED_AUDIT_DELETE_SQL)
      .bind(nowIso, batchSize).run();
    const changes = Number(result?.meta?.changes ?? result?.changes);
    if (!Number.isInteger(changes) || changes < 0 || changes > batchSize) {
      throw new Error("Audit retention did not confirm its delete count");
    }
    deleted += changes;
    if (changes < batchSize) return { deleted, pending: false };
    fullBatches++;
  }

  // The cap may leave an existing backlog. Report only counts, never row data.
  const pending = Boolean(await env.cybermeters_db.prepare(EXPIRED_AUDIT_EXISTS_SQL)
    .bind(nowIso).first());
  if (pending) {
    console.warn("[audit-retention-backlog]", JSON.stringify({ deleted, batch_limit: fullBatches }));
  }
  return { deleted, pending };
}
