#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import {
  AUDIT_RETENTION_BATCH_SIZE, AUDIT_RETENTION_MAX_BATCHES,
  cleanupExpiredAuditEvents,
} from "../workers/scan-api/src/cron/audit-retention.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const migration = fs.readFileSync(path.join(root,
  "database/migrations/122-audit-retention-index.sql"), "utf8");
const NOW = "2026-10-15T02:00:00.000Z";

function fixture() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE audit_events (id TEXT PRIMARY KEY, created_at TEXT)");
  db.exec(migration);
  const env = { cybermeters_db: {
    prepare(sql) {
      return { bind(...args) {
        const statement = db.prepare(sql);
        return {
          run: async () => ({ meta: { changes: statement.run(...args).changes } }),
          first: async () => statement.get(...args) ?? null,
        };
      } };
    },
  } };
  return { db, env };
}

function seed(db, entries) {
  const insert = db.prepare("INSERT INTO audit_events (id, created_at) VALUES (?, ?)");
  for (const [id, createdAt] of entries) insert.run(id, createdAt);
}

function ids(db) {
  return db.prepare("SELECT id FROM audit_events ORDER BY id").all().map(({ id }) => id);
}

{
  const { db, env } = fixture();
  // The migration is rerunnable and the time expression is actually indexed.
  db.exec(migration);
  const plan = db.prepare(`EXPLAIN QUERY PLAN SELECT rowid FROM audit_events
    WHERE unixepoch(created_at) < unixepoch(?, '-12 months')
    ORDER BY unixepoch(created_at), rowid LIMIT ?`).all(NOW, 250);
  assert.ok(plan.some((row) => String(row.detail).includes("idx_audit_events_retention_epoch")));
  seed(db, [
    ["old_sqlite", "2025-10-14 02:00:00"],
    ["old_iso", "2025-10-14T02:00:00.000Z"],
    ["before_boundary", "2025-10-15T01:59:59.999Z"],
    ["at_boundary", "2025-10-15T02:00:00.000Z"],
    ["new_sqlite", "2025-10-16 02:00:00"],
    ["new_iso", "2026-10-15T02:00:00.000Z"],
    ["malformed", "not-a-date"],
    ["unknown", null],
  ]);
  assert.deepEqual(await cleanupExpiredAuditEvents(env, NOW), { deleted: 3, pending: false });
  assert.deepEqual(ids(db), ["at_boundary", "malformed", "new_iso", "new_sqlite", "unknown"]);
  assert.deepEqual(await cleanupExpiredAuditEvents(env, NOW), { deleted: 0, pending: false });
  db.close();
}

{
  const { db, env } = fixture();
  seed(db, Array.from({ length: 5 }, (_, n) => [`old_${n}`, "2024-01-01 00:00:00"]));
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...parts) => warnings.push(parts);
  try {
    assert.deepEqual(await cleanupExpiredAuditEvents(env, NOW,
      { batchSize: 2, maxBatches: 2 }), { deleted: 4, pending: true });
  } finally { console.warn = originalWarn; }
  assert.deepEqual(ids(db), ["old_4"]);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0][0], "[audit-retention-backlog]");
  assert.deepEqual(JSON.parse(warnings[0][1]), { deleted: 4, batch_limit: 2 });
  assert.deepEqual(await cleanupExpiredAuditEvents(env, NOW,
    { batchSize: 2, maxBatches: 2 }), { deleted: 1, pending: false });
  db.close();
}

{
  const { db, env } = fixture();
  seed(db, [
    ["leap_day", "2024-02-29 12:00:00"],
    ["previous_day", "2024-02-28 11:59:59"],
  ]);
  // Subtracting 12 calendar months from 2025-02-28 never deletes leap-day
  // events before the next anniversary; the next daily run catches them.
  assert.deepEqual(await cleanupExpiredAuditEvents(env,
    "2025-02-28T12:00:00.000Z"), { deleted: 1, pending: false });
  assert.deepEqual(ids(db), ["leap_day"]);
  assert.deepEqual(await cleanupExpiredAuditEvents(env,
    "2025-03-01T12:00:00.000Z"), { deleted: 1, pending: false });
  db.close();
}

{
  const { db, env } = fixture();
  assert.equal(AUDIT_RETENTION_BATCH_SIZE * AUDIT_RETENTION_MAX_BATCHES, 5000);
  await assert.rejects(cleanupExpiredAuditEvents(env, "not-a-date"), /Invalid audit retention time/);
  await assert.rejects(cleanupExpiredAuditEvents(env, NOW, { batchSize: 251 }), /Invalid audit retention batch bound/);
  await assert.rejects(cleanupExpiredAuditEvents(env, NOW, { maxBatches: 21 }), /Invalid audit retention batch bound/);
  await assert.rejects(cleanupExpiredAuditEvents({}, NOW), /Audit database unavailable/);
  await assert.rejects(cleanupExpiredAuditEvents({ cybermeters_db: {
    prepare: () => ({ bind: () => ({ run: async () => { throw new Error("D1 down"); } }) }),
  } }, NOW), /D1 down/);
  db.close();
}

console.log("PASS audit retention: 12-calendar-month boundary, both UTC timestamp forms, bounded batches, index use and failures");
