#!/usr/bin/env node
//
// Hosted DNS v2 migration regression. Proves migration 071:
//   (1) creates hosted_dns_entries with NO CHECK on record_kind / verification_state
//       (any kind inserts — the whole point of the redesign: never migrate again);
//   (2) backfills existing hosted DMARC rows 1:1 with the exact column mapping,
//       carrying the full write-ahead saga + ramp state (not just the happy fields);
//   (3) is idempotent (re-run inserts nothing) and enforces one record per
//       (workspace, domain, kind);
//   (4) contains no DROP TABLE (additive-only, guard-clean).
// Fresh in-memory SQLite; Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const migDir = path.join(root, "database", "migrations");
let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));

// Apply migrations in order; seed a realistic hosted DMARC row into the OLD table
// immediately before 071 so the backfill has something to copy.
const files = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql")).sort();
for (const f of files) {
  if (f.startsWith("071-")) {
    db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('u1','a@x.co',1)").run();
    db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws1','W','u1')").run();
    // A mid-lifecycle DMARC row: connected, autopilot on, mid-ramp, with a pending
    // write-ahead intent and a prior failure — i.e. every field must survive.
    db.prepare(`INSERT INTO hosted_dns_records
      (id, workspace_id, domain, record_type, hosted_name, current_value, previous_value,
       cf_record_id, status, last_verified_at, last_change_at, created_by, created_at,
       updated_at, failure_count, last_error, autopilot, pass_rate_at_change,
       pending_value, pending_since)
      VALUES
      ('hd-live01','ws1','acme.co','dmarc','hd-live01.dmarc.cybermeters.com',
       'v=DMARC1; p=quarantine; pct=50','v=DMARC1; p=none',
       'cf-abc-123','connected','2026-07-12T09:00:00Z','2026-07-11T00:00:00Z','u1',
       '2026-07-01T00:00:00Z','2026-07-12T09:00:00Z',2,'temporary_issue',1,0.77,
       'v=DMARC1; p=quarantine; pct=100','2026-07-12T08:00:00Z')`).run();
  }
  apply(path.join(migDir, f));
}

// ── 1. Table + no-CHECK on the two enums ─────────────────────────────────────
const cols = db.prepare("SELECT name FROM pragma_table_info('hosted_dns_entries')").all().map((r) => r.name);
ok("hosted_dns_entries exists", cols.length > 0);
const insKind = (id, kind, state = "pending_dns") =>
  db.prepare(`INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state) VALUES (?, 'ws1', ?, ?, 'c.n', 't.n', 'v', ?)`)
    .run(id, id + ".co", kind, state);
for (const k of ["tlsrpt", "mtasts", "spf"]) ok(`record_kind '${k}' inserts (Phase C ready)`, (() => { try { insKind("k-" + k, k); return true; } catch { return false; } })());
ok("record_kind has NO CHECK (arbitrary kind inserts)", (() => { try { insKind("k-future", "future_kind"); return true; } catch { return false; } })());
ok("verification_state has NO CHECK (arbitrary state inserts)", (() => { try { insKind("s-x", "dmarc", "some_new_state"); return true; } catch { return false; } })());

// ── 2. Backfill 1:1 mapping (every field carried) ────────────────────────────
const e = db.prepare("SELECT * FROM hosted_dns_entries WHERE id='hd-live01'").get();
ok("DMARC row backfilled", !!e);
ok("record_type → record_kind", e.record_kind === "dmarc");
ok("customer_name derived '_dmarc.'+domain", e.customer_name === "_dmarc.acme.co");
ok("hosted_name → target_name", e.target_name === "hd-live01.dmarc.cybermeters.com");
ok("current_value → target_value", e.target_value === "v=DMARC1; p=quarantine; pct=50");
ok("provider defaulted cloudflare", e.provider === "cloudflare");
ok("cf_record_id → provider_record_id", e.provider_record_id === "cf-abc-123");
ok("status → verification_state", e.verification_state === "connected");
ok("last_verified_at → verified_at", e.verified_at === "2026-07-12T09:00:00Z");
ok("previous_value preserved", e.previous_value === "v=DMARC1; p=none");
ok("saga pending_value preserved", e.pending_value === "v=DMARC1; p=quarantine; pct=100");
ok("saga pending_since preserved", e.pending_since === "2026-07-12T08:00:00Z");
ok("failure_count preserved", e.failure_count === 2);
ok("last_error preserved", e.last_error === "temporary_issue");
ok("autopilot preserved", e.autopilot === 1);
ok("pass_rate_at_change preserved", e.pass_rate_at_change === 0.77);
ok("last_change_at preserved", e.last_change_at === "2026-07-11T00:00:00Z");
ok("created_by/created_at preserved", e.created_by === "u1" && e.created_at === "2026-07-01T00:00:00Z");

// ── 3. Idempotent re-run + uniqueness ────────────────────────────────────────
const before = db.prepare("SELECT COUNT(*) c FROM hosted_dns_entries").get().c;
db.exec(fs.readFileSync(path.join(migDir, "071-hosted-dns-entries.sql"), "utf8")); // re-apply whole migration
const after = db.prepare("SELECT COUNT(*) c FROM hosted_dns_entries").get().c;
ok("migration re-run is idempotent (no dupes)", before === after);
ok("UNIQUE (workspace,domain,kind) enforced", (() => { try { db.prepare(`INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value) VALUES ('dup','ws1','acme.co','dmarc','x','y','z')`).run(); return false; } catch { return true; } })());

// ── 4. Guard-clean: no DROP TABLE in the migration ───────────────────────────
const migText = fs.readFileSync(path.join(migDir, "071-hosted-dns-entries.sql"), "utf8").replace(/--[^\n]*/g, "");
ok("migration contains no DROP TABLE (additive-only)", !/\bDROP\s+TABLE\b/i.test(migText));

console.log(`\nHosted DNS v2 migration: ${pass}/${pass + fail} passed`);
if (fail) { console.error("hosted-dns-v2 validation FAILED"); process.exit(1); }
console.log("hosted-dns-v2 validation passed");
