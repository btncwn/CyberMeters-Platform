#!/usr/bin/env node
//
// Universal case-creation primitive (createManagedCase) — DB-backed proof.
// CI-blocking. Runs against an in-memory SQLite database with the production
// schema + all migrations.
//
// Proves: all six base case types are creatable through the ONE factory;
// case-type/domain mismatch is rejected; invalid domain/case_type is rejected;
// a soft-deleted workspace and an unlinked domain are rejected; deduplication
// returns the existing open case; the canonical remediation is linked (or null);
// and an append-only `case_created` event is written with the deterministic
// taxonomy shape.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const mcm = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "managed-case-model.js")).href);
const { createManagedCase, DEFAULT_CASE_TYPE_BY_DOMAIN, CANONICAL_DOMAIN_KEYS, CASE_TYPE_REGISTRY } = mcm;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, a, b) => ok(n, a === b, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const env = { cybermeters_db: makeD1(db) };
// Active workspace + linked domain, plus a soft-deleted workspace.
db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES ('ws1','Alpha','u1',datetime('now'),datetime('now'))").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at, deleted_at) VALUES ('wsDead','Dead','u1',datetime('now'),datetime('now'),datetime('now'))").run();
db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES ('u1','u1@example.com','x','U1','free','active',1,0)").run();
db.prepare("INSERT INTO domains (id, domain, user_id, created_at) VALUES ('d1','example.com','u1',datetime('now'))").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','d1')").run();

// ── 1. Each of the six base case types is creatable through the factory ──────
const BASE_DOMAINS = ["email_protection", "certificates_trust", "cyber_essentials_readiness", "website_security", "identity_exposure", "shadow_it_unmanaged_technology"];
let created = 0;
for (const dk of BASE_DOMAINS) {
  const ct = DEFAULT_CASE_TYPE_BY_DOMAIN[dk];
  const r = await createManagedCase(env, {
    workspace_id: "ws1", domain_key: dk, case_type: ct,
    source_finding_type: `probe_${dk}`, source_finding_id: `${dk}:example.com`,
    source_scan_id: "scan1", domain: "example.com", title: `Test ${dk}`,
    actor: { actor_type: "customer", actor_id: "u1" },
  });
  ok(`base case type ${ct} is creatable`, r.ok && r.created && r.case.status === "detected" && r.case.domain_key === dk);
  if (r.ok && r.created) created++;
}
eq("all six base case types were created", created, 6);

// ── 2. Canonical remediation linkage (or explicit null) ──────────────────────
const remCase = await createManagedCase(env, {
  workspace_id: "ws1", domain_key: "email_protection", case_type: "email_case",
  source_finding_type: "email_missing_spf", source_finding_id: "email_missing_spf:example.com",
  domain: "example.com", actor: { actor_type: "customer", actor_id: "u1" },
});
eq("known source finding links the canonical remediation_id", remCase.case?.remediation_id, "email.spf.publish");
const unknownRem = await createManagedCase(env, {
  workspace_id: "ws1", domain_key: "website_security", case_type: "website_case",
  source_finding_type: "totally_unknown_xyz", source_finding_id: "totally_unknown_xyz:example.com",
  domain: "example.com", actor: { actor_type: "customer", actor_id: "u1" },
});
eq("unknown source finding links a null remediation_id (honest)", unknownRem.case?.remediation_id, null);

// ── 3. Mismatch + invalid inputs are rejected ────────────────────────────────
eq("case_type/domain mismatch is rejected",
  (await createManagedCase(env, { workspace_id: "ws1", domain_key: "email_protection", case_type: "website_case", actor: { actor_id: "u1" } })).code, "domain_case_type_mismatch");
eq("invalid domain_key is rejected",
  (await createManagedCase(env, { workspace_id: "ws1", domain_key: "not_a_domain", case_type: "email_case", actor: { actor_id: "u1" } })).code, "invalid_domain_key");
eq("invalid case_type is rejected",
  (await createManagedCase(env, { workspace_id: "ws1", domain_key: "email_protection", case_type: "nope", actor: { actor_id: "u1" } })).code, "invalid_case_type");

// ── 4. Soft-deleted workspace + unlinked domain are rejected ─────────────────
eq("soft-deleted workspace creation is rejected",
  (await createManagedCase(env, { workspace_id: "wsDead", domain_key: "email_protection", case_type: "email_case", actor: { actor_id: "u1" } })).code, "workspace_inactive");
eq("unknown workspace creation is rejected",
  (await createManagedCase(env, { workspace_id: "ws_missing", domain_key: "email_protection", case_type: "email_case", actor: { actor_id: "u1" } })).code, "workspace_inactive");
eq("a domain not linked to the workspace is rejected",
  (await createManagedCase(env, { workspace_id: "ws1", domain_key: "email_protection", case_type: "email_case", domain: "unlinked.example", actor: { actor_id: "u1" } })).code, "domain_ineligible");

// ── 5. Deduplication returns the existing open case ──────────────────────────
const first = await createManagedCase(env, { workspace_id: "ws1", domain_key: "identity_exposure", case_type: "identity_case", source_finding_id: "dup:example.com", domain: "example.com", actor: { actor_id: "u1" } });
const second = await createManagedCase(env, { workspace_id: "ws1", domain_key: "identity_exposure", case_type: "identity_case", source_finding_id: "dup:example.com", domain: "example.com", actor: { actor_id: "u1" } });
ok("first create opens a new case", first.ok && first.created);
ok("second create for the same source dedupes (no new case)", second.ok && second.created === false && second.case.id === first.case.id);
eq("dedup did not insert a second row", db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1' AND finding_id='dup:example.com'").get().n, 1);

// ── 6. Append-only case_created event with the deterministic taxonomy shape ──
const ev = db.prepare("SELECT * FROM managed_case_events WHERE case_id = ? AND action = 'case_created'").get(first.case.id);
ok("a case_created event was appended", Boolean(ev) && ev.from_status === null && ev.to_status === "detected");
const detail = JSON.parse(ev.detail_json);
ok("case_created detail carries the canonical taxonomy keys",
  ["domain_key", "case_type", "source_finding_type", "source_scan_id", "remediation_id"].every((k) => k in detail));
// Append-only: the event count only ever grows (dedup wrote no new create event).
eq("exactly one case_created event exists for the deduped source", db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id = ? AND action = 'case_created'").get(first.case.id).n, 1);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
