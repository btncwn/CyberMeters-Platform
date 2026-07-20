#!/usr/bin/env node
//
// First-ever managed-alert watermark race — DB-backed, CI-blocking.
//
// P2 fixed July 2026: the firstEverCondition hatch in emitManagedAlert compared
// the occurrence event's datetime('now') against the LAZILY-created activation
// watermark's datetime('now') with a bare `>=`. Both stamps are second-precision
// and written moments apart in one evaluator pass, so a second boundary ticking
// between the two writes made the workspace's genuinely-first occurrence look 1s
// older than its own activation — suppressed as baseline, PERMANENTLY (later
// passes compare the same fixed observed_at against the same watermark). First
// seen as a one-off CI failure of validate-website-security-lifecycle
// ("alerted exactly once — got 0"); reproduced deterministically.
//
// The fix is a named, bounded grace (ACTIVATION_CLOCK_SKEW_GRACE_MS = 2000)
// applied ONLY to the first-ever hatch. This suite pins the eligibility band,
// proves the backlog guard survives, and mutation-proves the grace cannot be
// silently removed, widened, or the suppression dropped.
//
// e2e boundary choice: with second-precision stamps and live lazy activation,
// the observed-vs-activated gap for an event seeded at now-1s is 1000 or 2000 ms
// (both eligible — jitter-proof) and at now-3s is 3000 or 4000 ms (both
// suppressed — jitter-proof). The EXACT 2000 ms boundary is pinned at the pure
// predicate layer, where it is deterministic; an e2e now-2s case would itself be
// second-boundary flaky, which is the defect class this file exists to end.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engDir = path.join(root, "workers", "scan-api", "src", "engines");
const eng = (f) => pathToFileURL(path.join(engDir, f)).href;
const { withinActivationGrace, ACTIVATION_CLOCK_SKEW_GRACE_MS } = await import(eng("managed-alerts.js"));
const { emitLifecycleAlert } = await import(eng("alert-consumers.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
const db = buildDb();
const env = { cybermeters_db: makeD1(db) };
globalThis.fetch = async () => new Response("{}", { status: 200 });
AbortSignal.timeout = () => undefined;

db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u1','o@e.co',1)").run();

let seq = 0;
function seedScenario(label, createdAtSql, { extraOlderEvent = false } = {}) {
  const ws = `ws_${label}`;
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, 'u1', 'WS')").run(ws);
  const rec = `wsc_${label}`;
  db.prepare(`INSERT INTO website_security_conditions
      (id, workspace_id, domain_id, domain, condition_key, monitoring_status, recurrence_type, first_seen_at, last_seen_at, created_at, updated_at)
    VALUES (?, ?, 'd1', 'acme.example.com', 'header_missing_content_security_policy', 'observed', 'browser_protection_missing',
            datetime('now'), datetime('now'), datetime('now'), datetime('now'))`).run(rec, ws);
  if (extraOlderEvent) {
    // A prior occurrence long before the one under test: baseline_count > 0.
    db.prepare(`INSERT INTO website_security_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
                VALUES (?, ?, ?, 'system', 'monitoring_changed', ?, datetime('now', '-40 days'))`)
      .run(`wse_old_${label}`, rec, ws, JSON.stringify({ to_recurrence_type: "browser_protection_missing", entity: "old.example.com" }));
  }
  db.prepare(`INSERT INTO website_security_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES (?, ?, ?, 'system', 'monitoring_changed', ?, ${createdAtSql})`)
    .run(`wse_${++seq}_${label}`, rec, ws, JSON.stringify({ to_recurrence_type: "browser_protection_missing", entity: "acme.example.com" }));
  return { ws, rec };
}
const emit = (s) => emitLifecycleAlert(env, {
  workspace_id: s.ws, domain_key: "website_security", record_id: s.rec,
  entity: "acme.example.com", recurrence: "browser_protection_missing",
  record_severity: "high", finding_type: "header_missing_content_security_policy",
});
const notifs = (ws) => db.prepare("SELECT COUNT(*) c FROM notification_events WHERE workspace_id = ?").get(ws).c;
const lastReason = (ws) => db.prepare("SELECT reason FROM alert_deliveries WHERE workspace_id = ? ORDER BY rowid DESC LIMIT 1").get(ws)?.reason ?? null;

// ── 1. Pure boundary arithmetic (the exact 2000 ms edge, deterministic) ──────
{
  eq("grace constant is the bounded 2000 ms", ACTIVATION_CLOCK_SKEW_GRACE_MS, 2000);
  ok("same instant is eligible", withinActivationGrace(10_000, 10_000));
  ok("1s before activation is eligible", withinActivationGrace(9_000, 10_000));
  ok("EXACTLY 2s before activation is eligible (inclusive boundary)", withinActivationGrace(8_000, 10_000));
  ok("3s before activation is NOT eligible (backlog stays excluded)", !withinActivationGrace(7_000, 10_000));
  ok("far-older backlog is NOT eligible", !withinActivationGrace(0, 3_600_000));
  ok("an occurrence after activation is eligible", withinActivationGrace(11_000, 10_000));
}

// ── 2. e2e through the REAL pipeline (lazy activation, real schema) ──────────
{
  const same = seedScenario("same", "datetime('now')");
  const r1 = await emit(same);
  ok("same-second first-ever occurrence alerts exactly once", r1?.emitted === true && notifs(same.ws) === 1, lastReason(same.ws));

  const minus1 = seedScenario("minus1", "datetime('now', '-1 second')");
  const r2 = await emit(minus1);
  ok("occurrence 1s before lazy activation alerts exactly once (THE FIXED RACE)",
     r2?.emitted === true && notifs(minus1.ws) === 1, lastReason(minus1.ws));

  const minus3 = seedScenario("minus3", "datetime('now', '-3 seconds')");
  const r3 = await emit(minus3);
  ok("occurrence >2s before activation stays baseline-suppressed",
     r3?.emitted === false && notifs(minus3.ws) === 0 && r3?.reason === "alert_baseline_established");

  // Unchanged second pass: the SAME occurrence re-emitted must not duplicate.
  const r2b = await emit(minus1);
  ok("unchanged second pass emits no duplicate", r2b?.emitted === false && notifs(minus1.ws) === 1,
     `reason=${r2b?.reason}`);

  // A later genuinely NEW occurrence on the raced workspace alerts normally.
  db.prepare(`INSERT INTO website_security_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('wse_new_minus1', ?, ?, 'system', 'monitoring_changed', ?, datetime('now', '+2 seconds'))`)
    .run(minus1.rec, minus1.ws, JSON.stringify({ to_recurrence_type: "browser_protection_missing", entity: "acme.example.com" }));
  const r2c = await emit(minus1);
  ok("a later genuinely new occurrence alerts normally", r2c?.emitted === true && notifs(minus1.ws) === 2,
     `reason=${r2c?.reason}`);

  // Backlog guard intact: pre-existing history (baseline_count > 0) suppresses
  // even a fresh-looking occurrence on the activating pass.
  const backlog = seedScenario("backlog", "datetime('now')", { extraOlderEvent: true });
  const r4 = await emit(backlog);
  ok("pre-existing backlog still suppresses the activating pass",
     r4?.emitted === false && notifs(backlog.ws) === 0 && r4?.reason === "alert_baseline_established");
}

// ── 3. MUTATION HARNESS ──────────────────────────────────────────────────────
const LIB_URL = pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib")).href;
const ENG_URL = pathToFileURL(engDir).href;
const rewrite = (src) => src
  .replace(/from "\.\.\/lib\//g, `from "${LIB_URL}/`)
  .replace(/from "\.\//g, `from "${ENG_URL}/`);
async function mutantConsumers(from, to) {
  // Mutate managed-alerts.js and load a fresh alert-consumers that imports it.
  const orig = fs.readFileSync(path.join(engDir, "managed-alerts.js"), "utf8");
  if (!orig.includes(from)) return { anchor: false };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grace-"));
  const ma = path.join(tmp, "managed-alerts.mjs");
  fs.writeFileSync(ma, rewrite(orig.replace(from, to)));
  const acSrc = fs.readFileSync(path.join(engDir, "alert-consumers.js"), "utf8")
    .replace('from "./managed-alerts.js"', `from ${JSON.stringify(pathToFileURL(ma).href)}`);
  const ac = path.join(tmp, "alert-consumers.mjs");
  fs.writeFileSync(ac, rewrite(acSrc));
  try {
    return { anchor: true, mod: await import(`${pathToFileURL(ac).href}?t=${Date.now()}-${Math.random()}`) };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
const mutantEmit = (mod, s) => mod.emitLifecycleAlert(env, {
  workspace_id: s.ws, domain_key: "website_security", record_id: s.rec,
  entity: "acme.example.com", recurrence: "browser_protection_missing",
  record_severity: "high", finding_type: "header_missing_content_security_policy",
});

// M1 — grace removed: the fixed race must reappear (lost first alert).
{
  const m = await mutantConsumers("export const ACTIVATION_CLOCK_SKEW_GRACE_MS = 2000;",
                                  "export const ACTIVATION_CLOCK_SKEW_GRACE_MS = 0;");
  let caught = false;
  if (m.anchor) {
    const s = seedScenario("m1", "datetime('now', '-1 second')");
    const r = await mutantEmit(m.mod, s);
    caught = r?.emitted === false && r?.reason === "alert_baseline_established";
  }
  ok("mutation M1 (grace removed → first alert lost again) is CAUGHT", m.anchor && caught);
}

// M2 — grace widened beyond the bound: old backlog would alert.
{
  const m = await mutantConsumers("export const ACTIVATION_CLOCK_SKEW_GRACE_MS = 2000;",
                                  "export const ACTIVATION_CLOCK_SKEW_GRACE_MS = 3600000;");
  let caught = false;
  if (m.anchor) {
    const s = seedScenario("m2", "datetime('now', '-3 seconds')");
    const r = await mutantEmit(m.mod, s);
    caught = r?.emitted === true;   // the suppressed-band case now alerts
  }
  ok("mutation M2 (grace widened → old occurrence alerts) is CAUGHT", m.anchor && caught);
}

// M3 — backlog suppression removed entirely.
{
  const m = await mutantConsumers(
    "if (!firstEverCondition\n        && (activation.established_now || !observationIsAfterWatermark(observed_at, activation.activated_at))) {",
    "if (false) {");
  let caught = false;
  if (m.anchor) {
    const s = seedScenario("m3", "datetime('now')", { extraOlderEvent: true });
    const r = await mutantEmit(m.mod, s);
    caught = r?.emitted === true;   // backlog released
  }
  ok("mutation M3 (baseline suppression removed → backlog released) is CAUGHT", m.anchor && caught);
}

console.log(`\nalert-activation-grace: ${pass}/${pass + fail} passed`);
if (fail) { console.error("alert-activation-grace validation FAILED"); process.exit(1); }
console.log("alert-activation-grace validation passed");
