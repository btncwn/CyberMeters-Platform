#!/usr/bin/env node
//
// Weekly-digest regression: the Monday "what changed this week" email must go to
// ACTIVE workspaces only (verified owner + ≥1 monitored domain), at most once per
// ISO week (deduped), aggregate the last 7 days of exposure events, send a short
// "all quiet" reassurance on quiet weeks, and never mail dormant or unverified
// owners. Delivery (Resend) is mocked so send/skip is deterministic. Requires
// Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const mod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "weekly-digest.js")).href);
const { sendWeeklyDigests, computeWeeklyChanges, buildDigestEmail, isoWeekKey } = mod;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// Mock Resend delivery.
let deliverOk = true, sends = 0;
globalThis.fetch = async (url) => {
  if (String(url).includes("resend.com")) {
    sends++;
    if (!deliverOk) throw new Error("network down");
    return { ok: true, status: 200, json: async () => ({ id: "re_mock" }) };
  }
  throw new Error("network disabled");
};
AbortSignal.timeout = () => undefined;

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
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  RESEND_API_KEY: "re_test", HELLO_EMAIL_FROM: "hello@cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
};
const digestRows = (ws) => db.prepare("SELECT status FROM lifecycle_email_events WHERE workspace_id=? AND type='lifecycle_weekly_digest'").all(ws);

// Seed: owner user (verified) + one active workspace with a domain + events;
// one dormant workspace (no domains); one active workspace with unverified owner.
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_ok','owner@example.co.uk',1)").run();
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_unv','pending@example.co.uk',0)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_active','Acme', 'u_ok')").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_dormant','Dormant','u_ok')").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_unv','Unverified','u_unv')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_active','d1')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_unv','d2')").run();
let seq = 0;
const seedEvent = (ws, sev, type, age = "-1 day") =>
  db.prepare(`INSERT INTO asset_events (id, workspace_id, domain_id, event_type, hostname, severity, description, created_at)
              VALUES (?, ?, 'd1', ?, 'x.acme.co.uk', ?, 'detail', datetime('now', ?))`).run(`ev_${++seq}`, ws, type, sev, age);
seedEvent("ws_active", "high", "email_dmarc_policy_changed");
seedEvent("ws_active", "medium", "dns_ip_changed");
seedEvent("ws_active", "info", "new_asset_discovered");
seedEvent("ws_active", "high", "exposed_service_detected", "-30 days"); // outside window — must not count

// ── 1. isoWeekKey format ─────────────────────────────────────────────────────
ok("isoWeekKey looks like YYYY-Wnn", /^\d{4}-W\d{2}$/.test(isoWeekKey(new Date("2026-07-13T00:00:00Z"))));

// ── 2. computeWeeklyChanges: 7-day window + severity/category + top sort ─────
const changes = await computeWeeklyChanges(env, "ws_active");
ok("counts only events within 7 days (3, not 4)", changes.total === 3);
ok("severity breakdown correct", changes.bySeverity.high === 1 && changes.bySeverity.medium === 1 && changes.bySeverity.info === 1);
ok("category breakdown enriched (email + dns + asset)", changes.byCategory.email === 1 && changes.byCategory.dns === 1 && changes.byCategory.asset === 1);
ok("top events sorted by severity (high first)", changes.top[0]?.severity === "high");
ok("top events carry an enriched title", typeof changes.top[0]?.title === "string" && changes.top[0].title.length > 0);

// ── 3. buildDigestEmail: changes vs all-quiet ────────────────────────────────
const withChanges = buildDigestEmail("Acme", changes, env.FRONTEND_URL);
ok("digest subject names the change count", /3 changes on Acme/.test(withChanges.subject));
ok("digest body lists a top event", withChanges.text.includes(changes.top[0].title));
ok("digest links to the timeline", withChanges.html.includes("/exposure"));
const quiet = buildDigestEmail("Acme", { total: 0, bySeverity: {}, byCategory: {}, top: [] }, env.FRONTEND_URL);
ok("quiet week is the 'all quiet' reassurance", /all quiet on Acme/i.test(quiet.subject) && /stable/i.test(quiet.text));

// ── 4. sendWeeklyDigests: active workspace with changes → sent, deduped ──────
deliverOk = true; sends = 0;
await sendWeeklyDigests(env);
ok("active workspace received exactly one digest", digestRows("ws_active").length === 1);
ok("active workspace digest is 'sent'", digestRows("ws_active")[0]?.status === "sent");
ok("dormant workspace (no domains) got nothing", digestRows("ws_dormant").length === 0);
ok("unverified owner got nothing", digestRows("ws_unv").length === 0);
const sendsAfterFirst = sends;

// ── 5. Dedup: a second run in the same ISO week sends nothing more ───────────
await sendWeeklyDigests(env);
ok("second run in the same week does not re-send", digestRows("ws_active").length === 1 && sends === sendsAfterFirst);

// ── 6. Quiet week still sends the reassurance to an active workspace ─────────
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_quiet','Quiet','u_ok')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_quiet','d3')").run();
deliverOk = true;
await sendWeeklyDigests(env);
ok("quiet active workspace still receives a digest", digestRows("ws_quiet").length === 1 && digestRows("ws_quiet")[0]?.status === "sent");

console.log(`\nWeekly digest: ${pass}/${pass + fail} passed`);
if (fail) { console.error("weekly-digest validation FAILED"); process.exit(1); }
console.log("weekly-digest validation passed");
