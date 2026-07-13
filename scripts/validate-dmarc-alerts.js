#!/usr/bin/env node
//
// DMARC operational alerts regression. Proves runDmarcAlertsSweep turns classified
// sender data into the right notifications: a new high-volume risky source
// (dmarc_new_sender) and an unauthorised source failing auth at volume
// (dmarc_spoofing_spike) — and does NOT alert on legitimate, old, or low-volume
// senders; deduped across runs; tenant-scoped; manual classification respected.
// Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "dmarc-alerts.js")).href);
const { runDmarcAlertsSweep } = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
globalThis.fetch = async () => { throw new Error("network disabled"); };

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => { const wrap = (sql, a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: r.changes } }; } }); return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } }; };
const env = { cybermeters_db: makeD1(db) };

db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_a','Acme','u_a')").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_b','Other','u_b')").run();

// Seed senders. RECENT last_seen so the sweep window picks them up.
const seed = (id, ws, ip, { total = 0, failed = 0, aligned = 0, auto = "unknown", manual = "unknown", classifiedAt = null, firstSeen = "-1 hours" } = {}) =>
  db.prepare(`INSERT INTO email_sender_sources
    (id, workspace_id, domain, source_ip, provider_guess, total_messages, aligned_messages, failed_messages,
     first_seen, last_seen, classification, auto_classification, classified_at, created_at, updated_at)
    VALUES (?, ?, 'acme.co.uk', ?, 'unknown', ?, ?, ?, datetime('now', ?), datetime('now'), ?, ?, ?, datetime('now'), datetime('now'))`)
    .run(id, ws, ip, total, aligned, failed, firstSeen, manual, auto, classifiedAt);

seed("s_spoof", "ws_a", "9.9.9.9", { total: 80, failed: 70, auto: "unauthorised" });          // → spoofing_spike (high)
seed("s_new",   "ws_a", "1.1.1.1", { total: 120, failed: 20, aligned: 100, auto: "unknown" }); // → new_sender (new + risky)
seed("s_legit", "ws_a", "2.2.2.2", { total: 500, failed: 2, aligned: 498, auto: "authorised" });// → NO alert (legit)
seed("s_old",   "ws_a", "3.3.3.3", { total: 200, failed: 5, auto: "unknown", firstSeen: "-6 days" }); // → NO new_sender (not new)
seed("s_small", "ws_a", "4.4.4.4", { total: 8, failed: 1, auto: "unknown" });                  // → NO alert (below volume)
seed("s_manual_trust", "ws_a", "5.5.5.5", { total: 300, failed: 60, auto: "unauthorised", manual: "trusted", classifiedAt: "2026-07-13" }); // manual override → NOT unauthorised → NO spoofing
seed("s_spoof_b", "ws_b", "9.9.9.9", { total: 90, failed: 80, auto: "unauthorised" });          // ws_b isolation

// ── Run the sweep ─────────────────────────────────────────────────────────────
const r1 = await runDmarcAlertsSweep(env, { now: new Date("2026-07-13T12:00:00Z") });
ok("sweep runs and reports counts", r1 && typeof r1.alerts === "number" && r1.checked >= 6);

const notifs = (type, ws = "ws_a") => db.prepare("SELECT metadata_json FROM notification_events WHERE workspace_id=? AND type=?").all(ws, type);
const hasIp = (rows, ip) => rows.some((r) => String(r.metadata_json || "").includes(`"source_ip":"${ip}"`));

ok("spoofing_spike alert for the unauthorised high-fail source", hasIp(notifs("dmarc_spoofing_spike"), "9.9.9.9"));
ok("new_sender alert for the new risky high-volume source", hasIp(notifs("dmarc_new_sender"), "1.1.1.1"));
ok("NO alert for the legitimate sender", !hasIp(notifs("dmarc_new_sender"), "2.2.2.2") && !hasIp(notifs("dmarc_spoofing_spike"), "2.2.2.2"));
ok("NO new_sender for the OLD source (not new)", !hasIp(notifs("dmarc_new_sender"), "3.3.3.3"));
ok("NO alert for the low-volume source", !hasIp(notifs("dmarc_new_sender"), "4.4.4.4"));
ok("manual 'trusted' override suppresses the spoofing alert", !hasIp(notifs("dmarc_spoofing_spike"), "5.5.5.5"));

// ── Tenant isolation ──────────────────────────────────────────────────────────
ok("ws_b spoofing alert lives only in ws_b", hasIp(notifs("dmarc_spoofing_spike", "ws_b"), "9.9.9.9"));
const wsAspoofCount = db.prepare("SELECT COUNT(*) c FROM notification_events WHERE workspace_id='ws_a' AND type='dmarc_spoofing_spike'").get().c;
const wsBspoofCount = db.prepare("SELECT COUNT(*) c FROM notification_events WHERE workspace_id='ws_b' AND type='dmarc_spoofing_spike'").get().c;
ok("no cross-tenant alert bleed (1 each)", wsAspoofCount === 1 && wsBspoofCount === 1);

// ── Dedup: a second sweep in the window adds nothing ──────────────────────────
const before = db.prepare("SELECT COUNT(*) c FROM notification_events").get().c;
await runDmarcAlertsSweep(env, { now: new Date("2026-07-13T12:05:00Z") });
const after = db.prepare("SELECT COUNT(*) c FROM notification_events").get().c;
ok("second sweep is deduped (no duplicate alerts)", before === after);

console.log(`\nDMARC alerts: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-alerts validation FAILED"); process.exit(1); }
console.log("dmarc-alerts validation passed");
