#!/usr/bin/env node
//
// Hosted-DMARC self-driving lifecycle runtime proof. The apply/rollback/reconcile
// write-ahead saga is already covered by validate-regression-fixtures.js; this
// closes the remaining gap — the readiness / pass-rate / auto-rollback trio that
// gates real policy advancement was untested at runtime. Drives:
//   • getHostedDmarcPassRate  (windowed pass-rate from ingested aggregate records,
//                              tenant-scoped)
//   • evaluateRampReadiness   (safe-to-advance gating + reasons)
//   • shouldAutoRollback      (rollback trigger on pass-rate regression)
// Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "hosted-dmarc.js")).href);
const { getHostedDmarcPassRate, evaluateRampReadiness, shouldAutoRollback, runHostedDnsVerificationSweep } = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => { const wrap = (sql, a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: r.changes } }; } }); return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } }; };
const env = { cybermeters_db: makeD1(db) };

let seq = 0;
// Seed an aggregate record. agedDays shifts created_at into the past.
const rec = (ws, domain, msgs, aligned, agedDays = 0, source = "manual_paste") => {
  const reportId = `rep${++seq}`;
  db.prepare(`INSERT INTO dmarc_aggregate_reports
    (id, workspace_id, domain, external_report_id, record_count, message_count, source, created_at)
    VALUES (?, ?, ?, ?, 1, ?, ?, datetime('now', ?))`)
    .run(reportId, ws, domain, reportId, msgs, source, `-${agedDays} days`);
  db.prepare(`INSERT INTO dmarc_aggregate_records
    (id, report_id, workspace_id, domain, source_ip, message_count, disposition,
     dkim_aligned_result, spf_aligned_result, created_at)
    VALUES (?, ?, ?, ?, '1.1.1.1', ?, 'none', ?, ?, datetime('now', ?))`)
    .run(`r${++seq}`, reportId, ws, domain, msgs,
      aligned ? "pass" : "fail", aligned ? "pass" : "fail", `-${agedDays} days`);
};

// ── getHostedDmarcPassRate: external automation remains suspended ────────────
rec("ws_a", "acme.co.uk", 98, true);      // in-window aligned
rec("ws_a", "acme.co.uk", 2, false);      // in-window failing
rec("ws_a", "acme.co.uk", 1000, true, 30); // OUT of the 7-day window (must be ignored)
rec("ws_b", "acme.co.uk", 500, false);    // another tenant, SAME domain (isolation)
rec("ws_a", "acme.co.uk", 1_000_000, false, 0, "inbound_email"); // forged inbound: no authority
rec("ws_a", "acme.co.uk", 1_000_000, false, 0, "unknown_source"); // unknown: fail closed
rec("ws_c", "signed.example", 99, true, 0, "signed_upload");      // existing explicit path

const pr = await getHostedDmarcPassRate(env, "ws_a", "acme.co.uk", { sinceDays: 7 });
ok("aggregate reports cannot produce a hosted-DNS automation pass rate",
  pr.total === 0 && pr.pass_rate === null);
ok("external automation contract requires corroboration and fails closed",
  pr.external_automation_suspended === true && pr.corroboration_required === true);
ok("forged inbound and unknown-source records have zero hosted-DNS authority",
  pr.total === 0 && pr.pass_rate === null && pr.inbound_automation_suspended === true);
const prB = await getHostedDmarcPassRate(env, "ws_b", "acme.co.uk", { sinceDays: 7 });
ok("another tenant also fails closed while external automation is suspended",
  prB.total === 0 && prB.pass_rate === null);
const prSigned = await getHostedDmarcPassRate(env, "ws_c", "signed.example", { sinceDays: 7 });
ok("signed upload does not bypass destructive-automation corroboration",
  prSigned.total === 0 && prSigned.pass_rate === null);
const prEmpty = await getHostedDmarcPassRate(env, "ws_none", "nope.co", { sinceDays: 7 });
ok("no data → null pass-rate (honest, not a fake number)", prEmpty.total === 0 && prEmpty.pass_rate === null);

// ── evaluateRampReadiness: safe-to-advance gating ─────────────────────────────
const ready = evaluateRampReadiness({ pass_rate: 99, total_messages: 500, days_since_change: 7 });
ok("healthy metrics → ready to advance", ready.ready === true && ready.reasons.length === 0);

const lowPass = evaluateRampReadiness({ pass_rate: 80, total_messages: 500, days_since_change: 7 });
ok("low pass-rate blocks advance with a reason", lowPass.ready === false && lowPass.reasons.some((r) => /pass rate/i.test(r)));

const lowVol = evaluateRampReadiness({ pass_rate: 99, total_messages: 3, days_since_change: 7 });
ok("insufficient volume blocks advance with a reason", lowVol.ready === false && lowVol.reasons.some((r) => /volume|messages/i.test(r)));

const tooSoon = evaluateRampReadiness({ pass_rate: 99, total_messages: 500, days_since_change: 0 });
ok("too-soon since last change blocks advance with a reason", tooSoon.ready === false && tooSoon.reasons.some((r) => /change|days/i.test(r)));

const noData = evaluateRampReadiness({ pass_rate: null, total_messages: null, days_since_change: null });
ok("no measurement → not ready (never advance blind)", noData.ready === false && noData.reasons.length > 0);

// ── shouldAutoRollback: trigger on regression only ────────────────────────────
ok("big pass-rate drop at volume → rollback", shouldAutoRollback({ baseline_pass_rate: 99, current_pass_rate: 80, total_messages: 500 }) === true);
ok("small drop → no rollback", shouldAutoRollback({ baseline_pass_rate: 99, current_pass_rate: 98, total_messages: 500 }) === false);
ok("low volume → no rollback (too little evidence)", shouldAutoRollback({ baseline_pass_rate: 99, current_pass_rate: 50, total_messages: 5 }) === false);
ok("missing measurement → no rollback", shouldAutoRollback({ baseline_pass_rate: null, current_pass_rate: 50, total_messages: 500 }) === false);

// ── End-to-end: suspended evidence cannot satisfy readiness ───────────────────
const e2eReady = evaluateRampReadiness({ pass_rate: pr.pass_rate, total_messages: pr.total, days_since_change: 7 });
ok("suspended aggregate evidence cannot advance hosted-DMARC",
   e2eReady.ready === false && Array.isArray(e2eReady.reasons) && e2eReady.reasons.length > 0);

// ── The real sweep: autopilot and auto-rollback write customer DNS ─────────
// Autopilot changes a customer's live DMARC record, so its wiring inside
// runHostedDnsVerificationSweep is proven end to end here: the sweep reads the
// row, verifies DNS, reads the pass rate, decides, and PATCHes Cloudflare. The
// PATCH bodies are what would be published. RFC 9989: none may carry pct.
{
  const RUA = "rua=mailto:cmrua_x@reports.cybermeters.com";
  const zone = "e".repeat(32);
  const sweepEnv = { ...env, CLOUDFLARE_API_TOKEN: "t", CLOUDFLARE_ZONE_ID: zone };
  const served = new Map();   // hosted name → TXT value Cloudflare serves
  const patches = [];
  const fetchImpl = async (url, opts = {}) => {
    if ((opts.method || "GET") === "PATCH") {
      const body = JSON.parse(opts.body);
      patches.push(body.content);
      served.set(body.name, body.content);
      return new Response(JSON.stringify({ success: true, result: { id: "cf", content: body.content } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, result: [] }), { status: 200 });
  };
  // The customer's _dmarc CNAMEs to the hosted name, which serves its TXT.
  const dnsQueryImpl = async (name, type) => {
    const hosted = String(name).startsWith("_dmarc.") ? `hd-${String(name).slice(7).split(".")[0]}.dmarc.cybermeters.com` : name;
    const value = served.get(hosted);
    if (!value) return { Status: 3, Answer: [] };
    if (type === "CNAME") return { Status: 0, Answer: [{ type: 5, data: `${hosted}.` }] };
    const chain = hosted === name ? [] : [{ type: 5, data: `${hosted}.` }];
    return { Status: 0, Answer: [...chain, { type: 16, data: `"${value}"` }] };
  };
  const seed = (label, value, extra = {}) => {
    const id = `hd-${label}`, hosted = `hd-${label}.dmarc.cybermeters.com`;
    served.set(hosted, value);
    db.prepare(`INSERT INTO hosted_dns_entries (id, workspace_id, domain, record_kind, customer_name, target_name, target_value,
      previous_value, verification_state, provider_record_id, autopilot, pass_rate_at_change, last_change_at, created_at, updated_at)
      VALUES (?, 'ws_sweep', ?, 'dmarc', ?, ?, ?, ?, 'connected', ?, ?, ?, datetime('now','-10 days'), datetime('now','-30 days'), datetime('now','-10 days'))`)
      .run(id, `${label}.example`, `_dmarc.${label}.example`, hosted, value, extra.previous ?? null,
        "a".repeat(32), extra.autopilot ?? 1, extra.baseline ?? null);
    return id;
  };
  const value = (id) => db.prepare("SELECT target_value FROM hosted_dns_entries WHERE id = ?").get(id).target_value;
  const clear = () => db.prepare("DELETE FROM hosted_dns_entries WHERE workspace_id = 'ws_sweep'").run();
  const healthy = async () => ({ total: 500, pass_rate: 99.5 });
  const dropped = async () => ({ total: 500, pass_rate: 70 });

  // 1. Production pass rate (suspended): autopilot never writes DNS.
  const fresh = seed("fresh", `v=DMARC1; p=none; ${RUA}`);
  await runHostedDnsVerificationSweep(sweepEnv, { dnsQueryImpl, fetchImpl });
  ok("sweep: with the suspended production pass rate, autopilot writes nothing", patches.length === 0 && value(fresh) === `v=DMARC1; p=none; ${RUA}`);
  clear();

  // 2. A ready pass rate: autopilot takes the testing step first, no pct.
  const ramp = seed("ramp", `v=DMARC1; p=none; ${RUA}`);
  await runHostedDnsVerificationSweep(sweepEnv, { dnsQueryImpl, fetchImpl, passRateImpl: healthy });
  ok("sweep: autopilot publishes quarantine with t=y as its first step",
     JSON.stringify(patches) === JSON.stringify([`v=DMARC1; p=quarantine; t=y; ${RUA}`]) && value(ramp) === patches[0]);
  clear(); patches.length = 0;

  // 3. A record still carrying a legacy pct: autopilot's step removes it.
  const legacy = seed("legacy", `v=DMARC1; p=reject; pct=50; ${RUA}`);
  await runHostedDnsVerificationSweep(sweepEnv, { dnsQueryImpl, fetchImpl, passRateImpl: healthy });
  ok("sweep: autopilot's step from reject pct=50 publishes reject without pct",
     JSON.stringify(patches) === JSON.stringify([`v=DMARC1; p=reject; ${RUA}`]) && value(legacy) === patches[0]);
  clear(); patches.length = 0;

  // 4. Autopilot off: nothing is written even when ready.
  seed("manual", `v=DMARC1; p=none; ${RUA}`, { autopilot: 0 });
  await runHostedDnsVerificationSweep(sweepEnv, { dnsQueryImpl, fetchImpl, passRateImpl: healthy });
  ok("sweep: with autopilot off, nothing is written", patches.length === 0);
  clear();

  // 5. Auto-rollback after a drop restores the previous value without pct.
  const back = seed("back", `v=DMARC1; p=quarantine; ${RUA}`, { previous: `v=DMARC1; p=reject; pct=50; ${RUA}`, baseline: 99, autopilot: 0 });
  await runHostedDnsVerificationSweep(sweepEnv, { dnsQueryImpl, fetchImpl, passRateImpl: dropped });
  ok("sweep: auto-rollback restores reject with t=y, never the stored pct",
     JSON.stringify(patches) === JSON.stringify([`v=DMARC1; p=reject; t=y; ${RUA}`]) && value(back) === patches[0]);
  ok("sweep: no PATCH ever carried pct", patches.every((content) => !/pct\s*=/i.test(content)));
  clear(); patches.length = 0;
}

console.log(`\nHosted DMARC lifecycle: ${pass}/${pass + fail} passed`);
if (fail) { console.error("hosted-dmarc-lifecycle validation FAILED"); process.exit(1); }
console.log("hosted-dmarc-lifecycle validation passed");
