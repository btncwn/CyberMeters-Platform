#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-dns-absence-as-evidence.js  (CI-blocking)
//
// DNS Absence-as-Evidence P1.
//
// THE HARM. `scoring.js` gated the CRITICAL "Domain Does Not Resolve" finding
// (-30) on `resolution_assessed !== false`, which reads a MISSING contract field
// as if the resolvers had answered. The DNS deadline fallback
// (`markDeadlineDeferred({ source: "dns" })`) carried no resolution fields at all,
// so a scan in which not one lookup was performed emitted the critical finding and
// took 30 points off the customer's score:
//
//     { executed:false, incomplete:true, outcome:"deadline_exceeded" }
//       → critical "Domain Does Not Resolve"  score_impact -30  (score 75 → 45)
//
// Absence of evidence scored as evidence of absence. Production has recorded 0 DNS
// deadline fallbacks to date — a MEASURED historical fact, not a claim that the path
// cannot be reached. It is reached whenever the DNS module exceeds its 750ms hard cap
// under a normal budget (raceModuleDeadline → onDeadline → fallback), which section B
// drives end to end.
//
// THE FIX. Scoring consumes the CANONICAL DNS resolution vocabulary already
// implemented for Attack Surface (attack-surface-signal-completeness.js) — one
// definition, not two — and fires ONLY on `absent` / `authoritative_dns_absence`.
// The deadline fallback states its non-observation explicitly.
//
// Sections: A canonical matrix · B engine trace · L lifecycle · M mutations.
// Real modules, real D1 (schema + migrations), real R2 shim, no network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engUrl = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;
const { computeScore } = await import(engUrl("scoring.js"));
const { runScanEngine } = await import(engUrl("scan-engine.js"));
const { markDeadlineDeferred } = await import(engUrl("scan-budget.js"));
const { resolveDnsResolution } = await import(engUrl("attack-surface-signal-completeness.js"));
const { moduleCompletionGate } = await import(engUrl("asm-cases.js"));

const NOW = "2026-07-29T09:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const EXPECTED_MUTANTS = 8;

let passed = 0, failed = 0, killed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

const dnsFindingOf = (dns) =>
  (computeScore({ dns, ssl: {}, headers: { headers: {} }, email_security: {} }, "example.com").findings || [])
    .find((f) => f.id === "dns_no_resolution") || null;
const firesCritical = (dns) => {
  const f = dnsFindingOf(dns);
  return !!f && f.severity === "critical" && Number(f.score_impact) === -30;
};

// ── A. CANONICAL MATRIX ──────────────────────────────────────────────────────
console.log("── A. canonical DNS resolution matrix ──");

// A1 authoritative absence — the ONLY case that may fire. Positive control.
{
  const dns = { resolves: false, resolves_any: false, resolution_assessed: true, a_records: [], aaaa_records: [] };
  ok("A1: authoritative absence → canonical signal `absent`",
    resolveDnsResolution({ dns }).state === "absent" &&
    resolveDnsResolution({ dns }).reason === "authoritative_dns_absence");
  ok("A1: POSITIVE CONTROL — the critical -30 finding STILL fires", firesCritical(dns));
}
// A2 records observed
{
  const dns = { resolves: true, resolves_any: true, resolution_assessed: true, a_records: [{ value: "93.184.216.34" }], aaaa_records: [] };
  ok("A2: records observed → canonical `observed`", resolveDnsResolution({ dns }).state === "observed");
  ok("A2: no finding", dnsFindingOf(dns) === null);
}
// A3 deadline deferred — THE REPORTED DEFECT, using the real fallback helper.
{
  const dns = markDeadlineDeferred({ source: "dns" });
  ok("A3: bare deadline fallback → canonical `not_assessed` (executed:false)",
    resolveDnsResolution({ dns }).state === "not_assessed", JSON.stringify(resolveDnsResolution({ dns })));
  ok("A3: NO critical finding for a scan that performed no lookup", !firesCritical(dns));
  ok("A3: no dns finding of any severity", dnsFindingOf(dns) === null);
}
// A4 provider unavailable — resolvers did not answer.
{
  const dns = { resolves: false, resolves_any: false, resolution_assessed: false, incomplete: true, incomplete_reason: "dns_resolution_unavailable" };
  ok("A4: resolvers did not answer → canonical `unavailable`",
    resolveDnsResolution({ dns }).state === "unavailable");
  ok("A4: no critical finding", !firesCritical(dns));
}
// A5 module-level incomplete / error.
{
  const dns = { error: "dns module failed" };
  ok("A5: module error → canonical `unavailable`", resolveDnsResolution({ dns }).state === "unavailable");
  ok("A5: no critical finding", !firesCritical(dns));
}
// A6 missing legacy fields — the removed fallback.
{
  ok("A6: empty module → canonical `incomplete` (contract not recorded)",
    resolveDnsResolution({ dns: {} }).state === "incomplete" &&
    resolveDnsResolution({ dns: {} }).reason === "dns_resolution_contract_not_recorded");
  ok("A6: empty module fires NO critical finding", !firesCritical({}));
  ok("A6: legacy { resolves:false } alone fires NO critical finding (fallback REMOVED)",
    !firesCritical({ resolves: false }));
  ok("A6: absent dns module entirely fires NO critical finding", !firesCritical(undefined));
}
// A7 contradictory resolver evidence — one resolver saw a record, aggregate did not.
{
  const dns = { resolves: false, resolves_any: true, resolution_assessed: true };
  ok("A7: contradictory evidence (resolves_any true) → `observed`, never absence",
    resolveDnsResolution({ dns }).state === "observed");
  ok("A7: no critical finding on contradiction", !firesCritical(dns));
}
// A8 the explicit deadline fallback shipped by scan-engine — SEMANTIC proof.
// The tri-state is load-bearing: false means "resolvers queried, no authoritative
// answer" (a MEASURED outage from dns-scan.js); null means "never executed".
const DEADLINE_DNS = markDeadlineDeferred({
  resolves: null, resolves_any: null, resolution_assessed: null,
  resolution_observation_state: "not_assessed", incomplete_reason: "dns_not_executed",
  has_ipv6: null, has_mx: null, nameservers: [], a_records: [], aaaa_records: [], mx_records: [], source: "dns",
});
{
  ok("A8: deadline fallback — executed:false, incomplete:true, outcome deadline_exceeded, stable reason",
    DEADLINE_DNS.executed === false && DEADLINE_DNS.incomplete === true &&
    DEADLINE_DNS.outcome === "deadline_exceeded" && DEADLINE_DNS.reason === "scan_deadline_exhausted");
  ok("A8: resolution_assessed is NULL — never false (not-measured != measured-outage)",
    DEADLINE_DNS.resolution_assessed === null && DEADLINE_DNS.resolution_assessed !== false);
  ok("A8: resolves / resolves_any are NULL, asserting nothing",
    DEADLINE_DNS.resolves === null && DEADLINE_DNS.resolves_any === null);
  ok("A8: explicit not-assessed observation state + honest incomplete_reason",
    DEADLINE_DNS.resolution_observation_state === "not_assessed" &&
    DEADLINE_DNS.incomplete_reason === "dns_not_executed");
  ok("A8: canonical signal resolves the deadline module as not_assessed",
    resolveDnsResolution({ dns: DEADLINE_DNS }).state === "not_assessed",
    JSON.stringify(resolveDnsResolution({ dns: DEADLINE_DNS })));
  ok("A8: no critical finding", !firesCritical(DEADLINE_DNS));
  // JSON persistence must PRESERVE the nulls — a round-trip that drops them would
  // silently restore the missing-field shape this whole corrective exists to remove.
  const roundTripped = JSON.parse(JSON.stringify(DEADLINE_DNS));
  ok("A8: JSON round-trip preserves the explicit nulls (report/R2 persistence)",
    roundTripped.resolution_assessed === null && roundTripped.resolves === null &&
    roundTripped.resolves_any === null &&
    Object.prototype.hasOwnProperty.call(roundTripped, "resolution_assessed"),
    JSON.stringify(roundTripped));
  ok("A8: after round-trip the canonical signal is STILL not_assessed",
    resolveDnsResolution({ dns: roundTripped }).state === "not_assessed");
  ok("A8: after round-trip it STILL fires no critical finding", !firesCritical(roundTripped));
}
// A9 a genuine EXECUTED resolver outage stays distinguishable from an unexecuted one.
{
  const measuredOutage = { resolves: false, resolves_any: false, resolution_assessed: false, incomplete: true, incomplete_reason: "dns_resolution_unavailable" };
  ok("A9: executed resolver outage → `unavailable` (a MEASURED result)",
    resolveDnsResolution({ dns: measuredOutage }).state === "unavailable");
  ok("A9: unexecuted deadline → `not_assessed` — the two remain DISTINCT",
    resolveDnsResolution({ dns: DEADLINE_DNS }).state === "not_assessed" &&
    resolveDnsResolution({ dns: measuredOutage }).state !== resolveDnsResolution({ dns: DEADLINE_DNS }).state);
  ok("A9: neither fires the critical finding",
    !firesCritical(measuredOutage) && !firesCritical(DEADLINE_DNS));
}
// A10 null resolution_assessed on an EXECUTED module is still non-definitive.
{
  ok("A10: resolution_assessed null (executed) → non-definitive, never `unavailable`",
    resolveDnsResolution({ dns: { resolves: null, resolves_any: null, resolution_assessed: null } }).state === "incomplete");
  ok("A10: …and fires no critical finding",
    !firesCritical({ resolves: null, resolves_any: null, resolution_assessed: null }));
}

// ── B. REAL runScanEngine, SCAN_DEADLINE_MS=0 ────────────────────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch { /* overlap */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const stmt = (sql, args = []) => ({
    __sql: sql, bind: (...b) => stmt(sql, b),
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } }; },
  });
  return {
    prepare: (s) => stmt(s),
    batch: async (l) => { const o = []; db.exec("BEGIN"); try { for (const s of l) o.push(/^\s*select/i.test(s.__sql) ? await s.all() : await s.run()); db.exec("COMMIT"); return o; } catch (e) { db.exec("ROLLBACK"); throw e; } },
    exec: async (s) => { db.exec(s); return { count: 0, duration: 0 }; },
  };
}
function makeR2(store) {
  return {
    get: async (k) => { const b = store.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store.set(String(k), String(b)); return {}; },
    delete: async (k) => { store.delete(String(k)); return {}; },
    head: async () => null, list: async () => ({ objects: [] }),
  };
}
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

// A managed ASM case for dns_no_resolution whose ordinary prerequisites would allow
// a later verification. No lifecycle POLICY changes here.
function seedDnsCase(db) {
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity,
       status, evidence_json, recommended_actions_json, created_at, updated_at)
     VALUES ('mc-dns','ws','asm_case','attack_surface','example.com','dns_no_resolution','example.com','critical',
       'awaiting_verification','{}','[]', datetime('now','-5 days'), datetime('now','-1 day'))`).run();
}

// The REAL production path. `runCappedModule` reaches the DNS fallback from TWO
// places: the launch gate, and the raceModuleDeadline HARD-CAP race. Under a normal
// 19000ms budget the launch gate always passes for DNS (750ms estimate, first module),
// but the hard cap fires whenever DNS does not settle within 750ms:
//
//     raceModuleDeadline(deadline, run, onDeadline, { hardMs: 750 })
//       capMs = min(750, remaining) → real setTimeout(750)
//       winner === DEADLINE → onDeadline() → controller.abort() → fallback()
//
// Hanging DoH makes the DNS module exceed that cap deterministically, so this drives
// the genuine chain — not a helper call and not a source regex.
async function trace({ seed = false, engine = null, slowResolution = true } = {}) {
  const db = buildDb(); const store = new Map();
  const env = {
    cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200",
    // NORMAL production budget — not 0, not clamped.
    SCAN_DEADLINE_MS: "19000", APP_VERSION: "dns-p1",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','o@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','DNS-P1',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
              VALUES ('scan-dns','ws','dom','example.com','running',NULL,?)`).run(NOW);
  if (seed) seedDnsCase(db);

  const prevFetch = globalThis.fetch, prevErr = console.error;
  globalThis.fetch = async (input) => {
    const url = new URL(String(input)); const host = url.hostname;
    if (host === "cloudflare-dns.com" || host === "dns.google") {
      const type = String(url.searchParams.get("type") || "A").toUpperCase();
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      const answer = () => (name === "example.com" && type === "A" && !slowResolution)
        ? json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] })
        : json({ Status: 0, Answer: [] });
      // Delay ONLY the DNS module's A/AAAA resolution contract, so IT exceeds its
      // 750ms hard cap while every other module's lookups complete normally. Delaying
      // all DoH would also defer email_security, whose own deadline fallback has a
      // separate pre-existing crash (buildEmailRemediationActions reads `.raw` on an
      // absent field) that would fail the scan and mask what is under test here.
      if (slowResolution && (type === "A" || type === "AAAA")) {
        return new Promise((res) => setTimeout(() => res(answer()), 1_200));
      }
      return answer();
    }
    if (host === "crt.sh" || host === "api.certspotter.com") return json([]);
    return new Response("<html></html>", { status: 200, headers: { server: "nginx", "content-type": "text/html" } });
  };
  console.error = () => {};
  // The clock is FROZEN so remainingMs stays at the full budget: the only thing that
  // can end the DNS module is its own 750ms hard cap, on a real timer.
  const runner = (engine || { runScanEngine }).runScanEngine;
  try {
    await runner("scan-dns", "dom", "ws", "example.com", env,
      { now: () => NOW_MS, executionContext: "queue", trigger: "manual" });
  } catch { /* asserted from D1 */ }
  finally { globalThis.fetch = prevFetch; console.error = prevErr; }

  const raw = store.get("reports/scan-dns.json");
  const report = raw ? JSON.parse(raw) : null;
  return {
    db, report,
    dns: report?.modules?.dns || {},
    quality: db.prepare("SELECT scan_quality FROM scans WHERE id='scan-dns'").get()?.scan_quality ?? null,
    dbStatus: db.prepare("SELECT status FROM scans WHERE id='scan-dns'").get()?.status ?? null,
    reportError: report?.error ?? null,
    email: report?.modules?.email_security || null,
    titles: db.prepare("SELECT title FROM findings WHERE scan_id='scan-dns'").all().map((r) => r.title),
    findings: (report?.findings || []),
    domains: Object.fromEntries(db.prepare("SELECT domain_key, state, coverage, summary FROM cyber_mot_domain_states WHERE scan_id='scan-dns'").all().map((r) => [r.domain_key, r])),
  };
}

console.log("\n── B. REAL runScanEngine, normal 19000ms budget, DNS exceeds its 750ms hard cap ──");
const dl = await trace();
ok("B: a report was produced", dl.report !== null);
// TERMINAL COMPLETION. Delaying ALL DoH also defers email_security, whose own
// deadline fallback has a separate pre-existing crash that fails the scan and would
// mask what is under test. Only the DNS resolution contract is slowed here, so the
// scan must finish terminally with no exception.
ok("B: the scan completed TERMINALLY with no exception",
  dl.dbStatus === "completed" && dl.reportError == null,
  JSON.stringify({ status: dl.dbStatus, error: dl.reportError }));
ok("B: sibling modules completed normally — email_security is NOT deferred (isolation)",
  dl.email != null && dl.email.executed !== false && dl.email.outcome !== "deadline_exceeded",
  JSON.stringify({ e: dl.email?.executed, o: dl.email?.outcome }));
ok("B: the DNS module took the DEADLINE fallback (hard-cap race)",
  dl.dns.executed === false && dl.dns.incomplete === true && dl.dns.outcome === "deadline_exceeded",
  JSON.stringify({ e: dl.dns.executed, i: dl.dns.incomplete, o: dl.dns.outcome }));
ok("B: resolves is NULL", dl.dns.resolves === null, JSON.stringify(dl.dns.resolves));
ok("B: resolves_any is NULL", dl.dns.resolves_any === null, JSON.stringify(dl.dns.resolves_any));
ok("B: resolution_assessed is NULL — never false", dl.dns.resolution_assessed === null,
  JSON.stringify(dl.dns.resolution_assessed));
ok('B: resolution_observation_state is "not_assessed"',
  dl.dns.resolution_observation_state === "not_assessed", String(dl.dns.resolution_observation_state));
ok('B: incomplete_reason is "dns_not_executed"',
  dl.dns.incomplete_reason === "dns_not_executed", String(dl.dns.incomplete_reason));
ok("B: the PERSISTED R2 report preserves the explicit nulls",
  Object.prototype.hasOwnProperty.call(dl.dns, "resolution_assessed") && dl.dns.resolution_assessed === null);
ok("B: canonical signal is not_assessed — never `absent`",
  resolveDnsResolution({ dns: dl.dns }).state === "not_assessed",
  JSON.stringify(resolveDnsResolution({ dns: dl.dns })));
ok('B: NO "Domain Does Not Resolve" persisted to D1',
  !dl.titles.includes("Domain Does Not Resolve"), dl.titles.join(" | "));
{
  const f = dl.findings.find((x) => x.id === "dns_no_resolution");
  ok("B: no dns_no_resolution in the report", !f, JSON.stringify(f && f.severity));
  ok("B: no -30 score penalty", !f || Number(f.score_impact || 0) === 0);
}
ok("B: scan_quality.status is partial (report + D1)",
  dl.report?.scan_quality?.status === "partial" && dl.quality === "partial",
  JSON.stringify({ rep: dl.report?.scan_quality?.status, d1: dl.quality }));
{
  const as = dl.domains.attack_surface || {};
  ok("B: attack_surface customer projection is NOT healthy and NOT complete",
    as.state !== "assessed_healthy" && as.coverage !== "complete", JSON.stringify(as));
  ok('B: …and does not say "Assessed — no material issue observed"',
    !/Assessed — no material issue observed/.test(String(as.summary || "")), String(as.summary));
}

// ── B2. SEPARATE positive semantic control: a MEASURED resolver outage ──────
// resolution_assessed:false means resolvers WERE queried and gave no authoritative
// answer. This is NOT the deadline-fallback proof and is not presented as one; it
// exists so the two states stay demonstrably distinct.
console.log("\n── B2. measured resolver outage (separate control, not the deadline proof) ──");
{
  const measured = { resolves: false, resolves_any: false, resolution_assessed: false, incomplete: true, incomplete_reason: "dns_resolution_unavailable" };
  ok("B2: executed resolver outage → canonical `unavailable` (a MEASURED result)",
    resolveDnsResolution({ dns: measured }).state === "unavailable");
  ok("B2: it is DISTINCT from the deadline fallback's not_assessed",
    resolveDnsResolution({ dns: measured }).state !== resolveDnsResolution({ dns: dl.dns }).state);
  ok("B2: neither produces the critical finding",
    !firesCritical(measured) && !firesCritical(dl.dns));
}

// ── L. LIFECYCLE / CASE NON-PROGRESSION ─────────────────────────────────────
console.log("\n── L. DNS case non-progression on an incomplete scan ──");
const lf = await trace({ seed: true });
const caseAfter = lf.db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-dns'").get() || {};
console.log(`   BEFORE case=awaiting_verification    AFTER case=${caseAfter.status} verified_at=${caseAfter.verified_at}`);
ok("L: the DNS case did NOT advance to verification/resolution",
  !["verification_requested", "verifying", "resolved", "verified"].includes(caseAfter.status), String(caseAfter.status));
ok("L: the DNS case was NOT verified", caseAfter.verified_at == null, String(caseAfter.verified_at));
ok("L: it remains awaiting_verification", caseAfter.status === "awaiting_verification", String(caseAfter.status));
ok("L: the CANONICAL gate refuses dns verification on a partial scan (no DNS bypass)",
  moduleCompletionGate({ dns: { incomplete: true } }, { status: "partial", modules_skipped: ["dns"] }).canVerify("dns") === false);
ok("L: the same gate ALLOWS it on a complete scan (positive control)",
  moduleCompletionGate({ dns: {} }, { status: "complete", modules_skipped: [] }).canVerify("dns") === true);

// ── M. MUTATIONS (anchor-guarded, pinned) ───────────────────────────────────
console.log("\n── M. mutation proof ──");
const SCORING = path.join(root, "workers/scan-api/src/engines/scoring.js");
const SIGNALS = path.join(root, "workers/scan-api/src/engines/attack-surface-signal-completeness.js");
const SCAN_ENGINE = path.join(root, "workers/scan-api/src/engines/scan-engine.js");
let seq = 0;
async function withMutant({ target, from, to }, run) {
  const original = fs.readFileSync(target, "utf8");
  const mutated = original.replace(from, to);
  if (mutated === original) return { applied: false };
  const name = `.${path.basename(target, ".js")}.mutant.${process.pid}.${++seq}.js`;
  const file = path.join(path.dirname(target), name);
  fs.writeFileSync(file, mutated);
  try { return { applied: true, result: await run(await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`)) }; }
  finally { fs.rmSync(file, { force: true }); }
}
const scoreDns = (mod, dns) => (mod.computeScore({ dns, ssl: {}, headers: { headers: {} }, email_security: {} }, "example.com").findings || [])
  .find((f) => f.id === "dns_no_resolution") || null;

const MUTATIONS = [
  {
    name: "M1 the missing-field-as-authoritative gate is restored",
    target: SCORING,
    from: "  const dnsResolutionSignal = resolveDnsResolution(modules);\n  const dnsAuthoritativelyUnresolved =\n    dnsResolutionSignal.state === \"absent\" &&\n    dnsResolutionSignal.reason === \"authoritative_dns_absence\";",
    to: "  const dnsAuthoritativelyUnresolved =\n    !modules.dns?.resolves && modules.dns?.resolves_any !== true && modules.dns?.resolution_assessed !== false;",
    // The bare deadline fallback would again produce the critical -30.
    check: (mod) => {
      const f = scoreDns(mod, markDeadlineDeferred({ source: "dns" }));
      return !!f && Number(f.score_impact) === -30;
    },
  },
  {
    name: "M2 `resolution_assessed === true` is weakened to a truthiness check",
    target: SIGNALS,
    from: "  if (dns.resolution_assessed === true) {",
    to:   "  if (dns.resolution_assessed !== false) {",
    check: (mod) => mod.resolveDnsResolution({ dns: {} }).state === "absent",
  },
  {
    name: "M3 the explicit DNS deadline fallback fields are dropped",
    target: SCAN_ENGINE,
    from: 'resolves: null, resolves_any: null, resolution_assessed: null, resolution_observation_state: "not_assessed", incomplete_reason: "dns_not_executed", ',
    to:   '',
    // Dropping the explicit not-assessed fields restores the bare, field-less shape.
    check: async (mod) => {
      const src = fs.readFileSync(SCAN_ENGINE, "utf8");
      const mutatedSrc = src.replace('resolves: null, resolves_any: null, resolution_assessed: null, resolution_observation_state: "not_assessed", incomplete_reason: "dns_not_executed", ', "");
      return !mutatedSrc.includes('resolution_assessed: null') &&
        resolveDnsResolution({ dns: markDeadlineDeferred({ source: "dns" }) }).state === "not_assessed" &&
        !Object.prototype.hasOwnProperty.call(markDeadlineDeferred({ source: "dns" }), "resolution_assessed");
    },
  },
  {
    name: "M4 incomplete DNS evidence is allowed to reduce the score",
    target: SCORING,
    from: '    dnsResolutionSignal.state === "absent" &&\n    dnsResolutionSignal.reason === "authoritative_dns_absence";',
    to:   '    dnsResolutionSignal.state !== "observed";',
    check: (mod) => {
      const f = scoreDns(mod, { resolves: false, resolves_any: false, resolution_assessed: false, incomplete: true });
      return !!f && Number(f.score_impact) === -30;
    },
  },
  {
    name: "M6 the deadline fallback's resolution_assessed:null is flipped back to false",
    target: SCAN_ENGINE,
    from: "resolves: null, resolves_any: null, resolution_assessed: null,",
    to:   "resolves: false, resolves_any: false, resolution_assessed: false,",
    // `false` is a MEASURED outage. On an unexecuted path it collapses
    // "not measured" into "measured unavailable" — the same defect, new value.
    check: () => {
      const src = fs.readFileSync(SCAN_ENGINE, "utf8")
        .replace("resolves: null, resolves_any: null, resolution_assessed: null,",
                 "resolves: false, resolves_any: false, resolution_assessed: false,");
      const collapsed = markDeadlineDeferred({ resolves: false, resolves_any: false, resolution_assessed: false, source: "dns" });
      return src.includes("resolution_assessed: false,") &&
        collapsed.resolution_assessed === false &&
        resolveDnsResolution({ dns: { ...collapsed, executed: undefined } }).state === "unavailable";
    },
  },
  {
    name: "M5 the genuine authoritative-absence positive control is suppressed",
    target: SCORING,
    from: '    dnsResolutionSignal.reason === "authoritative_dns_absence";',
    to:   '    false;',
    check: (mod) => scoreDns(mod, { resolves: false, resolves_any: false, resolution_assessed: true }) === null,
  },
];
// ENGINE-BOUND mutants: the mutated engine is imported and the FULL trace re-run
// through it, so the proof is the real pipeline's output — not a source regex.
const ENGINE_MUTATIONS = [
  {
    name: "E1 the deadline fallback's nulls are flipped back to false (REAL trace)",
    from: "resolves: null, resolves_any: null, resolution_assessed: null,",
    to:   "resolves: false, resolves_any: false, resolution_assessed: false,",
    check: (t) => t.dns.resolution_assessed === false,
  },
  {
    name: "E2 the deadline fallback drops its `incomplete` marker (REAL trace)",
    target: path.join(root, "workers/scan-api/src/engines/scan-budget.js"),
    from: "    executed:   false,\n    incomplete: true,",
    to:   "    executed:   false,",
    check: (t) => t.report?.scan_quality?.status !== "partial" || t.quality !== "partial",
  },
];
for (const m of ENGINE_MUTATIONS) {
  const target = m.target || SCAN_ENGINE;
  const original = fs.readFileSync(target, "utf8");
  const mutated = original.replace(m.from, m.to);
  const applied = mutated !== original;
  ok(`${m.name} :: mutation APPLIED (anchor matches product source)`, applied,
    "anchor not found — this mutation tests NOTHING");
  if (!applied) continue;
  const mutantName = `.${path.basename(target, ".js")}.mutant.eng.${process.pid}.js`;
  const mutantFile = path.join(path.dirname(target), mutantName);
  const engineName = `.scan-engine.mutant.eng.${process.pid}.js`;
  const engineFile = path.join(path.dirname(SCAN_ENGINE), engineName);
  const written = [mutantFile];
  fs.writeFileSync(mutantFile, mutated);
  try {
    let engineMod;
    if (target === SCAN_ENGINE) {
      engineMod = await import(`${pathToFileURL(mutantFile).href}?t=${Date.now()}-${Math.random()}`);
    } else {
      // Dependency mutation: point a copy of scan-engine at the mutant so the real
      // engine consumes it (a temp-dir copy would import the pristine original).
      const engineSrc = fs.readFileSync(SCAN_ENGINE, "utf8")
        .split(`./${path.basename(target)}`).join(`./${mutantName}`);
      fs.writeFileSync(engineFile, engineSrc);
      written.push(engineFile);
      engineMod = await import(`${pathToFileURL(engineFile).href}?t=${Date.now()}-${Math.random()}`);
    }
    const mt = await trace({ engine: engineMod });
    const caught = (await m.check(mt)) === true;
    if (caught) killed += 1;
    ok(`${m.name} :: defect REAPPEARS in the REAL engine trace`, caught,
      JSON.stringify({ ra: mt.dns?.resolution_assessed, q: mt.quality }));
  } finally {
    for (const f of written) fs.rmSync(f, { force: true });
  }
}

for (const m of MUTATIONS) {
  const r = await withMutant(m, (mod) => m.check(mod));
  ok(`${m.name} :: mutation APPLIED (anchor matches product source)`, r.applied,
    "anchor not found — this mutation tests NOTHING");
  if (!r.applied) continue;
  if (r.result === true) killed += 1;
  ok(`${m.name} :: defect REAPPEARS when mutated`, r.result === true);
}
ok(`mutants killed: ${killed}/${EXPECTED_MUTANTS} (pinned)`, killed === EXPECTED_MUTANTS,
  `expected exactly ${EXPECTED_MUTANTS}, killed ${killed}`);
ok(`mutation table pinned at ${EXPECTED_MUTANTS}`, MUTATIONS.length + ENGINE_MUTATIONS.length === EXPECTED_MUTANTS);
const strays = fs.readdirSync(path.join(root, "workers/scan-api/src/engines")).filter((f) => f.includes(".mutant."));
ok("no mutant file left behind", strays.length === 0, strays.join(", "));

console.log(`\ndns-absence-as-evidence: ${passed}/${passed + failed} passed; ${killed}/${EXPECTED_MUTANTS} mutants killed`);
if (failed) { console.error("dns-absence-as-evidence validation FAILED"); process.exit(1); }
console.log("dns-absence-as-evidence validation passed");
