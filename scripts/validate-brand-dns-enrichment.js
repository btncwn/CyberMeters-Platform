#!/usr/bin/env node
//
// Brand DNS enrichment — lifecycle + tri-state truthfulness. CI-blocking.
//
// Proves the fix for the "Active DNS = 0 while 40 candidates exist" defect:
// scan-time candidates persist UNCHECKED (dns_resolves NULL), an automatic bounded
// cron sweep validates them incrementally, the manual and automatic paths share ONE
// canonical helper, tri-state truth (NULL/0/1) survives, transient failures never
// become 0, and unchecked is never presented as inactive.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const {
  probeCandidateDns, outcomeToPersistence, selectBrandCandidatesSql,
  enrichBrandCandidatesDns, runBrandDnsEnrichmentSweep,
  probeWatchlistDns, readWatchlistDnsReceipts, brandWatchlistDnsObservations,
} = await import(eng("brand-dns-enrichment.js"));
const { buildBrandProtectionSummary, brandCandidateToApi } = await import(eng("brand-protection.js"));
const { runTyposquatModule } = await import(eng("brand-typosquat.js"));

// ── DoH mock: outcome by candidate domain ────────────────────────────────────
const RESOLVES = { Status: 0, Answer: [{ type: 1, data: "104.247.81.99" }] };
const NXDOMAIN = { Status: 3, Answer: [] };
const NOERROR_NO_A = { Status: 0, Answer: [] };
const SERVFAIL = { Status: 2 };
function mockDns(map) {
  return async (name) => {
    const v = map[name];
    if (v === "throw") throw new Error("timeout");        // transient (network/timeout)
    if (v === "servfail") return SERVFAIL;                 // transient (resolver)
    if (v === "nxdomain") return NXDOMAIN;                 // conclusive no A
    if (v === "noerror") return NOERROR_NO_A;              // conclusive no A
    return RESOLVES;                                        // default: resolves
  };
}

// ── 1. Pure probe outcomes ───────────────────────────────────────────────────
{
  const dns = mockDns({ a: "resolves", b: "nxdomain", c: "noerror", d: "throw", e: "servfail" });
  eq("probe resolves", (await probeCandidateDns("a", dns)).outcome, "resolves");
  eq("probe NXDOMAIN → no_answer", (await probeCandidateDns("b", dns)).outcome, "no_answer");
  eq("probe NOERROR-no-A → no_answer", (await probeCandidateDns("c", dns)).outcome, "no_answer");
  eq("probe throw → transient", (await probeCandidateDns("d", dns)).outcome, "transient");
  eq("probe SERVFAIL → transient", (await probeCandidateDns("e", dns)).outcome, "transient");
}

// ── 2. Tri-state persistence mapping (break-list: NULL must never become 0) ───
{
  eq("resolves → 1", outcomeToPersistence({ outcome: "resolves", ip: "1.1.1.1" }).dns_resolves, 1);
  eq("no_answer → 0", outcomeToPersistence({ outcome: "no_answer" }).dns_resolves, 0);
  ok("transient → null (NEVER 0)", outcomeToPersistence({ outcome: "transient" }) === null);
  ok("undefined outcome → null", outcomeToPersistence(undefined) === null);
}

// ── DB harness ────────────────────────────────────────────────────────────────
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
  return {
    prepare(sql) {
      const wrap = (args) => ({
        __sql: sql, __args: args,
        first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
        all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
        run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
      });
      const b = wrap([]); b.bind = (...a) => wrap(a); return b;
    },
  };
}
let braSeq = 0;
function seedCandidate(db, ws, cand, { dns = null, risk = "low", cls = "unreviewed", lastChecked = null } = {}) {
  const domainId = `dom_${ws}`;
  db.prepare(`INSERT OR IGNORE INTO workspaces
    (id, name, owner_user_id, created_at, updated_at)
    VALUES (?, ?, 'brand-dns-fixture', datetime('now'), datetime('now'))`).run(ws, ws);
  db.prepare(`INSERT OR IGNORE INTO domains (id, user_id, domain, created_at)
    VALUES (?, 'brand-dns-fixture', 'cybermeters.com', datetime('now'))`).run(domainId);
  db.prepare(`INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
    VALUES (?, ?)`).run(ws, domainId);
  db.prepare(
    `INSERT INTO workspace_brand_assets
       (id, workspace_id, domain, candidate_domain, variant_type, similarity_score,
        risk_level, dns_resolves, status, classification, last_checked_at,
        first_seen, last_seen, created_at, updated_at)
     VALUES (?, ?, 'cybermeters.com', ?, 'omission', 80, ?, ?, ?, ?, ?,
             datetime('now'), datetime('now'), datetime('now'), datetime('now'))`
  ).run(`bra_${braSeq++}`, ws, cand, risk, dns, dns === 1 ? "active" : dns === 0 ? "inactive" : "unverified", cls, lastChecked);
}
function rowOf(db, ws, cand) {
  return db.prepare("SELECT dns_resolves, status, last_checked_at FROM workspace_brand_assets WHERE workspace_id = ? AND candidate_domain = ?").get(ws, cand);
}

// ── 3. Enrichment writes tri-state; transient stays NULL ─────────────────────
{
  const db = buildDb();
  seedCandidate(db, "wsA", "resolve.com");
  seedCandidate(db, "wsA", "nx.com");
  seedCandidate(db, "wsA", "flap.com");
  const env = { cybermeters_db: makeD1(db) };
  const dns = mockDns({ "resolve.com": "resolves", "nx.com": "nxdomain", "flap.com": "throw" });
  const stats = await enrichBrandCandidatesDns(env, "wsA", { batchSize: 10, dnsQuery: dns, fireEvents: false });
  eq("resolving persists as 1", rowOf(db, "wsA", "resolve.com").dns_resolves, 1);
  eq("no-answer persists as 0", rowOf(db, "wsA", "nx.com").dns_resolves, 0);
  ok("transient stays NULL (not 0)", rowOf(db, "wsA", "flap.com").dns_resolves === null);
  ok("transient leaves last_checked_at NULL (eligible for retry)", rowOf(db, "wsA", "flap.com").last_checked_at === null);
  eq("stats.checked counts only conclusive", stats.checked, 2);
  eq("stats.transient counts the flap", stats.transient, 1);
}

// ── 4. Unchecked-first selection + batch progression (break-list: not first-N repeat) ──
{
  const db = buildDb();
  for (const c of ["a.com", "b.com", "c.com"]) seedCandidate(db, "wsA", c, { risk: "high" });
  const env = { cybermeters_db: makeD1(db) };
  const dns = mockDns({});   // all resolve
  const s1 = await enrichBrandCandidatesDns(env, "wsA", { batchSize: 2, dnsQuery: dns, fireEvents: false });
  eq("batch 1 checks 2", s1.checked, 2);
  const uncheckedAfter1 = db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE workspace_id='wsA' AND dns_resolves IS NULL").get().n;
  eq("one candidate still unchecked after batch 1", uncheckedAfter1, 1);
  const s2 = await enrichBrandCandidatesDns(env, "wsA", { batchSize: 2, dnsQuery: dns, fireEvents: false });
  eq("batch 2 progresses to the remaining 1 (not the same first 2)", s2.checked, 1);
  const uncheckedAfter2 = db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE workspace_id='wsA' AND dns_resolves IS NULL").get().n;
  eq("all checked after batch 2", uncheckedAfter2, 0);
}

// ── 5. Idempotent within recheck window ──────────────────────────────────────
{
  const db = buildDb();
  seedCandidate(db, "wsA", "x.com");
  const env = { cybermeters_db: makeD1(db) };
  const dns = mockDns({});
  await enrichBrandCandidatesDns(env, "wsA", { batchSize: 10, dnsQuery: dns, fireEvents: false });
  const s2 = await enrichBrandCandidatesDns(env, "wsA", { batchSize: 10, dnsQuery: dns, fireEvents: false });
  eq("re-run within recheck window selects nothing", s2.selected, 0);
}

// ── 6. Tenant isolation ──────────────────────────────────────────────────────
{
  const db = buildDb();
  seedCandidate(db, "wsA", "shared.com");
  seedCandidate(db, "wsB", "shared.com");
  const env = { cybermeters_db: makeD1(db) };
  await enrichBrandCandidatesDns(env, "wsA", { batchSize: 10, dnsQuery: mockDns({}), fireEvents: false });
  ok("wsA candidate checked", rowOf(db, "wsA", "shared.com").dns_resolves === 1);
  ok("wsB candidate untouched (tenant-isolated)", rowOf(db, "wsB", "shared.com").dns_resolves === null);
}

// ── 7. Cron sweep only touches workspaces with pending candidates ────────────
{
  const db = buildDb();
  seedCandidate(db, "wsPending", "p.com");
  seedCandidate(db, "wsDone", "d.com", { dns: 1, lastChecked: new Date().toISOString() });
  const env = { cybermeters_db: makeD1(db) };
  const res = await runBrandDnsEnrichmentSweep(env, { workspacesPerTick: 10, batchSize: 10, dnsQuery: mockDns({}), fireEvents: false });
  eq("sweep selects only the pending workspace", res.workspaces, 1);
  ok("pending candidate now checked", rowOf(db, "wsPending", "p.com").dns_resolves === 1);
}

// ── 7b. Weekly recheck reaches fully-checked workspaces (21 Oct 2026) ────────
// The sweep used to select only workspaces with UNCHECKED candidates, so once
// every candidate had been checked once a workspace was never visited again and
// a lookalike registered later was never re-detected. In production every
// candidate's last check was months old.
{
  const db = buildDb();
  const old = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const fresh = new Date().toISOString();
  seedCandidate(db, "wsStale", "registered-later.com", { dns: 0, lastChecked: old });
  seedCandidate(db, "wsFresh", "f.com", { dns: 0, lastChecked: fresh });
  const env = { cybermeters_db: makeD1(db) };
  const res = await runBrandDnsEnrichmentSweep(env, { workspacesPerTick: 10, batchSize: 10,
    dnsQuery: mockDns({ "registered-later.com": "resolves" }), fireEvents: false });
  eq("sweep visits the fully-checked workspace whose candidate is stale", res.workspaces, 1);
  ok("a candidate that was NXDOMAIN and is now registered is re-detected",
    rowOf(db, "wsStale", "registered-later.com").dns_resolves === 1, JSON.stringify(rowOf(db, "wsStale", "registered-later.com")));
  ok("a freshly checked workspace is not re-probed", rowOf(db, "wsFresh", "f.com").last_checked_at === fresh);
}
{
  // Fairness: unchecked work first, then the longest-waiting workspace; a large
  // stale backlog cannot keep a smaller, older one out of the tick.
  const db = buildDb();
  const days = (n) => new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
  for (let i = 0; i < 30; i++) seedCandidate(db, "wsBig", `big${i}.com`, { dns: 0, lastChecked: days(10) });
  seedCandidate(db, "wsOld", "old.com", { dns: 0, lastChecked: days(40) });
  seedCandidate(db, "wsNew", "new.com");
  const env = { cybermeters_db: makeD1(db) };
  const picked = [];
  const original = env.cybermeters_db.prepare.bind(env.cybermeters_db);
  env.cybermeters_db.prepare = (sql) => {
    const stmt = original(sql);
    if (/GROUP BY a.workspace_id/.test(sql)) {
      const bind = stmt.bind;
      stmt.bind = (...args) => { const b = bind(...args); const all = b.all; b.all = async () => { const r = await all(); picked.push(...r.results.map((x) => x.workspace_id)); return r; }; return b; };
    }
    return stmt;
  };
  await runBrandDnsEnrichmentSweep(env, { workspacesPerTick: 2, batchSize: 10, dnsQuery: mockDns({}), fireEvents: false });
  eq("unchecked work is visited first", picked[0], "wsNew");
  eq("then the longest-waiting workspace, not the largest backlog", picked[1], "wsOld");
}

{
  // Mutant: put back the unchecked-only workspace selection; the stale
  // workspace must then be skipped, proving the fixture above is load-bearing.
  const file = path.join(root, "workers", "scan-api", "src", "engines", "brand-dns-enrichment.js");
  const source = fs.readFileSync(file, "utf8");
  const before = "WHERE (a.dns_resolves IS NULL OR a.last_checked_at IS NULL OR a.last_checked_at < ?)";
  ok("mutant anchor present exactly once", source.split(before).length === 2);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "brand-dns-mutant-"));
  try {
    const mutated = source.replace(before, "WHERE (a.dns_resolves IS NULL OR ? IS NULL)")
      .replace(/from "(\.\.?\/[^"]+)"/g, (_, rel) => `from ${JSON.stringify(pathToFileURL(path.resolve(path.dirname(file), rel)).href)}`);
    fs.writeFileSync(path.join(dir, "m.mjs"), mutated);
    const mutant = await import(pathToFileURL(path.join(dir, "m.mjs")).href);
    const db = buildDb();
    seedCandidate(db, "wsStale", "registered-later.com", { dns: 0, lastChecked: new Date(Date.now() - 30 * 86400000).toISOString() });
    const res = await mutant.runBrandDnsEnrichmentSweep({ cybermeters_db: makeD1(db) },
      { workspacesPerTick: 10, batchSize: 10, dnsQuery: mockDns({}), fireEvents: false });
    eq("MUTANT unchecked-only selection skips the stale workspace (caught)", res.workspaces, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// ── 8. Summary invariant + unchecked ≠ inactive (break-list) ─────────────────
{
  const cands = [
    { dns_active: true, risk_level: "low", classification: "unreviewed" },
    { dns_active: false, risk_level: "low", classification: "unreviewed" },
    { dns_active: null, risk_level: "low", classification: "unreviewed" },
    { dns_active: undefined, risk_level: "low", classification: "unreviewed" },
  ];
  const s = buildBrandProtectionSummary(cands);
  eq("active_dns", s.active_dns, 1);
  eq("inactive_dns", s.inactive_dns, 1);
  eq("unchecked_dns (null + undefined)", s.unchecked_dns, 2);
  eq("dns_checked_total", s.dns_checked_total, 2);
  ok("INVARIANT active+inactive+unchecked === total",
    s.active_dns + s.inactive_dns + s.unchecked_dns === s.total_candidates);
  ok("unchecked is NOT folded into inactive", s.inactive_dns === 1);
}

// ── 9. Serializer preserves NULL as tri-state null ───────────────────────────
{
  eq("NULL dns_resolves → dns_active null", brandCandidateToApi({ id: "x", candidate_domain: "a.com", dns_resolves: null }).dns_active, null);
  eq("0 dns_resolves → dns_active false", brandCandidateToApi({ id: "x", candidate_domain: "a.com", dns_resolves: 0 }).dns_active, false);
  eq("1 dns_resolves → dns_active true", brandCandidateToApi({ id: "x", candidate_domain: "a.com", dns_resolves: 1 }).dns_active, true);
}

// ── 10. Scan-created candidates start UNCHECKED ──────────────────────────────
{
  const mod = runTyposquatModule("cybermeters.com");
  ok("scan module marks candidates unvalidated", mod.candidates_validated === false);
  ok("scan module emits no dns_resolves on candidates",
    mod.domains.every((c) => c.dns_resolves === undefined));
}

// ── 11. Static wiring: manual + automatic share ONE canonical helper ─────────
{
  const brandRoute = fs.readFileSync(srcPath("routes", "brand.js"), "utf8");
  ok("manual refresh imports the canonical helper",
    /enrichBrandCandidatesDns[\s\S]*from ["']\.\.\/engines\/brand-dns-enrichment\.js["']/.test(brandRoute));
  ok("manual refresh calls the canonical helper", /enrichBrandCandidatesDns\(env,/.test(brandRoute));
  ok("manual refresh no longer runs its own inline slice(0, MAX_BRAND_DNS_CHECKS) loop",
    !/slice\(0,\s*MAX_BRAND_DNS_CHECKS\)/.test(brandRoute));

  const index = fs.readFileSync(srcPath("index.js"), "utf8");
  ok("index.js imports runBrandDnsEnrichmentSweep",
    /import \{ runBrandDnsEnrichmentSweep \} from ["']\.\/engines\/brand-dns-enrichment\.js["']/.test(index));
  ok("index.js registers the sweep in the cron tasks registry (auto trigger present)",
    /runBrandDnsEnrichmentSweep,/.test(index));

  const sched = fs.readFileSync(srcPath("cron", "scheduled.js"), "utf8");
  ok("cron dispatches the brand DNS enrichment sweep (break-list: removing auto trigger)",
    /tasks\.runBrandDnsEnrichmentSweep\(env\)/.test(sched));
}

// ── C-21: verified watchlist A/AAAA/MX receipts, no delivery/abuse inference ──
{
  const fixture = JSON.parse(fs.readFileSync(path.join(root, "scripts/fixtures/brand-watchlist-dns.json"), "utf8"));
  const byName = new Map(fixture.candidates.map((item) => [item.name, item]));
  const requests = [];
  const dns = async (name, type) => {
    requests.push({ name, type });
    const value = byName.get(name)?.[type];
    if (!value) throw new Error("unexpected fixture question");
    return structuredClone(value);
  };
  for (const item of fixture.candidates) {
    const result = await probeWatchlistDns(item.name, dns);
    ok(`C21 measured ${item.name}`, item.unavailable ? result === null
      : result?.resolves === item.resolves && result.mx_present === item.mx_present && result.null_mx === item.null_mx);
  }
  const db = buildDb();
  for (const item of fixture.candidates) seedCandidate(db, "wsC21", item.name);
  db.prepare("UPDATE domains SET domain=? WHERE id='dom_wsC21'").run(fixture.protected_domain);
  db.prepare("UPDATE workspace_brand_assets SET domain=? WHERE workspace_id='wsC21'").run(fixture.protected_domain);
  db.prepare("UPDATE workspace_domains SET verification_status='verified' WHERE workspace_id='wsC21'").run();
  requests.length = 0;
  const stats = await enrichBrandCandidatesDns({ cybermeters_db: makeD1(db) }, "wsC21", {
    dnsQuery: dns, now: fixture.checked_at, fireEvents: false,
  });
  eq("C21 only complete DNS receipts advance the watchlist", stats.checked, 3);
  ok("C21 failed DNS never becomes a definitive state", fixture.candidates.filter((item) => item.unavailable)
    .every((item) => rowOf(db, "wsC21", item.name).dns_resolves === null));
  ok("C21 requests stay within existing candidate cap and three DNS questions each",
    stats.selected === 6 && requests.length <= 3 * stats.selected && requests.every((q) => byName.has(q.name)));
  const rows = db.prepare("SELECT * FROM workspace_brand_assets WHERE workspace_id='wsC21' ORDER BY candidate_domain").all();
  const receipts = readWatchlistDnsReceipts(rows);
  const facts = brandWatchlistDnsObservations({ watchlist_dns: receipts }, {
    domain: fixture.protected_domain, verified: true, checkedAt: fixture.checked_at,
  });
  ok("C21 measured DNS becomes one non-scored observation", facts.length === 1
    && facts[0].finding_type === "observation" && facts[0].score_impact === 0 && facts[0].evidence.length === 4);
  ok("C21 Null MX never claims mail capability", facts[0]?.evidence.filter((e) => /receive mail/.test(e.value))
    .every((e) => e.label === "example-mail.net"));
  const queryCounts = [];
  seedCandidate(db, "wsC21Unverified", "unchecked.example");
  await enrichBrandCandidatesDns({ cybermeters_db: makeD1(db) }, "wsC21Unverified", {
    dnsQuery: async (_name, type) => { queryCounts.push(type); return { Status: 0, Answer: [{ type: 1, data: "203.0.113.20" }] }; },
  });
  eq("C21 unverified parent gains no new mail or IPv6 probing", queryCounts, ["A"]);
  db.close();
}

// Corrective: concurrent DNS/HTTP enrichments must retain each other's evidence.
{
  const { enrichBrandCandidatesHttp } = await import(eng("brand-http-enrichment.js"));
  const { writeBrandEvidence } = await import(eng("brand-evidence-persistence.js"));
  for (const order of ["dns_after_http", "http_after_dns"]) {
    const db = buildDb();
    seedCandidate(db, "wsRace", "race.example", { dns: 1, lastChecked: "2000-01-01T00:00:00.000Z" });
    db.prepare("UPDATE workspace_domains SET verification_status='verified' WHERE workspace_id='wsRace'").run();
    const env = { cybermeters_db: makeD1(db) };
    let injected = false, concurrent;
    const now = new Date().toISOString();
    const dns = async (_name, type) => {
      if (!injected && order === "dns_after_http") {
        injected = true;
        concurrent = await enrichBrandCandidatesHttp(env, "wsRace", { now, probeFetch });
      }
      return type === "MX" ? { Status: 0, Answer: [{ type: 15, data: "10 mx.race.example." }] }
        : { Status: 0, Answer: [{ type: 1, data: "203.0.113.50" }] };
    };
    const probeFetch = async () => {
      if (!injected && order === "http_after_dns") {
        injected = true;
        concurrent = await enrichBrandCandidatesDns(env, "wsRace", { now, dnsQuery: dns, fireEvents: false });
      }
      return new Response('<html><input type="password"></html>', { status: 200 });
    };
    const primary = order === "dns_after_http"
      ? await enrichBrandCandidatesDns(env, "wsRace", { now, dnsQuery: dns, fireEvents: false })
      : await enrichBrandCandidatesHttp(env, "wsRace", { now, probeFetch });
    const evidence = JSON.parse(db.prepare("SELECT evidence_json FROM workspace_brand_assets WHERE workspace_id='wsRace'").get().evidence_json);
    ok(`C21 ${order} both writers complete after a conflict`, primary.checked === 1 && concurrent?.checked === 1);
    ok(`C21 ${order} retains both independent measurements`, evidence.some((e) => e.signal === "looks_like_login" && e.value === true)
      && evidence.some((e) => e.signal === "watchlist_dns_observation" && e.value.mx_present === true));
    db.close();
  }
  let writes = 0, reads = 0;
  const exhausted = await writeBrandEvidence({ cybermeters_db: { prepare: () => ({ bind: () => ({
    first: async () => ({ evidence_json: String(++reads) }),
  }) }) } }, "ws", { id: "race", evidence_json: null }, async () => {
    writes++; return { meta: { changes: 0 } };
  });
  ok("C21 evidence retries stop after three conflicting writes", writes === 3 && reads === 2 && exhausted.meta.changes === 0);
}

console.log(`\nvalidate-brand-dns-enrichment: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
