#!/usr/bin/env node
//
// MSP Portfolio Per-Domain State and Trend — the honesty + isolation contract.
//
// The portfolio is the surface where absent evidence is most dangerous, because an MSP
// reads it to decide who to help FIRST. A domain nobody scanned must never sort below a
// domain verified healthy, a rule that stopped running must never read as a fix, and a
// resolver change must never read as forty customers deteriorating overnight.
//
// Drives the REAL worker fetch against the REAL schema with a seeded session, and logs
// every write so a GET that mutates is a failure rather than a footnote. Requires Node
// 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { resolveDomainTrend, DOMAIN_TREND, EVIDENCE_FRESHNESS, evidenceFreshness, readPortfolioDomainStates,
        buildDomainMatrix, CYBER_MOT_DOMAIN_KEYS, persistCyberMotDomainStates } = await import(eng("cyber-mot-state-history.js"));
const { computePortfolioDomainRows, applyPortfolioView, buildPortfolioDomainSummary } = await import(eng("portfolio-domains.js"));
const { CYBER_MOT_RESOLVER_VERSION, CYBER_MOT_STATES } = await import(eng("cyber-mot-domains.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
  apply(path.join(root, "database", "migrations", f));
}
db.exec("PRAGMA foreign_keys = OFF");

// Same exception list as validate-portfolio-read-purity: rate limiting and session
// liveness are cross-cutting platform writes that fire on EVERY authenticated request,
// before any handler runs. Anything else that writes on a GET is a finding.
const INFRA_WRITE = /^\s*(insert\s+into|update|replace\s+into)\s+(api_rate_limits|user_sessions)\b/i;
const writeLog = [];
const makeD1 = (db, log) => {
  const record = (sql) => { if (log && /^\s*(insert|update|delete|replace|drop|alter|create)\b/i.test(sql)) log.push(sql.trim().replace(/\s+/g, " ")); };
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all:   async () => ({ results: db.prepare(sql).all(...args) }),
    run:   async () => { record(sql); const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
    __sql: sql, __args: args,
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
};
const domainWrites = () => writeLog.filter((s) => !INFRA_WRITE.test(s));

const RV = CYBER_MOT_RESOLVER_VERSION;
const iso = (daysAgo) => new Date(Date.now() - daysAgo * 86400000).toISOString();
let cmdsN = 0;
// Seed one recorded state. `domain_key` defaults across all eight so a row is complete.
const seedState = (ws, domId, scanId, key, o = {}) => db.prepare(
  `INSERT INTO cyber_mot_domain_states
     (id, workspace_id, domain_id, scan_id, domain_key, state, coverage, summary,
      highest_severity, finding_count, evidence_count, finding_ids_json, scan_quality,
      resolver_version, assessed_at)
   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
).run(
  `cmds_${++cmdsN}`, ws, domId, scanId, key,
  o.state ?? CYBER_MOT_STATES.ASSESSED_HEALTHY, o.coverage ?? "complete",
  o.summary ?? "Assessed — no material issue observed.", o.highest_severity ?? null,
  o.finding_count ?? 0, o.evidence_count ?? 1, JSON.stringify(o.finding_ids ?? []),
  o.scan_quality ?? "complete", o.resolver_version ?? RV, o.assessed_at ?? iso(1),
);
const seedAllEight = (ws, domId, scanId, o = {}) => { for (const k of CYBER_MOT_DOMAIN_KEYS) seedState(ws, domId, scanId, k, o); };

// ── Seed ─────────────────────────────────────────────────────────────────────
// MSP A (entitled, business) with two customers; MSP B (entitled) with one. Both MSPs
// monitor THE SAME HOSTNAME, as two distinct domains.id rows — the duplicate-hostname
// isolation case, which is the one an MSP portfolio actually hits.
for (const [u, e] of [["u_a", "a@example.co.uk"], ["u_b", "b@example.co.uk"], ["u_free", "f@example.co.uk"]]) {
  db.prepare("INSERT INTO users (id, email, email_verified) VALUES (?,?,1)").run(u, e);
}
db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end) VALUES ('sub_a','u_a','business','active', datetime('now','+30 days'))").run();
db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end) VALUES ('sub_b','u_b','business','active', datetime('now','+30 days'))").run();

for (const [ws, owner, name] of [["ws_a1", "u_a", "Acme"], ["ws_a2", "u_a", "Beta Ltd"], ["ws_b1", "u_b", "Rival Co"], ["ws_dead", "u_a", "Deleted Co"]]) {
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?,?)").run(ws, name, owner);
  db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?,?, 'owner')").run(ws, owner);
}
db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'ws_dead'").run();

// shared.co.uk exists TWICE: d_a_shared owned by MSP A, d_b_shared owned by MSP B.
// domains has no UNIQUE on `domain`, so this is the real production shape.
for (const [dId, uId, host] of [
  ["d_a1", "u_a", "acme.co.uk"], ["d_a_shared", "u_a", "shared.co.uk"],
  ["d_b_shared", "u_b", "shared.co.uk"], ["d_dead", "u_a", "dead.co.uk"],
]) db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?,?,?)").run(dId, uId, host);

db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws_a1','d_a1','verified')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws_a2','d_a_shared','verified')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws_b1','d_b_shared','verified')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_dead','d_dead')").run();

const mkScan = (id, dId, host, q, score, ws, age, rating = "good") => db.prepare(
  "INSERT INTO scans (id, domain_id, domain, workspace_id, status, score, rating, scan_quality, created_at) VALUES (?,?,?,?, 'completed', ?, ?, ?, ?)"
).run(id, dId, host, ws, score, rating, q, iso(age));

// Acme: healthy everywhere except Email Protection, which has a NEW critical.
mkScan("sc_a1_old", "d_a1", "acme.co.uk", "complete", 80, "ws_a1", 10);
mkScan("sc_a1_new", "d_a1", "acme.co.uk", "complete", 60, "ws_a1", 1);
seedAllEight("ws_a1", "d_a1", "sc_a1_old", { assessed_at: iso(10) });
seedAllEight("ws_a1", "d_a1", "sc_a1_new", { assessed_at: iso(1) });
db.prepare("UPDATE cyber_mot_domain_states SET state='issue_detected', highest_severity='critical', finding_count=1, finding_ids_json='[\"dmarc_missing\"]', summary='1 issue detected.' WHERE scan_id='sc_a1_new' AND domain_key='email_protection'").run();

// MSP A's shared.co.uk: healthy, quiet.
mkScan("sc_a_shared", "d_a_shared", "shared.co.uk", "complete", 100, "ws_a2", 2, "excellent");
seedAllEight("ws_a2", "d_a_shared", "sc_a_shared", { assessed_at: iso(2) });

// MSP B's shared.co.uk — SAME hostname, different tenant: critical everywhere.
mkScan("sc_b_shared", "d_b_shared", "shared.co.uk", "complete", 10, "ws_b1", 2);
seedAllEight("ws_b1", "d_b_shared", "sc_b_shared", {
  assessed_at: iso(2), state: "issue_detected", highest_severity: "critical",
  finding_count: 3, finding_ids: ["B_SECRET_FINDING"], summary: "B_SECRET_SUMMARY",
});
db.prepare("INSERT INTO managed_cases (id, workspace_id, case_type, domain, domain_key, severity, status, title, created_at) VALUES ('mc_b','ws_b1','asm_exposure','shared.co.uk','attack_surface','critical','open','B_SECRET_CASE', datetime('now'))").run();

const TOKEN_A = "tok_a", TOKEN_B = "tok_b", TOKEN_FREE = "tok_free";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKEN_A));
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_b','u_b',?, datetime('now','+1 day'))").run(await hashToken(TOKEN_B));
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_f','u_free',?, datetime('now','+1 day'))").run(await hashToken(TOKEN_FREE));

const completedPhase5 = () => ({
  cve_intelligence: {},
  known_exploited_vulnerabilities: {},
  email_security_intelligence: {},
});
const storedReports = new Map([
  ["sc_a1_new", {
    modules: {
      ...completedPhase5(),
      cve_intelligence: {
        executed: false,
        incomplete: true,
        outcome: "deadline_exceeded",
      },
    },
  }],
  ["sc_a_shared", { modules: completedPhase5() }],
  ["sc_b_shared", { modules: completedPhase5() }],
]);
const env = {
  cybermeters_db: makeD1(db, writeLog),
  cybermeters_reports: {
    get: async (key) => {
      const report = storedReports.get(
        key.replace(/^reports\//, "").replace(/\.json$/, ""),
      );
      return report ? { json: async () => structuredClone(report) } : null;
    },
    put: async () => ({}),
    head: async () => null,
    delete: async () => ({}),
    list: async () => ({ objects: [] }),
  },
  ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const get = async (p, token) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx);
  let data = null; try { data = await res.json(); } catch { /* */ }
  return { status: res.status, data };
};
const D1 = makeD1(db);

// ═════════════════ 1. Tenant isolation + duplicate hostname ═════════════════
const a = await get("/api/portfolio/domains?limit=100", TOKEN_A);
ok("A: authorised (200)", a.status === 200);
const aRows = a.data?.domains ?? [];
ok("A sees exactly their 2 domains", aRows.length === 2, `got ${aRows.length}`);
ok("A never sees a soft-deleted workspace's domain", !aRows.some((r) => r.workspace_id === "ws_dead"));
const blob = JSON.stringify(a.data);
ok("CROSS-TENANT: none of B's state leaks into A", !blob.includes("B_SECRET_FINDING") && !blob.includes("B_SECRET_SUMMARY"));
ok("CROSS-TENANT: none of B's cases leak into A", !blob.includes("B_SECRET_CASE"));
ok("CROSS-TENANT: A's summary counts only A's rows", a.data?.summary?.total_domains === 2);

// The state reader's OWN scoping, asserted directly. Going through the route hides
// this: computePortfolioDomainRows looks each series up by `${workspace_id}::${domain_id}`
// from the already-authorised domain list, so an unscoped state query still cannot leak
// through it. That is real defence in depth — and it is exactly why the scoping in the
// query itself must be proved here rather than inferred from the route's output. If this
// function is ever called by something that trusts its keys, the WHERE clause is the
// only thing standing between tenants.
const aOnlyStates = await readPortfolioDomainStates(D1, ["ws_a1"]);
ok("STATE READER IS TENANT-SCOPED: asking for ws_a1 returns no other tenant's series",
   [...aOnlyStates.values()].every((v) => v.workspace_id === "ws_a1"),
   [...aOnlyStates.values()].map((v) => v.workspace_id).join(","));
ok("STATE READER: ws_a1 query never returns B's domain record",
   ![...aOnlyStates.keys()].some((k) => k.includes("d_b_shared")));
ok("STATE READER: an empty workspace list returns nothing (never the whole table)",
   (await readPortfolioDomainStates(D1, [])).size === 0);

// The engine's OWN soft-delete filter, asserted by handing it a deleted workspace id
// directly. getAccessibleWorkspaceIds already excludes ws_dead, so every route-level
// assertion passes with the engine's filter removed — the belt only gets tested if you
// take the braces off.
ok("SOFT-DELETE FAILS CLOSED IN THE ENGINE: a deleted workspace yields no rows even when asked for by id",
   (await computePortfolioDomainRows(D1, ["ws_dead"])).length === 0);
ok("soft-deleted workspace contributes nothing to a mixed request",
   (await computePortfolioDomainRows(D1, ["ws_a1", "ws_dead"])).every((r) => r.workspace_id !== "ws_dead"));

// The same hostname, two tenants, two verdicts. This is the case a hostname-keyed
// design silently merges.
const aShared = aRows.find((r) => r.hostname === "shared.co.uk");
const b = await get("/api/portfolio/domains?limit=100", TOKEN_B);
const bShared = (b.data?.domains ?? []).find((r) => r.hostname === "shared.co.uk");
ok("SAME HOSTNAME: both tenants have a row for shared.co.uk", !!aShared && !!bShared);
ok("SAME HOSTNAME: distinct domain records", aShared?.domain_id === "d_a_shared" && bShared?.domain_id === "d_b_shared");
ok("SAME HOSTNAME: A's is healthy, B's is critical — states do NOT merge",
   aShared?.priority === "low" && bShared?.priority === "critical", `${aShared?.priority} / ${bShared?.priority}`);
ok("SAME HOSTNAME: A's open-case count is 0, B's case does not bleed across",
   aShared?.open_case_count === 0 && bShared?.open_case_count === 1);
ok("SAME HOSTNAME: drill-down targets the caller's OWN workspace + domain record",
   aShared?.drill_down.workspace_id === "ws_a2" && aShared?.drill_down.domain_id === "d_a_shared");

// ═════════════════ 2. All eight domains, always ═════════════════════════════
for (const r of aRows) {
  ok(`all EIGHT domains present for ${r.hostname}`, r.cyber_mot_domains.length === 8);
  ok(`eight domains in canonical order for ${r.hostname}`,
     r.cyber_mot_domains.map((d) => d.domain_key).join(",") === CYBER_MOT_DOMAIN_KEYS.join(","));
}
ok("summary rolls up all EIGHT domains", a.data?.summary?.by_domain?.length === 8);

// A domain record with NO state rows at all → eight not_yet_assessed, never healthy.
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d_none','u_a','never-scanned.co.uk')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_a1','d_none')").run();
const withNone = await computePortfolioDomainRows(D1, ["ws_a1", "ws_a2"]);
const noneRow = withNone.find((r) => r.domain_id === "d_none");
ok("never-assessed domain is PRESENT, not dropped", !!noneRow);
ok("never-assessed domain shows eight domains", noneRow.cyber_mot_domains.length === 8);
ok("GREEN-BY-ABSENCE: no row ⇒ not_yet_assessed on all eight, never assessed_healthy",
   noneRow.cyber_mot_domains.every((d) => d.state === CYBER_MOT_STATES.NOT_YET_ASSESSED));
ok("never-assessed domain is NOT priority low", noneRow.priority !== "low", noneRow.priority);
ok("never-assessed domain has no fabricated score", noneRow.overall_score === null && noneRow.overall_rating === null);
ok("never-assessed domain freshness is none, not current", noneRow.evidence_freshness === EVIDENCE_FRESHNESS.NONE);
ok("no history ⇒ insufficient_history, NEVER stable",
   noneRow.cyber_mot_domains.every((d) => d.trend === DOMAIN_TREND.INSUFFICIENT_HISTORY));

// ═════════════════ 3. Trend honesty ═════════════════════════════════════════
const row = (o) => ({ scan_quality: "complete", resolver_version: RV, state: CYBER_MOT_STATES.ASSESSED_HEALTHY, assessed_at: iso(1), scan_id: "s1", finding_ids_json: "[]", highest_severity: null, ...o });

ok("no previous ⇒ insufficient_history, not stable",
   resolveDomainTrend(row({}), null).trend === DOMAIN_TREND.INSUFFICIENT_HISTORY);

// The load-bearing one: evidence vanished. previous said "issue", current cannot see.
const vanished = resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT }),
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "critical", finding_ids_json: '["x"]', assessed_at: iso(8) }),
);
ok("DISAPPEARED EVIDENCE IS NOT RECOVERY", vanished.trend !== DOMAIN_TREND.RECOVERED && vanished.trend !== DOMAIN_TREND.IMPROVING, vanished.trend);
ok("disappeared evidence says why", /not evidence that it has been resolved/i.test(vanished.trend_reason));

// A partial scan is not an improvement.
const partial = resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ASSESSED_HEALTHY, scan_quality: "partial" }),
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", assessed_at: iso(8) }),
);
ok("INCOMPLETE SCAN IS NOT RECOVERY/IMPROVEMENT", partial.trend === DOMAIN_TREND.NOT_COMPARABLE, partial.trend);
const failedPrev = resolveDomainTrend(row({}), row({ scan_quality: null, assessed_at: iso(8) }));
ok("failed/unknown-quality baseline is not comparable", failedPrev.trend === DOMAIN_TREND.NOT_COMPARABLE);

// THE resolver-version gate: identical evidence, different ruler.
const versionChanged = resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "critical", finding_ids_json: '["x"]', resolver_version: "9999-01-01.1" }),
  row({ state: CYBER_MOT_STATES.ASSESSED_HEALTHY, assessed_at: iso(8) }),
);
ok("RESOLVER-VERSION-ONLY CHANGE IS NOT WORSENING", versionChanged.trend === DOMAIN_TREND.NOT_COMPARABLE, versionChanged.trend);
ok("resolver-version change says it was US, not them",
   /would not describe a change in your security posture/i.test(versionChanged.trend_reason));

// Real movement still resolves.
ok("healthy → issue = new_risk", resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", finding_ids_json: '["dmarc_missing"]' }),
  row({ state: CYBER_MOT_STATES.ASSESSED_HEALTHY, assessed_at: iso(8) }),
).trend === DOMAIN_TREND.NEW_RISK);
ok("issue → healthy on two complete scans = recovered", resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ASSESSED_HEALTHY }),
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", finding_ids_json: '["x"]', assessed_at: iso(8) }),
).trend === DOMAIN_TREND.RECOVERED);
ok("severity escalation = worsening", resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "critical", finding_ids_json: '["x"]' }),
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "medium", finding_ids_json: '["x"]', assessed_at: iso(8) }),
).trend === DOMAIN_TREND.WORSENING);
ok("identical evidence = stable", resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", finding_ids_json: '["x"]' }),
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", finding_ids_json: '["x"]', assessed_at: iso(8) }),
).trend === DOMAIN_TREND.STABLE);
const named = resolveDomainTrend(
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", finding_ids_json: '["a","b"]' }),
  row({ state: CYBER_MOT_STATES.ISSUE_DETECTED, highest_severity: "high", finding_ids_json: '["a"]', assessed_at: iso(8) }),
);
ok("a trend names WHICH evidence changed, not just that a number moved",
   named.new_finding_ids.includes("b") && /b/.test(named.trend_reason));
// A score is not a cause: the trend never reads scans.score at all.
ok("score movement alone invents no cause (identical evidence at both ends ⇒ stable)",
   resolveDomainTrend(row({ finding_ids_json: "[]" }), row({ finding_ids_json: "[]", assessed_at: iso(8) })).trend === DOMAIN_TREND.STABLE);

// Acme's real Email Protection trend, end to end through the API.
const acme = aRows.find((r) => r.hostname === "acme.co.uk");
const email = acme?.cyber_mot_domains.find((d) => d.domain_key === "email_protection");
ok("API: Acme email_protection is issue_detected", email?.state === CYBER_MOT_STATES.ISSUE_DETECTED);
ok("API: Acme email_protection trend is new_risk", email?.trend === DOMAIN_TREND.NEW_RISK, email?.trend);
ok("API: trend cites the finding id", (email?.new_finding_ids || []).includes("dmarc_missing"));
ok("API: a critical domain is NOT hidden by a healthy overall score",
   acme?.priority === "critical" && acme?.cyber_mot_domains.filter((d) => d.state === "assessed_healthy").length === 7);

// ═════════════════ 4. Freshness ═════════════════════════════════════════════
ok("stale evidence is explicit", evidenceFreshness(iso(200)).freshness === EVIDENCE_FRESHNESS.STALE);
ok("stale says how old", /stale/i.test(evidenceFreshness(iso(200)).reason));
ok("aging evidence is explicit", evidenceFreshness(iso(20)).freshness === EVIDENCE_FRESHNESS.AGING);
ok("recent evidence is current", evidenceFreshness(iso(1)).freshness === EVIDENCE_FRESHNESS.CURRENT);
ok("absent evidence is `none`, NEVER current", evidenceFreshness(null).freshness === EVIDENCE_FRESHNESS.NONE);
ok("unparseable timestamp is `none`, never current", evidenceFreshness("not-a-date").freshness === EVIDENCE_FRESHNESS.NONE);

// A year-old COMPLETE healthy scan: state stays the resolver's word, freshness carries
// the truth, and the row does not read as a current all-clear.
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d_stale','u_a','stale.co.uk')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_a1','d_stale')").run();
mkScan("sc_stale", "d_stale", "stale.co.uk", "complete", 99, "ws_a1", 400);
seedAllEight("ws_a1", "d_stale", "sc_stale", { assessed_at: iso(400) });
const staleRows = await computePortfolioDomainRows(D1, ["ws_a1"]);
const staleRow = staleRows.find((r) => r.domain_id === "d_stale");
ok("STALE HEALTHY: state is still the resolver's verdict", staleRow.cyber_mot_domains[0].state === CYBER_MOT_STATES.ASSESSED_HEALTHY);
ok("STALE HEALTHY: freshness is stale, not current", staleRow.evidence_freshness === EVIDENCE_FRESHNESS.STALE);
ok("STALE HEALTHY: does not read as a clean low-priority customer", staleRow.priority !== "low", staleRow.priority);
ok("STALE HEALTHY: attention is required and says why",
   staleRow.attention_required && staleRow.attention_reasons.some((r) => r.kind === "evidence_stale"));

// ═════════════════ 5. Filters / sorting / pagination ════════════════════════
const all = await computePortfolioDomainRows(D1, ["ws_a1", "ws_a2"]);
const s1 = applyPortfolioView(all, { sort: "priority", limit: 100 });
const s2 = applyPortfolioView([...all].reverse(), { sort: "priority", limit: 100 });
ok("sorting is DETERMINISTIC regardless of input order",
   JSON.stringify(s1.rows.map((r) => r.domain_id)) === JSON.stringify(s2.rows.map((r) => r.domain_id)));
// DIRECTION, not just determinism. Reversing the comparator reverses both runs above,
// so the determinism assertion alone passes a portfolio that sorts the healthy customer
// to the top and buries the critical one — the exact opposite of the feature's purpose.
const PRI_ORDER = ["critical", "high", "medium", "unknown", "low"];
ok("SORT DIRECTION: the worst customer is FIRST, never last",
   s1.rows[0].priority === "critical", `first row is ${s1.rows[0].priority}`);
ok("SORT DIRECTION: priority is non-decreasing down the page (critical → low)",
   s1.rows.every((r, i) => i === 0 || PRI_ORDER.indexOf(s1.rows[i - 1].priority) <= PRI_ORDER.indexOf(r.priority)),
   s1.rows.map((r) => r.priority).join(" → "));
const sev = applyPortfolioView(all, { sort: "severity", limit: 100 });
ok("SORT DIRECTION: severity sorts the most severe FIRST",
   sev.rows[0].highest_severity === "critical", `first row is ${sev.rows[0].highest_severity}`);
const stalest = applyPortfolioView(all, { sort: "freshness", limit: 100 });
ok("SORT DIRECTION: freshness sorts the STALEST first (never-assessed is stalest)",
   stalest.rows[0].evidence_age_days === null || stalest.rows[0].domain_id === "d_stale",
   `first row age ${stalest.rows[0].evidence_age_days}`);
const p1 = applyPortfolioView(all, { sort: "priority", limit: 2, offset: 0 });
const p2 = applyPortfolioView(all, { sort: "priority", limit: 2, offset: 2 });
ok("pagination does not repeat a row across pages",
   !p1.rows.some((r) => p2.rows.some((x) => x.domain_id === r.domain_id)));
ok("pagination total is the FILTERED total, stable across pages", p1.total === p2.total && p1.total === all.length);
const filtered = applyPortfolioView(all, { filter: "attention", limit: 100 });
ok("filter `attention` narrows the set", filtered.total < all.length && filtered.total > 0);
ok("FILTER TOTAL does not leak the unfiltered count", filtered.total === filtered.rows.length);
ok("filter `stale` finds the 400-day domain", applyPortfolioView(all, { filter: "stale", limit: 100 }).rows.some((r) => r.domain_id === "d_stale"));
const nullScoreSort = applyPortfolioView(all, { sort: "score", limit: 100 });
ok("SORT BY SCORE: a null score is not treated as 0 (fake crisis) and lands last",
   nullScoreSort.rows[nullScoreSort.rows.length - 1].overall_score === null);
// Pagination is tenant-safe: paging B's portfolio can never surface an A row.
const bAll = await computePortfolioDomainRows(D1, ["ws_b1"]);
ok("pagination is tenant-safe (B's every page contains only B)",
   applyPortfolioView(bAll, { limit: 100 }).rows.every((r) => r.workspace_id === "ws_b1"));

// ═════════════════ 6. Summary reconciles with the rows ══════════════════════
const sum = buildPortfolioDomainSummary(all);
ok("summary total_domains equals the authorised row count", sum.total_domains === all.length);
ok("summary attention count equals the rows that require attention",
   sum.attention_required === all.filter((r) => r.attention_required).length);
ok("summary priority distribution sums to the row count",
   Object.values(sum.priority_distribution).reduce((x, y) => x + y, 0) === all.length);
ok("summary open_cases equals the sum over rows", sum.open_cases === all.reduce((s, r) => s + r.open_case_count, 0));
ok("summary discloses unassessed coverage rather than averaging it away",
   sum.unassessed_domains > 0 ? /not represented/i.test(sum.coverage_note || "") : true);
ok("NO BLENDED PORTFOLIO SCORE EXISTS", !("portfolio_score" in sum) && !("average_score" in sum) && !("avg_score" in sum));

// ═════════════════ 7. Entitlement + permission fail closed ══════════════════
for (const p of ["/api/portfolio/domains", "/api/portfolio/domains/ws_a1/d_a1"]) {
  const r = await get(p, TOKEN_FREE);
  ok(`un-entitled (free) user is 403 on ${p}`, r.status === 403 && r.data?.feature === "portfolio_monitoring");
  ok(`unauthenticated is 401 on ${p}`, (await get(p)).status === 401);
}
// Positive control: without this, a blanket 403 would pass every assertion above.
ok("entitled MSP reaches /api/portfolio/domains (200, not 403)", (await get("/api/portfolio/domains", TOKEN_A)).status === 200);
ok("entitled MSP reaches its own detail route (200)", (await get("/api/portfolio/domains/ws_a1/d_a1", TOKEN_A)).status === 200);

// Non-enumerating: a foreign real domain and a fake one are indistinguishable.
const foreignReal = await get("/api/portfolio/domains/ws_b1/d_b_shared", TOKEN_A);
const foreignFake = await get("/api/portfolio/domains/ws_nope/d_nope", TOKEN_A);
ok("PERMISSION FAILS CLOSED: A cannot read B's domain detail", foreignReal.status === 404);
ok("EXISTENCE ORACLE: foreign-real and nonexistent return the SAME status", foreignReal.status === foreignFake.status);
ok("foreign detail leaks no state", !JSON.stringify(foreignReal.data).includes("B_SECRET"));

// Detail route history.
const detail = await get("/api/portfolio/domains/ws_a1/d_a1", TOKEN_A);
ok("detail returns all eight domains", detail.data?.cyber_mot_domains?.length === 8);
ok("detail returns a history series per domain_key", Object.keys(detail.data?.history || {}).length === 8);
ok("history carries the comparability flag, so a reader sees WHY points differ",
   (detail.data?.history?.email_protection || []).every((h) => typeof h.comparable === "boolean"));

// The list and detail routes must traverse the same Phase-5 customer projection.
// Acme's frozen D1 score/rating are withheld because CVE evidence is deferred.
const listIncomplete = aRows.find((r) => r.domain_id === "d_a1");
ok("PHASE-5 LIST: incomplete historical evidence withholds frozen score/rating",
   listIncomplete?.overall_score === null && listIncomplete?.overall_rating === null);
ok("PHASE-5 DETAIL: incomplete historical evidence withholds frozen score/rating",
   detail.data?.overall_score === null && detail.data?.overall_rating === null);
ok("PHASE-5 LIST/DETAIL: incomplete assessment semantics are identical",
   detail.data?.phase5_evidence_read?.state === listIncomplete?.phase5_evidence_read?.state
     && detail.data?.phase5_assessment?.quality === listIncomplete?.phase5_assessment?.quality);

// Beta's immutable row is a genuine completed-zero positive control.
const listCompletedZero = aRows.find((r) => r.domain_id === "d_a_shared");
const completedZeroDetail =
  await get("/api/portfolio/domains/ws_a2/d_a_shared", TOKEN_A);
ok("PHASE-5 LIST: completed-zero retains 100/excellent",
   listCompletedZero?.overall_score === 100
     && listCompletedZero?.overall_rating === "excellent");
ok("PHASE-5 DETAIL: completed-zero retains 100/excellent",
   completedZeroDetail.data?.overall_score === 100
     && completedZeroDetail.data?.overall_rating === "excellent");
ok("PHASE-5 LIST/DETAIL: completed-zero assessment semantics are identical",
   completedZeroDetail.data?.phase5_evidence_read?.state
       === listCompletedZero?.phase5_evidence_read?.state
     && completedZeroDetail.data?.overall_score === listCompletedZero?.overall_score
     && completedZeroDetail.data?.overall_rating === listCompletedZero?.overall_rating);

// ═════════════════ 8. Read purity + no second alert engine ══════════════════
ok("GET /api/portfolio/domains performs NO domain write", domainWrites().length === 0, domainWrites().join(" | "));
ok("the platform's own writes still happen (rate limiting must not be disabled)",
   writeLog.some((s) => /api_rate_limits/i.test(s)));

const srcOf = (f) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", f), "utf8");
const portfolioSrc = srcOf("engines/portfolio-domains.js") + srcOf("engines/cyber-mot-state-history.js");
// The exact emitters and senders a portfolio must never reach. A portfolio that mints an
// occurrence would pass an evaluation timestamp as observed_at and clear the alert
// watermark — releasing the entire backlog to every customer at once.
for (const banned of [
  "emitManagedAlert", "ensureAlertActivation", "emitCaseLifecycleAlert", "emitLifecycleAlert",
  "processAlertsForWorkspace", "retryFailedAlertDeliveries",
  "sendAlertEmail", "sendTenantAlertEmail", "sendAssetChangeAlert", "sendWeeklyDigests",
  "sendLifecycleEmail", "deliverWorkspaceAlert", "buildAlertChannelPayload", "signAlertWebhookBody",
]) {
  ok(`portfolio code never calls ${banned}()`, !new RegExp(`\\b${banned}\\s*\\(`).test(portfolioSrc));
}
ok("portfolio code imports no alert or notification module",
   !/from\s+["'][^"']*(alerts|alert-consumers|managed-alerts|asset-alert-delivery|weekly-digest|lifecycle-email)[^"']*["']/.test(portfolioSrc));
const alertsBefore = db.prepare("SELECT COUNT(*) AS n FROM alert_deliveries").get().n;
const notifBefore = db.prepare("SELECT COUNT(*) AS n FROM notification_events").get().n;
await get("/api/portfolio/domains?limit=100", TOKEN_A);
ok("NO ALERT DELIVERY is minted by a portfolio read", db.prepare("SELECT COUNT(*) AS n FROM alert_deliveries").get().n === alertsBefore);
ok("NO NOTIFICATION is minted by a portfolio read", db.prepare("SELECT COUNT(*) AS n FROM notification_events").get().n === notifBefore);

// ═════════════════ 9. Append-only history ═══════════════════════════════════
const beforeRows = db.prepare("SELECT COUNT(*) AS n FROM cyber_mot_domain_states").get().n;
const report = {
  scan_id: "sc_a1_new", completed_at: iso(1), scan_quality: { status: "complete", modules_skipped: [] },
  modules: { dns: {}, ssl: {}, headers: {}, email_security: {}, subdomains: {}, certificate_intelligence: {}, brand_monitoring: {}, identity_discovery: {} },
  findings: [],
};
const again = await persistCyberMotDomainStates(env, { workspaceId: "ws_a1", domainId: "d_a1", scanId: "sc_a1_new", report, assessedAt: iso(1) });
ok("re-persisting the SAME scan is idempotent — no second identity",
   db.prepare("SELECT COUNT(*) AS n FROM cyber_mot_domain_states").get().n === beforeRows, `wrote ${again.written}`);
const preserved = db.prepare("SELECT state FROM cyber_mot_domain_states WHERE scan_id='sc_a1_new' AND domain_key='email_protection'").get();
ok("APPEND-ONLY: a prior snapshot is NOT overwritten by a re-persist", preserved.state === "issue_detected", preserved.state);
ok("engine issues no UPDATE/DELETE against the history table",
   !/(UPDATE|DELETE\s+FROM)\s+cyber_mot_domain_states/i.test(srcOf("engines/cyber-mot-state-history.js")));

// Fails closed on a missing identity rather than writing an unscopeable row.
ok("no workspace_id ⇒ nothing written (fails closed)", (await persistCyberMotDomainStates(env, { domainId: "d", scanId: "s", report })).written === 0);
ok("no domain_id ⇒ nothing written (fails closed)", (await persistCyberMotDomainStates(env, { workspaceId: "w", scanId: "s", report })).written === 0);
ok("no report ⇒ nothing written (fails closed)", (await persistCyberMotDomainStates(env, { workspaceId: "w", domainId: "d", scanId: "s", report: null })).written === 0);

// A new scan DOES append a new generation.
const newReport = { ...report, scan_id: "sc_a1_third", completed_at: iso(0) };
await persistCyberMotDomainStates(env, { workspaceId: "ws_a1", domainId: "d_a1", scanId: "sc_a1_third", report: newReport, assessedAt: iso(0) });
ok("a NEW scan appends a new generation (8 more rows)",
   db.prepare("SELECT COUNT(*) AS n FROM cyber_mot_domain_states").get().n === beforeRows + 8);
ok("every persisted row carries the resolver version",
   db.prepare("SELECT COUNT(*) AS n FROM cyber_mot_domain_states WHERE resolver_version IS NULL OR resolver_version = ''").get().n === 0);

// ═════════════════ 10. Purge ════════════════════════════════════════════════
ok("cyber_mot_domain_states is registered for workspace purge",
   worker.WORKSPACE_PURGE_TABLES.includes("cyber_mot_domain_states"));
ok("cyber_mot_domain_states is NOT in SCAN_CHILD_TABLES (no FK to scans)",
   !worker.SCAN_CHILD_TABLES.includes("cyber_mot_domain_states"));

console.log(`\nMSP Portfolio per-domain: ${pass}/${pass + fail} passed`);
if (fail) { console.error("MSP portfolio per-domain validation FAILED"); process.exit(1); }
console.log("MSP portfolio per-domain validation passed");
