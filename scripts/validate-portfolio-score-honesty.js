#!/usr/bin/env node
//
// Absent portfolio evidence must never become a risk verdict. CI-blocking. Node 24+.
//
// `generatePortfolioExecutiveSummary` classified the portfolio score with an inline
// ternary chain: `score >= 75 ? 'healthy' : score >= 55 ? 'moderate' : score >= 35 ?
// 'elevated' : 'serious'`. `null` fails all three comparisons, so a portfolio with no
// completed assessment fell through to 'serious' and the template interpolated the
// literal string:
//
//     "Your portfolio of 2 customer environments is showing serious overall risk
//      (portfolio score: null/100)."
//
// An MSP that had onboarded customers but not yet scanned them was told its portfolio
// was in serious danger, with a null printed at it as evidence. This is the inverse of
// the healthy-washing this platform's first rule forbids, and it is the same sin: the
// alerts post-mortem already recorded that removing fabricated deductions alone would
// have traded "a fabricated failure for a fabricated pass". Absent evidence is neither.
//
// Reachability, stated honestly: `/api/portfolio/risk` is gated on the
// `portfolio_monitoring` entitlement (business+), and production has no business or
// enterprise subscription — so this was latent, not customer-visible. It is fixed
// because the entitlement is a lock on the door, not a reason the room is safe.
//
// This suite drives the REAL worker fetch() handler against the REAL schema. The
// no-score cases are produced by seeding workspaces and withholding BRS rows — the
// engine decides, not a stub.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db, writeLog) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => {
      if (writeLog && /^\s*(insert|update|delete|replace)\b/i.test(sql)) writeLog.push(sql.trim().replace(/\s+/g, " ").slice(0, 110));
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeEnv(db, writeLog) {
  const noR2 = {
    get: async (key) => String(key).startsWith("reports/scan-")
      ? {
          json: async () => ({
            modules: {
              cve_intelligence: {
                technologies_checked: ["nginx"],
                lookup_statuses: { nginx: { status: "complete" } },
                results: { nginx: [] },
                total_cves: 0,
                critical_count: 0,
                high_count: 0,
                source: "nvd_api",
                cve_coverage: "complete",
              },
              known_exploited_vulnerabilities: {},
              email_security_intelligence: {},
            },
          }),
        }
      : null,
    put: async () => ({}), head: async () => null,
    delete: async () => ({}), list: async () => ({ objects: [] }),
  };
  return {
    cybermeters_db: makeD1(db, writeLog),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "score-honesty-mfa-key",
    STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x", STRIPE_PRICE_MAP: "{}",
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}

function seedProvenBrs(db, { workspaceId, ownerId, score, riskBand = "fixture" }) {
  const domainId = `domain-${workspaceId}`;
  const scanId = `scan-${workspaceId}`;
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)")
    .run(domainId, ownerId, `${workspaceId}.example.com`);
  db.prepare(`
    INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,created_at)
    VALUES (?,?,?,?,'completed','complete',datetime('now'))
  `).run(scanId, workspaceId, domainId, `${workspaceId}.example.com`);
  db.prepare(`
    INSERT INTO workspace_brs_scores
      (workspace_id,score,risk_band,calculated_at,payload_json)
    VALUES (?,?,?,datetime('now'),?)
  `).run(workspaceId, score, riskBand, JSON.stringify({
    basis_contract: "complete_scan/v1",
    score,
    risk_band: riskBand,
    basis_scan: { scan_id: scanId, status: "completed", scan_quality: "complete" },
  }));
}

// Same exception list as validate-portfolio-read-purity: rate limiting and session
// liveness are cross-cutting platform writes, not this route's domain writes.
const INFRA_WRITE = /^\s*(insert\s+into|update|replace\s+into)\s+(api_rate_limits|user_sessions)\b/i;
const domainWrites = (w) => w.filter((s) => !INFRA_WRITE.test(s));

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// Words that assert a risk verdict. If any appears in a summary that has no score, the
// engine invented a verdict from nothing.
const VERDICT_WORDS = /\b(healthy|moderate|elevated|serious)\b/i;

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;

  // ── Engine-level unit assertions ───────────────────────────────────────────
  // resolvePortfolioScoreState is the one contract; test it directly AND through HTTP.
  const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "portfolio-risk.js")).href);
  const { resolvePortfolioScoreState, PORTFOLIO_SCORE_STATES } = eng;

  ok("no workspaces resolves to no_workspaces",
     resolvePortfolioScoreState({ workspaceCount: 0, scoredCount: 0, score: null }).state === PORTFOLIO_SCORE_STATES.NO_WORKSPACES);
  ok("workspaces but zero scored resolves to evidence_insufficient",
     resolvePortfolioScoreState({ workspaceCount: 3, scoredCount: 0, score: null }).state === PORTFOLIO_SCORE_STATES.EVIDENCE_INSUFFICIENT);
  ok("some scored resolves to partial",
     resolvePortfolioScoreState({ workspaceCount: 5, scoredCount: 2, score: 70 }).state === PORTFOLIO_SCORE_STATES.PARTIAL);
  ok("all scored resolves to available",
     resolvePortfolioScoreState({ workspaceCount: 4, scoredCount: 4, score: 70 }).state === PORTFOLIO_SCORE_STATES.AVAILABLE);
  // The score itself is guarded, not merely the count: a positive scoredCount with a
  // non-finite score must not publish a number.
  for (const bad of [NaN, Infinity, -Infinity, undefined, null]) {
    ok(`a non-finite score (${String(bad)}) with scored>0 still resolves to evidence_insufficient`,
       resolvePortfolioScoreState({ workspaceCount: 3, scoredCount: 3, score: bad }).state === PORTFOLIO_SCORE_STATES.EVIDENCE_INSUFFICIENT,
       JSON.stringify(resolvePortfolioScoreState({ workspaceCount: 3, scoredCount: 3, score: bad })));
  }
  for (const s of ["no_workspaces", "evidence_insufficient", "partial", "available"]) {
    const r = Object.values(PORTFOLIO_SCORE_STATES).includes(s);
    ok(`state '${s}' is part of the published contract`, r);
  }
  ok("every state carries an attributable reason",
     [[0, 0, null], [3, 0, null], [5, 2, 70], [4, 4, 70]].every(([w, sc, s]) => {
       const r = resolvePortfolioScoreState({ workspaceCount: w, scoredCount: sc, score: s });
       return typeof r.reason === "string" && r.reason.length > 10;
     }));
  ok("partial's reason discloses the basis numerically",
     /2 of 5/.test(resolvePortfolioScoreState({ workspaceCount: 5, scoredCount: 2, score: 70 }).reason),
     resolvePortfolioScoreState({ workspaceCount: 5, scoredCount: 2, score: 70 }).reason);
  ok("basis reports scored and total",
     JSON.stringify(resolvePortfolioScoreState({ workspaceCount: 5, scoredCount: 2, score: 70 }).basis) ===
     JSON.stringify({ scored_workspaces: 2, total_workspaces: 5 }));

  // ── HTTP-level, real engine, real schema ───────────────────────────────────
  const db = buildDb();
  const writeLog = [];
  const env = makeEnv(db, writeLog);

  const tokA = "score-honesty-A", tokB = "score-honesty-B";
  const hA = await mod.hashToken(tokA), hB = await mod.hashToken(tokB);
  db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES ('uA','a@e.com','A','business','active',1,0)").run();
  db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES ('uB','b@e.com','B','free','active',1,0)").run();
  db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at,last_seen_at) VALUES ('sA','uA',?,datetime('now','+1 day'),'2020-01-01T00:00:00Z')").run(hA);
  db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('sB','uB',?,datetime('now','+1 day'))").run(hB);
  db.prepare("INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,current_period_end,created_at) VALUES ('subA','uA','business','active',datetime('now','+30 days'),datetime('now'))").run();

  const call = async (token = tokA) => {
    writeLog.length = 0;
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await worker.fetch(new Request("https://api.cybermeters.com/api/portfolio/risk", { headers }), env, ctx);
    let data = null; try { data = await res.json(); } catch { /* non-JSON */ }
    return { status: res.status, data, writes: [...writeLog] };
  };

  // ── CASE 1: no workspaces ──────────────────────────────────────────────────
  const none = await call();
  ok("no-workspace: 200", none.status === 200, `status ${none.status}`);
  ok("no-workspace: state is no_workspaces", none.data?.portfolio_score_state === "no_workspaces", none.data?.portfolio_score_state);
  ok("no-workspace: score is null", none.data?.portfolio_score === null);
  ok("no-workspace: band is null (no word for a score that does not exist)", none.data?.portfolio_score_band === null, String(none.data?.portfolio_score_band));
  ok("no-workspace: summary asserts no risk verdict", !VERDICT_WORDS.test(none.data?.executive_summary || ""), none.data?.executive_summary);
  ok("no-workspace: summary is not treated as healthy", !/\bhealthy\b/i.test(none.data?.executive_summary || ""));
  ok("no-workspace: reason is attributable", (none.data?.portfolio_score_reason || "").length > 10, none.data?.portfolio_score_reason);

  // ── CASE 2: workspaces exist, NO scan/BRS anywhere ─────────────────────────
  // The exact production shape that produced "serious ... null/100".
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('w1','uA','Alpha Ltd')").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('w2','uA','Beta Ltd')").run();
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m1','w1','uA','admin')").run();
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m2','w2','uA','admin')").run();

  const noScan = await call();
  ok("no-scan: 200", noScan.status === 200);
  ok("no-scan: score is null", noScan.data?.portfolio_score === null, String(noScan.data?.portfolio_score));
  ok("no-scan: state is evidence_insufficient", noScan.data?.portfolio_score_state === "evidence_insufficient", noScan.data?.portfolio_score_state);
  ok("no-scan: band is null", noScan.data?.portfolio_score_band === null, String(noScan.data?.portfolio_score_band));
  ok("NULL NEVER MAPS TO SERIOUS", !/\bserious\b/i.test(noScan.data?.executive_summary || ""), noScan.data?.executive_summary);
  ok("NULL NEVER MAPS TO HEALTHY", !/\bhealthy\b/i.test(noScan.data?.executive_summary || ""), noScan.data?.executive_summary);
  ok("null never maps to ANY risk band word", !VERDICT_WORDS.test(noScan.data?.executive_summary || ""), noScan.data?.executive_summary);
  ok("NEVER PRINTS null/100", !/null\/100/.test(noScan.data?.executive_summary || ""), noScan.data?.executive_summary);
  ok("never prints undefined/100", !/undefined\/100/.test(noScan.data?.executive_summary || ""));
  ok("never prints NaN/100", !/NaN\/100/.test(noScan.data?.executive_summary || ""));
  ok("no-scan: summary explains WHY the score is unavailable",
     /not available|cannot be calculated|no completed/i.test(noScan.data?.executive_summary || ""), noScan.data?.executive_summary);
  ok("no-scan: basis reports 0 of 2",
     JSON.stringify(noScan.data?.portfolio_score_basis) === JSON.stringify({ scored_workspaces: 0, total_workspaces: 2 }),
     JSON.stringify(noScan.data?.portfolio_score_basis));
  ok("no-scan: unscored workspaces still report band 'unknown', not a risk band",
     (noScan.data?.risk_rankings || []).every((r) => r.risk_band === "unknown"),
     JSON.stringify((noScan.data?.risk_rankings || []).map((r) => r.risk_band)));

  // The quiet half of the same defect. `critical_workspaces`/`high_risk_workspaces`
  // count bands equal to 'critical'/'high'; an unassessed environment's band is
  // 'unknown', so it counts toward neither, and the summary's unconditional else then
  // told an MSP we knew nothing about that "No customer environments are currently in
  // critical or high risk states." True of the data, false as an impression: zero
  // findings out of zero assessments is silence, not an all-clear. This one does not
  // print a number, which is exactly why it survived the first pass.
  ok("NO-SCAN: THE ALL-CLEAR IS WITHHELD ENTIRELY WHEN NOTHING WAS ASSESSED",
     !/no customer environments are currently in critical or high risk/i.test(noScan.data?.executive_summary || ""),
     noScan.data?.executive_summary);
  ok("no-scan: nothing in the summary implies the portfolio is safe",
     !/\b(no (customer )?environments? (are|is)|all clear|none .* at risk)\b/i.test(noScan.data?.executive_summary || ""),
     noScan.data?.executive_summary);

  // ── CASE 3: partial data ───────────────────────────────────────────────────
  // One of two scored, and scored HIGH. The average is 90 — presenting that as the
  // portfolio score lets the unassessed customer silently flatter the verdict.
  seedProvenBrs(db, { workspaceId: "w1", ownerId: "uA", score: 90, riskBand: "low" });
  const partial = await call();
  ok("partial: score reflects only the assessed environments", partial.data?.portfolio_score === 90, String(partial.data?.portfolio_score));
  ok("partial: state is partial", partial.data?.portfolio_score_state === "partial", partial.data?.portfolio_score_state);
  ok("partial: band is still published for the real score", partial.data?.portfolio_score_band === "healthy", String(partial.data?.portfolio_score_band));
  ok("partial: basis discloses 1 of 2",
     JSON.stringify(partial.data?.portfolio_score_basis) === JSON.stringify({ scored_workspaces: 1, total_workspaces: 2 }),
     JSON.stringify(partial.data?.portfolio_score_basis));
  ok("PARTIAL INCOMPLETENESS IS DISCLOSED IN THE SUMMARY ITSELF",
     /1 of 2/.test(partial.data?.executive_summary || ""), partial.data?.executive_summary);
  ok("partial: the summary does not claim the whole portfolio is healthy without qualification",
     /not represented|no completed assessment/i.test(partial.data?.executive_summary || ""), partial.data?.executive_summary);
  // A clean bill of health for the assessed subset must not be stated for the portfolio.
  ok("PARTIAL: THE ALL-CLEAR IS SCOPED TO THE ASSESSED SUBSET, NOT THE PORTFOLIO",
     !/^(?!.*assessed).*no customer environments are currently in critical or high risk/i.test(partial.data?.executive_summary || ""),
     partial.data?.executive_summary);
  ok("partial: the all-clear explicitly excludes the unassessed environments",
     !/critical or high risk/i.test(partial.data?.executive_summary || "") ||
     /not covered by this statement/i.test(partial.data?.executive_summary || ""),
     partial.data?.executive_summary);

  // ── CASE 4: full data ──────────────────────────────────────────────────────
  seedProvenBrs(db, { workspaceId: "w2", ownerId: "uA", score: 30, riskBand: "high" });
  const full = await call();
  ok("available: state is available", full.data?.portfolio_score_state === "available", full.data?.portfolio_score_state);
  ok("available: score is the mean of both (90+30)/2 = 60", full.data?.portfolio_score === 60, String(full.data?.portfolio_score));
  ok("available: band matches the preserved 55 boundary -> moderate", full.data?.portfolio_score_band === "moderate", String(full.data?.portfolio_score_band));
  ok("available: summary prints the real score out of 100", /60\/100/.test(full.data?.executive_summary || ""), full.data?.executive_summary);
  ok("available: no partial disclosure when nothing is missing",
     !/not represented/i.test(full.data?.executive_summary || ""), full.data?.executive_summary);
  ok("available: a critical customer is NOT hidden by a moderate portfolio average",
     (full.data?.risk_rankings || []).some((r) => r.risk_band === "high"),
     JSON.stringify((full.data?.risk_rankings || []).map((r) => [r.workspace_id, r.risk_band])));

  // ── CASE 5: band boundaries — the preserved contract ────────────────────────
  // Boundaries are asserted against the engine, not assumed. These are the values the
  // pre-existing code used; the corrective moved the ladder, it must not move the line.
  const bandOf = (score) => {
    const s = eng.resolvePortfolioScoreState({ workspaceCount: 1, scoredCount: 1, score });
    return s.state === "available" ? "has-score" : s.state;
  };
  ok("boundary sanity: 75 is sayable", bandOf(75) === "has-score");
  ok("boundary sanity: 0 is sayable (a real zero is evidence, not absence)", bandOf(0) === "has-score");
  ok("boundary sanity: 100 is sayable", bandOf(100) === "has-score");

  // Drive the real bands through HTTP at each boundary and either side of it.
  const bandAt = async (score) => {
    const d2 = buildDb();
    const e2 = makeEnv(d2, null);
    const t = "band-probe"; const h = await mod.hashToken(t);
    d2.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES ('u','u@e.com','U','business','active',1,0)").run();
    d2.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('s','u',?,datetime('now','+1 day'))").run(h);
    d2.prepare("INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,current_period_end,created_at) VALUES ('sb','u','business','active',datetime('now','+30 days'),datetime('now'))").run();
    d2.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('w','u','W')").run();
    d2.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m','w','u','admin')").run();
    seedProvenBrs(d2, { workspaceId: "w", ownerId: "u", score, riskBand: "x" });
    const res = await worker.fetch(new Request("https://api.cybermeters.com/api/portfolio/risk", { headers: { Authorization: `Bearer ${t}` } }), e2, ctx);
    return (await res.json()).portfolio_score_band;
  };
  const BOUNDARIES = [
    [0, "serious"], [34, "serious"], [35, "elevated"], [36, "elevated"],
    [54, "elevated"], [55, "moderate"], [56, "moderate"],
    [74, "moderate"], [75, "healthy"], [76, "healthy"], [100, "healthy"],
  ];
  for (const [score, expected] of BOUNDARIES) {
    const got = await bandAt(score);
    ok(`band boundary preserved: score ${score} -> ${expected}`, got === expected, `got ${got}`);
  }

  // ── CASE 6: the guarantees Gate 1 must not break ───────────────────────────
  const snap = () => db.prepare("SELECT COUNT(*) AS n FROM portfolio_risk_snapshots").get().n;
  const before = snap();
  const again = await call();
  ok("read purity holds: GET still appends no portfolio_risk_snapshots row", snap() === before, `${before} -> ${snap()}`);
  ok("read purity holds: GET still issues no domain write", domainWrites(again.writes).length === 0, domainWrites(again.writes).join(" | "));
  ok("rate limiting still records", again.writes.some((w) => /api_rate_limits/i.test(w)));
  ok("session liveness still records", again.writes.some((w) => /user_sessions/i.test(w)));

  const foreign = await call(tokB);
  ok("entitlement still fails closed for a free-plan user", foreign.status === 403, `status ${foreign.status}`);
  ok("the gate is the documented one", foreign.data?.error === "plan_feature_required");
  const anon = await call(null);
  ok("unauthenticated still 401", anon.status === 401);

  console.log(`\nportfolio-score-honesty: ${pass} passed, ${fail} failed`);
  if (fail > 0) { console.error("portfolio-score-honesty validation FAILED"); process.exit(1); }
  console.log("portfolio-score-honesty validation passed");
}

main().catch((err) => { console.error(err); process.exit(1); });
