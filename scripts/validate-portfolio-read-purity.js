#!/usr/bin/env node
//
// GET /api/portfolio/risk must not write to the database. CI-blocking. Node 24+.
//
// `computePortfolioRisk()` appended a row to `portfolio_risk_snapshots` every time it
// ran, and its only call site is `GET /api/portfolio/risk`. So opening the Portfolio
// Risk page mutated production state: one row per page load, per refresh, forever. No
// dedupe, no rate limit, no retention, and `catch { /* non-fatal */ }` swallowed any
// error it caused.
//
// Three separate problems, and the third is the one that matters:
//
//   1. A GET mutated state. Any prefetch, retry, double-click, uptime check or crawler
//      wrote a row. It is unauthenticated-adjacent: the write happens after auth, but
//      nothing about a read should reach the database in write mode.
//
//   2. `036-portfolio-risk-snapshots.sql:3` describes the write as running "typically
//      post-scan or on-demand". There is no post-scan path — the string appears in no
//      scan code — and no cron writes the table either. The comment describes a design
//      that was never built, so the table's contents are not a record of the portfolio
//      over time. They are a record of when someone happened to open a page.
//
//   3. Nothing reads the table. Not one SELECT exists against
//      `portfolio_risk_snapshots` anywhere in the repository. The 30-day trend that
//      the page actually renders comes from `workspace_brs_score_history`
//      (`portfolio-risk.js:125-131`), a different table with a different key. So the
//      write was pure cost: unbounded growth, zero readers.
//
// That combination is why the write is removed rather than moved to a cron. Moving it
// would preserve a sampling cadence nobody consumes; and the MSP Portfolio episode
// needs per-DOMAIN state over time, which this table cannot express — it holds four
// scalars keyed by `users.id`, with no domain dimension. A cron writing it would be
// building history for a question nobody asks.
//
// The table and its existing rows are deliberately KEPT. Historical evidence is
// append-only here; dropping it would be a destructive migration, and the rows —
// however unevenly sampled — are real observations that were really made.
//
// This suite drives the REAL worker fetch() handler against the REAL schema and counts
// rows. It is not a mock: `portfolio_risk_snapshots` is queried directly before and
// after. Against the pre-fix engine it fails, which is the proof.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

// Counts every write this request issues, so the assertion is "no write reached D1",
// not merely "one table did not grow". A future side effect on a different table is
// the same defect wearing a different name.
function makeD1(db, writeLog) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => {
      if (writeLog && /^\s*(insert|update|delete|replace|drop|alter|create)\b/i.test(sql)) {
        writeLog.push(sql.trim().replace(/\s+/g, " ").slice(0, 120));
      }
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeEnv(db, writeLog) {
  const noR2 = { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };
  return {
    cybermeters_db: makeD1(db, writeLog),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "portfolio-read-purity-test-mfa-key",
    STRIPE_WEBHOOK_SECRET: "whsec_test",
    STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ business_monthly: "price_bm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test",
    RESEND_API_KEY: "",
    ADMIN_EMAILS: "",
  };
}

// Rate limiting and session liveness are cross-cutting platform writes that fire on
// EVERY authenticated request, long before any route handler runs. They are not part
// of the portfolio read path and removing them would be a security regression, not a
// cleanup — `api_rate_limits` is how abuse is bounded, and `user_sessions.last_seen_at`
// is how idle sessions are aged out. This suite's subject is the DOMAIN write the
// portfolio engine performs on its own behalf, so those two are named and excused
// explicitly rather than quietly ignored: anything else that writes is a finding.
const INFRA_WRITE = /^\s*(insert\s+into|update|replace\s+into)\s+(api_rate_limits|user_sessions)\b/i;
const domainWrites = (writes) => writes.filter((w) => !INFRA_WRITE.test(w));

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { cond ? pass++ : fail++; if (!cond) console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); };

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const writeLog = [];
  const env = makeEnv(db, writeLog);

  const tokenA = "portfolio-purity-token-A";
  const tokenB = "portfolio-purity-token-B";
  const tokenHashA = await mod.hashToken(tokenA);
  const tokenHashB = await mod.hashToken(tokenB);

  // userA: business plan => holds the `portfolio_monitoring` entitlement.
  // userB: free plan, separate workspace => the isolation control.
  db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, 1, 0)")
    .run("userA", "a@example.com", "Alice", "business", "active");
  db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, 1, 0)")
    .run("userB", "b@example.com", "Bob", "free", "active");
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))")
    .run("sessA", "userA", tokenHashA);
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))")
    .run("sessB", "userB", tokenHashB);

  // getUserPlan() reads `subscriptions`, not `users.plan`.
  db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end, created_at)
              VALUES (?, ?, 'business', 'active', datetime('now','+30 days'), datetime('now'))`)
    .run("sub_A", "userA");

  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws1", "userA", "Alpha Ltd");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws2", "userA", "Beta Ltd");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws9", "userB", "Foreign Ltd");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("mA1", "ws1", "userA", "admin");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("mA2", "ws2", "userA", "admin");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("mB1", "ws9", "userB", "admin");

  // A non-null portfolio_score is required or the engine short-circuits before the
  // write — a seedless test would "pass" against the broken engine and prove nothing.
  db.prepare("INSERT INTO workspace_brs_scores (workspace_id, score, risk_band, calculated_at) VALUES (?, ?, ?, datetime('now'))")
    .run("ws1", 42, "high");
  db.prepare("INSERT INTO workspace_brs_scores (workspace_id, score, risk_band, calculated_at) VALUES (?, ?, ?, datetime('now'))")
    .run("ws2", 88, "low");

  const snapshotCount = () =>
    db.prepare("SELECT COUNT(*) AS n FROM portfolio_risk_snapshots").get().n;

  const call = async (pathname, token = tokenA) => {
    writeLog.length = 0;
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = new Request(`https://api.cybermeters.com${pathname}`, { method: "GET", headers });
    const res = await worker.fetch(req, env, ctx);
    let data = null; try { data = await res.json(); } catch { /* non-JSON */ }
    return { status: res.status, data, writes: [...writeLog] };
  };

  // ── 1. The engine still works ───────────────────────────────────────────────
  // Removing a side effect must not remove the feature. If these fail, the fix broke
  // the page rather than cleaning it.
  const before = snapshotCount();
  const risk = await call("/api/portfolio/risk");
  ok("GET /api/portfolio/risk returns 200 for an entitled user", risk.status === 200, `status ${risk.status}`);
  ok("the response still carries a portfolio score", typeof risk.data?.portfolio_score === "number",
     JSON.stringify(risk.data?.portfolio_score));
  ok("the response still ranks every accessible workspace", risk.data?.risk_rankings?.length === 2,
     `rankings: ${risk.data?.risk_rankings?.length}`);
  ok("the response still reports the workspace count", risk.data?.workspace_count === 2);
  ok("the response still carries an executive summary", typeof risk.data?.executive_summary === "string" && risk.data.executive_summary.length > 0);

  // ── 2. The read is pure ─────────────────────────────────────────────────────
  // THE defect. Pre-fix this fails: one row appears per request.
  ok("GET /api/portfolio/risk appends no portfolio_risk_snapshots row",
     snapshotCount() === before,
     `rows went ${before} -> ${snapshotCount()} — a GET mutated production state`);
  ok("GET /api/portfolio/risk issues no domain write to D1 (rate-limit + session liveness excepted)",
     domainWrites(risk.writes).length === 0,
     `writes: ${domainWrites(risk.writes).join(" | ")}`);
  ok("the legitimate platform writes are still happening (this fix must not disable rate limiting)",
     risk.writes.some((w) => /api_rate_limits/i.test(w)),
     "no rate-limit write observed — the read path lost a control it must keep");

  // ── 3. Refreshing the page is not a data source ─────────────────────────────
  // The growth was per REQUEST, so a single-request assertion could pass a
  // once-per-session write and miss the unbounded one.
  for (let i = 0; i < 5; i++) await call("/api/portfolio/risk");
  ok("five further page loads append nothing (growth was per-request, unbounded)",
     snapshotCount() === before,
     `rows after 6 total requests: ${snapshotCount()}, expected ${before}`);

  // ── 4. Determinism ──────────────────────────────────────────────────────────
  // A pure read of unchanged data returns unchanged output, `calculated_at` aside.
  const a = await call("/api/portfolio/risk");
  const b = await call("/api/portfolio/risk");
  const strip = (d) => JSON.stringify({ ...d, calculated_at: undefined, executive_summary: undefined });
  ok("two consecutive reads of unchanged data agree", strip(a.data) === strip(b.data));

  // ── 5. Tenant isolation survives the change ─────────────────────────────────
  const foreign = await call("/api/portfolio/risk", tokenB);
  ok("a free-plan user is gated by entitlement, not served another tenant's portfolio",
     foreign.status === 403, `status ${foreign.status}`);
  ok("the entitlement gate is the documented one", foreign.data?.error === "plan_feature_required",
     JSON.stringify(foreign.data));
  ok("the entitlement-gated request performs no domain write", domainWrites(foreign.writes).length === 0,
     domainWrites(foreign.writes).join(" | "));

  const unauth = await call("/api/portfolio/risk", null);
  ok("an unauthenticated request returns 401", unauth.status === 401);
  ok("the unauthenticated request performs no domain write", domainWrites(unauth.writes).length === 0,
     domainWrites(unauth.writes).join(" | "));

  // ── 6. The table and its history are preserved ──────────────────────────────
  // The fix stops writing; it must not erase. Historical evidence is append-only, and
  // rows already collected are real observations, unevenly sampled but really made.
  const tableStillExists = db.prepare(
    "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name='portfolio_risk_snapshots'").get().n;
  ok("portfolio_risk_snapshots still exists (no destructive migration)", tableStillExists === 1);

  db.prepare(`INSERT INTO portfolio_risk_snapshots (id, owner_id, portfolio_score, workspace_count, high_risk_count, critical_count, calculated_at)
              VALUES ('legacy_row', 'userA', 55, 2, 1, 0, datetime('now','-10 days'))`).run();
  const afterLegacy = snapshotCount();
  await call("/api/portfolio/risk");
  ok("a pre-existing snapshot row survives a read untouched", snapshotCount() === afterLegacy);
  ok("the pre-existing row's values are not rewritten",
     db.prepare("SELECT portfolio_score AS s FROM portfolio_risk_snapshots WHERE id='legacy_row'").get()?.s === 55);

  // ── 7. The dead writer is gone, not merely unreferenced ─────────────────────
  // A private function nobody calls is the next person's "why is this unused?" — and
  // the next person after that reconnects it. Delete it or keep it honest.
  const engineSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "portfolio-risk.js"), "utf8");
  ok("no INSERT into portfolio_risk_snapshots remains in the portfolio risk engine",
     !/INSERT\s+INTO\s+portfolio_risk_snapshots/i.test(engineSrc),
     "the writer is still present — a future edit re-enables the side effect");
  ok("the route no longer advertises a write it does not perform",
     !/Persists a snapshot to portfolio_risk_snapshots/.test(
       fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "portfolio.js"), "utf8")),
     "the route comment still claims to persist — a comment asserting behaviour nobody wrote is worse than none");

  console.log(`\nportfolio-read-purity: ${pass} passed, ${fail} failed`);
  if (fail > 0) { console.error("portfolio-read-purity validation FAILED"); process.exit(1); }
  console.log("portfolio-read-purity validation passed");
}

main().catch((err) => { console.error(err); process.exit(1); });
