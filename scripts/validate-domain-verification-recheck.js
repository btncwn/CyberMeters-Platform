#!/usr/bin/env node
//
// Hourly domain-verification auto-recheck (cron). CI-blocking.
//
// The defect: this task was dead code, and its deadness was invisible. It selected
// candidates on `domains.verification_token` / `domains.verification_initiated_at`,
// but since migration 079 NOTHING writes those columns — verification initiation
// moved to the workspace_domains link and the legacy domains.verification_* columns
// became read-only compatibility data. So the WHERE clause matched nothing, forever,
// and the customer-facing promise ("we re-check automatically every hour for 48
// hours") was false for every domain initiated after 079.
//
// Had it matched a pre-079 row it would have been worse: it wrote only the legacy
// `domains` table, never the authoritative workspace_domains link the scan gate
// reads, while notifying every linked workspace "ownership verified" — telling a
// customer they were verified while leaving them unable to scan.
//
// This harness drives the REAL cron task against a real in-memory SQLite with the
// real schema + every migration applied, and a scriptable DoH stub. Requires Node
// 24+ (node:sqlite).
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const modUrl = (...p) => pathToFileURL(path.join(root, ...p)).href;

// Bound to the real console.log before the worker module is imported: the telemetry
// tests below hijack it, and a result line landing in the capture buffer would make
// a failing run look silent.
const report = console.log.bind(console);
// The cron emits one telemetry line per candidate by design; at batch scale that
// buries the result line. Silence the sink globally — test 13 installs its own
// capture to prove the line is emitted and carries no token.
console.log = () => {};
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

// ── DoH stub ────────────────────────────────────────────────────────────────
// The cron's only network call is the TXT lookup. `dnsAnswers` maps a queried host
// to the TXT values it publishes; anything unlisted answers with an empty set.
let dnsAnswers = {};
let dnsThrows = false;
let dnsCalls = [];
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  const name = u.searchParams.get("name");
  dnsCalls.push(name);
  if (dnsThrows) throw new Error("resolver down");
  const vals = dnsAnswers[name] || [];
  return new Response(JSON.stringify({ Answer: vals.map((v) => ({ data: `"${v}"` })) }),
    { status: 200, headers: { "content-type": "application/json" } });
};
AbortSignal.timeout = () => undefined;

const worker = await import(modUrl("workers", "scan-api", "src", "index.js"));
const { retryPendingDomainVerifications } = worker;
const { VERIFICATION_OUTCOMES, VERIFICATION_WINDOW_HOURS, VERIFICATION_RECHECK_BATCH } =
  await import(modUrl("workers", "scan-api", "src", "lib", "domain-verification.js"));

ok("cron task is exported and callable", typeof retryPendingDomainVerifications === "function");

// ── DB ──────────────────────────────────────────────────────────────────────
let db, hooks = {};
const makeD1 = (d) => {
  const wrap = (sql, args) => ({
    first: async () => d.prepare(sql).get(...args) ?? null,
    all:   async () => ({ results: d.prepare(sql).all(...args) }),
    run:   async () => {
      if (hooks.runFor && hooks.runFor(sql)) return hooks.runFor(sql)(args);
      const r = d.prepare(sql).run(...args);
      return { meta: { changes: r.changes } };
    },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};
let env;

const TOKEN_A = "aa11bb22cc33dd44ee55ff66".repeat(2);  // 48-char hex
const TOKEN_B = "99887766554433221100aabb".repeat(2);

function reset() {
  db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  const migDir = path.join(root, "database", "migrations");
  for (const f of fs.readdirSync(migDir).filter((x) => x.endsWith(".sql")).sort()) apply(path.join(migDir, f));
  db.exec("PRAGMA foreign_keys = OFF");
  db.exec(`INSERT INTO users (id, email, password_hash, plan) VALUES ('u_a','a@example.com','x','pro'),('u_b','b@example.com','x','pro')`);
  db.exec(`INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_a','A','u_a'),('ws_b','B','u_b')`);
  env = { cybermeters_db: makeD1(db), ENVIRONMENT: "test" };
  dnsAnswers = {}; dnsThrows = false; dnsCalls = []; hooks = {};
}

// hoursAgo(1) → an initiated_at one hour in the past (inside the window).
const hoursAgo = (h) => `datetime('now', '-${h} hours')`;
const addDomain = (id, host, user = "u_a") =>
  db.exec(`INSERT INTO domains (id, user_id, domain, verification_status) VALUES ('${id}','${user}','${host}','unverified')`);
const addLink = (ws, dom, { status = "pending", token = TOKEN_A, initiatedHoursAgo = 1 } = {}) =>
  db.exec(`INSERT INTO workspace_domains (workspace_id, domain_id, verification_status, verification_token, verification_initiated_at)
           VALUES ('${ws}','${dom}','${status}',${token === null ? "NULL" : `'${token}'`}, ${initiatedHoursAgo === null ? "NULL" : hoursAgo(initiatedHoursAgo)})`);
const publishTxt = (host, token) => { dnsAnswers[`_cybermeters.${host}`] = [`cybermeters-verification=${token}`]; };
const linkOf = (ws, dom) => db.prepare("SELECT * FROM workspace_domains WHERE workspace_id=? AND domain_id=?").get(ws, dom);
const attempts = () => db.prepare("SELECT * FROM audit_events WHERE event_type='domain_verification_attempted' ORDER BY rowid").all();
const notifs = (type = "domain_verified") => db.prepare("SELECT * FROM notification_events WHERE type=? ORDER BY rowid").all(type);
const outcomesOf = () => attempts().map((r) => JSON.parse(r.metadata_json || "{}").outcome);

// ── 1. The authoritative source is workspace_domains, not legacy domains ────
// The regression that caused the incident: a link that IS eligible on the
// authoritative table, while the legacy domains row has NO token at all (which is
// the state of every domain created since 079). The old query found nothing here.
{
  reset();
  addDomain("d1", "alpha.example");                       // legacy columns: all NULL
  addLink("ws_a", "d1", { token: TOKEN_A, initiatedHoursAgo: 1 });
  publishTxt("alpha.example", TOKEN_A);

  const legacy = db.prepare("SELECT verification_token, verification_initiated_at FROM domains WHERE id='d1'").get();
  ok("precondition: legacy domains row has no token (post-079 reality)", !legacy.verification_token);
  ok("precondition: legacy domains row has no initiated_at", !legacy.verification_initiated_at);

  await retryPendingDomainVerifications(env);

  const link = linkOf("ws_a", "d1");
  eq("eligible pending link IS rechecked and verified", link.verification_status, "verified");
  ok("verified link has a persisted verified_at", Boolean(link.verified_at));
  eq("verified link records the method", link.verification_method, "dns_txt");
  eq("the DoH lookup actually happened", dnsCalls[0], "_cybermeters.alpha.example");
}

// ── 2. A 'failed' link is rechecked — this IS the incident's customer ────────
// The manual route writes 'failed' when the record has not propagated. A
// pending-only filter would skip exactly the row this task exists to rescue.
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { status: "failed", token: TOKEN_A, initiatedHoursAgo: 2 });
  publishTxt("alpha.example", TOKEN_A);
  await retryPendingDomainVerifications(env);
  eq("a 'failed' link (clicked Verify too early) is rechecked", linkOf("ws_a", "d1").verification_status, "verified");
}

// ── 3. Legacy domains token columns are never consulted ─────────────────────
// A legacy row carrying a token must NOT make an ineligible link eligible.
{
  reset();
  addDomain("d1", "alpha.example");
  db.exec(`UPDATE domains SET verification_status='pending', verification_token='${TOKEN_A}',
           verification_initiated_at=${hoursAgo(1)} WHERE id='d1'`);
  // The authoritative link has NO token → not a candidate, whatever the legacy row says.
  addLink("ws_a", "d1", { token: null, initiatedHoursAgo: null });
  publishTxt("alpha.example", TOKEN_A);

  await retryPendingDomainVerifications(env);
  eq("legacy token does not make an unlinked-token row eligible", linkOf("ws_a", "d1").verification_status, "pending");
  eq("no DoH lookup was made for it", dnsCalls.length, 0);
  eq("legacy domains row is never mutated by the cron", db.prepare("SELECT verification_status FROM domains WHERE id='d1'").get().verification_status, "pending");
}

// ── 4. Expired rows are skipped, and the expiry is observable exactly once ──
{
  reset();
  addDomain("d_exp", "expired.example");
  // 49h ago → outside the 48h window, inside the "expired during this hour" band.
  addLink("ws_a", "d_exp", { token: TOKEN_A, initiatedHoursAgo: VERIFICATION_WINDOW_HOURS + 0.5 });
  publishTxt("expired.example", TOKEN_A);   // even though the record IS now published

  await retryPendingDomainVerifications(env);
  eq("expired row is NOT verified even though the record is published", linkOf("ws_a", "d_exp").verification_status, "pending");
  eq("expired row gets no DoH lookup", dnsCalls.length, 0);
  ok("expiry is observable", outcomesOf().includes(VERIFICATION_OUTCOMES.RECHECK_WINDOW_EXPIRED));

  // A row that expired long ago must NOT be re-logged on every run, forever.
  reset();
  addDomain("d_old", "ancient.example");
  addLink("ws_a", "d_old", { token: TOKEN_A, initiatedHoursAgo: VERIFICATION_WINDOW_HOURS + 100 });
  await retryPendingDomainVerifications(env);
  eq("long-expired row is not re-logged (bounded expiry band)", attempts().length, 0);
}

// ── 5. A row just inside the window is still eligible (boundary) ────────────
{
  reset();
  addDomain("d_edge", "edge.example");
  addLink("ws_a", "d_edge", { token: TOKEN_A, initiatedHoursAgo: VERIFICATION_WINDOW_HOURS - 0.5 });
  publishTxt("edge.example", TOKEN_A);
  await retryPendingDomainVerifications(env);
  eq("row just inside the 48h window is still rechecked", linkOf("ws_a", "d_edge").verification_status, "verified");
}

// ── 6. Unchanged DNS failure does not mutate the row ────────────────────────
// The row must stay eligible for the next hourly run, not be pushed to a state
// the next run would skip.
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { status: "pending", token: TOKEN_A, initiatedHoursAgo: 1 });
  // No TXT published → not_found.
  await retryPendingDomainVerifications(env);
  const link = linkOf("ws_a", "d1");
  eq("DNS not found → status unchanged", link.verification_status, "pending");
  ok("DNS not found → verified_at still null", !link.verified_at);
  ok("DNS not found → outcome observable", outcomesOf().includes(VERIFICATION_OUTCOMES.DNS_NOT_FOUND));
  eq("DNS not found → no notification", notifs().length, 0);

  // And it is still eligible next hour.
  publishTxt("alpha.example", TOKEN_A);
  await retryPendingDomainVerifications(env);
  eq("still eligible on the next run once the record propagates", linkOf("ws_a", "d1").verification_status, "verified");
}

// ── 7. Mismatch and lookup-error are distinguished, and neither mutates ─────
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { token: TOKEN_A });
  dnsAnswers["_cybermeters.alpha.example"] = ["cybermeters-verification=WRONGVALUE"];
  await retryPendingDomainVerifications(env);
  ok("TXT present but wrong → dns_mismatch", outcomesOf().includes(VERIFICATION_OUTCOMES.DNS_MISMATCH));
  eq("dns_mismatch does not mutate the row", linkOf("ws_a", "d1").verification_status, "pending");

  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { token: TOKEN_A });
  dnsThrows = true;
  await retryPendingDomainVerifications(env);
  ok("resolver failure → dns_lookup_error, never 'not found'", outcomesOf().includes(VERIFICATION_OUTCOMES.DNS_LOOKUP_ERROR));
  ok("resolver failure is NOT reported as dns_not_found", !outcomesOf().includes(VERIFICATION_OUTCOMES.DNS_NOT_FOUND));
  eq("resolver failure does not mutate the row", linkOf("ws_a", "d1").verification_status, "pending");
}

// ── 8. Success persists THROUGH persistVerification's gate ──────────────────
// A zero-row UPDATE must not become a verification, and must not notify.
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { token: TOKEN_A });
  publishTxt("alpha.example", TOKEN_A);
  // Force the verified UPDATE to report zero changed rows.
  hooks = { runFor: (sql) => /verification_status = 'verified'/.test(sql) ? async () => ({ meta: { changes: 0 } }) : null };
  await retryPendingDomainVerifications(env);
  hooks = {};

  ok("zero-row persist → outcome is persistence_zero_rows", outcomesOf().includes(VERIFICATION_OUTCOMES.PERSISTENCE_ZERO_ROWS));
  ok("zero-row persist → NOT reported as verified", !outcomesOf().includes(VERIFICATION_OUTCOMES.VERIFIED_DNS_TXT));
  eq("zero-row persist → no domain_verified notification", notifs().length, 0);
  eq("zero-row persist → no domain_verified audit", db.prepare("SELECT COUNT(*) c FROM audit_events WHERE event_type='domain_verified'").get().c, 0);
}

// ── 9. Repeated runs do not duplicate verification or notifications ─────────
// Idempotency rests on the status transition: once persisted 'verified', the
// candidate query can never select the row again.
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { token: TOKEN_A });
  publishTxt("alpha.example", TOKEN_A);

  await retryPendingDomainVerifications(env);
  await retryPendingDomainVerifications(env);
  await retryPendingDomainVerifications(env);

  eq("three runs → verified once", linkOf("ws_a", "d1").verification_status, "verified");
  eq("three runs → exactly ONE domain_verified notification", notifs().length, 1);
  eq("three runs → exactly ONE domain_verified audit", db.prepare("SELECT COUNT(*) c FROM audit_events WHERE event_type='domain_verified'").get().c, 1);
  eq("three runs → exactly ONE verified attempt record", outcomesOf().filter((o) => o === VERIFICATION_OUTCOMES.VERIFIED_DNS_TXT).length, 1);
  eq("three runs → only the first run queried DNS", dnsCalls.length, 1);
}

// ── 10. Tenant isolation: one workspace's proof never verifies another ──────
{
  reset();
  addDomain("d_shared", "shared.example");
  addLink("ws_a", "d_shared", { token: TOKEN_A });
  addLink("ws_b", "d_shared", { token: TOKEN_B });
  // Only ws_a's token is published.
  publishTxt("shared.example", TOKEN_A);

  await retryPendingDomainVerifications(env);

  eq("ws_a proved its own token → verified", linkOf("ws_a", "d_shared").verification_status, "verified");
  eq("ws_b did NOT prove its token → still pending", linkOf("ws_b", "d_shared").verification_status, "pending");
  ok("ws_b has no verified_at", !linkOf("ws_b", "d_shared").verified_at);
  eq("only ws_a was notified", notifs().length, 1);
  eq("the notification belongs to ws_a", notifs()[0].workspace_id, "ws_a");
}

// ── 11. Soft-deleted workspaces receive no scheduled work ──────────────────
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { token: TOKEN_A });
  db.exec(`UPDATE workspaces SET deleted_at = datetime('now') WHERE id='ws_a'`);
  publishTxt("alpha.example", TOKEN_A);

  await retryPendingDomainVerifications(env);
  eq("soft-deleted workspace link is not rechecked", linkOf("ws_a", "d1").verification_status, "pending");
  eq("soft-deleted workspace gets no DoH lookup", dnsCalls.length, 0);
  eq("soft-deleted workspace gets no notification", notifs().length, 0);
}

// ── 12. Bounded batching + deterministic ordering ───────────────────────────
{
  reset();
  const n = VERIFICATION_RECHECK_BATCH + 5;
  for (let i = 0; i < n; i++) {
    addDomain(`d${i}`, `host${i}.example`);
    // Oldest first: i=0 is the oldest initiated_at.
    addLink("ws_a", `d${i}`, { token: TOKEN_A, initiatedHoursAgo: 40 - i * 0.1 });
    publishTxt(`host${i}.example`, TOKEN_A);
  }
  await retryPendingDomainVerifications(env);
  eq(`batch is bounded to VERIFICATION_RECHECK_BATCH`, dnsCalls.length, VERIFICATION_RECHECK_BATCH);
  const verified = db.prepare("SELECT COUNT(*) c FROM workspace_domains WHERE verification_status='verified'").get().c;
  eq("exactly the batch size was verified", verified, VERIFICATION_RECHECK_BATCH);
  // Deterministic: oldest initiated_at first.
  eq("oldest candidate processed first", dnsCalls[0], "_cybermeters.host0.example");

  // The remainder is picked up on the next run — nothing is stranded.
  await retryPendingDomainVerifications(env);
  eq("remaining candidates verified on the next run",
    db.prepare("SELECT COUNT(*) c FROM workspace_domains WHERE verification_status='verified'").get().c, n);
}

// ── 13. Token material never reaches logs or audit metadata ────────────────
{
  reset();
  addDomain("d1", "alpha.example");
  addLink("ws_a", "d1", { token: TOKEN_A });
  publishTxt("alpha.example", TOKEN_A);

  const captured = [];
  const realLog = console.log;
  console.log = (...a) => { captured.push(a.map(String).join(" ")); };
  await retryPendingDomainVerifications(env);
  console.log = realLog;

  const logText = captured.join("\n");
  ok("cron emitted a telemetry log line", logText.includes("[domain-verification/attempt]"));
  ok("cron log contains no token", !logText.includes(TOKEN_A));
  ok("cron log contains no raw expected TXT value", !logText.includes("cybermeters-verification="));

  const allAudit = db.prepare("SELECT metadata_json, description FROM audit_events").all()
    .map((r) => `${r.metadata_json || ""} ${r.description || ""}`).join("\n");
  ok("cron audit metadata contains no token", !allAudit.includes(TOKEN_A));
  ok("cron audit metadata contains no raw expected TXT value", !allAudit.includes("cybermeters-verification="));

  const allNotif = db.prepare("SELECT metadata_json, message, title FROM notification_events").all()
    .map((r) => `${r.metadata_json || ""} ${r.message || ""} ${r.title || ""}`).join("\n");
  ok("cron notification contains no token", !allNotif.includes(TOKEN_A));
}

// ── 14. The cron never throws, whatever D1 does ────────────────────────────
{
  reset();
  let threw = false;
  try { await retryPendingDomainVerifications({ cybermeters_db: { prepare() { throw new Error("D1 down"); } } }); }
  catch { threw = true; }
  ok("cron with dead D1 does not throw", !threw);
}

// ── 15. Source contract: no second implementation, no legacy read ──────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");
  const start = src.indexOf("async function retryPendingDomainVerifications");
  const end   = src.indexOf("\n}", src.indexOf("cron task must never throw"));
  const fn = src.slice(start, end);
  ok("harness: cron function slice is substantial", fn.length > 1500);

  ok("cron: selects from workspace_domains", /FROM workspace_domains wd/.test(fn));
  ok("cron: never selects verification_token FROM domains", !/verification_token\s+FROM\s+domains/i.test(fn));
  // Lookbehind matters: `wd.verification_initiated_at` (the authoritative link,
  // which we DO read) contains `d.verification_initiated_at` as a substring.
  ok("cron: does not read legacy domains.verification_initiated_at",
    !/(?<![A-Za-z_])d\.verification_initiated_at|domains\.verification_initiated_at/.test(fn));
  ok("cron: never UPDATEs the legacy domains table", !/UPDATE domains/.test(fn));
  ok("cron: excludes soft-deleted workspaces", /w\.deleted_at IS NULL/.test(fn));
  ok("cron: persists only via persistVerification", /persistVerification\(/.test(fn));
  ok("cron: contains no inline UPDATE to verified", !/verification_status\s*=\s*'verified'/.test(fn));
  ok("cron: reuses the canonical proof (no inline dnsQuery)", /checkDnsTxtProof\(/.test(fn) && !/dnsQuery\(/.test(fn));
  ok("cron: window is derived from the canonical constant", /VERIFICATION_WINDOW_HOURS/.test(fn));
  ok("cron: batch is derived from the canonical constant", /VERIFICATION_RECHECK_BATCH/.test(fn));
  ok("cron: notifies only the proven workspace", /createNotificationEvent\(env, row\.workspace_id/.test(fn));

  // The customer-facing promise must be generated from the same constants the cron
  // obeys — a hardcoded "48 hours" is how the copy drifted from reality last time.
  const routes = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "domains.js"), "utf8");
  ok("route: auto_recheck window comes from the canonical constant",
    /window_hours: VERIFICATION_WINDOW_HOURS/.test(routes));
  ok("route: auto_recheck interval comes from the canonical constant",
    /interval: VERIFICATION_RECHECK_INTERVAL/.test(routes));
  ok("route: the promise sentence is not a hardcoded cadence",
    !/re-check automatically every hour for 48 hours/.test(routes));
  ok("route: DNS proof is the shared canonical one", /checkDnsTxtProof\(/.test(routes));
}

report(`\nDomain-verification recheck (cron): ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
