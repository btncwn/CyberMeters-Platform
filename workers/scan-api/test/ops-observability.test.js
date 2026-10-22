import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { cleanupExpiredObservability, runScheduled } from "../src/cron/scheduled.js";
import { collectFounderDigest, formatFounderDigest } from "../src/lib/founder-digest.js";
import { CANARY_DOMAINS, canaryFingerprint, runFreeCheckCanary } from "../src/engines/free-check-canary.js";
import { bumpDailyCounter, observeApiResponse, routeFamily, utcDay } from "../src/lib/ops-counters.js";
import { consumeApiRateLimit, rateLimitScopeId } from "../src/lib/rate-limit.js";
import { cleanPath, opsIntakeRoutes } from "../src/routes/ops-intake.js";

const BUILD = "ca3ca9c9-b5b1-4493-bd35-e240b13a129a";

function fixture({ failWrites = null } = {}) {
  const sqlite = new DatabaseSync(":memory:");
  for (const file of ["026-api-rate-limits.sql", "130-ops-observability.sql", "131-ops-canary-results.sql", "137-feedback-reply-email.sql"]) {
    sqlite.exec(readFileSync(fileURLToPath(new URL(`../../../database/migrations/${file}`, import.meta.url)), "utf8"));
  }
  sqlite.exec(`
    CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT, created_at TEXT, email_verified INTEGER);
    CREATE TABLE workspaces(id TEXT PRIMARY KEY, owner_user_id TEXT);
    CREATE TABLE scans(id TEXT PRIMARY KEY, workspace_id TEXT);
    CREATE TABLE subscriptions(id TEXT PRIMARY KEY, stripe_subscription_id TEXT, subscription_status TEXT, created_at TEXT);
  `);
  const db = {
    prepare(sql) {
      if (failWrites && failWrites.test(sql)) throw new Error("D1 unavailable");
      const statement = sqlite.prepare(sql);
      return { bind(...args) { return {
        first: async () => statement.get(...args) ?? null,
        all: async () => ({ results: statement.all(...args) }),
        run: async () => ({ meta: { changes: Number(statement.run(...args).changes) } }),
      }; } };
    },
    async batch(statements) { return Promise.all(statements.map((s) => s.run())); },
  };
  const metrics = [];
  return { sqlite, metrics, env: { cybermeters_db: db, METRICS: { writeDataPoint: (point) => metrics.push(point) } } };
}

function post(env, path, body, { ip = "198.51.100.7", contentType = "application/json" } = {}) {
  const request = new Request(`https://api.cybermeters.com${path}`, {
    method: "POST", headers: { "Content-Type": contentType, "CF-Connecting-IP": ip },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return opsIntakeRoutes({ request, env, url: new URL(request.url),
    json: (data, status = 200) => Response.json(data, { status }), consumeApiRateLimit, rateLimitScopeId });
}

const feedback = (overrides = {}) => ({ message: "The DMARC result page froze.", surface: "free_tool",
  tool: "dmarc-checker", path: "/tools/dmarc-checker", build: BUILD, error_code: null, ...overrides });

test("route families replace every identifier and never carry a domain", () => {
  assert.equal(routeFamily("/api/workspaces/workspace_df864b4f-f114/scans/scan_9"), "/api/workspaces/:id/scans/:id");
  assert.equal(routeFamily("/api/domain/example.co.uk/history"), "/api/domain/:id/history");
  assert.equal(routeFamily("/api/tools/dmarc/check"), "/api/tools/dmarc/check");
  assert.equal(cleanPath("/invitations/cmi_abcdef0123456789"), "/invitations/:redacted");
  assert.equal(cleanPath(`/reset/${"a".repeat(40)}`), "/reset/:redacted");
  assert.equal(cleanPath("/tools?x=1"), null);
  assert.equal(cleanPath("/tools#share=v1"), null);
  assert.equal(cleanPath("tools"), null);
});

test("every refusal is one METRICS point; 5xx and free-scan/tool outcomes are daily counters", async () => {
  const { sqlite, metrics, env } = fixture();
  assert.equal(observeApiResponse(env, { pathname: "/api/workspaces/ws_1/scans", method: "GET", status: 403, data: { code: "forbidden" } }), null);
  assert.deepEqual(metrics.at(-1).blobs.slice(0, 4), ["api_rejection", "403", "forbidden", "/api/workspaces/:id/scans"]);
  await observeApiResponse(env, { pathname: "/api/scans/scan_1/report", method: "GET", status: 503, data: { error: "x" } });
  await observeApiResponse(env, { pathname: "/api/free-scan", method: "POST", status: 200, data: { preview_state: "complete" } });
  await observeApiResponse(env, { pathname: "/api/free-scan", method: "POST", status: 400, data: { code: "target_verification_unavailable" } });
  await observeApiResponse(env, { pathname: "/api/tools/spf/check", method: "POST", status: 200, data: { cached: true, result: { verdict: { level: "risk" } } } });
  await observeApiResponse(env, { pathname: "/api/tools/dmarc/check", method: "POST", status: 429, data: { status: "limit_reached" } });
  const rows = sqlite.prepare("SELECT metric, label, count FROM ops_daily_counters ORDER BY metric, label").all()
    .map((row) => `${row.metric}|${row.label}|${row.count}`);
  assert.deepEqual(rows, [
    "free_scan|ok_complete|1", "free_scan|target_verification_unavailable|1",
    "free_tool|dmarc:limit_reached|1", "free_tool|spf:ok_risk_cached|1",
    "http_5xx|503:/api/scans/:id/report|1",
  ]);
  // A 4xx outside the free surfaces writes nothing to D1.
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM ops_daily_counters WHERE metric NOT IN ('free_scan','free_tool','http_5xx')").get().n, 0);
});

test("a day admits a bounded number of labels per metric", async () => {
  const { sqlite, env } = fixture();
  for (let i = 0; i < 505; i++) await bumpDailyCounter(env, "client_error", `label_${i}`);
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM ops_daily_counters").get().n, 500);
  assert.equal(await bumpDailyCounter(env, "client_error", "label_0"), true, "an existing label still counts");
  assert.equal(await bumpDailyCounter({ cybermeters_db: { prepare() { throw new Error("down"); } } }, "x", "y"), false, "fail-open");
});

test("feedback: valid is stored without any IP; unknown fields and bad values are refused", async () => {
  const { sqlite, env } = fixture();
  const ok = await post(env, "/api/feedback", feedback({ path: "/invitations/cmi_abcdef0123456789abcdef" }));
  assert.equal(ok.status, 202);
  assert.deepEqual(await ok.json(), { ok: true });
  const row = sqlite.prepare("SELECT * FROM feedback_reports").get();
  assert.equal(row.path, "/invitations/:redacted");
  assert.equal(row.message, "The DMARC result page froze.");
  assert.equal(JSON.stringify(row).includes("198.51.100.7"), false);
  assert.equal(JSON.stringify(sqlite.prepare("SELECT * FROM api_rate_limits").all()).includes("198.51.100.7"), false);
  for (const bad of [
    feedback({ extra: 1 }), feedback({ message: "" }), feedback({ message: "x".repeat(2001) }),
    feedback({ surface: "admin" }), feedback({ surface: "app" }), feedback({ tool: null }),
    feedback({ tool: "Bad Tool" }), feedback({ path: "/tools?domain=example.com" }), feedback({ build: "v1" }),
    feedback({ error_code: "Has Spaces" }),
  ]) {
    const res = await post(env, "/api/feedback", bad, { ip: "203.0.113.50" });
    assert.equal(res.status, 400, JSON.stringify(bad));
    assert.equal((await res.json()).code, "invalid_feedback");
  }
  assert.equal((await post(env, "/api/feedback", feedback({ surface: "app", tool: null, path: "/dashboard" }), { ip: "203.0.113.51" })).status, 202);
  assert.equal((await post(env, "/api/feedback", "{not json", { ip: "203.0.113.52" })).status, 400);
  assert.equal((await post(env, "/api/feedback", feedback(), { ip: "203.0.113.53", contentType: "text/plain" })).status, 400);
  assert.equal((await post(env, "/api/feedback", "x".repeat(5000), { ip: "203.0.113.54" })).status, 400);
});

test("feedback: five an hour per IP, then a calm 429; limiter or storage failure is a 503", async () => {
  const { env } = fixture();
  for (let i = 0; i < 5; i++) assert.equal((await post(env, "/api/feedback", feedback())).status, 202);
  const limited = await post(env, "/api/feedback", feedback());
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).code, "rate_limited");
  const down = fixture({ failWrites: /api_rate_limits/ });
  const refused = await post(down.env, "/api/feedback", feedback());
  assert.equal(refused.status, 503);
  assert.equal((await refused.json()).code, "feedback_unavailable");
  const noStore = fixture({ failWrites: /INSERT INTO feedback_reports/ });
  assert.equal((await post(noStore.env, "/api/feedback", feedback())).status, 503);
});

test("feedback: a global daily cap holds across IPs", async () => {
  const { sqlite, env } = fixture();
  const start = new Date(Math.floor(Date.now() / 864e5) * 864e5).toISOString();
  sqlite.prepare(`INSERT INTO api_rate_limits (id, scope, scope_id, action, window_start, window_seconds, request_count)
    VALUES (?, 'global', 'feedback', 'feedback_global', ?, 86400, 200)`)
    .run(`rl_global_feedback_feedback_global_${start}`.replace(/[^a-zA-Z0-9_-]+/g, "_"), start);
  assert.equal((await post(env, "/api/feedback", feedback(), { ip: "203.0.113.90" })).status, 429);
});

test("browser errors are counted by kind, code, status, route and build, never stored as text", async () => {
  const { sqlite, env } = fixture();
  const res = await post(env, "/api/client-errors", { kind: "api_error", code: "rate_limit_unavailable", status: 503,
    path: "/workspaces/ws_123/scans", build: BUILD });
  assert.equal(res.status, 202);
  assert.deepEqual(sqlite.prepare("SELECT metric, label, count FROM ops_daily_counters").all().map((r) => ({ ...r })),
    [{ metric: "client_error", label: "api_error|rate_limit_unavailable|503|/workspaces/:id/scans|ca3ca9c9", count: 1 }]);
  for (const bad of [{ kind: "js_error", path: "/x", build: BUILD, message: "TypeError at foo@bar.com" },
    { kind: "other", path: "/x", build: BUILD }, { kind: "js_error", path: "/x?y", build: BUILD },
    { kind: "js_error", path: "/x", build: BUILD, status: 99 }]) {
    assert.equal((await post(env, "/api/client-errors", bad, { ip: "203.0.113.70" })).status, 400, JSON.stringify(bad));
  }
});

test("the founder's daily email puts anomalies first and carries counts, not identities", async () => {
  const { sqlite, env } = fixture();
  const now = Date.parse("2026-10-21T08:00:00Z");
  const yesterday = utcDay(now - 864e5);
  for (let d = 2; d <= 8; d++) {
    sqlite.prepare("INSERT INTO ops_daily_counters VALUES (?, 'http_5xx', '500:/api/scans', 1, 'x')").run(utcDay(now - d * 864e5));
  }
  sqlite.prepare("INSERT INTO ops_daily_counters VALUES (?, 'http_5xx', '500:/api/scans', 9, 'x')").run(yesterday);
  sqlite.prepare("INSERT INTO ops_daily_counters VALUES (?, 'free_scan', 'ok_complete', 10, 'x')").run(yesterday);
  sqlite.prepare("INSERT INTO ops_daily_counters VALUES (?, 'free_scan', 'target_verification_unavailable', 6, 'x')").run(yesterday);
  sqlite.exec(`INSERT INTO users VALUES ('u1','owner@shop.example','2026-10-20 09:00:00',1),
    ('u2','second@shop.example','2026-10-20 10:00:00',0),('u3','deleted_abc','2026-10-20 11:00:00',0),
    ('u4','old@shop.example','2026-10-01 10:00:00',1);
    INSERT INTO workspaces VALUES ('w1','u1'); INSERT INTO scans VALUES ('s1','w1');
    INSERT INTO subscriptions VALUES ('sub1','stripe_sub','active','2026-10-20T12:00:00Z');`);
  sqlite.prepare(`INSERT INTO feedback_reports VALUES ('fb1','2026-10-20T15:30:00.000Z','free_tool','spf-checker',
    '/tools/spf-checker','${BUILD}',NULL,'Tree did not load',NULL)`).run();
  const digest = await collectFounderDigest(env, { nowMs: now });
  assert.equal(digest.day, "2026-10-20");
  assert.deepEqual(digest.funnel, { signups: 2, verified: 1, scanned: 1, paid: 1 });
  assert.match(digest.anomalies[0], /1 feedback message/);
  assert.ok(digest.anomalies.some((a) => /Server errors \(5xx\): 9 yesterday \(7-day average 1\.0\)/.test(a)));
  assert.ok(digest.anomalies.some((a) => /Free scans: 6 of 16 did not return a result/.test(a)));
  const mail = formatFounderDigest(digest);
  assert.match(mail.subject, /3 to look at \(2026-10-20\)/);
  assert.ok(mail.text.indexOf("Needs a look") < mail.text.indexOf("Free scans by outcome"));
  assert.match(mail.text, /"Tree did not load"/);
  assert.equal(/@shop\.example/.test(mail.text), false, "no account email appears");
  const quiet = await collectFounderDigest(fixture().env, { nowMs: now });
  assert.deepEqual(quiet.anomalies, []);
  assert.match(formatFounderDigest(quiet).subject, /nothing unusual/);
});

const rendererDigest = (metrics = {}) => ({
  day: "2026-10-20", anomalies: [], metrics,
  funnel: { signups: 2, verified: 1, scanned: 1, paid: 0 }, feedback: [], canary: null,
});
const counted = (labels) => ({ total: labels.reduce((n, [, count]) => n + count, 0), weekAverage: 1.5, labels });

test("digest renders known outcomes and all browser error kinds in plain words", () => {
  const outcomes = [
    "domain_not_found", "domain_no_website_address", "target_verification_unavailable",
    "rate_limit_exceeded", "rate_limit_unavailable", "limiter_unavailable", "limit_reached", "capacity_paused",
    "invalid_input", "body_too_large", "invalid_json", "invalid_domain", "non_public_domain",
    "verification_required", "verification_failed", "verification_unavailable", "lookup_failed",
    "ok_issues_observed", "ok_no_issues_observed", "ok_evidence_incomplete", "ok_complete", "ok_unknown",
    "attempted", "completed", "failed", "partial", "incomplete", "unavailable", "server_error",
  ];
  for (const outcome of outcomes) {
    const { text } = formatFounderDigest(rendererDigest({ free_scan: counted([[outcome, 7]]) }));
    assert.doesNotMatch(text, /[a-z]+_[a-z_]+/, outcome);
    assert.doesNotMatch(text, /Other \(/, outcome);
    assert.match(text, /Free scans by outcome: 7 \(7-day average 1\.5\)/);
  }
  for (const kind of ["js_error", "unhandled_rejection", "chunk_load", "api_error", "render_error"]) {
    const { text } = formatFounderDigest(rendererDigest({
      client_error: counted([[`${kind}|rate_limit_unavailable|503|/workspaces/:id/scans|abc12345`, 3]]),
    }));
    assert.doesNotMatch(text, /[a-z]+_[a-z_]+|kind\|code\|status\|route\|build|Other \(/);
    assert.match(text, /Request limiting unavailable — 503 — \/workspaces\/:id\/scans — abc12345: 3/);
  }
});

test("digest preserves totals, order, row limits, routes, builds and quoted feedback", () => {
  const digest = rendererDigest({
    free_scan: counted([["domain_not_found", 7], ["ok_issues_observed", 2]]),
    free_tool: counted([["spf:ok_risk_cached", 4], ["dmarc:limit_reached", 1], ["headers:ok_good", 2],
      ["ssl:ok_unknown", 1], ["lookalike:ok_attention", 3]]),
    http_5xx: counted([["503:/api/scans/:id/report", 6]]),
  });
  digest.feedback.push({ created_at: "2026-10-20T15:30:00Z", surface: "free_scan", path: "/",
    error_code: "domain_not_found", message: "This is my original message." });
  const original = structuredClone(digest);
  const { text } = formatFounderDigest(digest);
  assert.match(text, /Domain not found: 7/);
  assert.match(text, /Completed — findings observed: 2/);
  assert.match(text, /SPF — Completed — risk observed \(cached\): 4/);
  assert.match(text, /DMARC — Daily limit reached: 1/);
  assert.match(text, /Free tools by outcome: 11 \(7-day average 1\.5\)/);
  assert.match(text, /Server errors \(5xx\) by route: 6/);
  assert.match(text, /503 — \/api\/scans\/:id\/report: 6/);
  assert.match(text, /\[15:30 UTC\] Free scans \/ \(Domain not found\)/);
  assert.match(text, /"This is my original message\."/);
  assert.doesNotMatch(text, /[a-z]+_[a-z_]+/);
  assert.ok(text.indexOf("Domain not found: 7") < text.indexOf("findings observed: 2"));
  assert.deepEqual(digest, original, "display does not rewrite the collected counters");
  const capped = formatFounderDigest(rendererDigest({ free_scan: counted(
    Array.from({ length: 13 }, (_, i) => ["domain_not_found", i + 1]),
  ) })).text;
  assert.equal((capped.match(/Domain not found:/g) || []).length, 12);
  assert.match(capped, /Free scans by outcome: 91/);
});

test("digest keeps unknown outcome, tool, kind and reason keys visible", () => {
  const { text } = formatFounderDigest(rendererDigest({
    free_scan: counted([["future_scan_outcome", 5]]),
    free_tool: counted([["future_tool:ok_future_cached", 2]]),
    client_error: counted([["future_kind|future_reason|418|/new-route|newbuild", 1]]),
    http_5xx: counted([["future_server_label", 3]]),
  }));
  for (const key of ["future_scan_outcome", "future_tool", "ok_future_cached", "future_kind", "future_reason", "future_server_label"]) {
    assert.ok(text.includes(`Other (${key})`), key);
  }
  assert.match(text, /418 — \/new-route — newbuild: 1/);
});

test("missing metric counters use readable labels in digest anomalies", async () => {
  const { env } = fixture();
  const originalPrepare = env.cybermeters_db.prepare.bind(env.cybermeters_db);
  env.cybermeters_db.prepare = (sql) => {
    if (sql.includes("ops_daily_counters")) throw new Error("counter storage unavailable");
    return originalPrepare(sql);
  };
  const digest = await collectFounderDigest(env, { nowMs: Date.parse("2026-10-21T08:00:00Z") });
  const { text } = formatFounderDigest(digest);
  assert.match(text, /Could not read Server errors \(5xx\) counters/);
  assert.match(text, /Could not read Browser error reports counters/);
  assert.doesNotMatch(text, /[a-z]+_[a-z_]+/);
});

test("feedback older than 90 days and counters older than 180 days are deleted", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO feedback_reports VALUES ('old','2026-01-01T00:00:00Z','app',NULL,'/','dev',NULL,'a',NULL),
    ('new','2026-10-19T00:00:00Z','app',NULL,'/','dev',NULL,'b',NULL);
    INSERT INTO ops_daily_counters VALUES ('2026-03-01','http_5xx','x',1,'x'),('2026-10-19','http_5xx','x',1,'x');`);
  await cleanupExpiredObservability(env, "2026-10-20T02:00:00Z");
  assert.deepEqual(sqlite.prepare("SELECT id FROM feedback_reports").all().map((r) => r.id), ["new"]);
  assert.deepEqual(sqlite.prepare("SELECT day FROM ops_daily_counters").all().map((r) => r.day), ["2026-10-19"]);
});

const canaryRunners = (overrides = {}) => ({
  target: async () => ({ state: "public" }),
  dmarc: async () => ({ verdict: { level: "good" }, ladder: { current: "reject" } }),
  spf: async () => ({ verdict: { level: "good" }, resolution_status: "complete" }),
  ...overrides,
});

test("the canary fingerprints outcomes, records the day before, and reports changes and errors", async () => {
  const { sqlite, env } = fixture();
  assert.equal(CANARY_DOMAINS.length, 20);
  const day1 = Date.parse("2026-10-20T07:00:00Z");
  const first = await runFreeCheckCanary(env, { nowMs: day1, domains: ["a.example.com", "b.example.com"], runners: canaryRunners() });
  assert.deepEqual([first.checked, first.changed.length, first.errors.length], [2, 0, 0], "a first run has nothing to compare");
  const day2 = Date.parse("2026-10-21T07:00:00Z");
  const second = await runFreeCheckCanary(env, { nowMs: day2, domains: ["a.example.com", "b.example.com"], runners: canaryRunners({
    target: async (domain) => (domain === "b.example.com" ? { state: "blocked", reason: "soa_rname_invalid" } : { state: "public" }),
    spf: async (domain) => { if (domain === "a.example.com") throw new Error("boom"); return { verdict: { level: "good" }, resolution_status: "complete" }; },
  }) });
  assert.deepEqual(second.changed.map((c) => c.domain).sort(), ["a.example.com", "b.example.com"]);
  assert.deepEqual(second.errors.map((e) => e.domain), ["a.example.com"]);
  const row = sqlite.prepare("SELECT * FROM ops_canary_results WHERE domain = 'b.example.com'").get();
  assert.equal(row.fingerprint, "target:blocked/soa_rname_invalid|dmarc:good/reject|spf:good/complete");
  assert.equal(row.previous_fingerprint, "target:public|dmarc:good/reject|spf:good/complete");
  assert.equal(row.changed_at, "2026-10-21T07:00:00.000Z");
  assert.equal(canaryFingerprint({}), "target:error|dmarc:error/none|spf:error/none");

  // The founder email that morning leads with both, and names the domains.
  const digest = await collectFounderDigest(env, { nowMs: Date.parse("2026-10-21T08:00:00Z") });
  assert.ok(digest.anomalies.some((a) => a === "Canary changed: b.example.com target:public|dmarc:good/reject|spf:good/complete -> target:blocked/soa_rname_invalid|dmarc:good/reject|spf:good/complete"));
  assert.ok(digest.anomalies.some((a) => /^Canary error: a\.example\.com /.test(a)));
  assert.match(formatFounderDigest(digest).text, /Free-check canary this morning: 2 of 2 domains checked, 2 changed, 1 errors/);

  // A morning with no canary run says so.
  const missed = await collectFounderDigest(env, { nowMs: Date.parse("2026-10-23T08:00:00Z") });
  assert.ok(missed.anomalies.includes("The free-check canary did not run this morning"));
});

test("the canary stops at its subrequest budget and lists what it did not run", async () => {
  const { env } = fixture();
  const spend = (accounting) => { for (let i = 0; i < 30; i++) accounting?.recordAttempt?.(); };
  const out = await runFreeCheckCanary(env, {
    domains: ["a.example.com", "b.example.com", "c.example.com"],
    limits: { totalSubrequests: 90, perDomainSubrequests: 40, perDomainDeadlineMs: 1000 },
    runners: canaryRunners({ target: async (_d, _q, { accounting }) => { spend(accounting); return { state: "public" }; } }),
  });
  assert.deepEqual([out.checked, out.not_run], [2, ["c.example.com"]]);
});

test("the canary runs from the cron only where FREE_CHECK_CANARY is on (it makes real DNS lookups)", async () => {
  const { env } = fixture();
  const runs = async (flag) => {
    let calls = 0;
    const waits = [];
    await runScheduled({ cron: "0 * * * *" }, { ...env, ...(flag ? { FREE_CHECK_CANARY: flag } : {}) },
      { waitUntil: (promise) => waits.push(promise) }, { runFreeCheckCanary: async () => { calls += 1; } });
    await Promise.allSettled(waits);
    return calls;
  };
  const sevenUtc = new Date().getUTCHours() === 7;
  assert.equal(await runs(null), 0, "no flag: never, whatever the hour");
  assert.equal(await runs("off"), 0, "flag off: never");
  assert.equal(await runs("on"), sevenUtc ? 1 : 0, "flag on: once, at 07:00 UTC only");
});

// ── S2-FEEDBACK-NOW: the founder hears about feedback immediately ───────────
function withMailbox(env) {
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes("resend")) { sent.push(JSON.parse(init.body)); return Response.json({ id: `email_${sent.length}` }); }
    return realFetch(url, init);
  };
  Object.assign(env, { RESEND_API_KEY: "re_test", ALERT_EMAIL_TO: "ops@cybermeters.com", ALERT_EMAIL_FROM: "alerts@cybermeters.com" });
  return { sent, restore: () => { globalThis.fetch = realFetch; } };
}

test("feedback-now: every accepted report emails the ops address at once, with no IP", async () => {
  const { sqlite, env } = fixture();
  const mail = withMailbox(env);
  try {
    const res = await post(env, "/api/feedback", feedback({ reply_email: "  pat@example.co.uk " }), { ip: "203.0.113.77" });
    assert.equal(res.status, 202);
    assert.equal(mail.sent.length, 1);
    const email = mail.sent[0];
    assert.deepEqual(email.to, ["ops@cybermeters.com"]);
    assert.match(email.subject, /CyberMeters feedback \(free_tool: dmarc-checker\)/);
    assert.match(email.text, /The DMARC result page froze\./);
    assert.match(email.text, /Reply to: pat@example\.co\.uk/);
    assert.ok(!JSON.stringify(email).includes("203.0.113.77"), "the sender IP never appears in the email");
    assert.equal(sqlite.prepare("SELECT reply_email FROM feedback_reports").get().reply_email, "pat@example.co.uk");
  } finally { mail.restore(); }
});

test("feedback-now: reply_email is optional and validated; a bad one refuses the report", async () => {
  const { sqlite, env } = fixture();
  const mail = withMailbox(env);
  try {
    assert.equal((await post(env, "/api/feedback", feedback(), { ip: "203.0.113.80" })).status, 202);
    assert.equal((await post(env, "/api/feedback", feedback({ reply_email: "" }), { ip: "203.0.113.81" })).status, 202);
    assert.match(mail.sent[0].text, /Reply to: not given/);
    for (const bad of ["not-an-email", 42, `${"a".repeat(250)}@x.io`]) {
      const res = await post(env, "/api/feedback", feedback({ reply_email: bad }), { ip: "203.0.113.82" });
      assert.equal(res.status, 400);
    }
    assert.deepEqual(sqlite.prepare("SELECT reply_email FROM feedback_reports ORDER BY rowid").all().map((r) => r.reply_email), [null, null]);
  } finally { mail.restore(); }
});

test("feedback-now: beyond 30 emails an hour reports are stored for the digest only", async () => {
  const { sqlite, env } = fixture();
  const mail = withMailbox(env);
  try {
    for (let i = 0; i < 32; i++) {
      assert.equal((await post(env, "/api/feedback", feedback(), { ip: `198.51.100.${10 + i}` })).status, 202);
    }
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM feedback_reports").get().n, 32);
    assert.equal(mail.sent.length, 30);
  } finally { mail.restore(); }
});

test("feedback-now: a mail outage never fails or delays the customer's answer", async () => {
  const { sqlite, env } = fixture();
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("mail provider down"); };
  Object.assign(env, { RESEND_API_KEY: "re_test", ALERT_EMAIL_TO: "ops@cybermeters.com", ALERT_EMAIL_FROM: "alerts@cybermeters.com" });
  try {
    assert.equal((await post(env, "/api/feedback", feedback(), { ip: "203.0.113.90" })).status, 202);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM feedback_reports").get().n, 1);
  } finally { globalThis.fetch = realFetch; }
});
