#!/usr/bin/env node
//
// End-to-end request-pipeline tests: drive the worker's REAL fetch() handler
// (router → middleware → requireAuth → RBAC → D1 → Response) against a real
// in-memory SQLite seeded with the ACTUAL schema (schema.sql + migrations). This
// is the true integration layer above the leaf-function tests in
// validate-integration.js. Requires Node 24+ (node:sqlite). Exits non-zero on
// any failure so CI blocks.
//
import fs from "node:fs";
import path from "node:path";
import { webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

// ── Load the worker's default export (the { fetch, scheduled, email } object) ──
// ESM worker loading (vm-free): the worker is a real module since Sprint 9
// split it up — vm.runInContext cannot evaluate `import`. Network stays
// disabled and Workers-global stubs are applied process-wide before import.
async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

// ── Real schema (best-effort: a few migrations are ordering/idempotency no-ops) ──
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

// ── D1-compatible adapter over node:sqlite ────────────────────────────────────
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeEnv(db) {
  const noR2 = { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "pipeline-test-mfa-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm", professional_monthly: "price_pm", business_monthly: "price_bm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const RATE_LIMIT_EPOCH_MS = 1_800_000_001_234;
const EXPECTED_ASSERTION_COUNT = 45;
const PIPELINE_HARNESS_MUTANT = process.env.F4_PR1_PIPELINE_MUTANT || "";
const withRateLimitClock = async (operation) => {
  const originalDateNow = Date.now;
  Date.now = () => RATE_LIMIT_EPOCH_MS;
  try {
    return await operation();
  } finally {
    Date.now = originalDateNow;
  }
};
const rateLimitWindowStart = (windowSeconds) => new Date(
  Math.floor(RATE_LIMIT_EPOCH_MS / (windowSeconds * 1000)) * windowSeconds * 1000,
).toISOString();
const rateLimitScopeIdForTest = async (prefix, value) => {
  const digest = await webcrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value || "unknown")),
  );
  return `${prefix}_${Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 16)}`;
};
const scopedActionCounter = (db, { scope, scopeId, action, windowStart }) => db.prepare(
  `SELECT scope, scope_id, action, window_start, window_seconds, request_count
   FROM api_rate_limits
   WHERE scope = ? AND scope_id = ? AND action = ? AND window_start = ?
   LIMIT 1`,
).get(scope, scopeId, action, windowStart);

// Independent HMAC-SHA256 hex — forges the Stripe-Signature the way Stripe does,
// so the webhook signature gate is tested against a real (not stubbed) signature.
async function hmacHex(secret, message) {
  const key = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Tests are grouped into sections (Auth, Tenant, Billing, …) so the suite stays
// navigable as it grows toward 80-100 assertions.
let passed = 0, failed = 0, currentSection = "General";
const results = []; const sectionCounts = new Map();
function section(name) { currentSection = name; }
function ok(name, cond) {
  const s = sectionCounts.get(currentSection) ?? { passed: 0, failed: 0 };
  if (cond) { passed++; s.passed++; results.push(`PASS [${currentSection}] ${name}`); }
  else      { failed++; s.failed++; results.push(`FAIL [${currentSection}] ${name}`); }
  sectionCounts.set(currentSection, s);
}
function enforceExpectedAssertionCount() {
  const observed = passed + failed;
  if (observed === EXPECTED_ASSERTION_COUNT) return;
  const harnessSection = "Harness integrity";
  failed += 1;
  results.push(
    `FAIL [${harnessSection}] assertion-count interlock expected ${EXPECTED_ASSERTION_COUNT}, observed ${observed}`,
  );
  const s = sectionCounts.get(harnessSection) ?? { passed: 0, failed: 0 };
  s.failed += 1;
  sectionCounts.set(harnessSection, s);
}

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const hash = { hashToken: mod.hashToken, hashPassword: mod.hashPassword };
  const db = buildDb();
  const env = makeEnv(db);

  // ── Seed: two tenants; userA is an admin member of ws1 only ──
  const pwHash = await hash.hashPassword("Sup3r-secret-pw");
  const tokenA = "session-raw-token-A";
  const tokenHashA = await hash.hashToken(tokenA);
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, 1, 0)")
    .run("userA", "a@example.com", pwHash, "Alice", "free", "active");
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?, 1, 0)")
    .run("userC", "c@example.com", pwHash, "Carol", "free", "active");
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))")
    .run("sessA", "userA", tokenHashA);
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws1", "userA", "Alpha");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws2", "userC", "Bravo");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("m1", "ws1", "userA", "admin");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("m2", "ws2", "userC", "owner");

  const call = async (method, pathname, {
    token,
    body,
    headers: additionalHeaders = {},
    requestEnv = env,
  } = {}) => {
    const headers = { ...additionalHeaders };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (body) headers["Content-Type"] = "application/json";
    const req = new Request("https://api.cybermeters.com" + pathname, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const res = await worker.fetch(req, requestEnv, ctx);
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch { /* non-JSON */ }
    if (process.env.PIPE_DEBUG) console.error(`  [${method} ${pathname}] → ${res.status}  ${text.slice(0, 160)}`);
    return { status: res.status, data, text };
  };
  const has = (r, sub) => JSON.stringify(r.data ?? r.text ?? "").includes(sub);

  // ── The pipeline actually runs (status AND body, so a pass can't be a coincidence) ──
  section("Health / pipeline");
  const health = await call("GET", "/health");
  ok("GET /health drives the real fetch() → 200 {status:ok}", health.status === 200 && health.data?.status === "ok");

  // ── Auth gate at the HTTP layer ──
  section("Auth gate");
  const noAuth = await call("GET", "/api/workspaces/ws1");
  ok("unauthenticated workspace request → 401 Unauthorized", noAuth.status === 401 && has(noAuth, "nauthorized"));

  const badToken = await call("GET", "/api/workspaces/ws1", { token: "not-a-real-token" });
  ok("invalid token → 401", badToken.status === 401);

  // ── Tenant isolation through the FULL pipeline (router→auth→RBAC→DB→response) ──
  section("Tenant isolation");
  const own = await call("GET", "/api/workspaces/ws1", { token: tokenA });
  ok("owner reaches OWN workspace → 200 with the real record (id ws1, name Alpha)",
    own.status === 200 && own.data?.workspace?.id === "ws1" && own.data?.workspace?.name === "Alpha");

  const foreign = await call("GET", "/api/workspaces/ws2", { token: tokenA });
  ok("CROSS-TENANT via HTTP: userA (ws1) → ws2 is FORBIDDEN (403) with no workspace data",
    foreign.status === 403 && has(foreign, "orbidden") && !has(foreign, "Bravo"));

  // ── Login / session lifecycle through the real pipeline ──
  section("Login / session lifecycle");
  const badLogin = await call("POST", "/api/auth/login", { body: { email: "a@example.com", password: "wrong-password" } });
  ok("login with wrong password → 401 (no token leaked)", badLogin.status === 401 && !badLogin.data?.token);

  const login = await call("POST", "/api/auth/login", { body: { email: "a@example.com", password: "Sup3r-secret-pw" } });
  const liveToken = login.data?.token;
  ok("login with correct password → 200 + a session token", login.status === 200 && typeof liveToken === "string" && liveToken.length > 20);

  const me = await call("GET", "/api/auth/me", { token: liveToken });
  ok("the issued token authenticates GET /api/auth/me → 200 (right user)", me.status === 200 && has(me, "a@example.com"));

  const logout = await call("POST", "/api/auth/logout", { token: liveToken });
  ok("POST /api/auth/logout succeeds (2xx)", logout.status >= 200 && logout.status < 300);

  const afterLogout = await call("GET", "/api/auth/me", { token: liveToken });
  ok("the session is DEAD after logout → 401 (token no longer resolves)", afterLogout.status === 401);

  // ── Stripe webhook → entitlement, through the real signature gate ──
  section("Billing / webhook → entitlement");

  // Before any webhook: userA is on the free plan, so the professional-gated
  // audit-events endpoint must refuse with a clear upgrade signal.
  const preGate = await call("GET", "/api/workspaces/ws1/audit-events", { token: tokenA });
  ok("FEATURE GATE before upgrade: audit-events on free plan → 403 plan_feature_required",
    preGate.status === 403 && preGate.data?.error === "plan_feature_required");

  // /billing/plans must reflect real Stripe config, not a hardcoded flag
  // (regression guard: checkout_enabled was hardcoded false, disabling the UI
  // even when Stripe was fully configured).
  const plansResp = await call("GET", "/api/billing/plans");
  ok("billing/plans: checkout_enabled reflects config (true when Stripe configured, not hardcoded false)",
    plansResp.status === 200 && plansResp.data?.checkout_enabled === true && plansResp.data?.stripe?.configured === true);

  const secret = env.STRIPE_WEBHOOK_SECRET;
  const postWebhook = async (payload, { sign = true, ts = Math.floor(Date.now() / 1000) } = {}) => {
    const raw = JSON.stringify(payload);
    const headers = { "Content-Type": "application/json" };
    if (sign) headers["Stripe-Signature"] = `t=${ts},v1=${await hmacHex(secret, `${ts}.${raw}`)}`;
    const req = new Request("https://api.cybermeters.com/api/billing/webhook", { method: "POST", headers, body: raw });
    const res = await worker.fetch(req, env, ctx);
    const text = await res.text();
    if (process.env.PIPE_DEBUG) console.error(`  [POST /api/billing/webhook ${payload.type}] → ${res.status}  ${text.slice(0, 120)}`);
    return { status: res.status, text };
  };
  const subEvent = {
    id: "evt_pipeline_test",
    type: "customer.subscription.created",
    data: { object: {
      id: "sub_pipeline_test", customer: "cus_pipeline_test", status: "active",
      items: { data: [] }, current_period_start: Math.floor(Date.now() / 1000),
      current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
      metadata: { user_id: "userA", workspace_id: "ws1", plan: "professional" },
    } },
  };

  // A forged/unsigned webhook must NOT be able to mutate billing.
  const unsigned = await postWebhook(subEvent, { sign: false });
  ok("webhook with NO signature is rejected (4xx, not processed)", unsigned.status >= 400 && unsigned.status < 500);

  // Wrong-secret signature = forgery. Sign the exact bytes but with the wrong key.
  const rawForged = JSON.stringify(subEvent); const tsF = Math.floor(Date.now() / 1000);
  const forgedReq = new Request("https://api.cybermeters.com/api/billing/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "Stripe-Signature": `t=${tsF},v1=${await hmacHex("whsec_WRONG", `${tsF}.${rawForged}`)}` }, body: rawForged });
  const forgedRes = await worker.fetch(forgedReq, env, ctx);
  ok("webhook with a WRONG-secret signature → 400 (forgery rejected)", forgedRes.status === 400);

  // A correctly-signed subscription event actually changes the stored entitlement.
  const signed = await postWebhook(subEvent);
  ok("correctly-signed subscription.created webhook is accepted → 2xx", signed.status >= 200 && signed.status < 300);
  const subRow = db.prepare("SELECT plan, subscription_status FROM subscriptions WHERE workspace_id = ? ORDER BY updated_at DESC LIMIT 1").get("ws1");
  if (process.env.PIPE_DEBUG) console.error("  [subscriptions ws1 row]", JSON.stringify(subRow));
  ok("ENTITLEMENT: the webhook upserted ws1's subscription to the paid plan (professional, active)",
    subRow?.plan === "professional" && String(subRow?.subscription_status).toLowerCase() === "active");

  // Replay protection: re-delivering the SAME event id is acknowledged (Stripe
  // stops retrying) but must NOT be processed again.
  const replay = await postWebhook(subEvent);
  ok("REPLAY: a re-delivered Stripe event id is acknowledged (2xx) and deduped, not reprocessed",
    replay.status >= 200 && replay.status < 300 && replay.text.includes("deduped"));

  // The upgrade must actually TAKE EFFECT: the same endpoint that refused on
  // free now serves — billing → entitlement → feature gate, end to end.
  const postGate = await call("GET", "/api/workspaces/ws1/audit-events", { token: tokenA });
  ok("FEATURE GATE after upgrade: the same endpoint now serves → 200 (entitlement took effect)",
    postGate.status === 200 && Array.isArray(postGate.data?.events));

  // ── Pagination contract through the real pipeline (Sprint 3 helpers) ──
  // The endpoint self-audits (each view writes an audit_log_viewed event — the
  // harness caught that), so the assertions filter to event_type=test_event to
  // stay deterministic. This exercises the filter parameter too.
  section("Pagination");
  const ae = db.prepare("INSERT INTO audit_events (id, workspace_id, user_id, event_type, description) VALUES (?, ?, ?, ?, ?)");
  ae.run("ae1", "ws1", "userA", "test_event", "first");
  ae.run("ae2", "ws1", "userA", "test_event", "second");
  ae.run("ae3", "ws1", "userA", "test_event", "third");
  const page = await call("GET", "/api/workspaces/ws1/audit-events?event_type=test_event&limit=2&offset=0", { token: tokenA });
  const pg = page.data?.pagination;
  ok("limit is honoured (3 matching rows, limit=2 → exactly 2 events)", page.status === 200 && page.data?.events?.length === 2);
  ok("pagination meta is correct ({limit:2, offset:0, count:2, has_more:true, total:3})",
    pg?.limit === 2 && pg?.offset === 0 && pg?.count === 2 && pg?.has_more === true && pg?.total === 3);
  const page2 = await call("GET", "/api/workspaces/ws1/audit-events?event_type=test_event&limit=2&offset=2", { token: tokenA });
  ok("offset walks to the last page (1 event, has_more:false)",
    page2.data?.events?.length === 1 && page2.data?.pagination?.has_more === false);

  // ── Billing lifecycle: payment failure → grace → cancellation → re-subscribe ──
  // The remaining webhook tail (S6 Phase 3). Every event goes through the real
  // signature gate; every consequence is asserted on D1 AND on the customer-
  // visible feature gate (never silently remove paid access).
  section("Billing lifecycle (webhook tail)");

  const payFailed = await postWebhook({
    type: "invoice.payment_failed",
    data: { object: { id: "in_test_1", customer: "cus_pipeline_test", subscription: "sub_pipeline_test" } },
  });
  const rowFail = db.prepare("SELECT subscription_status, payment_failed_at, payment_retry_count FROM subscriptions WHERE workspace_id = ?").get("ws1");
  ok("invoice.payment_failed → past_due + payment_failed_at + retry_count 1",
    payFailed.status < 300 && rowFail?.subscription_status === "past_due"
    && rowFail?.payment_failed_at != null && rowFail?.payment_retry_count === 1);

  const graceGate = await call("GET", "/api/workspaces/ws1/audit-events?limit=1", { token: tokenA });
  ok("GRACE: paid access is NOT silently removed while past_due (gate still 200)", graceGate.status === 200);

  const deleted = await postWebhook({
    type: "customer.subscription.deleted",
    data: { object: { id: "sub_pipeline_test", customer: "cus_pipeline_test", status: "canceled", metadata: { user_id: "userA", workspace_id: "ws1" } } },
  });
  const rowDel = db.prepare("SELECT subscription_status FROM subscriptions WHERE workspace_id = ?").get("ws1");
  ok("subscription.deleted → status canceled in D1", deleted.status < 300 && rowDel?.subscription_status === "canceled");

  const postCancelGate = await call("GET", "/api/workspaces/ws1/audit-events?limit=1", { token: tokenA });
  ok("CANCELLATION takes effect: the gate closes again (403 plan_feature_required)",
    postCancelGate.status === 403 && postCancelGate.data?.error === "plan_feature_required");

  const resub = await postWebhook({
    type: "checkout.session.completed",
    data: { object: {
      id: "cs_test_resub", customer: "cus_pipeline_test", subscription: "sub_resub_1",
      client_reference_id: "userA",
      metadata: { user_id: "userA", workspace_id: "ws1", plan: "professional", interval: "monthly" },
    } },
  });
  const rowResub = db.prepare("SELECT plan, subscription_status, stripe_subscription_id FROM subscriptions WHERE workspace_id = ?").get("ws1");
  ok("checkout.session.completed → active professional again with the new stripe ids",
    resub.status < 300 && rowResub?.plan === "professional"
    && rowResub?.subscription_status === "active" && rowResub?.stripe_subscription_id === "sub_resub_1");

  const resubGate = await call("GET", "/api/workspaces/ws1/audit-events?limit=1", { token: tokenA });
  ok("RE-SUBSCRIBE restores access end to end (gate 200)", resubGate.status === 200);

  // ── Cyber Essentials Readiness answers endpoint (Phase 1) ──
  // ws1 is professional at this point (re-subscribed above), so the plan gate
  // passes. Tests auth gate, PUT/GET round-trip, and server-side key validation.
  section("Cyber Essentials Readiness");
  const ceUnauth = await call("PUT", "/api/workspaces/ws1/cyber-essentials/answers", { body: { answers: [] } });
  ok("CE answers PUT unauthenticated → 401", ceUnauth.status === 401);

  const cePut = await call("PUT", "/api/workspaces/ws1/cyber-essentials/answers", { token: tokenA, body: { answers: [
    { control_key: "access_control", question_key: "mfa_enabled", answer: "yes" },
    { control_key: "malware_protection", question_key: "endpoint_av_enabled", answer: "no" },
    { control_key: "BOGUS_CONTROL", question_key: "nope", answer: "yes" },              // unknown control → ignored
    { control_key: "access_control", question_key: "mfa_enabled", answer: "banana" },   // invalid answer → ignored (keeps 'yes')
  ] } });
  ok("CE answers PUT (professional) → 200 with the 5-control question set",
    cePut.status === 200 && !!cePut.data?.question_set_version && Array.isArray(cePut.data?.questions) && cePut.data.questions.length === 5);
  ok("CE saved answers round-trip (mfa_enabled=yes, endpoint_av_enabled=no)",
    cePut.data?.answers?.access_control?.mfa_enabled === "yes" && cePut.data?.answers?.malware_protection?.endpoint_av_enabled === "no");
  ok("CE server-side validation drops unknown control keys (BOGUS not stored)", !cePut.data?.answers?.BOGUS_CONTROL);

  const ceGet = await call("GET", "/api/workspaces/ws1/cyber-essentials/answers", { token: tokenA });
  ok("CE answers GET persists across requests", ceGet.status === 200 && ceGet.data?.answers?.access_control?.mfa_enabled === "yes");

  // ── Cron orchestration (Sprint 9 extraction proof) ──
  // Drives the real scheduled() entry: the task registry in index.js must wire
  // every task into src/cron/scheduled.js. A mis-wired registry surfaces as a
  // "is not a function" cron_task error datapoint; a healthy run records one
  // datapoint per wrapped task (hourly incl. asset_alert_retry and brand follow-up; retention
  // joins only at 02:00 UTC — triggerScheduledScan is fire-and-forget outside
  // runCronTask by design).
  section("Cron orchestration");
  const datapoints = [];
  env.METRICS = { writeDataPoint: (d) => datapoints.push(d) };
  const pending = [];
  await worker.scheduled({ cron: "0 * * * *", scheduledTime: Date.now() },
    env, { waitUntil: (p) => pending.push(p) });
  await Promise.allSettled(pending);
  delete env.METRICS;
  const cronPoints = datapoints.filter((d) => d.blobs?.[0] === "cron_task");
  // Exact NAME-SET match, not just a count: a renamed/typo'd registry entry
  // with a compensating extra would pass a count but not this.
  // `dmarc_alerts_sweep` was REMOVED in PR-B3 and must not return. It graded
  // senders from cumulative lifetime counters that never decrease, so its
  // threshold latched true forever and re-alerted on a 24h cycle for the life of
  // the sender. Its canonical replacement is deliberately not a scheduled task:
  // sender evaluation runs in dmarc-ingest.js when new receiver evidence arrives,
  // so it cannot fire without new evidence and has nothing to schedule.
  const expectedTasks = ["scheduled_reports", "user_scheduled_reports", "hosted_dns_sweep",
    "alert_delivery_retry", "brand_takedown_followup", "brand_dns_enrichment",
    "deletion_purge", "lifecycle_email_retry", "asset_alert_retry", "domain_verify_retry",
    // PR-1 (22 Jul 2026): canonical interrupted-scan terminal recovery — the ONE
    // repair path for scans abandoned mid-flight (GET list/detail are read-only).
    "interrupted_scan_recovery"];
  // Time-gated tasks must mirror src/cron/scheduled.js exactly, or this exact
  // name-set match fails whenever CI happens to run in the relevant window
  // (retention 02:00 UTC; ops-health 08:00 UTC; weekly digest Mon 08:00 UTC).
  const nowD = new Date();
  if (nowD.getUTCHours() === 2) expectedTasks.push("report_retention");
  if (nowD.getUTCHours() === 3) expectedTasks.push("brand_passive_discovery");
  if (nowD.getUTCHours() === 4) expectedTasks.push("brand_http_enrichment");
  if (nowD.getUTCHours() === 8) expectedTasks.push("ops_health_heartbeat");
  if (nowD.getUTCDay() === 1 && nowD.getUTCHours() === 8) expectedTasks.push("weekly_digest");
  const seenTasks = cronPoints.map((d) => String(d.blobs?.[1] ?? "")).sort();
  if (process.env.PIPE_DEBUG) console.error("  [cron outcomes]", cronPoints.map((d) => `${d.blobs?.[1]}:${d.blobs?.[2]}`).join(" "));
  ok(`scheduled() runs exactly the registered task set (${expectedTasks.length} tasks, names matched)`,
    JSON.stringify(seenTasks) === JSON.stringify([...expectedTasks].sort()));
  ok("every task completed ok on the harness env (outcome blob = ok for all)",
    cronPoints.length > 0 && cronPoints.every((d) => d.blobs?.[2] === "ok"));
  ok("no task failed with a wiring error (no 'is not a function')",
    !cronPoints.some((d) => (d.blobs ?? []).some((b) => String(b).includes("is not a function"))));

  // ── Login rate limiting (10/15min per hashed IP) — LAST: it poisons login for this run ──
  section("Rate limiting");
  const sameIpDateNow = Date.now;
  let loginResponses = [];
  await withRateLimitClock(async () => {
    for (let i = 0; i < 12; i++) {
      loginResponses.push(await call("POST", "/api/auth/login", { body: { email: "nobody@example.com", password: "x" } }));
    }
  });
  const statuses = loginResponses.map((response) => response.status);
  const sameIpScopeId = await rateLimitScopeIdForTest("login", "unknown");
  const loginCounter = scopedActionCounter(db, {
    scope: "ip",
    scopeId: sameIpScopeId,
    action: "login",
    windowStart: rateLimitWindowStart(900),
  });
  ok("same-IP login cap request is rejected by login action (not global_write)", loginResponses[10]?.status === 429 && loginResponses[10]?.data?.action !== "global_write" && (loginCounter?.request_count ?? 0) >= 10);
  ok("once login cap is tripped it STAYS tripped in the window", loginResponses[11]?.status === 429 && loginResponses[11]?.data?.action !== "global_write");
  ok("the login limiter fails closed, never crashes (only 401/429, no 5xx)", statuses.every((s) => s === 401 || s === 429));
  ok("Date.now is restored after the same-IP login fixture", Date.now === sameIpDateNow);

  // ── Per-account brute-force ceiling (distributed: many IPs, one account) ──
  // Each attempt from a UNIQUE source IP, so the per-IP limit (10) never trips —
  // only the per-account limit (20/15min) can stop it. Proves a distributed
  // attack against one account is capped regardless of source-IP spread.
  const accountEmail = "distributed-bf@example.com";
  const accountScopeId = await rateLimitScopeIdForTest("login_acct", accountEmail);
  const accountWindowStart = rateLimitWindowStart(900);
  const accountCheckResults = ({ responses, counter }) => {
    const responseStatuses = responses.map((response) => response.status);
    const correctlyScopedCounter = Boolean(
      counter &&
      counter.scope === "user" &&
      counter.scope_id === accountScopeId &&
      counter.action === "login_account" &&
      counter.window_start === accountWindowStart &&
      counter.window_seconds === 900 &&
      counter.request_count >= 20
    );
    return [
      {
        name: "distributed brute-force 21st response is parsed 429 from login_account, not global_write",
        pass: responses[20]?.status === 429 &&
          responses[20]?.data?.action !== "global_write" &&
          correctlyScopedCounter,
      },
      {
        name: "per-account limit lets the first 20 through (401), no single IP over its own limit",
        pass: responseStatuses.slice(0, 20).every((status) => status === 401),
      },
      {
        name: "per-account limit keeps the parsed 22nd response at 429, not global_write",
        pass: responses[21]?.status === 429 && responses[21]?.data?.action !== "global_write",
      },
      {
        name: "per-account limiter fails closed too (only 401/429, no 5xx)",
        pass: responseStatuses.every((status) => status === 401 || status === 429),
      },
    ];
  };
  const runAccountFixture = async (fixtureDb, fixtureEnv, { globalWriteIndexes = [] } = {}) => {
    const accountIps = Array.from({ length: 22 }, (_, index) => `203.0.113.${index + 1}`);
    const globalWindowStart = rateLimitWindowStart(300);
    for (const index of globalWriteIndexes) {
      const ip = accountIps[index];
      const globalScopeId = await rateLimitScopeIdForTest("global_write", ip);
      fixtureDb.prepare(
        `INSERT INTO api_rate_limits
           (id, scope, scope_id, action, window_start, window_seconds, request_count)
         VALUES (?, 'ip', ?, 'global_write', ?, 300, 60)`,
      ).run(`mutant_global_write_${index}`, globalScopeId, globalWindowStart);
    }
    const responses = [];
    for (let index = 0; index < accountIps.length; index++) {
      responses.push(await call("POST", "/api/auth/login", {
        body: { email: accountEmail, password: "x" },
        headers: { "CF-Connecting-IP": accountIps[index] },
        requestEnv: fixtureEnv,
      }));
    }
    return {
      responses,
      counter: scopedActionCounter(fixtureDb, {
        scope: "user",
        scopeId: accountScopeId,
        action: "login_account",
        windowStart: accountWindowStart,
      }),
    };
  };

  const accountDateNow = Date.now;
  const accountFixture = await withRateLimitClock(() => runAccountFixture(db, env));
  for (const check of accountCheckResults(accountFixture)) ok(check.name, check.pass);
  ok("Date.now is restored after the distinct-IP account fixture", Date.now === accountDateNow);

  // Controlled right-reason proof: pre-cap only requests 21 and 22 at the
  // unrelated global_write layer. The same account predicates must turn red
  // because call() parsed the response body; raw Response objects would make
  // `data?.action` undefined and let this mutant escape.
  const globalMutantDb = buildDb();
  const globalMutantEnv = makeEnv(globalMutantDb);
  const globalMutantFixture = await withRateLimitClock(
    () => runAccountFixture(globalMutantDb, globalMutantEnv, { globalWriteIndexes: [20, 21] }),
  );
  const globalMutantFailures = accountCheckResults(globalMutantFixture)
    .filter((check) => !check.pass)
    .map((check) => check.name);
  if (PIPELINE_HARNESS_MUTANT !== "omit_global_write_control_assertion") {
    ok("controlled global_write bite makes exactly the 21st/22nd per-account assertions red", JSON.stringify(globalMutantFailures) === JSON.stringify([
      "distributed brute-force 21st response is parsed 429 from login_account, not global_write",
      "per-account limit keeps the parsed 22nd response at 429, not global_write",
    ]) && globalMutantFixture.responses[20]?.data?.action === "global_write" &&
      globalMutantFixture.responses[21]?.data?.action === "global_write");
  }

  enforceExpectedAssertionCount();
  for (const line of results) if (line.startsWith("FAIL")) console.error(line);
  console.log("");
  for (const [name, s] of sectionCounts) console.log(`  ${s.failed === 0 ? "✓" : "✗"} ${name}: ${s.passed}/${s.passed + s.failed}`);
  console.log(`\nPipeline tests: ${passed}/${passed + failed} passed`);
  if (failed > 0) { console.error("pipeline validation FAILED"); process.exit(1); }
  console.log("pipeline validation passed");
}

main().catch((e) => { console.error("pipeline runner crashed:", e); process.exit(1); });
