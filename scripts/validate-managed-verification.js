#!/usr/bin/env node
//
// Managed-verification profile — hard-limit + lifecycle proof (Tier-1 Commit 4).
//
// Runs the ACTUAL verifyManagedCaseById against a stateful D1 mock, an R2 mock, and a
// fetch that throws the real "Too many subrequests" on call 51. Proves: one-host cost
// stays far below 50, only the affected host is resolved/probed, no CT/DKIM/CVE/KEV/
// cloud calls, the lifecycle (present→open, fixed→resolve, incomplete→defer, returns→
// reopen once), foreign tenant fails closed, arbitrary host injection is impossible,
// and duplicate concurrent requests are idempotent. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { verifyManagedCaseById } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asm-cases.js")).href);
const { classifyRequest } = await import(pathToFileURL(path.join(root, "scripts", "validate-scan-subrequest-budget.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);
const realFetch = globalThis.fetch;

// ── Stateful D1 mock (only the queries verifyManagedCaseById touches) ─────────
function makeDb({ cases, links }) {
  const events = [];
  const notifications = [];
  const q = (rawSql) => ({
    _a: [],
    bind(...a) { this._a = a; return this; },
    async first() {
      const sql = rawSql.replace(/\s+/g, " ").trim();
      if (/FROM managed_cases WHERE id = \? AND workspace_id = \?/.test(sql)) {
        const [id, ws] = this._a; const c = cases.get(id);
        return c && c.workspace_id === ws ? { ...c } : null;
      }
      if (/FROM domains d JOIN workspace_domains/.test(sql)) {
        const [ws, domain] = this._a;
        return links.has(`${ws}|${domain}`) ? { id: `dom_${domain}` } : null;
      }
      return null;
    },
    async run() {
      const s = rawSql.replace(/\s+/g, " ").trim();
      if (/^UPDATE managed_cases SET status/.test(s)) {
        if (/AND status = \?$/.test(s)) {                       // compare-and-set claim
          const to = this._a[0]; const [id, ws, from] = this._a.slice(-3);
          const c = cases.get(id);
          if (c && c.workspace_id === ws && c.status === from) {
            c.status = to;
            if (/reopened_count/.test(s)) c.reopened_count = (c.reopened_count || 0) + 1;
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        }
        const to = this._a[0]; const [id, ws] = this._a.slice(-2);   // updateCaseStatus
        const c = cases.get(id); if (c && c.workspace_id === ws) c.status = to;
        return { meta: { changes: 1 } };
      }
      if (/INSERT INTO managed_case_events/.test(s)) { events.push(this._a); return { meta: { changes: 1 } }; }
      if (/INSERT INTO notification_events/.test(s)) { notifications.push({ type: this._a[3] }); return { meta: { changes: 1 } }; }
      return { meta: { changes: 1 } };
    },
    async all() { return { results: [] }; },
  });
  return { prepare: q, batch: async () => [], _events: events, _notifications: notifications };
}
const r2 = { put: async () => ({}), get: async () => null, delete: async () => ({}) };

function mkCase(status) {
  return {
    id: "case_1", workspace_id: "ws_1", case_type: "asm_exposure", domain: "example.com",
    asset_ref: "admin.example.com", finding_id: "asset_exposure_admin_interface", status,
    severity: "medium", reopened_count: 0,
    evidence_json: JSON.stringify({ finding: { id: "asset_exposure_admin_interface", module: "asset_exposure", title: "Admin interface" } }),
  };
}

// fetch that resolves admin.example.com (A public), returns a scripted GET, throws past 50.
function installFetch({ getStatus = 200, getTitle = "Admin Login", throwAt = 51, budgetThrowsOnGet = false }) {
  const calls = [];
  globalThis.fetch = async (url) => {
    const s = String(url); const n = calls.length + 1; const cat = classifyRequest(s);
    if (n >= throwAt) { const e = new Error("Too many subrequests by single Worker invocation."); throw e; }
    calls.push({ n, url: s, cat });
    if (cat === "doh") {
      const u = new URL(s); const name = u.searchParams.get("name"); const type = u.searchParams.get("type");
      if (type === "A" && name === "admin.example.com") return new Response(JSON.stringify({ Answer: [{ data: "93.184.216.34" }] }), { status: 200 });
      return new Response(JSON.stringify({ Answer: [] }), { status: 200 });
    }
    if (cat === "exposure") {
      if (budgetThrowsOnGet) { throw new Error("Too many subrequests by single Worker invocation."); }
      return new Response(`<title>${getTitle}</title>`, { status: getStatus, headers: { "content-type": "text/html" } });
    }
    return new Response("{}", { status: 200 });
  };
  return calls;
}

async function scenario(status, fetchOpts, { workspaceId = "ws_1", caseId = "case_1" } = {}) {
  const cases = new Map([["case_1", mkCase(status)]]);
  const links = new Set(["ws_1|example.com"]);
  const db = makeDb({ cases, links });
  const env = { cybermeters_db: db, cybermeters_reports: r2 };
  const calls = installFetch(fetchOpts);
  const result = await verifyManagedCaseById(env, { workspaceId, caseId });
  globalThis.fetch = realFetch;
  return { result, calls, caseAfter: cases.get("case_1"), db };
}

// ── 1. still present → verification_failed (stays open), no exception ─────────
{
  const { result, calls, caseAfter } = await scenario("verification_requested", { getStatus: 200, getTitle: "Admin Login" });
  console.log(`still_present: calls=${calls.length} decision=${result.decision} status=${caseAfter.status} cats=${JSON.stringify([...new Set(calls.map(c=>c.cat))])}`);
  ok("still_present: cost far below 50 (~3-5 calls)", calls.length <= 5, `calls ${calls.length}`);
  ok("still_present: no runtime exception", result.ok === true);
  eq("still_present: decision", result.decision, "still_present");
  ok("still_present: case stays open (verification_failed, not resolved)", caseAfter.status === "verification_failed");
  ok("still_present: only affected host resolved/probed", calls.every((c) => c.url.includes("admin.example.com")));
  ok("still_present: no CT/DKIM/CVE/KEV/cloud calls", calls.every((c) => c.cat === "doh" || c.cat === "exposure"));
}

// ── 2. conclusively fixed → system resolves ──────────────────────────────────
{
  const { result, caseAfter } = await scenario("verification_requested", { getStatus: 200, getTitle: "Welcome" }); // no admin title
  eq("fixed: decision", result.decision, "fixed");
  ok("fixed: system resolved the case", caseAfter.status === "resolved");
}

// ── 3. incomplete evidence (budget on the GET) → deferred + RETRYABLE ─────────
{
  const { result, caseAfter } = await scenario("verification_requested", { budgetThrowsOnGet: true });
  eq("incomplete: decision deferred", result.decision, "deferred");
  eq("incomplete: completeness", result.completeness, "incomplete");
  ok("incomplete: NOT resolved", caseAfter.status !== "resolved");
  ok("incomplete: claim released → back to verification_requested (retryable, not locked in verifying)",
     caseAfter.status === "verification_requested");
}

// ── 3b. deferred then retry: second verification actually probes again + resolves ─
{
  const cases = new Map([["case_1", mkCase("verification_requested")]]);
  const links = new Set(["ws_1|example.com"]);
  const db = makeDb({ cases, links });
  const env = { cybermeters_db: db, cybermeters_reports: r2 };
  // 1st: budget on GET → deferred → released to verification_requested
  installFetch({ budgetThrowsOnGet: true });
  const first = await verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" });
  const afterFirst = cases.get("case_1").status;
  // 2nd: now succeeds (conclusively fixed)
  const calls2 = installFetch({ getStatus: 200, getTitle: "Welcome" });
  const second = await verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" });
  globalThis.fetch = realFetch;
  eq("retry: first deferred", first.decision, "deferred");
  eq("retry: released to verification_requested", afterFirst, "verification_requested");
  ok("retry: second run actually probed again", calls2.length >= 3);
  eq("retry: second run resolves normally", second.decision, "fixed");
  ok("retry: case resolved after retry", cases.get("case_1").status === "resolved");
}

// ── 4. returned finding → reopen exactly once (idempotent on repeat) ──────────
{
  const cases = new Map([["case_1", mkCase("resolved")]]);
  const links = new Set(["ws_1|example.com"]);
  const env = { cybermeters_db: makeDb({ cases, links }), cybermeters_reports: r2 };
  installFetch({ getStatus: 200, getTitle: "Admin Login" });
  const r1 = await verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" });
  const afterFirst = { ...cases.get("case_1") };
  // second run (case now remediation_in_progress) must not double-reopen
  installFetch({ getStatus: 200, getTitle: "Admin Login" });
  const r2res = await verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" });
  globalThis.fetch = realFetch;
  eq("reopen: first run decision still_present", r1.decision, "still_present");
  ok("reopen: reopened_count incremented exactly once", afterFirst.reopened_count === 1);
  ok("reopen: second run does not re-reopen (idempotent; state not resolved/reopened again)", cases.get("case_1").reopened_count === 1);
}

// ── 5. foreign tenant / case → fail closed (not found, non-enumerating) ───────
{
  const { result } = await scenario("verification_requested", {}, { workspaceId: "ws_OTHER" });
  eq("foreign workspace → not_found (fail closed)", result.code, "not_found");
  ok("foreign workspace → no verification ran", result.ok === false);
}

// ── 6. arbitrary host injection impossible (scope always from stored case) ────
{
  // verifyManagedCaseById takes NO host param; even if a caller tried, scope is the case's
  // asset_ref. Confirm the probed host is exactly the stored asset_ref.
  const { calls } = await scenario("verification_requested", { getStatus: 200, getTitle: "Welcome" });
  ok("host injection impossible: every call targets the stored asset_ref only",
     calls.length > 0 && calls.every((c) => c.url.includes("admin.example.com")) && !calls.some((c) => /evil|attacker|169\.254|127\.0\.0\.1/.test(c.url)));
}

// ── 7a. two SIMULTANEOUS verification_requested calls → exactly ONE probe ──────
{
  const cases = new Map([["case_1", mkCase("verification_requested")]]);
  const links = new Set(["ws_1|example.com"]);
  const db = makeDb({ cases, links });
  const env = { cybermeters_db: db, cybermeters_reports: r2 };
  const calls = installFetch({ getStatus: 200, getTitle: "Admin Login" });
  const [a, b] = await Promise.all([
    verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" }),
    verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" }),
  ]);
  globalThis.fetch = realFetch;
  const probes = calls.filter((c) => c.cat === "exposure").length;
  const inProgress = [a, b].filter((r) => r.code === "in_progress" && r.idempotent).length;
  ok("concurrent verification_requested: exactly ONE probe (CAS deduped)", probes === 1, `probes ${probes}`);
  eq("concurrent verification_requested: one call reports in_progress", inProgress, 1);
  const failNotifs = db._notifications.filter((n) => n.type === "managed_case_verification_failed").length;
  ok("concurrent verification: no duplicate verification_failed notification", failNotifs <= 1, `notifs ${failNotifs}`);
}

// ── 7b. two SIMULTANEOUS reappearance checks → reopen ONCE + one notification ──
{
  const cases = new Map([["case_1", mkCase("resolved")]]);
  const links = new Set(["ws_1|example.com"]);
  const db = makeDb({ cases, links });
  const env = { cybermeters_db: db, cybermeters_reports: r2 };
  installFetch({ getStatus: 200, getTitle: "Admin Login" });
  await Promise.all([
    verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" }),
    verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" }),
  ]);
  globalThis.fetch = realFetch;
  eq("concurrent reappearance: reopened exactly once", cases.get("case_1").reopened_count, 1);
  const reopenNotifs = db._notifications.filter((n) => n.type === "managed_case_reopened").length;
  eq("concurrent reappearance: exactly one reopen notification", reopenNotifs, 1);
}

console.log(`\nmanaged-verification: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
