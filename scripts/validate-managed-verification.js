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

// PR-B1: ASM alerts now route through emitCaseLifecycleAlert, which persists an
// append-only managed_case_events row (action='monitoring_changed') and then emits
// through the canonical pipeline. This suite's D1 stub models managed_cases and
// captures event INSERTs, but its all() returns [] — it deliberately does not model
// occurrence lookup, activation watermarks or the delivery ledger, because its
// subject is probe verification, not alerting.
//
// So the no-duplicate invariant is asserted where this stub genuinely knows the
// answer: exactly one PERSISTED monitoring_changed event per real transition. That
// is the same guarantee the old notification count stood for — the event IS the
// occurrence, and one occurrence is one alert — and it is now the honest layer to
// assert it at. End-to-end delivery is proven against a real database in
// validate-alert-b1-canonical-cases.js.
const monitoringEvents = (db, recurrence) => db._events.filter((args) => {
  const action = args[7], detail = args[8];
  if (action !== "monitoring_changed") return false;
  try { return JSON.parse(detail || "{}").to_recurrence_type === recurrence; } catch { return false; }
}).length;
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
  const failEvents = monitoringEvents(db, "case_verification_failed");
  ok("concurrent verification: no duplicate verification_failed occurrence", failEvents <= 1, `events ${failEvents}`);
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
  const reopenEvents = monitoringEvents(db, "case_reopened");
  eq("concurrent reappearance: exactly ONE reopen occurrence (one event = one alert)", reopenEvents, 1);
}

// ── 8. Dispatch coverage is an explicit, honest allowlist ────────────────────
{
  const { ASM_VERIFICATION_SUPPORT, isSupportedVerification, supportedVerificationTypes,
          runManagedVerificationProbe, verificationSupportFor } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "managed-verification.js")).href);

  const supported = supportedVerificationTypes();
  for (const id of ["asset_exposure_admin_interface", "asset_exposure_sensitive_tool", "asset_exposure_dev_env",
                    "admin_surface_critical", "admin_surface_high", "admin_surface_medium",
                    "subdomain_takeover", "dse_missing_caa", "dse_caa_no_issuers",
                    "dse_hsts_short_maxage", "dse_hsts_not_preload_eligible",
                    "dse_cookie_no_secure", "dse_cookie_no_httponly", "dse_cookie_no_samesite"]) {
    ok(`dispatch: ${id} is verifiable`, supported.includes(id) && isSupportedVerification({ id }));
  }
  // Types that must NOT claim verification support. Each fails closed with a reason.
  for (const id of ["cloud_storage_public_listing", "cloud_storage_takeover_risk", "cloud_storage_exposure_observed",
                    "asset_exposure_interface_observed", "asset_provider_infrastructure_observed"]) {
    ok(`dispatch: ${id} is NOT claimed as verifiable`, !supported.includes(id) && !isSupportedVerification({ id }));
    const probe = await runManagedVerificationProbe({ id }, "admin.example.com");
    ok(`dispatch: ${id} fails closed (deferred, never fixed)`,
       probe.decision === "deferred" && probe.completeness === "unsupported_finding_type");
    ok(`dispatch: ${id} states WHY it is unsupported`, typeof probe.support_reason === "string" && probe.support_reason.length > 10);
  }
  // cloud_storage_* stays a deliberate scope boundary, not an oversight.
  eq("matrix: cloud_storage_public_listing is intentionally unsupported", ASM_VERIFICATION_SUPPORT.cloud_storage_public_listing.support, "unsupported");
  eq("matrix: cloud_storage_takeover_risk is intentionally unsupported", ASM_VERIFICATION_SUPPORT.cloud_storage_takeover_risk.support, "unsupported");
  eq("matrix: observed findings are verification-not-applicable", ASM_VERIFICATION_SUPPORT.asset_exposure_interface_observed.support, "not_applicable");

  // The matrix and the dispatch must never disagree — the matrix is what the product
  // claims, the dispatch is what it can actually do.
  const automated = Object.entries(ASM_VERIFICATION_SUPPORT).filter(([, v]) => v.support === "automated").map(([k]) => k).sort();
  eq("matrix: automated entries exactly match the dispatch", JSON.stringify(automated), JSON.stringify(supported));
  ok("matrix: every non-automated entry gives a reason",
     Object.values(ASM_VERIFICATION_SUPPORT).filter((v) => v.support !== "automated").every((v) => typeof v.reason === "string" && v.reason.length > 10));
  ok("matrix: every automated entry names a technique",
     Object.values(ASM_VERIFICATION_SUPPORT).filter((v) => v.support === "automated").every((v) => typeof v.technique === "string"));
  eq("matrix: an unknown finding type is unsupported by default", verificationSupportFor("totally_unknown").support, "unsupported");

  // A client-supplied value can never select a verifier.
  const injected = await runManagedVerificationProbe({ id: "constructor" }, "admin.example.com");
  eq("dispatch: prototype key cannot select a verifier", injected.decision, "deferred");
}

// ── 9. Multi-host findings: "fixed" requires EVERY affected host observed clear ─
{
  const { runManagedVerificationProbe, MAX_VERIFICATION_HOSTS } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "managed-verification.js")).href);

  // fetch resolving any *.example.com, with a per-host page title.
  const installMulti = (titles, { budgetHosts = new Set() } = {}) => {
    const calls = [];
    globalThis.fetch = async (url) => {
      const s = String(url); const cat = classifyRequest(s);
      calls.push({ url: s, cat });
      if (cat === "doh") {
        const name = new URL(s).searchParams.get("name");
        const type = new URL(s).searchParams.get("type");
        return new Response(JSON.stringify({ Answer: type === "A" && /\.example\.com$/.test(name || "") ? [{ data: "93.184.216.34" }] : [] }), { status: 200 });
      }
      if (cat === "exposure") {
        const host = new URL(s).hostname;
        if (budgetHosts.has(host)) throw new Error("Too many subrequests by single Worker invocation.");
        return new Response(`<title>${titles[host] ?? "Welcome"}</title>`, { status: 200, headers: { "content-type": "text/html" } });
      }
      return new Response("{}", { status: 200 });
    };
    return calls;
  };
  const finding = { id: "asset_exposure_admin_interface" };
  const hosts = ["admin.example.com", "portal.example.com"];

  installMulti({ "admin.example.com": "Welcome", "portal.example.com": "Welcome" });
  const allClear = await runManagedVerificationProbe(finding, hosts);
  eq("multi-host: every host clear → fixed", allClear.decision, "fixed");
  eq("multi-host: fixed reports both hosts checked", allClear.evidence.hosts_checked, 2);

  installMulti({ "admin.example.com": "Welcome", "portal.example.com": "Admin Login" });
  const oneLive = await runManagedVerificationProbe(finding, hosts);
  eq("multi-host: ANY host still exposed → still_present", oneLive.decision, "still_present");

  // One host inconclusive and none present: absence on a subset is NOT remediation.
  installMulti({ "admin.example.com": "Welcome", "portal.example.com": "Welcome" }, { budgetHosts: new Set(["portal.example.com"]) });
  const partial = await runManagedVerificationProbe(finding, hosts);
  eq("multi-host: inconclusive host blocks 'fixed' → deferred", partial.decision, "deferred");

  // Over the bound → defer rather than conclude from a subset. No probing at all.
  const many = Array.from({ length: MAX_VERIFICATION_HOSTS + 1 }, (_, i) => `h${i}.example.com`);
  const capCalls = installMulti({});
  const capped = await runManagedVerificationProbe(finding, many);
  eq("multi-host: over the host cap → deferred", capped.decision, "deferred");
  eq("multi-host: over the host cap → completeness", capped.completeness, "too_many_affected_hosts");
  eq("multi-host: over the host cap → no probing at all", capCalls.length, 0);
  globalThis.fetch = realFetch;
}

// ── 10. Stored affected_hosts are re-validated: out-of-scope hosts never probed ─
{
  const cases = new Map([["case_1", {
    ...mkCase("verification_requested"),
    // A stored finding carrying an out-of-scope host (and a bare non-hostname).
    evidence_json: JSON.stringify({ finding: {
      id: "asset_exposure_admin_interface", module: "asset_exposure", title: "Admin interface",
      affected_hosts: ["admin.example.com", "attacker.evil.com", "169.254.169.254", "not a hostname"],
    } }),
  }]]);
  const links = new Set(["ws_1|example.com"]);
  const env = { cybermeters_db: makeDb({ cases, links }), cybermeters_reports: r2 };
  const calls = installFetch({ getStatus: 200, getTitle: "Welcome" });
  const res = await verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" });
  globalThis.fetch = realFetch;
  eq("stored hosts: in-scope host still verifies", res.decision, "fixed");
  ok("stored hosts: out-of-scope/metadata hosts are never probed",
     calls.length > 0 && !calls.some((c) => /evil|attacker|169\.254|127\.0\.0\.1/.test(c.url)));
  ok("stored hosts: only the in-scope affected host is probed",
     calls.every((c) => c.url.includes("admin.example.com")));
}

// ── 11. Legacy prose asset_ref defers instead of probing the wrong host ────────
{
  // Cases created before affected_hosts existed stored the finding DESCRIPTION in
  // asset_ref. That must never be coerced into a probe target.
  const cases = new Map([["case_1", {
    ...mkCase("verification_requested"),
    asset_ref: "1 administrative or login interface is publicly accessible: admin.example.com. Restrict access.",
    evidence_json: JSON.stringify({ finding: { id: "asset_exposure_admin_interface", module: "asset_exposure", title: "Admin interface" } }),
  }]]);
  const links = new Set(["ws_1|example.com"]);
  const db = makeDb({ cases, links });
  const env = { cybermeters_db: db, cybermeters_reports: r2 };
  const calls = installFetch({ getStatus: 200, getTitle: "Welcome" });
  const res = await verifyManagedCaseById(env, { workspaceId: "ws_1", caseId: "case_1" });
  globalThis.fetch = realFetch;
  eq("legacy prose asset_ref → host_scope_mismatch", res.code, "host_scope_mismatch");
  ok("legacy prose asset_ref → nothing probed", calls.length === 0);
  ok("legacy prose asset_ref → case NOT resolved", cases.get("case_1").status !== "resolved");
  // _events rows are raw bind arrays; the action + reason travel in them.
  ok("legacy prose asset_ref → deferral is audited",
     db._events.some((binds) => binds.includes("verification_deferred")
       && binds.some((b) => typeof b === "string" && b.includes("no_affected_host_in_scope"))));
}

// ── 12. subdomain_takeover: risks=[] is NOT remediation ──────────────────────
// The whole point of this section: runTakeoverModule returns risks=[] both when a
// CNAME is genuinely no longer dangling AND when we simply could not look. Only the
// first may resolve a case.
{
  const { runManagedVerificationProbe } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "managed-verification.js")).href);
  const finding = { id: "subdomain_takeover" };
  const HOST = "old.example.com";

  // cname → answers; body → response text. dnsQueryImpl is injected so DNS is scripted.
  const run = ({ cname = null, dnsThrows = false, body = null, bodyRefused = false, bodyThrows = false }) => {
    const dnsQueryImpl = async () => {
      if (dnsThrows) throw new Error("DoH 502 for CNAME");
      return { Answer: cname ? [{ data: cname }] : [] };
    };
    globalThis.fetch = async (url) => {
      const s = String(url);
      if (classifyRequest(s) === "doh") {
        // The reserved probe resolves the target itself. Pointing it at a reserved IP
        // makes the real SSRF guard refuse — that is what "refused" must look like.
        const type = new URL(s).searchParams.get("type");
        if (type === "A") {
          return new Response(JSON.stringify({ Answer: [{ data: bodyRefused ? "127.0.0.1" : "93.184.216.34" }] }), { status: 200 });
        }
        return new Response(JSON.stringify({ Answer: [] }), { status: 200 });
      }
      if (bodyThrows) throw new Error("network down");
      return new Response(body ?? "", { status: 200 });
    };
    return runManagedVerificationProbe(finding, HOST, { dnsQueryImpl });
  };

  const lookupFailed = await run({ dnsThrows: true });
  eq("takeover: CNAME lookup failure → deferred (never fixed)", lookupFailed.decision, "deferred");
  eq("takeover: CNAME lookup failure reason", lookupFailed.reason, "dns_indeterminate");

  const noCname = await run({ cname: null });
  eq("takeover: no CNAME → fixed (nothing dangles)", noCname.decision, "fixed");

  const harmlessCname = await run({ cname: "myapp.herokudns-not-a-fingerprint.example" });
  eq("takeover: CNAME to a non-vulnerable target → fixed", harmlessCname.decision, "fixed");

  // THE TRAP: the CNAME still points at a takeover-prone provider, but the body probe
  // was refused. Pre-fix this fell through to risks=[] and looked exactly like a fix.
  const refused = await run({ cname: "victim.github.io", bodyRefused: true });
  eq("takeover: vulnerable CNAME + refused probe → deferred (NOT fixed)", refused.decision, "deferred");
  eq("takeover: refused probe reason", refused.reason, "probe_refused");

  const fetchFailed = await run({ cname: "victim.github.io", bodyThrows: true });
  eq("takeover: vulnerable CNAME + failed fetch → deferred (NOT fixed)", fetchFailed.decision, "deferred");
  eq("takeover: failed fetch reason", fetchFailed.reason, "fetch_failed");

  const stillPresent = await run({ cname: "victim.github.io", body: "There isn't a GitHub Pages site here." });
  eq("takeover: vulnerable CNAME + takeover fingerprint → still_present", stillPresent.decision, "still_present");

  const claimed = await run({ cname: "victim.github.io", body: "<h1>Our real site</h1>" });
  eq("takeover: vulnerable CNAME + service claimed → fixed (conclusive)", claimed.decision, "fixed");
  globalThis.fetch = realFetch;
}

// ── 13. dse_* CAA: a DNS failure is not a fix ────────────────────────────────
{
  const { runManagedVerificationProbe } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "managed-verification.js")).href);
  const HOST = "example.com";
  const run = (id, { records = [], throws = false }) => {
    const dnsQueryImpl = async () => {
      if (throws) throw new Error("DoH 502 for CAA");
      return { Answer: records.map((data) => ({ data })) };
    };
    return runManagedVerificationProbe({ id }, HOST, { dnsQueryImpl });
  };

  eq("dse_missing_caa: CAA lookup failure → deferred", (await run("dse_missing_caa", { throws: true })).decision, "deferred");
  eq("dse_missing_caa: still no CAA record → still_present", (await run("dse_missing_caa", { records: [] })).decision, "still_present");
  eq("dse_missing_caa: CAA now published → fixed", (await run("dse_missing_caa", { records: ['0 issue "letsencrypt.org"'] })).decision, "fixed");

  eq("dse_caa_no_issuers: records but no issuers → still_present",
     (await run("dse_caa_no_issuers", { records: ['0 iodef "mailto:security@example.com"'] })).decision, "still_present");
  eq("dse_caa_no_issuers: issuer added → fixed",
     (await run("dse_caa_no_issuers", { records: ['0 issue "letsencrypt.org"'] })).decision, "fixed");
  eq("dse_caa_no_issuers: no CAA at all → fixed (this finding no longer applies)",
     (await run("dse_caa_no_issuers", { records: [] })).decision, "fixed");
}

// ── 14. dse_* headers: an unread response is not a fix ───────────────────────
{
  const { runManagedVerificationProbe } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "managed-verification.js")).href);
  const HOST = "example.com";
  const run = (id, { headers = {}, refused = false, throws = false }) => {
    globalThis.fetch = async (url) => {
      const s = String(url);
      if (classifyRequest(s) === "doh") {
        const name = new URL(s).searchParams.get("name");
        const type = new URL(s).searchParams.get("type");
        return new Response(JSON.stringify({ Answer: type === "A" && name === HOST ? [{ data: "93.184.216.34" }] : [] }), { status: 200 });
      }
      if (refused) return new Response("blocked", { status: 403 }); // reachable but not our target shape
      if (throws) throw new Error("network down");
      return new Response("<html></html>", { status: 200, headers });
    };
    return runManagedVerificationProbe({ id }, HOST);
  };

  eq("dse_hsts_short_maxage: unreachable host → deferred",
     (await run("dse_hsts_short_maxage", { throws: true })).decision, "deferred");
  eq("dse_hsts_short_maxage: max-age still short → still_present",
     (await run("dse_hsts_short_maxage", { headers: { "strict-transport-security": "max-age=86400" } })).decision, "still_present");
  eq("dse_hsts_short_maxage: max-age raised to a year → fixed",
     (await run("dse_hsts_short_maxage", { headers: { "strict-transport-security": "max-age=31536000; includeSubDomains; preload" } })).decision, "fixed");
  eq("dse_hsts_not_preload_eligible: missing directives → still_present",
     (await run("dse_hsts_not_preload_eligible", { headers: { "strict-transport-security": "max-age=31536000" } })).decision, "still_present");
  eq("dse_hsts_not_preload_eligible: fully preload-eligible → fixed",
     (await run("dse_hsts_not_preload_eligible", { headers: { "strict-transport-security": "max-age=31536000; includeSubDomains; preload" } })).decision, "fixed");

  // THE COOKIE TRAP: a response that sets no cookies cannot distinguish "flags fixed"
  // from "this request just set no cookies". It must never read as remediation.
  eq("dse_cookie_no_secure: no cookies observed → deferred (NOT fixed)",
     (await run("dse_cookie_no_secure", { headers: {} })).decision, "deferred");
  eq("dse_cookie_no_secure: no-cookies deferral reason",
     (await run("dse_cookie_no_secure", { headers: {} })).reason, "no_cookies_observed");
  eq("dse_cookie_no_secure: insecure cookie still set → still_present",
     (await run("dse_cookie_no_secure", { headers: { "set-cookie": "sid=1; HttpOnly; SameSite=Lax" } })).decision, "still_present");
  eq("dse_cookie_no_secure: Secure flag added → fixed",
     (await run("dse_cookie_no_secure", { headers: { "set-cookie": "sid=1; Secure; HttpOnly; SameSite=Lax" } })).decision, "fixed");
  eq("dse_cookie_no_httponly: HttpOnly missing → still_present",
     (await run("dse_cookie_no_httponly", { headers: { "set-cookie": "sid=1; Secure; SameSite=Lax" } })).decision, "still_present");
  eq("dse_cookie_no_samesite: SameSite missing → still_present",
     (await run("dse_cookie_no_samesite", { headers: { "set-cookie": "sid=1; Secure; HttpOnly" } })).decision, "still_present");
  eq("dse_cookie_no_samesite: SameSite set → fixed",
     (await run("dse_cookie_no_samesite", { headers: { "set-cookie": "sid=1; Secure; HttpOnly; SameSite=Strict" } })).decision, "fixed");
  globalThis.fetch = realFetch;
}

console.log(`\nmanaged-verification: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
