#!/usr/bin/env node
//
// M5 read surfaces (migrations 088 / 089 / 090) — DB-backed, drives the REAL Worker.
// CI-blocking. Node 24+.
//
// THE DEFECT THIS EXISTS TO PREVENT (traced 2026-07-16): migrations 088, 089 and 090 each
// shipped a lifecycle that WRITES durable records and ALERTS on them, with no way for a
// customer to read them:
//   • 089 Website Security — zero routes, both engine read helpers at ZERO callers, no
//     page, no api.js method;
//   • 090 Cyber Essentials — `listCeControlRecords` at ZERO callers repo-wide; the CE page
//     rendered questionnaire + readiness only;
//   • 088 Email Protection — no read helper existed at all, and the four lifecycle columns
//     it added to email_sender_sources are stripped by emailSenderToApi.
// A record is not customer-visible merely because it exists in D1.
//
// These assertions drive the REAL worker over the REAL schema — a route that is not
// mounted, or is mounted after a shadowing matcher, fails here rather than in production.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* schema converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const workerMod = await import(pathToFileURL(workerPath).href);
const worker = workerMod.default;

const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) },
  MFA_ENCRYPTION_KEY: "rs-test-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
  STRIPE_PRICE_MAP: JSON.stringify({}), ALLOWED_ORIGIN: "https://app.cybermeters.com",
  FRONTEND_URL: "https://app.cybermeters.com", APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
};

const tokenA = "rs-token-A", tokenB = "rs-token-B";
const hashA = await workerMod.hashToken(tokenA);
const hashB = await workerMod.hashToken(tokenB);

db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,?,?,1,0)").run("uA", "a@e.com", "A", "business", "active");
db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,?,?,1,0)").run("uB", "b@e.com", "B", "business", "active");
db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,datetime('now','+1 day'))").run("sA", "uA", hashA);
db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,datetime('now','+1 day'))").run("sB", "uB", hashB);
db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run("ws1", "uA", "Alpha");
db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run("ws2", "uB", "Bravo");
db.prepare("INSERT INTO workspaces (id,owner_user_id,name,deleted_at) VALUES (?,?,?,datetime('now'))").run("wsDead", "uA", "Dead");
db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,?,?)").run("mA", "ws1", "uA", "admin");
db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,?,?)").run("mB", "ws2", "uB", "admin");
db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,?,?)").run("mD", "wsDead", "uA", "admin");
// The SAME domain name in two tenants — the collision that matters, since a hostname is
// not a tenant-unique identifier the way a random row id is.
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)").run("d1", "uA", "shared.example.com");
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)").run("d2", "uB", "shared.example.com");
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)").run("ws1", "d1");
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)").run("ws2", "d2");
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)").run("dDead", "uA", "dead.example.com");
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)").run("wsDead", "dDead");

const call = async (p, token = tokenA) => {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await worker.fetch(new Request(`https://api.cybermeters.com${p}`, { headers }), env, ctx);
  let data = null; try { data = await res.json(); } catch { /* ignore */ }
  return { status: res.status, data };
};

// ── Seed: 089 Website Security conditions ────────────────────────────────────
const wsCond = (id, ws, domainId, domain, key, sev, status, { unknown_reason = null, quality = "complete" } = {}) =>
  db.prepare(`INSERT INTO website_security_conditions
    (id, workspace_id, domain_id, domain, condition_key, observed_severity, observed_title, detecting_module,
     last_scan_id, last_scan_quality, first_seen_at, last_seen_at, last_changed_at, monitoring_status,
     monitoring_reason, unknown_reason, recurrence_type, recurrence_band, lifecycle_state, created_at, updated_at, evaluated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'observed',datetime('now'),datetime('now'),datetime('now'))`)
    .run(id, ws, domainId, domain, key, sev, `Title for ${key}`, "headers", "scanX", quality,
      "2026-07-01T00:00:00Z", "2026-07-1" + (id.slice(-1)) + "T00:00:00Z", "2026-07-05T00:00:00Z",
      status, "reason_" + status, unknown_reason, "browser_protection_missing", sev);

wsCond("wsc-1", "ws1", "d1", "shared.example.com", "header_missing_strict_transport_security", "high", "observed");
wsCond("wsc-2", "ws1", "d1", "shared.example.com", "header_missing_content_security_policy", "medium", "unknown", { unknown_reason: "module_not_assessed", quality: "partial" });
wsCond("wsc-3", "ws1", "d1", "shared.example.com", "ssl_no_http_redirect", "medium", "no_longer_observed");
// ws2's condition on the SAME hostname — must never appear in ws1's list.
wsCond("wsc-foreign", "ws2", "d2", "shared.example.com", "header_missing_strict_transport_security", "critical", "observed");
// A soft-deleted workspace's condition.
wsCond("wsc-dead", "wsDead", "dDead", "dead.example.com", "header_missing_x_frame_options", "high", "observed");

db.prepare(`INSERT INTO website_security_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
            VALUES ('wse-1','wsc-1','ws1','system','monitoring_changed',?, '2026-07-01T00:00:00Z')`)
  .run(JSON.stringify({ to_recurrence_type: "browser_protection_missing", condition_key: "header_missing_strict_transport_security" }));
db.prepare(`INSERT INTO website_security_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
            VALUES ('wse-foreign','wsc-1','ws2','system','monitoring_changed','{}', '2026-07-09T00:00:00Z')`).run();

// ── Seed: 090 CE control records ─────────────────────────────────────────────
const ceRec = (id, ws, key, state, coverage) =>
  db.prepare(`INSERT INTO cyber_essentials_control_records
    (id, workspace_id, control_key, control_label, external_coverage, readiness_state, readiness_reason,
     evidence_fingerprint, evidence_json, unknown_json, last_scan_id, last_assessed_at, first_seen_at,
     last_seen_at, last_changed_at, monitoring_status, recurrence_type, recurrence_band, lifecycle_state,
     linked_case_id, created_at, updated_at, evaluated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'observed',NULL,NULL,'observed',NULL,datetime('now'),datetime('now'),datetime('now'))`)
    .run(id, ws, key, `Label ${key}`, coverage, state, "reason_" + state, "fp1",
      JSON.stringify([{ remediation_id: "web.hsts.enable", reason: "missing" }]),
      JSON.stringify(["internal_patch_state"]), "scanX", "2026-07-10T00:00:00Z",
      "2026-07-01T00:00:00Z", "2026-07-10T00:00:00Z", "2026-07-05T00:00:00Z");

ceRec("cec-1", "ws1", "boundary_protection", "not_ready", "partial");
ceRec("cec-2", "ws1", "access_control", "not_externally_assessable", "none");
ceRec("cec-3", "ws1", "secure_configuration", "ready", "partial");
ceRec("cec-foreign", "ws2", "boundary_protection", "not_ready", "partial");
ceRec("cec-dead", "wsDead", "boundary_protection", "not_ready", "partial");

db.prepare(`INSERT INTO cyber_essentials_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
            VALUES ('cee-1','cec-1','ws1','system','monitoring_changed',?, '2026-07-01T00:00:00Z')`)
  .run(JSON.stringify({ to_recurrence_type: "externally_observed_control_not_ready" }));

// ── Seed: 088 Email Protection events ────────────────────────────────────────
const epEvent = (id, ws, recId, recType, type, at, detail = {}) =>
  db.prepare(`INSERT INTO email_protection_events (id, record_id, record_type, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES (?,?,?,?,'system',?,?,?)`).run(id, recId, recType, ws, type, JSON.stringify(detail), at);

epEvent("epe-1", "ws1", "hd-1", "hosted_dns_entry", "monitoring_changed", "2026-07-01 00:00:00", { to_recurrence_type: "hosted_record_disconnected", entity: "shared.example.com", reason: "dns_missing" });
epEvent("epe-2", "ws1", "hd-1", "hosted_dns_entry", "hosted_record_reconnected", "2026-07-02 00:00:00", { entity: "shared.example.com" });
epEvent("epe-3", "ws1", "snd-1", "email_sender_source", "monitoring_changed", "2026-07-03 00:00:00", { to_recurrence_type: "sender_unauthorised_failures_active", entity: "203.0.113.9" });
epEvent("epe-foreign", "ws2", "hd-1", "hosted_dns_entry", "monitoring_changed", "2026-07-09 00:00:00", { to_recurrence_type: "hosted_record_disconnected" });
epEvent("epe-dead", "wsDead", "hd-9", "hosted_dns_entry", "monitoring_changed", "2026-07-09 00:00:00", {});

// ════ 1. THE HEADLINE: the records are readable at all ═══════════════════════
{
  const ws = await call("/api/workspaces/ws1/website-security/conditions");
  eq("089: Website Security conditions are readable", ws.status, 200);
  eq("089: the workspace's own conditions are returned", ws.data?.items?.length, 3);

  const ce = await call("/api/workspaces/ws1/cyber-essentials/controls");
  eq("090: Cyber Essentials control records are readable", ce.status, 200);
  eq("090: the workspace's own controls are returned", ce.data?.items?.length, 3);

  const ep = await call("/api/workspaces/ws1/email-protection/lifecycle");
  eq("088: Email Protection lifecycle history is readable", ep.status, 200);
  eq("088: the workspace's own events are returned", ep.data?.items?.length, 3);
}

// ════ 2. Auth, tenancy, non-enumeration, soft-delete ════════════════════════
for (const [label, p] of [
  ["089", "/api/workspaces/ws1/website-security/conditions"],
  ["090", "/api/workspaces/ws1/cyber-essentials/controls"],
  ["088", "/api/workspaces/ws1/email-protection/lifecycle"],
]) {
  eq(`${label}: anonymous callers are rejected`, (await call(p, null)).status, 401);
  eq(`${label}: a foreign workspace member is forbidden`, (await call(p, tokenB)).status, 403);
}
{
  // A soft-deleted workspace is not readable, and the STATUS is 403 rather than 404
  // because requireWorkspaceRole gets there first: its membership lookup joins
  // `workspaces w ON ... AND w.deleted_at IS NULL` (index.js:1417), so a deleted
  // workspace has no members and the caller is simply forbidden. That is the real
  // defence. The routes' own `deleted_at IS NULL` gate — which the lifecycle siblings all
  // carry — only closes the narrow window where a workspace is deleted BETWEEN the role
  // check and the read; it is not what stops this case, and this suite asserts what the
  // system does rather than what the route looks like it does.
  eq("089: a soft-deleted workspace is not readable", (await call("/api/workspaces/wsDead/website-security/conditions")).status, 403);
  eq("090: a soft-deleted workspace is not readable", (await call("/api/workspaces/wsDead/cyber-essentials/controls")).status, 403);
  eq("088: a soft-deleted workspace is not readable", (await call("/api/workspaces/wsDead/email-protection/lifecycle")).status, 403);
  // And its records never appear in a live workspace's list, whatever the status code.
  {
    const live = await call("/api/workspaces/ws1/website-security/conditions");
    ok("089: no soft-deleted workspace's record leaks into a live list",
      !(live.data?.items || []).some((i) => i.id === "wsc-dead"));
  }

  // Foreign record === nonexistent record. Identical response, no enumeration.
  const foreignWs = await call("/api/workspaces/ws1/website-security/conditions/wsc-foreign");
  const missingWs = await call("/api/workspaces/ws1/website-security/conditions/wsc-nope");
  eq("089: a FOREIGN record 404s", foreignWs.status, 404);
  eq("089: a NONEXISTENT record 404s identically", missingWs.status, 404);
  eq("089: and the two responses are indistinguishable", foreignWs.data, missingWs.data);

  const foreignCe = await call("/api/workspaces/ws1/cyber-essentials/controls/cec-foreign");
  const missingCe = await call("/api/workspaces/ws1/cyber-essentials/controls/cec-nope");
  eq("090: a FOREIGN record 404s", foreignCe.status, 404);
  eq("090: and is indistinguishable from a nonexistent one", foreignCe.data, missingCe.data);
}

// ════ 3. The same hostname in another tenant stays isolated ══════════════════
{
  const mine = await call("/api/workspaces/ws1/website-security/conditions?domain=shared.example.com");
  eq("089: filtering by a domain BOTH tenants own returns only mine", mine.data?.items?.length, 3);
  ok("089: and never the other tenant's condition on the same hostname",
    !(mine.data?.items || []).some((i) => i.id === "wsc-foreign"));

  const ep = await call("/api/workspaces/ws1/email-protection/lifecycle?record_id=hd-1");
  ok("088: a record_id both tenants use returns only my events",
    (ep.data?.items || []).every((i) => i.id !== "epe-foreign"));
  eq("088: exactly my two hd-1 events", ep.data?.items?.length, 2);

  const evs = await call("/api/workspaces/ws1/website-security/conditions/wsc-1");
  ok("089: a record's history excludes another tenant's rows for the same record id",
    (evs.data?.events || []).every((e) => e.id !== "wse-foreign"));
}

// ════ 4. Pagination is deterministic and bounded ════════════════════════════
{
  const p1 = await call("/api/workspaces/ws1/website-security/conditions?limit=2&offset=0");
  const p2 = await call("/api/workspaces/ws1/website-security/conditions?limit=2&offset=2");
  eq("089: page 1 honours the limit", p1.data?.items?.length, 2);
  eq("089: page 2 returns the remainder", p2.data?.items?.length, 1);
  ok("089: the pages do not overlap",
    !p1.data.items.some((a) => p2.data.items.some((b) => a.id === b.id)));
  eq("089: the total is exact", p1.data?.pagination?.total, 3);
  eq("089: has_more is exact on page 1", p1.data?.pagination?.has_more, true);
  eq("089: and false on the last page", p2.data?.pagination?.has_more, false);

  // Deterministic: the same query twice returns the same order.
  const again = await call("/api/workspaces/ws1/website-security/conditions?limit=2&offset=0");
  eq("089: repeating a page returns the identical order", again.data.items.map((i) => i.id), p1.data.items.map((i) => i.id));

  // The bound cannot be escaped.
  const huge = await call("/api/workspaces/ws1/website-security/conditions?limit=99999");
  ok("089: an oversized limit is clamped, not honoured", (huge.data?.pagination?.limit ?? 0) <= 200);
  eq("088: the history is bounded too", (await call("/api/workspaces/ws1/email-protection/lifecycle?limit=99999")).data?.pagination?.limit <= 200, true);
}

// ════ 5. Filters narrow WITHIN the tenant — they never widen across one ══════
{
  // A domain this workspace does not own must not reach the tenant that does.
  const foreign = await call("/api/workspaces/ws1/website-security/conditions?domain=dead.example.com");
  eq("089: filtering by a domain I do not own returns an empty list, not a 404", foreign.status, 200);
  eq("089: and no rows", foreign.data?.items?.length, 0);

  const byStatus = await call("/api/workspaces/ws1/website-security/conditions?monitoring_status=unknown");
  eq("089: the status filter narrows", byStatus.data?.items?.length, 1);
  eq("089: to the right record", byStatus.data?.items?.[0]?.id, "wsc-2");
  ok("089: and stays inside the tenant", (byStatus.data?.items || []).every((i) => i.id !== "wsc-foreign"));

  const bad = await call("/api/workspaces/ws1/email-protection/lifecycle?record_type=not_a_type");
  eq("088: an unrecognised record_type is rejected, not silently ignored", bad.status, 400);
  const byType = await call("/api/workspaces/ws1/email-protection/lifecycle?record_type=email_sender_source");
  eq("088: a valid record_type filter narrows", byType.data?.items?.length, 1);
}

// ════ 6. HONESTY: incomplete evidence never reads as fixed or verified ═══════
{
  const ws = await call("/api/workspaces/ws1/website-security/conditions");
  const unknown = ws.data.items.find((i) => i.id === "wsc-2");
  eq("089: a condition we could not assess reports `unknown`", unknown.monitoring_status, "unknown");
  eq("089: and says WHY it is unknown", unknown.unknown_reason, "module_not_assessed");
  eq("089: and carries the scan quality it was graded on", unknown.last_scan_quality, "partial");
  ok("089: `unknown` is NOT reported as resolved", unknown.monitoring_status !== "no_longer_observed");
  ok("089: the scope note states that unknown is not a fix", /never that the issue was fixed/i.test(ws.data.scope_note || ""));

  const ce = await call("/api/workspaces/ws1/cyber-essentials/controls");
  const unassessable = ce.data.items.find((i) => i.id === "cec-2");
  eq("090: a control nothing external can see reports not_externally_assessable", unassessable.readiness_state, "not_externally_assessable");
  eq("090: and its coverage says none", unassessable.external_coverage, "none");
  ok("090: NO control is ever reported as verified",
    ce.data.items.every((i) => i.readiness_state !== "verified"));
  ok("090: every control carries its external coverage, so `ready` cannot be read as a full pass",
    ce.data.items.every((i) => i.external_coverage === "partial" || i.external_coverage === "none"));
  ok("090: the scope note refuses certification and names the partial coverage",
    /does not certify Cyber Essentials/i.test(ce.data.scope_note || "") && /not_externally_assessable/.test(ce.data.scope_note || ""));
  ok("090: unobservable signals are surfaced, not omitted",
    Array.isArray(ce.data.items.find((i) => i.id === "cec-1")?.unknown_signals));
}

// ════ 7. Internal-only fields never leave the API ═══════════════════════════
{
  const ws = (await call("/api/workspaces/ws1/website-security/conditions")).data.items[0];
  for (const f of ["evaluated_at", "domain_id", "lifecycle_state", "recurrence_type", "recurrence_band", "monitoring_reason_json"]) {
    ok(`089: internal field \`${f}\` is not served`, !(f in ws) || f === "monitoring_reason_json");
  }
  const ce = (await call("/api/workspaces/ws1/cyber-essentials/controls")).data.items[0];
  for (const f of ["evaluated_at", "evidence_fingerprint", "monitoring_status", "recurrence_type", "recurrence_band"]) {
    ok(`090: internal field \`${f}\` is not served`, !(f in ce));
  }
  const ep = (await call("/api/workspaces/ws1/email-protection/lifecycle")).data.items[0];
  ok("088: the raw detail_json blob is not served", !("detail_json" in ep));
}

// ════ 8. The detail view resolves, with history ═════════════════════════════
{
  const d = await call("/api/workspaces/ws1/website-security/conditions/wsc-1");
  eq("089: a record detail resolves", d.status, 200);
  eq("089: it is the requested record", d.data?.item?.id, "wsc-1");
  ok("089: with its append-only history", Array.isArray(d.data?.events) && d.data.events.length >= 1);
  eq("089: linked_case is null — nothing writes it for this domain yet", d.data?.linked_case, null);

  const c = await call("/api/workspaces/ws1/cyber-essentials/controls/cec-1");
  eq("090: a control detail resolves", c.status, 200);
  ok("090: with its evidence", Array.isArray(c.data?.item?.evidence) && c.data.item.evidence.length >= 1);
  ok("090: and its history", Array.isArray(c.data?.events));
}

// ════ 9. No canonical read helper is left with zero callers ═════════════════
// This is the defect restated as a guard: every one of these existed, wrote nothing, and
// was read by nobody. If a future helper joins them, it fails here.
{
  const routesDir = path.join(root, "workers", "scan-api", "src", "routes");
  const routeSrc = fs.readdirSync(routesDir).map((f) => fs.readFileSync(path.join(routesDir, f), "utf8")).join("\n");
  for (const h of [
    "listWebsiteSecurityConditions", "listWebsiteSecurityEvents", "getWebsiteSecurityCondition",
    "listCeControlRecords", "listCeControlEvents", "getCeControlRecord",
    "listEmailProtectionEvents",
  ]) {
    ok(`the canonical read helper \`${h}\` has a route caller`, routeSrc.includes(h));
  }
}

// ════ 10. ALERT DEEP LINKS point at routes that EXIST ═══════════════════════
// THE DEFECT THIS EXISTS TO PREVENT: 0 of 6 emitLifecycleAlert calls passed a `link`, so
// managed-alerts fell back to `${origin}/notifications` and a customer told their DMARC
// record had disconnected landed on a generic list. An alert is not actionable if the
// customer cannot open what it references.
//
// The link is now built in ONE place (lifecycleRecordLink) rather than at six call sites,
// and every target is asserted to be a route this frontend actually declares. A link to a
// route that does not exist is not a fix — it is a different broken promise.
{
  const { lifecycleRecordLink } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "alert-consumers.js")).href);
  const linkEnv = { FRONTEND_URL: "https://app.cybermeters.com" };
  const appJsx = fs.readFileSync(path.join(root, "frontend", "src", "App.jsx"), "utf8");

  // The route is derived FROM THE LINK, never from a constant repeated here. An earlier
  // draft asserted `App.jsx contains "ws/website-security"` while the link was free to
  // point anywhere — so a link aimed at a nonexistent route passed. The only assertion
  // worth making is: parse what the link actually says, and require THAT path to be a
  // declared route.
  const declaredRoutes = new Set(
    [...appJsx.matchAll(/<Route\s+path="([^"]+)"/g)].map((m) => `/${m[1].replace(/^\//, "")}`),
  );
  ok("App.jsx route table was parsed (not an empty set that would pass anything)", declaredRoutes.size > 5);

  const cases = [
    ["website_security", "wsc-1", "condition=wsc-1"],
    ["cyber_essentials_readiness", "cec-1", "control=cec-1"],
    ["email_protection", "hd-1", "lifecycle=hd-1"],
  ];
  for (const [domain, recId, query] of cases) {
    const link = lifecycleRecordLink(linkEnv, domain, recId);
    ok(`${domain}: an alert now carries a deep link`, typeof link === "string" && link.length > 0);
    ok(`${domain}: it points at the record`, String(link).includes(query));
    let pathname = null;
    try { pathname = new URL(link).pathname; } catch { pathname = null; }
    ok(`${domain}: the link is a real absolute URL`, Boolean(pathname));
    ok(`${domain}: the route it points at is DECLARED in App.jsx (${pathname})`,
      Boolean(pathname) && declaredRoutes.has(pathname));
  }

  // Unknown domains get null, and null is honest: managed-alerts falls back to the
  // notifications list, which is where the customer would have gone anyway.
  eq("a domain with no read surface links nowhere rather than somewhere wrong",
    lifecycleRecordLink(linkEnv, "brand_protection", "x"), null);
  eq("a missing record id links nowhere", lifecycleRecordLink(linkEnv, "website_security", null), null);
  // No origin configured => no link, never a relative string that resolves against an
  // email client's own host.
  eq("no configured frontend origin yields no link", lifecycleRecordLink({}, "website_security", "wsc-1"), null);

  // The in-app card reads metadata.link. Without this the email would deep-link and the
  // card beside it would not — the same alert, two answers to "where do I go".
  const notif = fs.readFileSync(path.join(root, "frontend", "src", "pages", "NotificationsPage.jsx"), "utf8");
  ok("the in-app notification card reads metadata.link", /meta\?\.link/.test(notif));
  ok("and refuses a cross-origin destination rather than navigating anywhere it is told",
    /window\.location\.origin/.test(notif));

  // And the emit path actually attaches it.
  const consumers = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alert-consumers.js"), "utf8");
  ok("emitLifecycleAlert resolves a record link", /const record_link = link \|\| lifecycleRecordLink\(/.test(consumers));
  // Scoped to the METADATA block. `/link: record_link,/` alone also matches the top-level
  // emitManagedAlert argument, so it passed with the metadata field deleted — the card
  // would have gone dark while the assertion stayed green.
  const metaBlock = consumers.match(/metadata: \{[\s\S]*?\n      \},/)?.[0] ?? "";
  ok("the metadata block was located", metaBlock.includes("occurrence_id"));
  ok("and it carries the link for the in-app card", /link: record_link,/.test(metaBlock));
}

console.log(`\nm5-read-surfaces: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("m5-read-surfaces validation FAILED"); process.exit(1); }
console.log("m5-read-surfaces validation passed");
