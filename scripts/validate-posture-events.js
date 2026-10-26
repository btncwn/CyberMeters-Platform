#!/usr/bin/env node
//
// Posture-events regression: recordPostureEvents compares the previous R2 scan
// report with current in-memory modules and writes Exposure Timeline asset_events
// for email-auth and internet-exposed service changes. Uses a real in-memory
// SQLite schema (schema.sql + migrations) plus a small R2 stub. Requires Node
// 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { recordPostureEvents } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "posture-events.js")).href);
const { buildAssetTimelineTrustMetadata } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "timeline-trust.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

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

function makeR2(report) {
  return {
    async get(key) {
      if (key !== "reports/scan_prev.json" || report == null) return null;
      return { json: async () => report };
    },
  };
}

function harness(prevReport) {
  const db = buildDb();
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: makeR2(prevReport),
  };
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("usr_1", "owner@example.co.uk");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom_1", "usr_1", "example.co.uk");
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run("ws_1", "Acme");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws_1", "dom_1");
  // Baseline must be a COMPLETE assessment — the posture-change comparator only
  // fires against a complete previous scan (partial/degraded baselines are not
  // authoritative and cannot anchor a change event).
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("scan_prev", "dom_1", "example.co.uk", "completed", "complete", "ws_1", "2026-07-01T10:00:00.000Z");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("scan_current", "dom_1", "example.co.uk", "completed", "complete", "ws_1", "2026-07-02T10:00:00.000Z");
  db.prepare(
    `INSERT INTO workspace_assets
       (id, workspace_id, domain_id, hostname, asset_type, source,
        first_seen, last_seen, status, wildcard_dns, created_at, updated_at)
     VALUES ('asset_x', 'ws_1', 'dom_1', 'x.example.co.uk', 'exposed_service', 'exposure_probe',
             datetime('now','-1 day'), datetime('now','-1 day'), 'active', 0, datetime('now','-1 day'), datetime('now','-1 day'))`
  ).run();
  return { db, env };
}

async function record(env, modules, options = {}) {
  await recordPostureEvents("scan_current", "dom_1", "example.co.uk", modules, env, { currentReport: report(modules, options) });
}

const report = (modules, options = {}) => ({ domain: "example.co.uk", scan_quality: { status: options.scanQuality ?? "complete" }, timeline_trust: buildAssetTimelineTrustMetadata(), modules });
const CIDRA = "ip4:c0000200/24";
const CIDRB = "ip4:cb007100/24";
// DKIM carries the persisted selector coverage a real email-scan result has, so a
// present<->absent change is comparable (posture-events DKIM coverage guard).
const FIXTURE_DKIM_SELECTORS = ["default", "selector1", "selector2"];
const email = ({ spfPresent = true, spfRecord = "v=spf1 include:example.net -all", dmarcPresent = true, dmarcPolicy = "none", dkimPresent = true } = {}) => ({
  spf: {
    present: spfPresent,
    record: spfRecord,
    resolution_status: "complete",
    resolved_pass_authorisations: spfPresent ? [CIDRA] : [],
  },
  dmarc: { present: dmarcPresent, policy: dmarcPolicy },
  dkim: { present: dkimPresent, selector: dkimPresent ? "selector1" : null,
    selectors_probed: FIXTURE_DKIM_SELECTORS, selectors_answered: FIXTURE_DKIM_SELECTORS },
});
const service = (hostname, product, severity = "high") => ({ hostname, product, severity, risk_level: severity });
const modules = ({ email_security = email(), services = [], admin_evidence_status } = {}) => ({
  email_security,
  admin_surface_detection: {
    services,
    // A3 evidence_status: default reflects the services (issue when present, healthy when
    // the assessment completed with none); tests may override to unavailable/not_assessed.
    evidence_status: admin_evidence_status ?? (services.length > 0 ? "issue_detected" : "assessed_healthy"),
  },
});
const rows = (db) => db.prepare("SELECT event_type, hostname, severity, description FROM asset_events ORDER BY created_at, event_type").all();
const rowsFor = (db, eventType) => rows(db).filter((row) => row.event_type === eventType);

// 1. SPF present -> absent emits high-severity email_spf_changed.
{
  const { db, env } = harness(report(modules({ email_security: email({ spfPresent: true }) })));
  await record(env, modules({ email_security: email({ spfPresent: false, spfRecord: null }) }));
  const events = rowsFor(db, "email_spf_changed");
  ok("SPF present -> absent emits one event", events.length === 1);
  ok("SPF present -> absent severity is high", events[0]?.severity === "high");
  ok("SPF description is customer-safe", events[0]?.description === "SPF record changed for example.co.uk");
}

// 1b. SPF per-signal completeness: unrelated partial scan quality does NOT silence
//     a complete SPF resolved-set change.
{
  const root = "v=spf1 include:example.net -all";
  const prevSpf = { present: true, record: root, resolution_status: "complete", resolved_pass_authorisations: [CIDRA] };
  const currSpf = { present: true, record: root, resolution_status: "complete", resolved_pass_authorisations: [CIDRA, CIDRB] };
  const { db, env } = harness(report(modules({ email_security: { ...email(), spf: prevSpf } }), { scanQuality: "partial" }));
  await record(env, modules({ email_security: { ...email(), spf: currSpf }, admin_evidence_status: "unavailable" }), { scanQuality: "partial" });
  const events = rowsFor(db, "email_spf_authorization_changed");
  ok("SPF resolved-set change emits under unrelated partial scan", events.length === 1);
  ok("SPF resolved-set event writes a human CIDR under partial scan",
    events[0]?.description.includes("203.0.113.0/24") &&
    !events[0]?.description.includes(CIDRB));
}

// 1c. Incomplete SPF evidence never produces a root-record or resolved-set change.
{
  const prevSpf = { present: true, record: "v=spf1 include:old.example -all", resolution_status: "complete", resolved_pass_authorisations: [CIDRA] };
  const currSpf = { present: true, record: "v=spf1 include:new.example -all", resolution_status: "temperror", resolved_pass_authorisations: null };
  const { db, env } = harness(report(modules({ email_security: { ...email(), spf: prevSpf } })));
  await record(env, modules({ email_security: { ...email(), spf: currSpf } }));
  ok("current incomplete SPF emits no root-record event", rowsFor(db, "email_spf_changed").length === 0);
  ok("current incomplete SPF emits no authorization event", rowsFor(db, "email_spf_authorization_changed").length === 0);
}

// 2. DMARC none -> reject is an improvement and emits low severity.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "none" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }));
  const events = rowsFor(db, "email_dmarc_policy_changed");
  ok("DMARC none -> reject emits one event", events.length === 1);
  ok("DMARC none -> reject severity is low", events[0]?.severity === "low");
  ok("DMARC none -> reject description includes old -> new", events[0]?.description === "DMARC policy changed: none → reject");
}

// 3. DMARC reject -> none is a regression and emits high severity.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "reject" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "none" }) }));
  const events = rowsFor(db, "email_dmarc_policy_changed");
  ok("DMARC reject -> none emits one event", events.length === 1);
  ok("DMARC reject -> none severity is high", events[0]?.severity === "high");
}

// 4. DKIM present -> absent emits medium severity.
{
  const { db, env } = harness(report(modules({ email_security: email({ dkimPresent: true }) })));
  await record(env, modules({ email_security: email({ dkimPresent: false }) }));
  const events = rowsFor(db, "email_dkim_changed");
  ok("DKIM present -> absent emits one event", events.length === 1);
  ok("DKIM present -> absent severity is medium", events[0]?.severity === "medium");
}

// 4b. DKIM coverage guard on REAL email-scan output (synthetic DoH answers, no network).
//     A domain whose key is published only under a provider (phase 2) selector loses
//     that probe when the root TXT lookup fails. Prior and current reports are both
//     round-tripped through JSON, as the previous report is read back from R2.
{
  const DOMAIN = "proton.example.com";
  const SPF = "v=spf1 include:_spf.protonmail.ch ~all";
  const realFetch = globalThis.fetch;
  let fail = null, published = { protonmail: true, google: false };
  globalThis.fetch = async (input) => {
    const u = new URL(typeof input === "string" ? input : input.url);
    if (u.hostname !== "cloudflare-dns.com") throw new Error(`offline validator refused ${u.hostname}`);
    const name = u.searchParams.get("name"), type = u.searchParams.get("type");
    const failing = (fail || []).find((f) => f.name === name && type === "TXT");
    if (failing) {
      if (failing.kind === "timeout") throw new Error("synthetic timeout");
      return new Response(JSON.stringify({ Status: 2, Answer: [] }), { status: 200 });
    }
    let answer = [];
    if (name === DOMAIN && type === "TXT") answer = [{ type: 16, data: `"${SPF}"` }];
    for (const sel of ["protonmail", "google"]) {
      if (name === `${sel}._domainkey.${DOMAIN}` && type === "TXT" && published[sel]) answer = [{ type: 16, data: '"v=DKIM1; k=rsa; p=MIIB"' }];
    }
    return new Response(JSON.stringify({ Status: answer.length ? 0 : 3, Answer: answer }), { status: 200 });
  };
  const { runEmailModule } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "email-scan.js")).href);
  const scan = async ({ failing = null, keys = { protonmail: true, google: false } } = {}) => {
    fail = failing ? [].concat(failing) : null; published = keys;
    return JSON.parse(JSON.stringify(await runEmailModule(DOMAIN, { dmarcOwnedByCore: true })));
  };
  const rootFail = (kind) => ({ name: DOMAIN, kind });
  const includeFail = { name: "_spf.protonmail.ch", kind: "timeout" };
  const s = {
    full: await scan(),
    rootTimeout: await scan({ failing: rootFail("timeout") }),
    rootServfail: await scan({ failing: rootFail("servfail") }),
    includeTimeout: await scan({ failing: includeFail }),
    removed: await scan({ keys: { protonmail: false, google: false } }),
    phase1: await scan({ keys: { protonmail: false, google: true } }),
    phase1RootFail: await scan({ failing: rootFail("timeout"), keys: { protonmail: false, google: true } }),
    phase1RemovedRootFail: await scan({ failing: rootFail("timeout"), keys: { protonmail: false, google: false } }),
    // The decisive selector itself was asked but did not answer conclusively.
    providerTimeout: await scan({ failing: { name: `protonmail._domainkey.${DOMAIN}`, kind: "timeout" } }),
    providerServfail: await scan({ failing: { name: `protonmail._domainkey.${DOMAIN}`, kind: "servfail" } }),
    rootAndPhase1Timeout: await scan({ failing: [rootFail("timeout"), { name: `google._domainkey.${DOMAIN}`, kind: "timeout" }],
      keys: { protonmail: false, google: true } }),
    rootAndPhase1Servfail: await scan({ failing: [rootFail("servfail"), { name: `google._domainkey.${DOMAIN}`, kind: "servfail" }],
      keys: { protonmail: false, google: true } }),
  };
  globalThis.fetch = realFetch;
  const dkimEvents = async (prev, cur) => {
    const { db, env } = harness(JSON.parse(JSON.stringify(report(modules({ email_security: prev })))));
    await record(env, modules({ email_security: cur }));
    return rowsFor(db, "email_dkim_changed");
  };
  ok("fixture: full sweep finds the provider-only key", s.full.dkim.present === true && s.full.dkim.selector === "protonmail");
  ok("fixture: failed root TXT skips the provider selector", s.rootTimeout.dkim.selectors_probed.includes("protonmail") === false);
  ok("DKIM: root TXT timeout, key still published -> no false event", (await dkimEvents(s.full, s.rootTimeout)).length === 0);
  ok("DKIM: root TXT SERVFAIL, key still published -> no false event", (await dkimEvents(s.full, s.rootServfail)).length === 0);
  ok("DKIM: narrowed previous scan -> full current scan emits no false 'published' event",
    (await dkimEvents(s.rootTimeout, s.full)).length === 0);
  ok("DKIM: SPF include failure does not narrow the sweep -> no event", (await dkimEvents(s.full, s.includeTimeout)).length === 0);
  ok("DKIM: stable full scans -> no event", (await dkimEvents(s.full, s.full)).length === 0);
  const removedEvents = await dkimEvents(s.full, s.removed);
  ok("DKIM: genuine removal with comparable coverage -> one medium event",
    removedEvents.length === 1 && removedEvents[0].severity === "medium");
  const publishedEvents = await dkimEvents(s.removed, s.full);
  ok("DKIM: genuine publication with comparable coverage -> one low event",
    publishedEvents.length === 1 && publishedEvents[0].severity === "low");
  ok("DKIM: phase-1 key survives a failed root TXT lookup -> no event", (await dkimEvents(s.phase1, s.phase1RootFail)).length === 0);
  ok("DKIM: phase-1 key genuinely removed during a failed root TXT lookup -> one event",
    (await dkimEvents(s.phase1, s.phase1RemovedRootFail)).length === 1);
  ok("fixture: a failed decisive selector is probed but not answered",
    s.providerTimeout.dkim.selectors_probed.includes("protonmail") && !(s.providerTimeout.dkim.selectors_answered ?? []).includes("protonmail") &&
    s.rootAndPhase1Timeout.dkim.selectors_probed.includes("google") && !(s.rootAndPhase1Timeout.dkim.selectors_answered ?? []).includes("google") &&
    (s.full.dkim.selectors_answered ?? []).includes("protonmail"));
  for (const [label, cur] of [
    ["provider selector timeout, root SPF ok", s.providerTimeout],
    ["provider selector SERVFAIL, root SPF ok", s.providerServfail],
  ]) {
    ok(`DKIM: ${label}, key still published -> no false event`, (await dkimEvents(s.full, cur)).length === 0);
    ok(`DKIM: ${label} as the PREVIOUS scan -> no false 'published' event`, (await dkimEvents(cur, s.full)).length === 0);
  }
  for (const [label, cur] of [
    ["root TXT + phase-1 selector timeout", s.rootAndPhase1Timeout],
    ["root TXT + phase-1 selector SERVFAIL", s.rootAndPhase1Servfail],
  ]) {
    ok(`DKIM: ${label}, key still published -> no false event`, (await dkimEvents(s.phase1, cur)).length === 0);
    ok(`DKIM: ${label} as the PREVIOUS scan -> no false 'published' event`, (await dkimEvents(cur, s.phase1)).length === 0);
  }
  ok("DKIM: stable completed no-key scans -> no event", (await dkimEvents(s.removed, s.removed)).length === 0);
  ok("DKIM: phase-1 key removal answered conclusively despite root failure -> one medium event",
    (await dkimEvents(s.phase1, s.phase1RemovedRootFail))[0]?.severity === "medium");
  const legacy = (present) => ({ ...email(), dkim: { present } });
  const attemptedOnly = (present) => ({ ...email(), dkim: { present, selector: present ? "protonmail" : null,
    selectors_probed: ["default", "protonmail"] } });
  ok("DKIM: report with attempted-only coverage (present -> absent) -> no event",
    (await dkimEvents(s.full, attemptedOnly(false))).length === 0);
  ok("DKIM: report with attempted-only coverage (absent -> present) -> no event",
    (await dkimEvents(attemptedOnly(false), s.full)).length === 0);
  ok("DKIM: legacy previous report without coverage (present -> absent) -> no event",
    (await dkimEvents(legacy(true), s.removed)).length === 0);
  ok("DKIM: legacy previous report without coverage (absent -> present) -> no event",
    (await dkimEvents(legacy(false), s.full)).length === 0);
}

// 5. Admin-surface services are diffed by hostname + product. A prior service missing
//    from a current pass that is NOT a completed clean assessment (here: current
//    issue_detected) must NOT be reported as resolved.
{
  const prev = report(modules({ services: [service("old.example.co.uk", "Jenkins")] }));
  const { db, env } = harness(prev);
  await record(env, modules({ services: [service("x.example.co.uk", "Rundeck")] }));
  const detected = rowsFor(db, "exposed_service_detected");
  const resolved = rowsFor(db, "exposed_service_resolved");
  ok("new exposed service emits exposed_service_detected", detected.length === 1);
  ok("new exposed service description includes product and host", detected[0]?.description === "New internet-exposed service detected: Rundeck on x.example.co.uk");
  ok("prior service missing but current NOT assessed_healthy → no false resolved", resolved.length === 0);
}

// 5b. Genuine completed clean assessment (current assessed_healthy, service gone) → one resolved.
{
  const prev = report(modules({ services: [service("old.example.co.uk", "Jenkins")] }));
  const { db, env } = harness(prev);
  await record(env, modules({ services: [], admin_evidence_status: "assessed_healthy" }));
  const resolved = rowsFor(db, "exposed_service_resolved");
  ok("prior service + current assessed_healthy → exactly one resolved", resolved.length === 1);
  ok("resolved service severity is low", resolved[0]?.severity === "low");
}

// 5c. Non-SPF posture events still require whole-scan comparability; a partial scan
//     with a DMARC change is suppressed while a complete SPF event may pass separately.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "none" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }), { scanQuality: "partial" });
  ok("DMARC change remains suppressed when whole scan is partial", rowsFor(db, "email_dmarc_policy_changed").length === 0);
}

// 6. Previous scan row exists but R2 report is missing: no baseline, no events.
{
  const { db, env } = harness(null);
  await record(env, modules({ email_security: email({ spfPresent: false, spfRecord: null }) }));
  ok("missing previous R2 report emits no events", rows(db).length === 0);
}

// 7. No changes emit no events.
{
  const baseline = modules({ services: [service("x.example.co.uk", "Rundeck")] });
  const { db, env } = harness(report(baseline));
  await record(env, baseline);
  ok("unchanged email posture and services emit no events", rows(db).length === 0);
}

// 8. Dedupe: same event_type:hostname within 24h is suppressed on second run.
{
  const { db, env } = harness(report(modules({ email_security: email({ dmarcPolicy: "none" }) })));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }));
  await record(env, modules({ email_security: email({ dmarcPolicy: "reject" }) }));
  ok("second DMARC policy event within 24h is deduped", rowsFor(db, "email_dmarc_policy_changed").length === 1);
}

console.log(`\nPosture events: ${pass}/${pass + fail} passed`);
if (fail) { console.error("posture-events validation FAILED"); process.exit(1); }
console.log("posture-events validation passed");
