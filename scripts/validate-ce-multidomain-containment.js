#!/usr/bin/env node
// CE-WORKSPACE-MULTIDOMAIN-FLIP-FLOP — Stage-1 containment proof.
// Real schema, real readiness/lifecycle/accessors, scan-id-keyed R2 fixtures.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(src("engines", f)).href;
const EXPECTED_ASSERTIONS = 22;
const ONLY = process.env.CE_CONTAINMENT_ONLY || null;

const readinessMod = await import(eng("ce-readiness.js"));
const lifecycleMod = await import(eng("ce-lifecycle.js"));
const occurrenceMod = await import(eng("alert-occurrence.js"));
const {
  buildCyberEssentialsReadiness,
  CE_WORKSPACE_MULTI_DOMAIN_REASON,
  CE_WORKSPACE_NO_DOMAIN_REASON,
  CE_WORKSPACE_DOMAIN_COUNT_UNAVAILABLE_REASON,
} = readinessMod;
const {
  evaluateCyberEssentialsLifecycle, listCeControlRecords, countCeControlRecords,
  getCeControlRecord,
} = lifecycleMod;

const HEALTHY = () => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'",
  }, present: [], missing: [] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
} });
const GAPS = () => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: {}, present: [], missing: [
    "strict-transport-security", "content-security-policy",
  ] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
} });

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive convergence */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','ce-owner@example.com','Owner','professional',datetime('now'))").run();
  db.prepare("UPDATE users SET email_verified=1 WHERE id='u1'").run();
  db.prepare(`INSERT INTO subscriptions
    (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at)
    VALUES ('sub1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
  return db;
}

function makeD1(db, { failDomainCount = false, calls = [] } = {}) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (column) => {
      calls.push({ method: "first", sql, args });
      if (failDomainCount && /SELECT COUNT\(\*\) AS n\s+FROM workspace_domains\s+WHERE workspace_id = \?/s.test(sql)) {
        throw new Error("domain count unavailable");
      }
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => {
      calls.push({ method: "all", sql, args });
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      calls.push({ method: "run", sql, args });
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return {
    prepare(sql) { const base = wrap(sql, []); base.bind = (...args) => wrap(sql, args); return base; },
    async batch(stmts) {
      return Promise.all(stmts.map((stmt) => /^\s*SELECT/i.test(stmt.__sql) ? stmt.all() : stmt.run()));
    },
  };
}

function envFor(db, reports = {}, options = {}) {
  const r2Reads = [];
  const calls = [];
  const env = {
    cybermeters_db: makeD1(db, { ...options, calls }),
    // Load-bearing: one report object per scan id. Never return one global report.
    cybermeters_reports: {
      get: async (key) => {
        r2Reads.push(key);
        return Object.hasOwn(reports, key) ? { json: async () => reports[key] } : null;
      },
    },
    RESEND_API_KEY: "",
    ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  };
  return { env, r2Reads, calls };
}

function seedWorkspace(db, ws, domainSpecs = []) {
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,'u1',?)").run(ws, ws);
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,'u1','owner')").run(`mem_${ws}`, ws);
  for (const [index, spec] of domainSpecs.entries()) {
    const id = spec.id || `${ws}_d${index + 1}`;
    const name = spec.name || `${id}.example.com`;
    db.prepare("INSERT OR IGNORE INTO domains (id,user_id,domain,verification_status,created_at) VALUES (?,'u1',?,?,datetime('now'))")
      .run(id, name, spec.verification || "unverified");
    db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id,verification_status) VALUES (?,?,?)")
      .run(ws, id, spec.verification || "unverified");
  }
}

function seedScan(db, { id, ws, domainId, domain = null, createdAt = "2026-08-02T01:15:00Z" }) {
  const name = domain || db.prepare("SELECT domain FROM domains WHERE id=?").get(domainId)?.domain || `${domainId}.example.com`;
  db.prepare(`INSERT INTO scans
    (id,domain_id,workspace_id,domain,score,rating,status,scan_quality,created_at)
    VALUES (?,?,?, ?,70,'fair','completed','complete',?)`).run(id, domainId, ws, name, createdAt);
}

function seedRecord(db, { id = "cec-ready", ws, key = "secure_configuration", state = "ready", linkedCaseId = null }) {
  db.prepare(`INSERT INTO cyber_essentials_control_records
    (id,workspace_id,control_key,control_label,external_coverage,readiness_state,readiness_reason,
     evidence_fingerprint,evidence_json,unknown_json,last_scan_id,last_assessed_at,first_seen_at,
     last_seen_at,last_changed_at,monitoring_status,recurrence_type,recurrence_band,lifecycle_state,
     linked_case_id,created_at,updated_at,evaluated_at)
    VALUES (?,?,?,'Secure Configuration','partial',?,?,?,?,'[]','scan_historical',
      datetime('now'),datetime('now'),datetime('now'),datetime('now'),'observed',NULL,NULL,'observed',?,
      datetime('now'),datetime('now'),datetime('now'))`)
    .run(
      id, ws, key, state,
      state === "ready" ? "external_evidence_supports_readiness" : "external_evidence_shows_gaps",
      state === "not_ready" ? "web.header.hsts" : null,
      JSON.stringify([{ remediation_id: "web.header.hsts", reason: "historical evidence" }]),
      linkedCaseId,
    );
  return id;
}

function seedCase(db, { id = "case-ce", ws, recordId, status = "awaiting_verification" }) {
  db.prepare(`INSERT INTO managed_cases
    (id,workspace_id,case_type,finding_id,asset_ref,severity,status,remediation_id,title,summary,created_at,updated_at)
    VALUES (?,?,'cyber_essentials_case',?, 'secure_configuration','medium',?,
      'ce.readiness.control_review','CE case','Historical CE case',datetime('now'),datetime('now'))`)
    .run(id, ws, recordId, status);
  return id;
}

function seedBaselineAndActivation(db, ws) {
  db.prepare(`INSERT INTO cyber_essentials_events
    (id,record_id,workspace_id,actor_type,event_type,detail_json,created_at)
    VALUES (?,? ,?,'system','workspace_baseline_established','{}','2026-08-01T00:00:00Z')`)
    .run(`baseline_${ws}`, ws, ws);
  db.prepare(`INSERT INTO alert_activation
    (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
    VALUES (?,?,'cyber_essentials_readiness','2026-08-01T00:00:00Z',0,datetime('now'))`)
    .run(`activation_${ws}`, ws);
}

function durableState(db, ws) {
  const tables = [
    "cyber_essentials_control_records", "cyber_essentials_events", "managed_cases",
    "managed_case_events", "notification_events", "alert_deliveries",
  ];
  return Object.fromEntries(tables.map((table) => [table,
    db.prepare(`SELECT * FROM ${table} WHERE workspace_id=? ORDER BY rowid`).all(ws),
  ]));
}

function permutations(values) {
  if (values.length <= 1) return [values];
  return values.flatMap((value, index) => permutations(values.filter((_, i) => i !== index))
    .map((rest) => [value, ...rest]));
}

function listJsFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? listJsFiles(full) : (entry.isFile() && entry.name.endsWith(".js") ? [full] : []);
  });
}

function runUi(title) {
  const result = spawnSync(
    path.join(root, "frontend", "node_modules", ".bin", "vitest"),
    ["run", "src/pages/ws/__tests__/WorkspaceCyberEssentialsPage.containment.test.jsx", "-t", title],
    { cwd: path.join(root, "frontend"), encoding: "utf8", timeout: 120000 },
  );
  return {
    ok: !result.error && result.signal == null && result.status === 0,
    detail: `${result.stdout || ""}\n${result.stderr || ""}`.trim().slice(-2000),
  };
}

const tests = [
  ["single-domain readiness preserves the existing positive path", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1", verification: "unverified" }]);
    seedScan(db, { id: "scan_one", ws: "ws1", domainId: "d1" });
    const { env, r2Reads } = envFor(db, { "reports/scan_one.json": HEALTHY() });
    const out = await buildCyberEssentialsReadiness("ws1", env);
    return {
      ok: out?.assessable === true && out.status === "likely_ready" && out.score === 100 &&
        out.grade === "A" && out.categories?.length === 5 && out.containment_reason == null &&
        r2Reads.length > 0 && r2Reads.every((key) => key === "reports/scan_one.json"),
      detail: JSON.stringify({ out, r2Reads }),
    };
  }],
  ["multi-domain readiness is not assessed before scan or R2 work", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [
      { id: "d1", verification: "verified" }, { id: "d2", verification: "unverified" },
    ]);
    seedScan(db, { id: "scan_gap", ws: "ws1", domainId: "d1" });
    const { env, r2Reads, calls } = envFor(db, { "reports/scan_gap.json": GAPS() });
    const out = await buildCyberEssentialsReadiness("ws1", env);
    return {
      ok: out?.assessable === false && out.status === "not_assessed" && out.score == null &&
        out.grade == null && out.containment_reason === CE_WORKSPACE_MULTI_DOMAIN_REASON &&
        out.categories?.length === 0 && out.latest_scan === null && r2Reads.length === 0 &&
        !calls.some((call) => /FROM scans s/.test(call.sql)),
      detail: JSON.stringify({ out, r2Reads, sql: calls.map((c) => c.sql) }),
    };
  }],
  ["multi-domain lifecycle performs zero durable case and alert writes", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]);
    seedScan(db, { id: "scan_clean", ws: "ws1", domainId: "d2" });
    const { env } = envFor(db, { "reports/scan_clean.json": HEALTHY() });
    const before = durableState(db, "ws1");
    const out = await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_clean" });
    const after = durableState(db, "ws1");
    return { ok: out.skipped === "workspace_domain_containment" && JSON.stringify(before) === JSON.stringify(after), detail: JSON.stringify({ out, before, after }) };
  }],
  ["three same-time scans stay contained across all six completion permutations", async () => {
    const results = [];
    for (const order of permutations(["s1", "s2", "s3"])) {
      const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }, { id: "d3" }]);
      const reports = {};
      order.forEach((id, index) => {
        const domainId = `d${index + 1}`;
        seedScan(db, { id, ws: "ws1", domainId, createdAt: "2026-08-02T01:15:00Z" });
        reports[`reports/${id}.json`] = id === "s2" ? GAPS() : HEALTHY();
      });
      const { env, r2Reads } = envFor(db, reports);
      const out = await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: order.at(-1) });
      results.push(out.skipped === "workspace_domain_containment" && r2Reads.length === 0 &&
        db.prepare("SELECT COUNT(*) n FROM cyber_essentials_events").get().n === 0);
    }
    return { ok: results.length === 6 && results.every(Boolean), detail: JSON.stringify(results) };
  }],
  ["one gap domain plus one clean domain cannot project ready or recover", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "gap" }, { id: "clean" }]);
    seedScan(db, { id: "scan_gap", ws: "ws1", domainId: "gap", createdAt: "2026-08-02T01:14:00Z" });
    seedScan(db, { id: "scan_clean", ws: "ws1", domainId: "clean", createdAt: "2026-08-02T01:15:00Z" });
    const recordId = seedRecord(db, { ws: "ws1", state: "not_ready" });
    const { env } = envFor(db, { "reports/scan_gap.json": GAPS(), "reports/scan_clean.json": HEALTHY() });
    const out = await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_clean" });
    const stored = db.prepare("SELECT readiness_state,last_scan_id FROM cyber_essentials_control_records WHERE id=?").get(recordId);
    const recovered = db.prepare("SELECT COUNT(*) n FROM cyber_essentials_events WHERE record_id=? AND event_type='control_recovered'").get(recordId).n;
    return { ok: out.skipped === "workspace_domain_containment" && stored.readiness_state === "not_ready" && stored.last_scan_id === "scan_historical" && recovered === 0, detail: JSON.stringify({ out, stored, recovered }) };
  }],
  ["unlinking the second domain resumes the existing single-domain lifecycle", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]);
    seedScan(db, { id: "scan_one", ws: "ws1", domainId: "d1" });
    const { env } = envFor(db, { "reports/scan_one.json": HEALTHY() });
    const held = await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_one" });
    db.prepare("DELETE FROM workspace_domains WHERE workspace_id='ws1' AND domain_id='d2'").run();
    const resumed = await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_one" });
    return { ok: held.skipped === "workspace_domain_containment" && resumed.evaluated === 5 && resumed.created === 5 && db.prepare("SELECT COUNT(*) n FROM cyber_essentials_control_records WHERE workspace_id='ws1'").get().n === 5, detail: JSON.stringify({ held, resumed }) };
  }],
  ["zero linked domains are not assessed", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", []);
    const { env, r2Reads } = envFor(db, {});
    const out = await buildCyberEssentialsReadiness("ws1", env);
    return { ok: out.assessable === false && out.status === "not_assessed" && out.containment_reason === CE_WORKSPACE_NO_DOMAIN_REASON && r2Reads.length === 0, detail: JSON.stringify({ out, r2Reads }) };
  }],
  ["domain-count query failure fails closed instead of becoming count zero or one", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }]); seedRecord(db, { ws: "ws1", state: "ready" });
    const { env, r2Reads } = envFor(db, {}, { failDomainCount: true });
    const out = await buildCyberEssentialsReadiness("ws1", env);
    return { ok: out.assessable === false && out.containment_reason === CE_WORKSPACE_DOMAIN_COUNT_UNAVAILABLE_REASON && r2Reads.length === 0, detail: JSON.stringify({ out, r2Reads }) };
  }],
  ["foreign workspace sharing a domain has no cross-tenant effect", async () => {
    const db = buildDb(); seedWorkspace(db, "wsA", [{ id: "shared" }]); seedWorkspace(db, "wsB", []);
    db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id,verification_status) VALUES ('wsB','shared','verified')").run();
    seedScan(db, { id: "scan_foreign", ws: "wsB", domainId: "shared" });
    const { env, r2Reads } = envFor(db, { "reports/scan_foreign.json": HEALTHY() });
    const out = await buildCyberEssentialsReadiness("wsA", env);
    return { ok: out.assessable === false && out.status === "not_assessed" && out.containment_reason == null && r2Reads.length === 0, detail: JSON.stringify({ out, r2Reads }) };
  }],
  ["stored ready projects unknown with explicit recorded historical fields", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]);
    const id = seedRecord(db, { ws: "ws1", state: "ready" });
    const { env } = envFor(db);
    const item = await getCeControlRecord(env, "ws1", id);
    const raw = db.prepare("SELECT readiness_state,evidence_json FROM cyber_essentials_control_records WHERE id=?").get(id);
    return { ok: item.readiness_state === "unknown" && item.readiness_reason === CE_WORKSPACE_MULTI_DOMAIN_REASON && item.containment_active === true && item.evidence.length === 0 && item.unknown_signals.length === 1 && item.recorded_readiness_state === "ready" && item.recorded_readiness_reason === "external_evidence_supports_readiness" && item.recorded_evidence.length === 1 && raw.readiness_state === "ready", detail: JSON.stringify({ item, raw }) };
  }],
  ["contained list projection cannot bypass the durable read-side gate", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]); seedRecord(db, { id: "r1", ws: "ws1", state: "ready" });
    const { env } = envFor(db); const items = await listCeControlRecords(env, "ws1");
    return { ok: items.length === 1 && items[0].readiness_state === "unknown" && items[0].containment_active === true, detail: JSON.stringify(items) };
  }],
  ["contained list count filter limit and offset remain projection-consistent", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]);
    seedRecord(db, { id: "r1", ws: "ws1", key: "boundary_protection", state: "ready" });
    seedRecord(db, { id: "r2", ws: "ws1", key: "secure_configuration", state: "not_ready" });
    seedRecord(db, { id: "r3", ws: "ws1", key: "access_control", state: "ready" });
    const { env } = envFor(db);
    const page = await listCeControlRecords(env, "ws1", { limit: 1, offset: 1 });
    const unknownPage = await listCeControlRecords(env, "ws1", { readiness_state: "unknown", limit: 2, offset: 1 });
    const blocked = await Promise.all(["ready", "not_ready", "not_externally_assessable"].map(async (state) => ({
      state, list: await listCeControlRecords(env, "ws1", { readiness_state: state }),
      count: await countCeControlRecords(env, "ws1", { readiness_state: state }),
    })));
    const totals = [await countCeControlRecords(env, "ws1"), await countCeControlRecords(env, "ws1", { readiness_state: "unknown" })];
    return { ok: page.length === 1 && page[0].readiness_state === "unknown" && unknownPage.length === 2 && unknownPage.every((x) => x.readiness_state === "unknown") && JSON.stringify(totals) === "[3,3]" && blocked.every((x) => x.list.length === 0 && x.count === 0), detail: JSON.stringify({ page, unknownPage, totals, blocked }) };
  }],
  ["count failure never falls back to stored ready on durable get", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }]); const id = seedRecord(db, { ws: "ws1", state: "ready" });
    const { env } = envFor(db, {}, { failDomainCount: true }); const item = await getCeControlRecord(env, "ws1", id);
    return { ok: item.readiness_state === "unknown" && item.readiness_reason === CE_WORKSPACE_DOMAIN_COUNT_UNAVAILABLE_REASON && item.recorded_readiness_state === "ready", detail: JSON.stringify(item) };
  }],
  ["awaiting-verification case is not verified by an unrelated clean scan", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "gap" }, { id: "clean" }]);
    seedScan(db, { id: "scan_clean", ws: "ws1", domainId: "clean" });
    const recordId = "cec-case"; seedCase(db, { ws: "ws1", recordId }); seedRecord(db, { id: recordId, ws: "ws1", state: "not_ready", linkedCaseId: "case-ce" });
    seedBaselineAndActivation(db, "ws1"); const { env } = envFor(db, { "reports/scan_clean.json": HEALTHY() });
    await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_clean" });
    const kase = db.prepare("SELECT status,last_verified_at FROM managed_cases WHERE id='case-ce'").get();
    return { ok: kase.status === "awaiting_verification" && kase.last_verified_at == null && db.prepare("SELECT COUNT(*) n FROM cyber_essentials_events WHERE record_id=? AND event_type='control_recovered'").get(recordId).n === 0, detail: JSON.stringify(kase) };
  }],
  ["alert resolver finds no actionable transition under containment", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]); seedScan(db, { id: "scan_gap", ws: "ws1", domainId: "d1" });
    const recordId = seedRecord(db, { ws: "ws1", state: "ready" }); seedBaselineAndActivation(db, "ws1");
    const { env } = envFor(db, { "reports/scan_gap.json": GAPS() }); await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_gap" });
    const occurrence = await occurrenceMod.findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "cyber_essentials_readiness", record_id: recordId, recurrence_type: "externally_observed_control_not_ready" });
    return { ok: occurrence == null && db.prepare("SELECT COUNT(*) n FROM notification_events WHERE workspace_id='ws1'").get().n === 0, detail: JSON.stringify({ occurrence }) };
  }],
  ["repeated contained evaluation appends no rows events cases or alerts", async () => {
    const db = buildDb(); seedWorkspace(db, "ws1", [{ id: "d1" }, { id: "d2" }]); seedScan(db, { id: "scan_gap", ws: "ws1", domainId: "d1" });
    seedRecord(db, { ws: "ws1", state: "ready" }); const { env } = envFor(db, { "reports/scan_gap.json": GAPS() }); const before = durableState(db, "ws1");
    const runs = []; for (let i = 0; i < 3; i++) runs.push(await evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_gap" }));
    return { ok: runs.every((x) => x.skipped === "workspace_domain_containment") && JSON.stringify(before) === JSON.stringify(durableState(db, "ws1")), detail: JSON.stringify(runs) };
  }],
  ["canonical snapshot and report consumer inventory is pinned", async () => {
    const expected = {
      "routes/workspace-analytics.js": "buildCyberEssentialsReadiness",
      "routes/executive-dashboard.js": "getCyberEssentialsSnapshot",
      "engines/scan-engine.js": "getCyberEssentialsSnapshot",
      "engines/report-snapshot.js": "buildCyberEssentialsReadiness|getCyberEssentialsSnapshot",
    };
    const present = Object.entries(expected).every(([file, pattern]) => pattern.split("|").every((symbol) => new RegExp(`\\b${symbol}\\(`).test(fs.readFileSync(src(...file.split("/")), "utf8"))));
    const snapshotSource = fs.readFileSync(src("engines", "ce-readiness.js"), "utf8");
    return { ok: present && /export async function getCyberEssentialsSnapshot[\s\S]*buildCyberEssentialsReadiness\(wsId, env\)/.test(snapshotSource), detail: JSON.stringify(expected) };
  }],
  ["direct durable readiness reader inventory cannot bypass canonical projection", async () => {
    const files = listJsFiles(src()); const offenders = [];
    for (const file of files) {
      if (file.endsWith(path.join("engines", "ce-lifecycle.js"))) continue;
      const text = fs.readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
      if (/SELECT[\s\S]{0,500}cyber_essentials_control_records/i.test(text)) offenders.push(path.relative(root, file));
    }
    const lifecycle = fs.readFileSync(src("engines", "ce-lifecycle.js"), "utf8");
    const accessors = ["listCeControlRecords", "countCeControlRecords", "getCeControlRecord"];
    const gated = accessors.every((name) => {
      const start = lifecycle.indexOf(`export async function ${name}`);
      const next = lifecycle.indexOf("export async function ", start + 1);
      const body = lifecycle.slice(start, next < 0 ? lifecycle.length : next);
      return body.includes("resolveCeWorkspaceDomainCount") && body.includes("ceWorkspaceContainmentReason");
    });
    return { ok: offenders.length === 0 && gated, detail: JSON.stringify({ offenders, gated }) };
  }],
  ["foreign durable record remains non-enumerating", async () => {
    const db = buildDb(); seedWorkspace(db, "wsA", [{ id: "a" }]); seedWorkspace(db, "wsB", [{ id: "b" }]); const foreignId = seedRecord(db, { id: "foreign-ready", ws: "wsB", state: "ready" });
    const { env } = envFor(db); const item = await getCeControlRecord(env, "wsA", foreignId);
    return { ok: item === null, detail: JSON.stringify(item) };
  }],
  ["frontend neutral not-assessed fixture rejects green zero gaps", async () => runUi("CE-NOT-ASSESSED-GREEN-ZERO-GAPS")],
  ["frontend contained control cards hide current and recorded ready claims", async () => runUi("contained live and durable control cards")],
  ["frontend single-domain positive control path remains visible", async () => runUi("single-domain positive readiness")],
];

if (tests.length !== EXPECTED_ASSERTIONS) {
  console.error(`validator assertion count drift: got ${tests.length}, want ${EXPECTED_ASSERTIONS}`);
  process.exit(2);
}
if (ONLY && !tests.some(([name]) => name === ONLY)) {
  console.error(`unknown targeted assertion: ${ONLY}`);
  process.exit(2);
}

let pass = 0, fail = 0;
for (const [name, test] of tests) {
  if (ONLY && name !== ONLY) continue;
  try {
    const result = await test();
    if (result?.ok) { pass++; console.log(`PASS ${name}`); }
    else { fail++; console.log(`FAIL ${name}${result?.detail ? ` — ${result.detail}` : ""}`); }
  } catch (error) {
    fail++;
    console.log(`FAIL ${name} — runtime: ${error?.stack || error}`);
  }
}

console.log(`\nce-multidomain-containment: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
