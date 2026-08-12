#!/usr/bin/env node
//
// Pre-Item11 Blocker 3 — workspace Related-Changes scope + ASM takeover traceability.
//
// Production evidence (frozen, founder-recorded): a sheshire.co.uk Executive PDF
// rendered "Related Changes observed in this period (1) … New host with a
// certificate signal - cybermeters.com" with no statement that the section is
// workspace-level or which domain the change affects; and "Takeover candidate:
// Observed" passive evidence coexisted with no current-scan finding while an open
// ASM case could remain visible with no honest provenance classification.
//
// This harness drives the REAL engines (related-changes orchestrator, pdf builder,
// attack-surface customer presentation, ASM case engine, real route handlers)
// against an in-memory SQLite (schema.sql + every migration) with D1/R2 shims.
// Fail-first: every assertion here encodes the REQUIRED post-corrective contract.
// Requires Node 24+ (node:sqlite). CI-blocking.
//
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const rte = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "routes", f)).href;

const orch = await import(eng("related-changes.js"));
const pdf = await import(eng("pdf.js"));
const presentation = await import(eng("attack-surface-customer-presentation.js"));
const asmCases = await import(eng("asm-cases.js"));
const snapshotEngine = await import(eng("report-snapshot.js"));
const relatedChangesRoutesModule = await import(rte("related-changes.js"));
const attackSurfaceRoutesModule = await import(rte("attack-surface.js"));
const managedCasesRoutesModule = await import(rte("managed-cases.js"));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  if (!cond) console.log(`FAIL ${name}${detail ? " — " + detail : ""}`);
};

// ── DB / D1 / R2 harness (M6 B1 + posture-events precedent) ──────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema converges */ } };
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
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}
function makeR2() {
  const store = new Map();
  return {
    __store: store,
    async get(key) {
      if (!store.has(key)) return null;
      const raw = store.get(key);
      return { text: async () => raw, json: async () => JSON.parse(raw) };
    },
    async put(key, value) { store.set(key, typeof value === "string" ? value : Buffer.from(value).toString("utf8")); },
  };
}
function makeEnv(db) { return { cybermeters_db: makeD1(db), cybermeters_reports: makeR2() }; }

const sha256 = (v) => crypto.createHash("sha256").update(v).digest("hex");

const T_PREV = "2026-07-01T10:00:00.000Z";
const T_CUR = "2026-07-08T10:00:00.000Z";
const T_MID = "2026-07-08T09:30:00.000Z";
const T_OLD = "2026-06-01T10:00:00.000Z";

let seq = 0;
const nid = (p) => `${p}_${++seq}`;

function seedWorkspace(db, { ws, user, name = "Founder" } = {}) {
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run(user, `${user}@example.co.uk`);
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run(ws, name);
}
function seedDomain(db, { ws, user, domId, domain }) {
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run(domId, user, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run(ws, domId);
}
function seedScan(db, { id, domId, domain, ws, at, quality = "complete" }) {
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run(id, domId, domain, "completed", quality, ws, at);
}
function addAssetEvent(db, { ws, domId, scan, event_type, hostname, at = T_MID }) {
  const id = nid("ae");
  db.prepare("INSERT INTO asset_events (id, workspace_id, domain_id, scan_id, event_type, hostname, severity, description, created_at) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(id, ws, domId, scan, event_type, hostname, "info", "", at);
  return id;
}

// The three founder-recorded workspace domains. blackbull is present so the
// fixture workspace mirrors the production shape (three domains, one workspace).
function seedBlockerWorkspace(db) {
  seedWorkspace(db, { ws: "ws_1", user: "usr_1" });
  seedDomain(db, { ws: "ws_1", user: "usr_1", domId: "dom_she", domain: "sheshire.co.uk" });
  seedDomain(db, { ws: "ws_1", user: "usr_1", domId: "dom_cyb", domain: "cybermeters.com" });
  seedDomain(db, { ws: "ws_1", user: "usr_1", domId: "dom_bbb", domain: "blackbullbarbers.co.uk" });
  seedScan(db, { id: "scan_she_prev", domId: "dom_she", domain: "sheshire.co.uk", ws: "ws_1", at: T_PREV });
  seedScan(db, { id: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk", ws: "ws_1", at: T_CUR });
  seedScan(db, { id: "scan_cyb_prev", domId: "dom_cyb", domain: "cybermeters.com", ws: "ws_1", at: T_PREV });
  seedScan(db, { id: "scan_cyb_cur", domId: "dom_cyb", domain: "cybermeters.com", ws: "ws_1", at: T_CUR });
}

async function correlate(env, { domId = "dom_cyb", scanId = "scan_cyb_cur" } = {}) {
  return orch.correlateRelatedChanges(env, {
    workspaceId: "ws_1", domainId: domId, scanId, scanQuality: "complete", assessedAt: T_CUR,
  });
}

// Minimal-but-real snapshot read shape for the PDF builder (BRS-honesty precedent).
function minimalRead(snapshot) {
  return { snapshot, row: { id: snapshot?.snapshot?.snapshot_id || "snap_x" }, integrity: { verified: true }, dmarcPolicy: null };
}

function minimalReport({ scanId, domId, domain, findings = [], modules = {}, at = T_CUR }) {
  return {
    scan_id: scanId, domain_id: domId, domain,
    status: "completed", started_at: at, completed_at: at,
    cyber_metrics_score: 80, risk_level: "medium",
    scan_quality: { status: "complete" },
    findings, modules,
  };
}

function composeMinimalSnapshot({ scanId, domId, domain, findings = [], modules = {}, at = T_CUR, ws = "ws_1" }) {
  return snapshotEngine.composeSnapshot({
    snapshotId: `snap_${scanId}`, workspaceId: ws, domainId: domId, scanId, domain,
    report: minimalReport({ scanId, domId, domain, findings, modules, at }),
    cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    supersedesSnapshotId: null, builtAt: at,
  });
}

// Persist a completed, checksum-bound snapshot row + R2 object (immutable law:
// the harness writes it once and never mutates it afterwards).
function persistSnapshot(db, env, snapshot, { ws = "ws_1", at = T_CUR } = {}) {
  const meta = snapshot.snapshot;
  const raw = JSON.stringify(snapshot, null, 2);
  const key = `reports/snapshots/${ws}/${meta.scan_id}/${meta.snapshot_id}.json`;
  env.cybermeters_reports.__store.set(key, raw);
  db.prepare(`INSERT INTO scan_report_snapshots
      (id, workspace_id, domain_id, scan_id, status, r2_key, checksum_sha256, size_bytes,
       snapshot_schema_version, resolver_version, scan_quality, assessed_at, created_at, completed_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(meta.snapshot_id, ws, meta.domain_id, meta.scan_id, "completed", key, sha256(raw),
      Buffer.byteLength(raw), String(meta.snapshot_schema_version), "harness", "complete", at, at, at);
  return { key, raw };
}

const TAKEOVER_FINDING = Object.freeze({
  id: "subdomain_takeover",
  finding_type: "finding",
  module: "subdomain_takeover",
  severity: "high",
  score_impact: -15,
  title: "Subdomain takeover risk detected",
  description: "A dangling CNAME with a matching provider fingerprint was observed.",
  affected_hosts: ["shop.sheshire.co.uk"],
});

function insertAsmCase(db, {
  id, ws = "ws_1", domain = "sheshire.co.uk", findingId = "subdomain_takeover",
  status = "open", sourceScanId = null, evidenceScanId = null, reopened = 0, createdAt = T_OLD,
}) {
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, source_finding_type, source_scan_id,
       asset_ref, severity, status, evidence_json, reopened_count, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, ws, "asm_exposure", "attack_surface", domain, findingId, findingId, sourceScanId,
      "shop.sheshire.co.uk", "high", status,
      JSON.stringify(evidenceScanId ? { scan_id: evidenceScanId, finding: { id: findingId } } : { finding: { id: findingId } }),
      reopened, createdAt, createdAt);
}

// Row-level fingerprint of every historical store the projection must not touch.
function historyFingerprint(db) {
  const dump = (sql) => JSON.stringify(db.prepare(sql).all());
  return sha256([
    dump("SELECT * FROM managed_cases ORDER BY id"),
    dump("SELECT * FROM managed_case_events ORDER BY id"),
    dump("SELECT * FROM scan_report_snapshots ORDER BY id"),
    dump("SELECT * FROM related_changes ORDER BY id"),
    dump("SELECT * FROM related_change_evidence ORDER BY id"),
  ].join("\0"));
}

// Invoke a REAL route handler with a stubbed request context.
async function callRoute(handler, env, { method = "GET", path: routePath, body = null, role = true }) {
  const url = new URL(`https://api.example${routePath}`);
  const request = new Request(url, {
    method,
    ...(body ? { body: JSON.stringify(body), headers: { "content-type": "application/json" } } : {}),
  });
  let out = null;
  const json = (payload, status = 200) => { out = { status, body: payload }; return out; };
  const res = await handler({
    request, env, url, json,
    requireAuth: async () => ({ id: "usr_1" }),
    requireWorkspaceRole: async () => role,
  });
  return res === null ? null : out;
}

// Extract the PDF's shown text: collect every `(...) Tj` show-string, unescape
// the PDF string escapes (\( \) \\), and whitespace-normalize so a sentence the
// writer wrapped across lines can still be matched as one phrase. Raw-byte
// matching would silently pass/fail on escaping artefacts instead of content.
const pdfText = (bytes) => {
  const raw = new TextDecoder("latin1").decode(bytes);
  const parts = [];
  for (const m of raw.matchAll(/\(((?:\\.|[^\\)])*)\) Tj/g)) {
    parts.push(m[1].replace(/\\([()\\])/g, "$1"));
  }
  return parts.join("\n").replace(/\s+/g, " ");
};

// ═════════════════════════════════════════════════════════════════════════════
// DEFECT A — workspace Related-Changes scope attribution
// ═════════════════════════════════════════════════════════════════════════════

// ── A1: sheshire.co.uk report carrying a cybermeters.com change ──────────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "new_asset_discovered", hostname: "app.cybermeters.com" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "certificate_new_detected", hostname: "app.cybermeters.com" });
  await correlate(env);
  const summary = await orch.buildRelatedChangesSummary(env, "ws_1");
  ok("A1a summary declares workspace scope", summary?.scope === "workspace");
  ok("A1b summary carries the workspace scope note",
    typeof summary?.scope_note === "string" && /workspace-level/i.test(summary.scope_note));
  ok("A1c summary item names the canonical affected domain",
    summary?.items?.length === 1 && summary.items[0].affected_domain === "cybermeters.com");

  const snapshot = composeMinimalSnapshot({ scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk" });
  const bytes = pdf.buildScanReportPdf(
    { id: "scan_she_cur", domain_id: "dom_she", domain: "sheshire.co.uk" },
    minimalRead(snapshot), null, null, summary,
  );
  const text = pdfText(bytes);
  ok("A1d PDF section heading is workspace-level",
    text.includes("Workspace-level Related Changes observed in this period (1)"));
  ok("A1e PDF row names the affected domain", text.includes("affects cybermeters.com"));
  ok("A1f PDF never attributes a cross-domain change to the report subject",
    !text.includes("affects sheshire.co.uk") &&
    !text.includes("New host with a certificate signal - sheshire.co.uk") &&
    text.includes("not necessarily a change to sheshire.co.uk"));
  ok("A1g PDF renders the workspace scope note", text.includes("workspace-level: related changes are correlated across all domains"));
}

// ── A2: same-domain change keeps explicit workspace scope + correct domain ───
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  addAssetEvent(db, { ws: "ws_1", domId: "dom_she", scan: "scan_she_cur", event_type: "new_asset_discovered", hostname: "mail.sheshire.co.uk" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_she", scan: "scan_she_cur", event_type: "certificate_new_detected", hostname: "mail.sheshire.co.uk" });
  await correlate(env, { domId: "dom_she", scanId: "scan_she_cur" });
  const summary = await orch.buildRelatedChangesSummary(env, "ws_1");
  const snapshot = composeMinimalSnapshot({ scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk" });
  const text = pdfText(pdf.buildScanReportPdf(
    { id: "scan_she_cur", domain_id: "dom_she", domain: "sheshire.co.uk" },
    minimalRead(snapshot), null, null, summary,
  ));
  ok("A2a same-domain row stays workspace-labeled with its affected domain",
    text.includes("Workspace-level Related Changes observed in this period (1)") &&
    text.includes("affects sheshire.co.uk") &&
    summary.items[0].affected_domain === "sheshire.co.uk");
  ok("A2b same-domain row is marked as the report's own domain",
    text.includes("this report's domain"));
}

// ── A3: multiple domains — deterministic ordering, every affected domain ─────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "new_asset_discovered", hostname: "a.cybermeters.com" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "certificate_new_detected", hostname: "a.cybermeters.com" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_she", scan: "scan_she_cur", event_type: "new_asset_discovered", hostname: "b.sheshire.co.uk" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_she", scan: "scan_she_cur", event_type: "certificate_new_detected", hostname: "b.sheshire.co.uk" });
  await correlate(env);
  await correlate(env, { domId: "dom_she", scanId: "scan_she_cur" });
  const s1 = await orch.buildRelatedChangesSummary(env, "ws_1");
  const s2 = await orch.buildRelatedChangesSummary(env, "ws_1");
  const affected = (s1.items || []).map((i) => i.affected_domain).sort();
  ok("A3a multi-domain summary is deterministic and retains each affected domain",
    JSON.stringify(s1) === JSON.stringify(s2) &&
    s1.items.length === 2 &&
    JSON.stringify(affected) === JSON.stringify(["cybermeters.com", "sheshire.co.uk"]));
}

// ── A4: an identically shaped change in ANOTHER workspace is excluded ────────
{
  const db = buildDb(); seedBlockerWorkspace(db);
  seedWorkspace(db, { ws: "ws_2", user: "usr_2", name: "Other" });
  seedDomain(db, { ws: "ws_2", user: "usr_2", domId: "dom_other", domain: "othertenant.co.uk" });
  seedScan(db, { id: "scan_o_prev", domId: "dom_other", domain: "othertenant.co.uk", ws: "ws_2", at: T_PREV });
  seedScan(db, { id: "scan_o_cur", domId: "dom_other", domain: "othertenant.co.uk", ws: "ws_2", at: T_CUR });
  const env = makeEnv(db);
  addAssetEvent(db, { ws: "ws_2", domId: "dom_other", scan: "scan_o_cur", event_type: "new_asset_discovered", hostname: "x.othertenant.co.uk" });
  addAssetEvent(db, { ws: "ws_2", domId: "dom_other", scan: "scan_o_cur", event_type: "certificate_new_detected", hostname: "x.othertenant.co.uk" });
  await orch.correlateRelatedChanges(env, { workspaceId: "ws_2", domainId: "dom_other", scanId: "scan_o_cur", scanQuality: "complete", assessedAt: T_CUR });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "new_asset_discovered", hostname: "y.cybermeters.com" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "certificate_new_detected", hostname: "y.cybermeters.com" });
  await correlate(env);
  const summary = await orch.buildRelatedChangesSummary(env, "ws_1");
  ok("A4a different-workspace change is excluded from the summary",
    summary.items.length === 1 && summary.items.every((i) => i.affected_domain !== "othertenant.co.uk"));
  const snapshot = composeMinimalSnapshot({ scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk" });
  const text = pdfText(pdf.buildScanReportPdf(
    { id: "scan_she_cur", domain_id: "dom_she", domain: "sheshire.co.uk" },
    minimalRead(snapshot), null, null, summary,
  ));
  ok("A4b different-workspace change is excluded from the PDF", !text.includes("othertenant.co.uk"));
}

// ── A5: API projection exposes scope + affected domain (real route) ──────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "new_asset_discovered", hostname: "z.cybermeters.com" });
  addAssetEvent(db, { ws: "ws_1", domId: "dom_cyb", scan: "scan_cyb_cur", event_type: "certificate_new_detected", hostname: "z.cybermeters.com" });
  await correlate(env);
  const res = await callRoute(relatedChangesRoutesModule.relatedChangesRoutes, env, {
    path: "/api/workspaces/ws_1/related-changes",
  });
  const rc = res?.body?.related_changes?.[0];
  ok("A5a API cluster projection exposes workspace scope and affected domain",
    res?.status === 200 && rc?.scope === "workspace" && rc?.affected_domain === "cybermeters.com" &&
    typeof res.body.workspace_scope_note === "string" && /workspace-level/i.test(res.body.workspace_scope_note));
  ok("A5b API projection keeps every existing field (compatibility)",
    rc?.registrable_domain === "cybermeters.com" && rc?.rule_id === "new_host_with_cert" &&
    typeof rc?.customer_state === "string" && "linked_case_id" in rc);
  const detail = await callRoute(relatedChangesRoutesModule.relatedChangesRoutes, env, {
    path: `/api/workspaces/ws_1/related-changes/${rc.id}`,
  });
  ok("A5c API detail projection carries scope and affected domain",
    detail?.status === 200 && detail.body.related_change?.scope === "workspace" &&
    detail.body.related_change?.affected_domain === "cybermeters.com");
}

// ═════════════════════════════════════════════════════════════════════════════
// DEFECT B — takeover observation / finding / case traceability
// ═════════════════════════════════════════════════════════════════════════════

// ── B1: passive takeover observation is informational, never a confirmation ──
{
  const built = presentation.buildAttackSurfaceCustomerPresentation({
    signalCompleteness: {
      model_version: "attack-surface-signal-completeness-v2",
      signals: {
        takeover_candidate: {
          state: "observed", reason: "takeover_candidate_observed",
          evidence_count: 1, sources: ["dns_cname", "provider_fingerprint"], limitations: [],
        },
      },
    },
    asOf: T_CUR,
  });
  const sig = built.signals?.takeover_candidate;
  ok("B1a takeover observed presentation is informational, never confirmed",
    sig?.state === "observed" && sig?.state_label === "Observed" &&
    /not a confirmed takeover/.test(sig?.customer_message || "") &&
    /not a verified exploitable vulnerability/.test(sig?.customer_message || "") &&
    /does not establish maliciousness or compromise/.test(sig?.customer_message || "") &&
    !/confirmed takeover was/.test(sig?.customer_message || ""));

  // A FROZEN historical snapshot whose recorded prose predates this corrective is
  // re-projected from its preserved state identities (P5 wording precedent). The
  // stored object stays byte-identical; only the read-time prose is canonical.
  const frozen = {
    schema: "attack-surface-customer-presentation-v1",
    status: "current",
    signals: {
      takeover_candidate: {
        signal_key: "takeover_candidate", label: "Takeover candidate", status: "recorded",
        state: "observed", state_label: "Observed",
        customer_message: "Takeover candidate evidence was observed in the recorded scope. Detection alone does not establish maliciousness or compromise.",
        reason: "takeover_candidate_observed", evidence_count: 1, sources: [], limitations: [],
        coverage_state: "not_recorded", coverage: null,
      },
    },
    lifecycle: { status: "not_recorded", records: [], customer_message: "n/a" },
    alert_eligibility: { status: "not_recorded", decisions: [], customer_message: "n/a" },
  };
  const projected = presentation.attackSurfaceAssuranceFromSnapshot({ attack_surface_assurance: frozen });
  ok("B1b frozen takeover observed message is re-projected to the canonical wording",
    /not a confirmed takeover/.test(projected.signals?.takeover_candidate?.customer_message || ""));
}

// ── B2: passive candidate creates NO finding and NO case ─────────────────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  // Snapshot for the current scan: takeover module ran, unconfirmed candidate only,
  // NO takeover finding (the finding contract is not satisfied).
  const snapshot = composeMinimalSnapshot({
    scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk",
    modules: { subdomain_takeover: { checked: 5, risks: [], unconfirmed: [{ host: "shop.sheshire.co.uk", reason: "probe_refused" }], potential_risks: 1 } },
  });
  persistSnapshot(db, env, snapshot);
  ok("B2a an unconfirmed candidate never satisfies the finding contract",
    (snapshot.observed_findings || []).every((f) => f.finding_id !== "subdomain_takeover") &&
    (snapshot.observations || []).every((f) => f.finding_id !== "subdomain_takeover"));
  const trace = await asmCases.deriveAsmCaseTraceability?.(env, "ws_1", []);
  ok("B2b traceability over no cases fabricates nothing",
    trace instanceof Map && trace.size === 0 &&
    db.prepare("SELECT COUNT(*) c FROM managed_cases").get().c === 0);
}

// ── B6/B7/B8: linked vs retained-historical vs identifiers ───────────────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  // Current sheshire scan HAS the takeover finding.
  persistSnapshot(db, env, composeMinimalSnapshot({
    scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk",
    findings: [TAKEOVER_FINDING],
    modules: { subdomain_takeover: { checked: 5, risks: [{ host: "shop.sheshire.co.uk" }], unconfirmed: [] } },
  }));
  insertAsmCase(db, { id: "case_linked", sourceScanId: "scan_she_old", evidenceScanId: "scan_she_old" });
  const trace = await asmCases.deriveAsmCaseTraceability?.(env, "ws_1",
    db.prepare("SELECT * FROM managed_cases").all());
  const t = trace?.get("case_linked");
  ok("B6a case with a qualifying current finding is linked to current evidence",
    t?.relationship === "linked_current_evidence" &&
    t?.current_scan?.scan_id === "scan_she_cur" && t?.current_scan?.assessed === true);
  ok("B8a linkage preserves exact bounded identifiers",
    t?.case_id === "case_linked" && t?.finding_id === "subdomain_takeover" &&
    t?.origin?.scan_id === "scan_she_old" && t?.origin?.known === true &&
    t?.affected?.domain === "sheshire.co.uk");
}
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  // Current sheshire scan has NO takeover finding; the open case predates it.
  persistSnapshot(db, env, composeMinimalSnapshot({
    scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk",
    modules: { subdomain_takeover: { checked: 5, risks: [], unconfirmed: [] } },
  }));
  insertAsmCase(db, { id: "case_hist", sourceScanId: "scan_she_old", evidenceScanId: "scan_she_old" });
  const trace = await asmCases.deriveAsmCaseTraceability?.(env, "ws_1",
    db.prepare("SELECT * FROM managed_cases").all());
  const t = trace?.get("case_hist");
  ok("B7a open case without a current finding is retained historical",
    t?.relationship === "retained_historical" &&
    /not.*absent, removed or remediated/i.test(t?.customer_message || ""));
  ok("B7b historical case is never attributed to the current scan",
    t?.origin?.scan_id === "scan_she_old" &&
    t?.current_scan?.scan_id === "scan_she_cur" &&
    t?.relationship !== "linked_current_evidence" &&
    t?.current_scan?.has_matching_finding === false);
}

// ── B-recurrence: lifecycle recurrence/monitoring states are honest ──────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  persistSnapshot(db, env, composeMinimalSnapshot({
    scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk",
    modules: { subdomain_takeover: { checked: 5, risks: [], unconfirmed: [] } },
  }));
  insertAsmCase(db, { id: "case_reopened", status: "reopened", sourceScanId: "scan_she_old", evidenceScanId: "scan_she_old", reopened: 1 });
  const trace = await asmCases.deriveAsmCaseTraceability?.(env, "ws_1",
    db.prepare("SELECT * FROM managed_cases").all());
  const t = trace?.get("case_reopened");
  ok("B7c reopened case without a current finding reads as recurrence/monitoring",
    t?.relationship === "recurrence_monitoring" &&
    !/new observation/.test((t?.customer_message || "").replace("not a new observation", "")));
}

// ── B9: "not observed" never claims absence / removal / remediation ──────────
{
  const built = presentation.buildAttackSurfaceCustomerPresentation({
    signalCompleteness: {
      model_version: "attack-surface-signal-completeness-v2",
      signals: { takeover_candidate: { state: "not_observed", reason: "complete_takeover_probe_no_candidate", evidence_count: 0 } },
    },
    lifecycleRecords: [{ asset_id: "a1", hostname: "shop.sheshire.co.uk", lifecycle_state: "not_observed", last_observation_state: "not_observed" }],
    asOf: T_CUR,
  });
  const sig = built.signals?.takeover_candidate;
  const rec = built.lifecycle?.records?.[0];
  ok("B9a not-observed wording never claims absence or removal",
    /No absence or removal conclusion is inferred/.test(sig?.customer_message || "") &&
    /not confirmed removal/.test(rec?.lifecycle_message || "") &&
    !/is removed|was removed|is absent\b/.test(sig?.customer_message || ""));
}

// ── B10: legacy case with irreducible provenance ─────────────────────────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  persistSnapshot(db, env, composeMinimalSnapshot({
    scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk",
    modules: { subdomain_takeover: { checked: 5, risks: [], unconfirmed: [] } },
  }));
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, severity, status, evidence_json, reopened_count, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run("case_legacy", "ws_1", "asm_exposure", "attack_surface", "sheshire.co.uk",
      "subdomain_takeover_legacy", "high", "open", JSON.stringify({ finding: {} }), 0, T_OLD, T_OLD);
  const trace = await asmCases.deriveAsmCaseTraceability?.(env, "ws_1",
    db.prepare("SELECT * FROM managed_cases").all());
  const t = trace?.get("case_legacy");
  ok("B10a legacy case provenance is explicit unknown, never attributed to a scan",
    t?.relationship === "legacy_unknown" && t?.origin?.known === false && t?.origin?.scan_id === null &&
    /legacy or unknown/i.test(t?.customer_message || "") && /remains visible/i.test(t?.customer_message || ""));
}

// ── B11: parity — universal route, ASM route, engine, PDF ────────────────────
{
  const db = buildDb(); seedBlockerWorkspace(db); const env = makeEnv(db);
  persistSnapshot(db, env, composeMinimalSnapshot({
    scanId: "scan_she_cur", domId: "dom_she", domain: "sheshire.co.uk",
    modules: { subdomain_takeover: { checked: 5, risks: [], unconfirmed: [] } },
  }));
  insertAsmCase(db, { id: "case_parity", sourceScanId: "scan_she_old", evidenceScanId: "scan_she_old" });
  const before = historyFingerprint(db);

  const universal = await callRoute(managedCasesRoutesModule.managedCasesRoutes, env, {
    path: "/api/workspaces/ws_1/cases",
  });
  const asm = await callRoute(attackSurfaceRoutesModule.attackSurfaceRoutes, env, {
    path: "/api/workspaces/ws_1/managed-cases",
  });
  const uc = universal?.body?.cases?.find((c) => c.case_id === "case_parity");
  const ac = asm?.body?.cases?.find((c) => c.id === "case_parity");
  ok("B11a universal and ASM case surfaces attach identical traceability",
    Boolean(uc?.traceability) && Boolean(ac?.traceability) &&
    JSON.stringify(uc.traceability) === JSON.stringify(ac.traceability) &&
    uc.traceability.relationship === "retained_historical");
  const universalDetail = await callRoute(managedCasesRoutesModule.managedCasesRoutes, env, {
    path: "/api/workspaces/ws_1/cases/case_parity",
  });
  ok("B11b case detail surfaces the same traceability classification",
    universalDetail?.body?.case?.traceability?.relationship === "retained_historical" &&
    JSON.stringify(universalDetail.body.case.traceability) === JSON.stringify(uc.traceability));

  // PDF parity: the canonical takeover wording travels into the Executive PDF via
  // attackSurfaceAssuranceFromSnapshot re-projection — the PDF derives nothing.
  const frozenSnap = composeMinimalSnapshot({
    scanId: "scan_she_prev", domId: "dom_she", domain: "sheshire.co.uk",
    modules: {},
  });
  frozenSnap.attack_surface_assurance = {
    schema: "attack-surface-customer-presentation-v1",
    status: "current",
    signal_order: ["takeover_candidate"],
    signals: {
      takeover_candidate: {
        signal_key: "takeover_candidate", label: "Takeover candidate", status: "recorded",
        state: "observed", state_label: "Observed",
        customer_message: "Takeover candidate evidence was observed in the recorded scope. Detection alone does not establish maliciousness or compromise.",
        reason: "takeover_candidate_observed", evidence_count: 1, sources: [], limitations: [],
        coverage_state: "not_recorded", coverage: null,
      },
    },
    lifecycle: { status: "not_recorded", records: [], customer_message: "n/a" },
    alert_eligibility: { status: "not_recorded", decisions: [], customer_message: "n/a" },
  };
  const text = pdfText(pdf.buildScanReportPdf(
    { id: "scan_she_prev", domain_id: "dom_she", domain: "sheshire.co.uk" },
    minimalRead(frozenSnap), null, null, null,
  ));
  ok("B11c PDF renders the canonical takeover wording via the shared projection",
    text.includes("not a confirmed takeover"));

  ok("B12d traceability projection never mutates case rows or history",
    historyFingerprint(db) === before);
}

// ── B12: tenant isolation, soft delete, permission ───────────────────────────
{
  const db = buildDb(); seedBlockerWorkspace(db);
  seedWorkspace(db, { ws: "ws_2", user: "usr_2", name: "Other" });
  seedDomain(db, { ws: "ws_2", user: "usr_2", domId: "dom_other", domain: "othertenant.co.uk" });
  const env = makeEnv(db);
  insertAsmCase(db, { id: "case_foreign", ws: "ws_2", domain: "othertenant.co.uk", sourceScanId: "scan_f", evidenceScanId: "scan_f" });
  const list = await callRoute(managedCasesRoutesModule.managedCasesRoutes, env, {
    path: "/api/workspaces/ws_1/cases",
  });
  ok("B12a foreign-workspace cases are invisible through the case surface",
    list?.status === 200 && (list.body.cases || []).every((c) => c.case_id !== "case_foreign"));
  const forbidden = await callRoute(managedCasesRoutesModule.managedCasesRoutes, env, {
    path: "/api/workspaces/ws_1/cases", role: false,
  });
  ok("B12b read permission is enforced", forbidden?.status === 403);
  db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'ws_1'").run();
  const deleted = await callRoute(managedCasesRoutesModule.managedCasesRoutes, env, {
    path: "/api/workspaces/ws_1/cases",
  });
  ok("B12c soft-deleted workspace behaves as absent", deleted?.status === 404);
}

// ── B13: frontend consumes the backend classification verbatim (source contract)
{
  const detailSrc = fs.readFileSync(path.join(root, "frontend", "src", "pages", "ws", "WorkspaceCaseDetailPage.jsx"), "utf8");
  ok("B13a case detail page renders backend relationship label + message verbatim",
    detailSrc.includes("traceability.relationship_label") &&
    detailSrc.includes("traceability.customer_message"));
  ok("B13b frontend never derives the relationship from raw enum values",
    !/(['"`])(linked_current_evidence|retained_historical|recurrence_monitoring|legacy_unknown)\1/.test(detailSrc));
  const listSrc = fs.readFileSync(path.join(root, "frontend", "src", "components", "RelatedChangesList.jsx"), "utf8");
  ok("B13c related-changes list surfaces the affected domain",
    listSrc.includes("affected_domain"));
}

const total = pass + fail;
console.log(`\nReport scope & takeover traceability: ${pass} passed, ${fail} failed (${total} total)`);
if (fail > 0) { console.error("report scope & traceability validation FAILED"); process.exit(1); }
console.log("report scope & traceability validation passed");
