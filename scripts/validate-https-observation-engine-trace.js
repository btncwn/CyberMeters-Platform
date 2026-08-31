#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-https-observation-engine-trace.js  (CI-blocking)
//
// PR-A faithful runScanEngine trace. The unit matrix proves the classifier; this
// proves the WHOLE pipeline — real runScanEngine, real D1 (in-memory SQLite with
// schema + migrations applied), real R2 shim, real report — so a fix that works in
// isolation but is discarded downstream cannot pass.
//
// Four propagation properties, each the customer-visible end of the reported harm:
//   T1 an edge-synthesised error CANNOT generate ssl_not_available;
//   T2 it reaches Cyber Essentials as unknown/incomplete, NOT a control gap;
//   T3 a genuine origin 500 PROVES HTTPS transport, while the application-health
//      fact stays separately available;
//   T4 independently reliable sibling evidence remains publishable — one
//      inconclusive signal never erases the rest of the scan.
//
// No live D1/R2/network: every outbound fetch is routed by the fixture. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engUrl = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;
const { runScanEngine } = await import(engUrl("scan-engine.js"));

const NOW = "2026-07-28T13:00:00.000Z";
const NOW_MS = Date.parse(NOW);

let passed = 0, failed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => { try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* schema/migration overlap is intentional */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const stmt = (sql, args = []) => ({
    __sql: sql,
    bind: (...b) => stmt(sql, b),
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } }; },
  });
  return {
    prepare: (sql) => stmt(sql),
    batch: async (list) => {
      const out = []; db.exec("BEGIN");
      try { for (const s of list) out.push(/^\s*select/i.test(s.__sql) ? await s.all() : await s.run()); db.exec("COMMIT"); return out; }
      catch (e) { db.exec("ROLLBACK"); throw e; }
    },
    exec: async (sql) => { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeR2(store) {
  return {
    get: async (k) => { const b = store.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store.set(String(k), String(b)); return {}; },
    delete: async (k) => { store.delete(String(k)); return {}; },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// `httpsMode` decides ONLY what the origin does on https://example.com — every
// other dependency (DNS, CT) answers identically across scenarios, so any
// difference in the report is attributable to the HTTPS observation alone.
function installFetch(httpsMode) {
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    const host = url.hostname;
    if (host === "crt.sh" || host === "api.certspotter.com") {
      // A reliable SIBLING signal: CT is independent of origin reachability and
      // must keep producing evidence whatever the HTTPS probe saw (T4).
      return host === "crt.sh" ? json([]) : json([{
        id: "trace-cert", not_before: "2026-06-27T00:00:00.000Z", not_after: "2026-09-25T00:00:00.000Z",
        issuer: { name: "PR-A Fixture CA" }, dns_names: ["example.com", "www.example.com"],
      }]);
    }
    if (host === "cloudflare-dns.com" || host === "dns.google") {
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      const type = String(url.searchParams.get("type") || "A").toUpperCase();
      if (name === "example.com" && type === "A") return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
      return json({ Status: 0, Answer: [] });
    }
    // http:// answers with a GENUINE origin 301 in every scenario. The redirect
    // probe drawing a definitive verdict from a Cloudflare edge response is a real
    // defect, but it is PR-A2's scope — isolating it here keeps this trace a test of
    // HTTPS observation classification and not of the redirect path.
    if (url.protocol === "http:" && (host === "example.com" || host === "www.example.com")) {
      return new Response("", { status: 301, headers: { location: `https://${host}/`, server: "nginx" } });
    }
    if (url.protocol === "https:" && (host === "example.com" || host === "www.example.com")) {
      if (httpsMode === "edge_522") return new Response("edge", { status: 522, headers: { server: "cloudflare", "content-type": "text/html" } });
      if (httpsMode === "edge_530") return new Response("edge", { status: 530, headers: { server: "cloudflare", "content-type": "text/html" } });
      if (httpsMode === "origin_500") return new Response("boom", { status: 500, headers: { server: "nginx", "content-type": "text/html" } });
      return new Response("<html><title>Example</title></html>", { status: 200, headers: { server: "nginx", "content-type": "text/html" } });
    }
    return new Response("<html><title>Example</title></html>", { status: 200, headers: { "content-type": "text/html", server: "pra-trace" } });
  };
}

async function trace(httpsMode) {
  const db = buildDb();
  const store = new Map();
  const env = {
    cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "115000", APP_VERSION: "pra-engine-trace",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','owner@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','PR-A',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
              VALUES ('scan-pra','ws','dom','example.com','running',NULL,?)`).run(NOW);

  const prevFetch = globalThis.fetch;
  const prevErr = console.error;
  installFetch(httpsMode);
  console.error = () => {};                       // benign module-level noise
  let engineError = null;
  try {
    await runScanEngine("scan-pra", "dom", "ws", "example.com", env,
      { now: () => NOW_MS, executionContext: "queue", trigger: "manual" });
  } catch (e) { engineError = e; }
  finally { globalThis.fetch = prevFetch; console.error = prevErr; }

  const raw = store.get("reports/scan-pra.json");
  const report = raw ? JSON.parse(raw) : null;
  // The findings table persists the customer-visible TITLE (no finding_id column),
  // so this asserts on the exact string the founder's domain was sent: "HTTPS Not Available".
  const findings = db.prepare("SELECT title, severity FROM findings WHERE scan_id='scan-pra'").all().map((r) => r.title);
  // PR-A1: the honest-state oracle. Absence of a bad finding is not proof of an
  // honest assessment — the persisted per-domain state is what the customer reads.
  const domainStates = {};
  for (const r of db.prepare("SELECT domain_key, state, coverage, summary FROM cyber_mot_domain_states WHERE scan_id='scan-pra'").all()) {
    domainStates[r.domain_key] = r;
  }
  const persistedQuality = db.prepare("SELECT scan_quality FROM scans WHERE id='scan-pra'").get()?.scan_quality ?? null;
  return { db, report, findings, engineError, domainStates, persistedQuality };
}

// ── T1/T2/T4 — Cloudflare-synthesised edge error ─────────────────────────────
for (const mode of ["edge_522", "edge_530"]) {
  const t = await trace(mode);
  ok(`T1 ${mode}: engine completed and wrote a report`, t.report !== null,
    String(t.engineError?.message || "no report"));
  const ssl = t.report?.modules?.ssl || {};
  ok(`T1 ${mode}: https_available is NULL, never false`,
    ssl.https_available === null, JSON.stringify(ssl.https_available));
  ok(`T1 ${mode}: observation state is the edge error, and the probe DID execute`,
    ssl.https_observation_state === "cloudflare_edge_error" && ssl.https_probe_executed === true,
    JSON.stringify({ s: ssl.https_observation_state, e: ssl.https_probe_executed }));
  // THE REPORTED HARM: a critical finding telling the owner to install a certificate.
  const reportIds = (t.report?.findings || []).map((f) => f.id);
  ok(`T1 ${mode}: NO ssl_not_available finding in the report`, !reportIds.includes("ssl_not_available"),
    reportIds.join(","));
  ok(`T1 ${mode}: NO "HTTPS Not Available" finding persisted to D1`, !t.findings.includes("HTTPS Not Available"),
    t.findings.join(","));

  // T2 — Cyber Essentials must read this as unknown/incomplete, not a control gap.
  const ce = t.report?.cyber_essentials || t.report?.modules?.cyber_essentials || null;
  const ceText = JSON.stringify(ce || {});
  ok(`T2 ${mode}: Cyber Essentials does not record an HTTPS control GAP from an edge error`,
    !/"https_available"\s*:\s*false/.test(ceText) && !/no_https|https_missing/.test(ceText),
    ceText.slice(0, 200));

  // ── PR-A1 T5 — POSITIVE honest states, not merely absence of a bad finding ──
  ok(`T5 ${mode}: SSL module carries canonical incompleteness`,
    ssl.incomplete === true && ssl.incomplete_reason === "https_origin_not_observed",
    JSON.stringify({ i: ssl.incomplete, r: ssl.incomplete_reason }));
  ok(`T5 ${mode}: https_probe_executed stays TRUTHFUL (an edge Response DID execute)`,
    ssl.https_probe_executed === true);
  ok(`T5 ${mode}: global scan_quality is PARTIAL, in the report and in D1`,
    t.report?.scan_quality?.status === "partial" && t.persistedQuality === "partial",
    JSON.stringify({ rep: t.report?.scan_quality?.status, d1: t.persistedQuality }));
  ok(`T5 ${mode}: SSL appears in canonical incompleteness metadata`,
    (t.report?.scan_quality?.modules_skipped || []).includes("ssl") &&
    (t.report?.scan_quality?.warnings || []).some((w) => /ssl/.test(w)),
    JSON.stringify(t.report?.scan_quality));
  const ws = t.domainStates.website_security || {};
  ok(`T5 ${mode}: website_security is evidence_insufficient, coverage NOT complete`,
    ws.state === "evidence_insufficient" && ws.coverage !== "complete",
    JSON.stringify(ws));
  const ct = t.domainStates.certificates_trust || {};
  // certificates_trust REQUIRES certificate_intelligence (CT), which WAS collected,
  // so the existing contract yields `provisional` + non-complete coverage rather
  // than evidence_insufficient. What matters for the law is that it is NOT healthy
  // and NOT complete. Changing its required-module set is an eight-domain semantics
  // decision deliberately NOT taken in this PR.
  ok(`T5 ${mode}: certificates_trust is NOT assessed_healthy and coverage NOT complete`,
    ct.state !== "assessed_healthy" && ct.coverage !== "complete",
    JSON.stringify(ct));
  for (const [key, row] of [["website_security", ws], ["certificates_trust", ct]]) {
    ok(`T5 ${mode}: ${key} does NOT say "Assessed — no material issue observed"`,
      !/Assessed — no material issue observed/.test(String(row.summary || "")),
      String(row.summary));
  }
  const signals = t.report?.monitoring_states?.signals || {};
  ok(`T5 ${mode}: website_security monitoring state is NOT monitoring_healthy`,
    signals.website_security?.state !== "monitoring_healthy",
    JSON.stringify(signals.website_security));
  // CE must resolve to a positive unknown, not merely "no gap string found".
  const ceState = t.domainStates.cyber_essentials_readiness || {};
  ok(`T5 ${mode}: Cyber Essentials is unknown/insufficient, never a control GAP`,
    ["customer_input_required", "evidence_insufficient", "not_yet_assessed", "provisional"].includes(ceState.state) &&
    ceState.coverage !== "complete",
    JSON.stringify(ceState));

  // T4 — the reliable sibling (CT-derived certificate identity) still publishes.
  ok(`T4 ${mode}: reliable sibling CT evidence is still published`,
    (ssl.cert_not_after || ssl.cert_issuer || ssl.cert_subject) != null,
    JSON.stringify({ na: ssl.cert_not_after, iss: ssl.cert_issuer }));
}

// ── T3 — genuine origin 500 ──────────────────────────────────────────────────
{
  const t = await trace("origin_500");
  const ssl = t.report?.modules?.ssl || {};
  ok("T3 origin 500: engine completed and wrote a report", t.report !== null,
    String(t.engineError?.message || "no report"));
  ok("T3 origin 500: HTTPS transport is PROVEN (https_available true)",
    ssl.https_available === true, JSON.stringify(ssl.https_available));
  ok("T3 origin 500: the application-health fact is retained separately",
    ssl.https_origin_status === 500 && ssl.https_observation_state === "origin_response",
    JSON.stringify({ st: ssl.https_origin_status, s: ssl.https_observation_state }));
  ok("T3 origin 500: SSL module is NOT marked incomplete (transport WAS observed)",
    ssl.incomplete !== true && ssl.incomplete_reason === undefined,
    JSON.stringify({ i: ssl.incomplete, r: ssl.incomplete_reason }));
  ok("T3 origin 500: SSL is NOT listed in canonical incompleteness metadata",
    !(t.report?.scan_quality?.modules_skipped || []).includes("ssl"),
    JSON.stringify(t.report?.scan_quality?.modules_skipped));
  ok("T3 origin 500: NO ssl_not_available finding (5xx is not certificate absence)",
    !t.findings.includes("HTTPS Not Available") &&
    !(t.report?.findings || []).map((f) => f.id).includes("ssl_not_available"),
    t.findings.join(","));
}

// ── Positive control — a healthy 200 still reads as available ────────────────
{
  const t = await trace("origin_200");
  const ssl = t.report?.modules?.ssl || {};
  ok("PC origin 200: https_available true (the fix did not blunt the healthy path)",
    ssl.https_available === true);
  ok("PC origin 200: NO ssl_not_available finding", !t.findings.includes("HTTPS Not Available"));
}

console.log(`\nhttps-observation engine trace: ${passed}/${passed + failed} passed`);
if (failed) { console.error("https-observation-engine-trace validation FAILED"); process.exit(1); }
console.log("https-observation-engine-trace validation passed");
