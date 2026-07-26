#!/usr/bin/env node
// Item 9 P2 — faithful runScanEngine certificate integration trace.
//
// Executes the real production scan engine against in-memory D1/R2. Only network
// edges are deterministic. This proves the P1 model is attached after production
// callers, shares the one CT cache, stays inside the existing SSL allocation and
// persists workspace-scoped evidence without writing soft-deleted tenants.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { runScanEngine } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "scan-engine.js",
)).href);
const { upsertCertificateObservation } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "cert-events.js",
)).href);
const p5Trace = process.argv.includes("--p5");
const { readScanReportSnapshot } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "report-snapshot.js",
)).href);
const { buildScanReportPdf, buildWorkspaceExecutivePdf } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "pdf.js",
)).href);
const { scanRoutes } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "routes",
  "scans.js",
)).href);
const { attackSurfaceRoutes } = await import(pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "routes",
  "attack-surface.js",
)).href);

const NOW = "2026-07-26T13:00:00.000Z";
const NOW_MS = Date.parse(NOW);
let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want,
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({
      results: db.prepare(sql).all(...args),
      success: true,
      meta: {},
    }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return {
        success: true,
        meta: {
          changes: result.changes,
          last_row_id: Number(result.lastInsertRowid || 0),
        },
      };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) =>
      Promise.all(statements.map((entry) =>
        /^\s*select/i.test(entry.__sql) ? entry.all() : entry.run())),
  };
}

function makeR2(store) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => {
      store.set(String(key), String(body));
      return {};
    },
    delete: async (key) => {
      store.delete(String(key));
      return {};
    },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

const providerCalls = { crt_sh: 0, certspotter: 0 };
let outboundCalls = 0;
const realFetch = globalThis.fetch;
const realRandom = Math.random;
globalThis.fetch = async (input) => {
  outboundCalls += 1;
  const url = new URL(String(input));
  if (url.hostname === "crt.sh") {
    providerCalls.crt_sh += 1;
    // Non-transient provider isolation: no retry and no effect on CertSpotter.
    return jsonResponse({}, 403);
  }
  if (url.hostname === "api.certspotter.com") {
    providerCalls.certspotter += 1;
    return jsonResponse([
      {
        id: "live-candidate",
        not_before: "2026-07-01T00:00:00.000Z",
        not_after: "2026-11-01T00:00:00.000Z",
        issuer: { name: "Trace Fallback CA" },
        dns_names: ["example.com", "www.example.com", "*.example.com"],
      },
      {
        id: "historical-candidate",
        not_before: "2026-01-01T00:00:00.000Z",
        not_after: "2026-09-01T00:00:00.000Z",
        issuer: { name: "Trace Historical CA" },
        dns_names: ["example.com", "old.example.com"],
      },
    ]);
  }
  if (
    url.hostname === "cloudflare-dns.com" ||
    url.hostname === "dns.google"
  ) {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "example.com" && type === "A") {
      return jsonResponse({
        Status: 0,
        Answer: [{ type: 1, data: "93.184.216.34" }],
      });
    }
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("<html><title>Example</title></html>", {
    status: 200,
    headers: {
      "content-type": "text/html",
      server: "item9-p2-fixture",
    },
  });
};
Math.random = () => 0.123456789;

const db = buildDb();
const store = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: makeR2(store),
  SCAN_CAPACITY_MODE: "legacy",
  SCAN_SUBREQUEST_LIMIT: "200",
  SCAN_DEADLINE_MS: "19000",
  APP_VERSION: "item9-p2-engine-trace",
};

db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')")
  .run();
for (const [id, name, deletedAt] of [
  ["ws-a", "Active A", null],
  ["ws-b", "Active B", null],
  ["ws-deleted", "Deleted", "2026-07-25T00:00:00.000Z"],
  ["ws-other", "Other tenant", null],
]) {
  db.prepare(
    "INSERT INTO workspaces (id, name, deleted_at) VALUES (?, ?, ?)",
  ).run(id, name, deletedAt);
}
db.prepare(
  "INSERT INTO domains (id, user_id, domain) VALUES ('dom', 'usr', 'example.com')",
).run();
for (const workspaceId of ["ws-a", "ws-b", "ws-deleted"]) {
  db.prepare(
    "INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'dom')",
  ).run(workspaceId);
}
db.prepare(
  `INSERT INTO scans
    (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
   VALUES ('scan-item9-p2', 'ws-a', 'dom', 'example.com', 'running', NULL,
           '2026-07-26T13:00:00.000Z')`,
).run();

try {
  let engineError = null;
  try {
    await runScanEngine(
      "scan-item9-p2",
      "dom",
      "ws-a",
      "example.com",
      env,
      {
        now: () => NOW_MS,
        executionContext: "queue",
        trigger: "manual",
      },
    );
  } catch (error) {
    engineError = error;
  }

  eq("real runScanEngine trace completes", engineError, null);
  eq("real engine terminal status is completed",
    db.prepare("SELECT status FROM scans WHERE id = 'scan-item9-p2'")
      .get()?.status, "completed");
  ok("real engine exercised outbound provider paths", outboundCalls > 0);
  eq("real engine uses one shared crt.sh logical lookup",
    providerCalls.crt_sh, 1);
  eq("real engine uses one shared CertSpotter logical lookup",
    providerCalls.certspotter, 1);

  const raw = store.get("reports/scan-item9-p2.json");
  ok("real engine writes a terminal raw report", typeof raw === "string");
  const report = JSON.parse(raw || "{}");
  const intelligence = report.modules?.certificate_intelligence;
  const completeness = intelligence?.signal_completeness;
  const signals = completeness?.signals || {};
  eq("production caller attaches the P1 model",
    completeness?.model_version, "certificate-signal-completeness-v2");
  eq("isolated crt.sh failure degrades only CT completeness",
    signals.certificate_transparency?.completeness_state,
    "monitoring_degraded");
  eq("fallback issuer remains a scoped degraded positive",
    signals.issuer?.completeness_state, "monitoring_degraded");
  eq("fallback issuer observation is retained",
    signals.issuer?.observation, "present");
  eq("active-service sibling remains independently complete",
    signals.active_service?.completeness_state, "monitoring_healthy");
  eq("active-service sibling remains observed",
    signals.active_service?.observation, "present");
  eq("CT-only evidence never claims a live leaf",
    signals.leaf?.observation, "unknown");
  eq("CT-only evidence never claims a live chain",
    signals.chain?.observation, "unknown");
  eq("multiple CT records never claim a parallel live certificate set",
    signals.parallel_certificate_set?.observation, "unknown");
  eq("P4 current DNS CAA absence is independently assessed",
    signals.caa?.completeness_state, "monitoring_healthy");
  eq("P4 current DNS CAA absence is not confused with a lookup failure",
    signals.caa?.observation, "absent");
  eq("P4 hostname match stays unknown without a peer leaf",
    signals.hostname_match?.observation, "unknown");
  eq("P4 intermediate validity stays unknown without a presented chain",
    signals.intermediate_validity?.observation, "unknown");
  eq("P4 certificate algorithm stays unknown without live leaf metadata",
    signals.certificate_algorithm?.observation, "unknown");
  eq("P4 trust-store acceptance stays unknown without declared validation",
    signals.trust_store_validation?.observation, "unknown");
  eq("P4 revocation stays independently unknown without validated OCSP",
    signals.revocation_assurance?.observation, "unknown");
  eq("P4 production trace does not claim revocation collection support",
    completeness?.assurance_families?.revocation_assurance?.supported, false);
  eq("P4 production trace labels CT issuance without a live leaf as CT-only",
    completeness?.summary?.ct_only, true);
  eq("P4 missing revocation does not erase CT issuer",
    signals.issuer?.observation, "present");
  eq("P4 missing revocation does not erase active service",
    signals.active_service?.observation, "present");
  eq("legacy live-certificate flag remains honest",
    intelligence?.live_certificate_verified, false);
  eq("SSL declares the additive P4 evidence schema",
    report.modules?.ssl?.certificate_evidence?.schema_version,
    "external-certificate-observation-v2");
  eq("SSL declares that live leaf collection was unavailable",
    report.modules?.ssl?.certificate_evidence?.live_tls?.leaf_collected,
    false);
  eq("SSL declares simultaneous endpoint collection was not performed",
    report.modules?.ssl?.certificate_evidence
      ?.parallel_certificate_set?.collection_performed,
    false);

  const diagnostics = report.execution_diagnostics || {};
  eq("real engine uses the 19-second whole-scan executable budget",
    diagnostics.deadline_budget_ms, 19_000);
  const sslDiagnostic = (diagnostics.modules || [])
    .find((row) => row.module === "ssl");
  eq("real engine allocated exactly the 9-second SSL cap",
    sslDiagnostic?.allocated_ms, 9_000);
  ok("real engine observed no more than six SSL subrequests",
    Number(sslDiagnostic?.outbound_attempts_observed) <= 6,
    `attempts ${sslDiagnostic?.outbound_attempts_observed}`);
  eq("real engine SSL subrequest accounting is complete",
    sslDiagnostic?.outbound_measurement_complete, true);
  eq("R2 diagnostics preserve provider isolation",
    diagnostics.provider_health?.crt_sh?.outcome, "unavailable");
  eq("R2 diagnostics preserve fallback provider success",
    diagnostics.provider_health?.certspotter?.outcome, "available");

  const activeRows = db.prepare(
    `SELECT workspace_id, certificate_key, evidence_json
     FROM certificate_observations
     WHERE domain_id = 'dom'
     ORDER BY workspace_id`,
  ).all();
  eq("certificate persistence fans out to the two active tenants only",
    activeRows.length, 2);
  eq("first active tenant receives its own observation",
    activeRows[0]?.workspace_id, "ws-a");
  eq("second active tenant receives its own observation",
    activeRows[1]?.workspace_id, "ws-b");
  eq("soft-deleted tenant receives no certificate observation",
    db.prepare(
      `SELECT COUNT(*) AS n FROM certificate_observations
       WHERE workspace_id = 'ws-deleted'`,
    ).get().n, 0);
  eq("soft-deleted tenant receives no certificate timeline event",
    db.prepare(
      `SELECT COUNT(*) AS n FROM asset_events
       WHERE workspace_id = 'ws-deleted'
         AND event_type LIKE 'certificate_%'`,
    ).get().n, 0);

  for (const row of activeRows) {
    const evidence = JSON.parse(row.evidence_json || "{}");
    eq(`${row.workspace_id}: D1 evidence persists the P1 model`,
      evidence.signal_completeness?.model_version,
      "certificate-signal-completeness-v2");
    eq(`${row.workspace_id}: persisted CT state is scoped and degraded`,
      evidence.signal_completeness?.signals
        ?.certificate_transparency?.completeness_state,
      "monitoring_degraded");
    eq(`${row.workspace_id}: persisted active-service sibling stays complete`,
      evidence.signal_completeness?.signals
        ?.active_service?.completeness_state,
      "monitoring_healthy");
    eq(`${row.workspace_id}: persisted CAA state remains independent`,
      evidence.signal_completeness?.signals?.caa?.observation,
      "absent");
    eq(`${row.workspace_id}: persisted trust-store state remains unknown`,
      evidence.signal_completeness?.signals
        ?.trust_store_validation?.observation,
      "unknown");
    eq(`${row.workspace_id}: persisted revocation state remains unknown`,
      evidence.signal_completeness?.signals
        ?.revocation_assurance?.observation,
      "unknown");
  }

  if (p5Trace) {
    const snapshotRow = db.prepare(
      `SELECT id, r2_key, checksum_sha256
       FROM scan_report_snapshots
       WHERE scan_id = 'scan-item9-p2' AND status = 'completed'`,
    ).get();
    ok("P5 trace: runScanEngine finalizes the immutable snapshot",
      Boolean(snapshotRow?.id && snapshotRow?.r2_key));
    const frozenBody = store.get(snapshotRow?.r2_key);
    const read = await readScanReportSnapshot(env, "scan-item9-p2", {
      repair: false,
    });
    eq("P5 trace: snapshot integrity read succeeds", read.status, "ok");
    const snapshotAssurance = read.snapshot?.certificate_assurance;
    eq("P5 trace: snapshot freezes the customer presentation schema",
      snapshotAssurance?.schema, "certificate-customer-presentation-v1");
    eq("P5 trace: CT-only fact survives scan -> persistence -> snapshot",
      snapshotAssurance?.summary?.ct_only, true);
    eq("P5 trace: CT issuance is presented as observed",
      snapshotAssurance?.signals?.certificate_transparency?.state, "observed");
    ok("P5 trace: CT issuance does not become live-serving",
      snapshotAssurance?.signals?.leaf?.state !== "observed" &&
      snapshotAssurance?.summary?.live_tls_certificate?.state !== "observed");
    ok("P5 trace: unavailable live trust siblings remain non-favourable",
      ["unknown", "unavailable", "incomplete", "not_observed"].includes(
        snapshotAssurance?.signals?.trust_store_validation?.state,
      ) &&
      ["unknown", "unavailable", "incomplete", "not_observed"].includes(
        snapshotAssurance?.signals?.revocation_assurance?.state,
      ));
    ok("P5 trace: independently reliable active-service sibling survives",
      snapshotAssurance?.signals?.active_service?.state === "observed");
    ok("P5 trace: evidence grade/source/provenance survive persistence",
      snapshotAssurance?.signals?.certificate_transparency?.evidence_grade?.achieved &&
      snapshotAssurance?.signals?.certificate_transparency?.source_type &&
      snapshotAssurance?.signals?.certificate_transparency?.provenance?.source &&
      snapshotAssurance?.signals?.certificate_transparency?.cited_authorities?.length);

    const routeJson = (body, status = 200) => jsonResponse(body, status);
    const serverError = (_scope, error) =>
      routeJson({ error: String(error?.message || error) }, 500);
    const scanApi = async (pathname) => {
      const request = new Request(`https://api.cybermeters.com${pathname}`);
      const response = await scanRoutes({
        request,
        env,
        ctx: { waitUntil() {} },
        url: new URL(request.url),
        json: routeJson,
        serverError,
        corsHeaders: {},
        requireAuth: async () => ({ id: "usr" }),
        requireScanReadAccess: async () => true,
      });
      return {
        status: response.status,
        body: await response.json(),
      };
    };
    const snapshotApi = await scanApi(
      "/api/scans/scan-item9-p2/snapshot",
    );
    const reportApi = await scanApi(
      "/api/scans/scan-item9-p2/report",
    );
    const executiveApi = await scanApi(
      "/api/scans/scan-item9-p2/executive-report-v2",
    );
    eq("P5 trace: snapshot API renders", snapshotApi.status, 200);
    eq("P5 trace: report API renders", reportApi.status, 200);
    eq("P5 trace: Executive Report API renders", executiveApi.status, 200);
    for (const [surface, value] of [
      ["snapshot API", snapshotApi.body?.certificate_assurance],
      ["report API", reportApi.body?.certificate_assurance],
      ["Executive Report", executiveApi.body?.certificate_assurance],
    ]) {
      eq(`P5 trace: ${surface} matches frozen certificate semantics`,
        JSON.stringify(value), JSON.stringify(snapshotAssurance));
    }

    const certificateRequest = new Request(
      "https://api.cybermeters.com/api/workspaces/ws-a/certificates",
    );
    const certificateResponse = await attackSurfaceRoutes({
      request: certificateRequest,
      env,
      url: new URL(certificateRequest.url),
      json: routeJson,
      requireAuth: async () => ({ id: "usr" }),
      requireWorkspaceRole: async () => true,
    });
    const certificateApi = await certificateResponse.json();
    eq("P5 trace: certificate inventory API renders",
      certificateResponse.status, 200);
    eq("P5 trace: certificate inventory retains CT-only distinction",
      certificateApi.certificates?.[0]?.certificate_assurance?.summary?.ct_only,
      true);
    ok("P5 trace: certificate inventory does not promote CT to live leaf",
      certificateApi.certificates?.[0]?.certificate_assurance
        ?.signals?.leaf?.state !== "observed");

    const pdfText = new TextDecoder().decode(buildScanReportPdf(
      { id: "scan-item9-p2", domain: "example.com" },
      read,
    ));
    for (const phrase of [
      "Certificate Evidence & Trust",
      "CT issuance observed",
      "Declared trust-store validation",
      "OCSP / revocation assurance",
      "Evidence grade:",
      "Cited authorities:",
    ]) {
      ok(`P5 trace: PDF renders ${phrase}`, pdfText.includes(phrase));
    }
    ok("P5 trace: PDF keeps CT and live-serving as separate states",
      pdfText.includes("CT issuance observed") &&
      pdfText.includes("Live TLS certificate: incomplete"));
    const executivePdfText = new TextDecoder().decode(
      buildWorkspaceExecutivePdf({
        workspaceName: "Active A",
        reads: [read],
        generatedAt: NOW,
      }),
    );
    ok("P5 trace: Executive PDF renders the same CT-only distinction",
      executivePdfText.includes("Certificate Evidence & Trust") &&
      executivePdfText.includes("CT issuance observed") &&
      executivePdfText.includes("Live TLS certificate: incomplete"));
    ok("P5 trace: Executive PDF retains evidence provenance appendix",
      executivePdfText.includes("Evidence grade:") &&
      executivePdfText.includes("Cited authorities:"));
    eq("P5 trace: report rendering does not rewrite immutable R2 bytes",
      store.get(snapshotRow?.r2_key), frozenBody);
  }

  const beforeUnavailablePersistence = db.prepare(
    "SELECT COUNT(*) AS n FROM certificate_observations WHERE domain_id = 'dom'",
  ).get().n;
  await upsertCertificateObservation(
    "scan-item9-p2",
    "dom",
    {
      ...intelligence,
      issuer: null,
      subject: "example.com",
      san_hostnames: [],
      san_count: 0,
      expires_at: null,
      signal_completeness: {
        ...completeness,
        signals: {
          ...signals,
          san: { ...signals.san, observation: "unknown", value: null },
          issuer: { ...signals.issuer, observation: "unknown", value: null },
          expiry: { ...signals.expiry, observation: "unknown", value: null },
          certificate_transparency: {
            ...signals.certificate_transparency,
            completeness_state: "signal_unavailable",
            observation: "unknown",
            value: null,
          },
        },
      },
    },
    env,
    { currentReport: report },
  );
  eq("provider-unavailable evidence creates no pseudo-certificate row",
    db.prepare(
      "SELECT COUNT(*) AS n FROM certificate_observations WHERE domain_id = 'dom'",
    ).get().n,
    beforeUnavailablePersistence);

  // Same certificate key in an unrelated, unmapped workspace must remain byte
  // unchanged when the production persistence function runs again.
  const sharedKey = activeRows[0]?.certificate_key;
  const sentinelEvidence = JSON.stringify({ tenant: "other", untouched: true });
  db.prepare(
    `INSERT INTO certificate_observations
      (id, workspace_id, domain_id, scan_id, certificate_key, subject,
       issuer, san_count, expires_at, first_seen, last_seen, evidence_json,
       created_at, updated_at)
     VALUES ('certobs-other', 'ws-other', 'dom', 'scan-item9-p2', ?,
             'sentinel', 'Sentinel CA', 0, NULL,
             '2026-07-26T00:00:00.000Z', '2026-07-26T00:00:00.000Z', ?,
             '2026-07-26T00:00:00.000Z', '2026-07-26T00:00:00.000Z')`,
  ).run(sharedKey, sentinelEvidence);
  await upsertCertificateObservation(
    "scan-item9-p2",
    "dom",
    intelligence,
    env,
    { currentReport: report },
  );
  const otherTenant = db.prepare(
    `SELECT subject, issuer, evidence_json
     FROM certificate_observations
     WHERE workspace_id = 'ws-other' AND certificate_key = ?`,
  ).get(sharedKey);
  eq("unmapped tenant subject is not overwritten",
    otherTenant?.subject, "sentinel");
  eq("unmapped tenant issuer is not overwritten",
    otherTenant?.issuer, "Sentinel CA");
  eq("unmapped tenant evidence is byte-unchanged",
    otherTenant?.evidence_json, sentinelEvidence);

  if (p5Trace) {
    const callCertificateInventory = async (workspaceId) => {
      const request = new Request(
        `https://api.cybermeters.com/api/workspaces/${workspaceId}/certificates`,
      );
      const response = await attackSurfaceRoutes({
        request,
        env,
        url: new URL(request.url),
        json: (body, status = 200) => jsonResponse(body, status),
        requireAuth: async () => ({ id: "usr" }),
        requireWorkspaceRole: async () => true,
      });
      return {
        status: response.status,
        body: await response.json(),
      };
    };
    const isolated = await callCertificateInventory("ws-other");
    eq("P5 trace: unlinked tenant cannot read another tenant's certificate",
      isolated.status, 200);
    eq("P5 trace: unlinked tenant inventory stays empty despite sentinel row",
      isolated.body?.total, 0);
    const deleted = await callCertificateInventory("ws-deleted");
    eq("P5 trace: soft-deleted workspace certificate surface is closed",
      deleted.status, 404);
  }

  const indexSource = fs.readFileSync(path.join(
    root,
    "workers",
    "scan-api",
    "src",
    "index.js",
  ), "utf8");
  const observationIndex = indexSource.indexOf('"certificate_observations"');
  const lifecycleEventIndex = indexSource.indexOf('"certificate_lifecycle_events"');
  const lifecycleIndex = indexSource.indexOf('"certificate_lifecycle"');
  ok("existing purge list still covers certificate observations",
    observationIndex >= 0);
  ok("existing purge order keeps lifecycle events before lifecycle parent",
    lifecycleEventIndex >= 0 &&
      lifecycleIndex >= 0 &&
      lifecycleEventIndex < lifecycleIndex);
} finally {
  globalThis.fetch = realFetch;
  Math.random = realRandom;
  db.close();
}

console.log(`\nItem 9 ${p5Trace ? "P5 customer-surface" : "P2"} runScanEngine trace: ${pass} passed, ${fail} failed`);
if (!fail) console.log(`Item 9 ${p5Trace ? "P5 customer-surface" : "P2"} runScanEngine trace passed`);
process.exit(fail ? 1 : 0);
