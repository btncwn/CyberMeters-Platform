#!/usr/bin/env node
//
// A1 report_preparing — real Worker route + canonical resolver proof.
//
// Drives the production Worker against the real schema/migrations and exercises
// lifecycle, snapshot claim/repair, tenant/soft-delete gates, renderer routes,
// terminal integrity errors, and the frontend's finite polling policy. Mutations
// may supply temporary production modules through the two URL environment
// variables; normal CI imports the repository sources.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRequire = createRequire(
  path.join(root, "workers", "scan-api", "package.json"),
);
const { parse } = workerRequire("acorn");
const srcPath = (...parts) => path.join(root, "workers", "scan-api", "src", ...parts);
const moduleUrl = (envName, fallback) =>
  process.env[envName] || pathToFileURL(fallback).href;
const scanRoutesSourcePath =
  process.env.REPORT_PREPARING_SCAN_ROUTES_SOURCE_PATH ||
  srcPath("routes", "scans.js");

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;

let pass = 0;
let fail = 0;
function ok(name, condition, hint = "") {
  if (condition) {
    pass += 1;
  } else {
    fail += 1;
    console.log(`FAIL ${name}${hint ? ` — ${hint}` : ""}`);
  }
}

function walkAst(node, visitor, parent = null, parentKey = null) {
  if (!node || typeof node !== "object") return;
  visitor(node, parent, parentKey);
  for (const [key, value] of Object.entries(node)) {
    if (key === "start" || key === "end" || key === "loc") continue;
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child.type === "string") {
          walkAst(child, visitor, node, key);
        }
      }
    } else if (value && typeof value.type === "string") {
      walkAst(value, visitor, node, key);
    }
  }
}

function isIdentifier(node, name) {
  return node?.type === "Identifier" && node.name === name;
}

function isResolverCallee(node) {
  if (isIdentifier(node, "resolveScanReportAvailability")) return true;
  if (node?.type !== "MemberExpression") return false;
  return node.computed
    ? node.property?.type === "Literal" &&
        node.property.value === "resolveScanReportAvailability"
    : isIdentifier(node.property, "resolveScanReportAvailability");
}

function isCanonicalRetryDecision(node) {
  const init = node?.init;
  const getCall = init?.left;
  const getMember = getCall?.callee;
  const searchParamsMember = getMember?.object;
  return (
    node?.type === "VariableDeclarator" &&
    isIdentifier(node.id, "customerRequestedReportRetry") &&
    init?.type === "BinaryExpression" &&
    init.operator === "===" &&
    getCall?.type === "CallExpression" &&
    getMember?.type === "MemberExpression" &&
    getMember.computed === false &&
    isIdentifier(getMember.property, "get") &&
    searchParamsMember?.type === "MemberExpression" &&
    searchParamsMember.computed === false &&
    isIdentifier(searchParamsMember.object, "url") &&
    isIdentifier(searchParamsMember.property, "searchParams") &&
    getCall.arguments?.length === 1 &&
    getCall.arguments[0]?.type === "Literal" &&
    getCall.arguments[0].value === "retry_report" &&
    init.right?.type === "Literal" &&
    init.right.value === "1"
  );
}

function isCanonicalRetryOption(call) {
  const options = call?.arguments?.[2];
  const property = options?.properties?.[0];
  return (
    call?.arguments?.length === 3 &&
    options?.type === "ObjectExpression" &&
    options.properties.length === 1 &&
    property?.type === "Property" &&
    property.kind === "init" &&
    property.computed === false &&
    property.shorthand === false &&
    isIdentifier(property.key, "retryFailed") &&
    isIdentifier(property.value, "customerRequestedReportRetry")
  );
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (filename) => {
    try { db.exec(fs.readFileSync(filename, "utf8")); } catch { /* additive drift */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const filename of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", filename));
  }
  return db;
}

function makeD1(db, writeLog) {
  const statement = (sql, args) => ({
    __sql: sql,
    __args: args,
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
      if (/^\s*(insert|update|delete)/i.test(sql) && /scan_report_snapshots/i.test(sql)) {
        writeLog.push(sql.replace(/\s+/g, " ").trim());
      }
      const result = db.prepare(sql).run(...args);
      return {
        success: true,
        meta: {
          changes: result.changes,
          last_row_id: Number(result.lastInsertRowid ?? 0),
        },
      };
    },
  });
  return {
    prepare(sql) {
      const unbound = statement(sql, []);
      unbound.bind = (...args) => statement(sql, args);
      return unbound;
    },
    async batch(statements) {
      return Promise.all(statements.map((item) =>
        /^\s*select/i.test(item.__sql) ? item.all() : item.run()));
    },
    async exec(sql) {
      db.exec(sql);
      return { count: 0, duration: 0 };
    },
  };
}

function makeR2(store) {
  return {
    get: async (key) => {
      const value = store.get(key);
      if (value == null) return null;
      return {
        json: async () => JSON.parse(value),
        text: async () => String(value),
      };
    },
    put: async (key, value) => {
      store.set(key, String(value));
      return {};
    },
    delete: async (key) => {
      store.delete(key);
      return {};
    },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

function makeReport(scanId, domainId, completedAt, status = "completed") {
  return {
    scan_id: scanId,
    domain_id: domainId,
    domain: "a1.example",
    status,
    cyber_metrics_score: status === "completed" ? 82 : null,
    risk_level: status === "completed" ? "good" : null,
    started_at: "2026-07-30T09:00:00.000Z",
    ...(completedAt ? { completed_at: completedAt } : {}),
    findings: [],
    recommendations: [],
    scan_quality: {
      status: status === "completed" ? "complete" : "unknown",
      modules_skipped: [],
      warnings: [],
    },
    monitoring_states: {
      version: "signal-monitoring-state-v1",
      signals: {},
    },
    modules: {
      dns: {},
      ssl: {},
      headers: {},
      email_security: {},
      subdomains: {},
      cve_intelligence: {
        technologies_checked: ["nginx"],
        lookup_statuses: { nginx: { status: "complete" } },
        results: { nginx: [] },
        total_cves: 0,
        critical_count: 0,
        high_count: 0,
        source: "nvd_api",
        cve_coverage: "complete",
      },
      known_exploited_vulnerabilities: {},
      email_security_intelligence: {},
    },
  };
}

async function main() {
  // Production retry-authority inventory. The resolver definition is excluded
  // deliberately: this counts every caller under Worker production source, not
  // the option declaration itself. A new caller must update this proof and may
  // never silently acquire failed-build retry authority.
  const productionFiles = [];
  const collectProductionFiles = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) collectProductionFiles(absolute);
      else if (
        entry.isFile() &&
        entry.name.endsWith(".js") &&
        !entry.name.includes(".a1-mutant.")
      ) {
        productionFiles.push(absolute);
      }
    }
  };
  collectProductionFiles(srcPath());
  const resolverDefinitionPath = srcPath("engines", "report-availability.js");
  const productionUnits = productionFiles.map((filename) => {
    const source = filename === srcPath("routes", "scans.js")
      ? fs.readFileSync(scanRoutesSourcePath, "utf8")
      : fs.readFileSync(filename, "utf8");
    return {
      filename,
      relativeFilename: path.relative(srcPath(), filename),
      source,
      ast: parse(source, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true,
      }),
    };
  });
  const availabilityCallers = [];
  const resolverModuleImports = [];
  const resolverImports = [];
  const resolverDefinitions = [];
  const unexpectedResolverReferences = [];
  const retryGrantIdentifiers = [];
  const canonicalRetryDecisions = [];

  for (const unit of productionUnits) {
    walkAst(unit.ast, (node, parent, parentKey) => {
      if (
        node.type === "CallExpression" &&
        isResolverCallee(node.callee)
      ) {
        availabilityCallers.push({
          ...unit,
          node,
          line: node.loc.start.line,
        });
      }
      if (
        node.type === "ImportDeclaration" &&
        node.source?.value?.endsWith("/report-availability.js")
      ) {
        resolverModuleImports.push({ ...unit, node });
      }
      if (node.type === "ImportSpecifier") {
        if (
          isIdentifier(node.imported, "resolveScanReportAvailability") ||
          isIdentifier(node.local, "resolveScanReportAvailability")
        ) {
          resolverImports.push({ ...unit, node });
        }
      }
      if (
        node.type === "FunctionDeclaration" &&
        isIdentifier(node.id, "resolveScanReportAvailability")
      ) {
        resolverDefinitions.push({ ...unit, node });
      }
      if (isIdentifier(node, "resolveScanReportAvailability")) {
        const isDirectCall =
          parent?.type === "CallExpression" &&
          parentKey === "callee";
        const isImport = parent?.type === "ImportSpecifier";
        const isDefinition =
          parent?.type === "FunctionDeclaration" &&
          parentKey === "id";
        if (!isDirectCall && !isImport && !isDefinition) {
          unexpectedResolverReferences.push({ ...unit, node });
        }
      }
      if (
        unit.filename !== resolverDefinitionPath &&
        isIdentifier(node, "retryFailed")
      ) {
        retryGrantIdentifiers.push({ ...unit, node, parent, parentKey });
      }
      if (isCanonicalRetryDecision(node)) {
        canonicalRetryDecisions.push({ ...unit, node });
      }
    });
  }

  const optionsCallers = availabilityCallers.filter(
    ({ node }) => node.arguments.length !== 2,
  );
  const passiveCallers = availabilityCallers.filter(
    ({ node }) => node.arguments.length === 2,
  );
  const canonicalOptionsCaller = optionsCallers.length === 1
    ? optionsCallers[0]
    : null;
  const canonicalRetryProperty = canonicalOptionsCaller?.node.arguments?.[2]
    ?.properties?.[0];

  console.log(
    "report-availability AST inventory:"
    + ` callers=${availabilityCallers.length}`
    + ` routes=${[...new Set(availabilityCallers.map(({ relativeFilename }) => relativeFilename))].join(",") || "none"}`
    + ` passive_default=${passiveCallers.length}`
    + ` options=${optionsCallers.length}`
    + ` retry_identifiers=${retryGrantIdentifiers.length}`,
  );
  ok("production report-availability caller inventory is complete and route-owned",
    availabilityCallers.length === 5 &&
    availabilityCallers.every(
      (caller) => caller.relativeFilename === "routes/scans.js",
    ));
  ok("resolver identifier has one canonical definition/import and no alias or wrapper reference",
    resolverDefinitions.length === 1 &&
    resolverDefinitions[0].filename === resolverDefinitionPath &&
    resolverModuleImports.length === 1 &&
    resolverModuleImports[0].relativeFilename === "routes/scans.js" &&
    resolverModuleImports[0].node.specifiers.length === 2 &&
    resolverModuleImports[0].node.specifiers.every(
      (specifier) =>
        specifier.type === "ImportSpecifier" &&
        ["reportAvailabilityError", "resolveScanReportAvailability"]
          .includes(specifier.imported?.name) &&
        specifier.local?.name === specifier.imported?.name,
    ) &&
    resolverImports.length === 1 &&
    resolverImports[0].relativeFilename === "routes/scans.js" &&
    isIdentifier(resolverImports[0].node.local, "resolveScanReportAvailability") &&
    unexpectedResolverReferences.length === 0);
  ok("only scan-detail customer action may pass report-availability options",
    optionsCallers.length === 1 &&
    canonicalOptionsCaller?.relativeFilename === "routes/scans.js" &&
    isCanonicalRetryOption(canonicalOptionsCaller?.node) &&
    canonicalRetryDecisions.length === 1 &&
    canonicalRetryDecisions[0].relativeFilename === "routes/scans.js");
  ok("retry authority has one canonical production grant",
    retryGrantIdentifiers.length === 1 &&
    retryGrantIdentifiers[0].node === canonicalRetryProperty?.key &&
    isCanonicalRetryOption(canonicalOptionsCaller?.node));
  ok("all four passive renderer callers use resolver default retry policy",
    passiveCallers.length === 4 &&
    passiveCallers.every(
      ({ relativeFilename, node }) =>
        relativeFilename === "routes/scans.js" &&
        isIdentifier(node.arguments[0], "env") &&
        isIdentifier(node.arguments[1], "scan"),
    ));
  ok("resolver default remains retryFailed false outside caller inventory",
    /\{\s*allowRepair\s*=\s*true,\s*retryFailed\s*=\s*false\s*\}/
      .test(fs.readFileSync(resolverDefinitionPath, "utf8")));

  const workerModule = await import(moduleUrl(
    "REPORT_PREPARING_WORKER_MODULE_URL",
    srcPath("index.js"),
  ));
  const availabilityModule = await import(moduleUrl(
    "REPORT_PREPARING_RESOLVER_MODULE_URL",
    srcPath("engines", "report-availability.js"),
  ));
  const frontendModule = await import(moduleUrl(
    "REPORT_PREPARING_FRONTEND_MODULE_URL",
    path.join(root, "frontend", "src", "lib", "reportAvailability.js"),
  ));
  const snapshotModule = await import(pathToFileURL(
    srcPath("engines", "report-snapshot.js"),
  ).href);

  const worker = workerModule.default;
  const { hashPassword, hashToken } = workerModule;
  const {
    resolveScanReportAvailability,
    MAX_REPORT_REPAIR_ATTEMPTS,
  } = availabilityModule;
  const {
    REPORT_PREPARING_MAX_ATTEMPTS,
    isReportPreparing,
    nextReportPreparationDelay,
    reportPreparationPresentation,
  } = frontendModule;

  const db = buildDb();
  const store = new Map();
  const writeLog = [];
  const env = {
    cybermeters_db: makeD1(db, writeLog),
    cybermeters_reports: makeR2(store),
    RESEND_API_KEY: "",
    APP_VERSION: "a1-validator",
  };
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

  const password = await hashPassword("A1-valid-password");
  for (const [id, email] of [["u1", "owner@a1.example"], ["u2", "other@a1.example"]]) {
    db.prepare(
      "INSERT INTO users (id,email,password_hash,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,'A1','business','active',1,0)"
    ).run(id, email, password);
    db.prepare(
      "INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,datetime('now','+1 day'))"
    ).run(`sess-${id}`, id, await hashToken(`token-${id}`));
  }
  for (const [ws, owner, deleted] of [
    ["ws1", "u1", null],
    ["ws2", "u2", null],
    ["wsDead", "u1", "2026-07-30 10:00:00"],
  ]) {
    db.prepare(
      "INSERT INTO workspaces (id,owner_user_id,name,deleted_at) VALUES (?,?,?,?)"
    ).run(ws, owner, ws, deleted);
    db.prepare(
      "INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,?,'admin')"
    ).run(`member-${ws}`, ws, owner);
    const domainId = `domain-${ws}`;
    db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,'a1.example')")
      .run(domainId, owner);
    db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)")
      .run(ws, domainId);
  }

  const seedScan = (id, workspaceId, status, createdAt = "2026-07-30 10:00:00") => {
    db.prepare(
      `INSERT INTO scans
         (id,workspace_id,domain_id,domain,status,score,rating,scan_quality,created_at)
       VALUES (?,?,?,'a1.example',?,82,'good','complete',?)`
    ).run(id, workspaceId, `domain-${workspaceId}`, status, createdAt);
  };
  const putReport = (id, workspaceId, completedAt, status = "completed") => {
    store.set(
      `reports/${id}.json`,
      JSON.stringify(makeReport(id, `domain-${workspaceId}`, completedAt, status)),
    );
  };
  const call = async (pathname, token = "token-u1") => {
    const response = await worker.fetch(
      new Request(`https://api.cybermeters.com${pathname}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      }),
      env,
      ctx,
    );
    const text = await response.text();
    let data = null;
    try { data = JSON.parse(text); } catch { /* PDF bytes */ }
    return { status: response.status, data, text };
  };

  // 1. NON-TERMINAL SCAN — lifecycle remains active; no report claim/repair.
  seedScan("scan-running", "ws1", "running");
  putReport("scan-running", "ws1", null, "running");
  const writesBeforeRunning = writeLog.length;
  const running = await call("/api/scans/scan-running");
  ok("non-terminal scan preserves running lifecycle",
    running.status === 200 && running.data?.scan?.status === "running");
  ok("non-terminal scan is not report_preparing",
    running.data?.report_availability?.status === "scan_in_progress");
  ok("non-terminal read creates no snapshot work", writeLog.length === writesBeforeRunning);

  // 2. COMPLETED + REPORT READY.
  seedScan("scan-ready", "ws1", "completed", "2026-07-30 09:00:00");
  const readyReport = makeReport(
    "scan-ready",
    "domain-ws1",
    "2026-07-30T09:01:00.000Z",
  );
  store.set("reports/scan-ready.json", JSON.stringify(readyReport));
  for (let index = 1; index <= MAX_REPORT_REPAIR_ATTEMPTS; index += 1) {
    db.prepare(
      `INSERT INTO scan_report_snapshots
         (id,workspace_id,domain_id,scan_id,status,r2_key,snapshot_schema_version,
          resolver_version,assessed_at,metadata_json,created_at)
       VALUES (?,?,?,'scan-ready','failed',?,'1','test',
               '2026-07-30T09:01:00.000Z','{"failure_reason":"old"}',
               datetime('now', ?))`
    ).run(
      `snap-ready-old-failure-${index}`,
      "ws1",
      "domain-ws1",
      `reports/snapshots/ws1/scan-ready/old-${index}.json`,
      `-${3 - index} minutes`,
    );
  }
  const readyBuild = await snapshotModule.buildScanReportSnapshot(env, {
    workspaceId: "ws1",
    domainId: "domain-ws1",
    scanId: "scan-ready",
    domain: "a1.example",
    report: readyReport,
    assessedAt: readyReport.completed_at,
  });
  ok("ready fixture canonical snapshot built", readyBuild.status === "completed");
  const readyDetail = await call("/api/scans/scan-ready");
  ok("completed scan reports authoritative report_ready",
    readyDetail.status === 200 &&
    readyDetail.data?.report_availability?.status === "report_ready");
  const readyTechnical = await call("/api/scans/scan-ready/report");
  ok("ready technical report renders normally", readyTechnical.status === 200);

  // 3. COMPLETED + LEGITIMATELY PREPARING, then transitions to ready.
  seedScan("scan-preparing", "ws1", "completed", "2026-07-30 10:00:00");
  const preparingReport = makeReport(
    "scan-preparing",
    "domain-ws1",
    new Date().toISOString(),
  );
  store.set("reports/scan-preparing.json", JSON.stringify(preparingReport));
  const preparing = await call("/api/scans/scan-preparing");
  ok("finalize window returns report_preparing",
    preparing.status === 200 &&
    preparing.data?.scan?.status === "completed" &&
    preparing.data?.report_availability?.status === "report_preparing");
  ok("preparing response is explicit and retryable",
    preparing.data?.report_availability?.code === "report_preparing" &&
    preparing.data?.report_availability?.retryable === true &&
    /preparing the report/i.test(preparing.data?.report_availability?.message || ""));
  ok("fresh finalize window does not race Phase 8o with read repair",
    db.prepare("SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-preparing'")
      .get().count === 0);
  const writesBeforePreparingPolls = writeLog.length;
  await call("/api/scans/scan-preparing");
  await call("/api/scans/scan-preparing");
  ok("preparation polling does not create a repair operation per request",
    writeLog.length === writesBeforePreparingPolls &&
    db.prepare("SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-preparing'")
      .get().count === 0);

  for (const pathSuffix of ["/report", "/executive-report-v2", "/snapshot", "/report/pdf"]) {
    const response = await call(`/api/scans/scan-preparing${pathSuffix}`);
    ok(`renderer ${pathSuffix} carries canonical report_preparing`,
      response.status === 409 &&
      response.data?.code === "report_preparing" &&
      response.data?.report_availability?.status === "report_preparing");
  }

  const preparingBuild = await snapshotModule.buildScanReportSnapshot(env, {
    workspaceId: "ws1",
    domainId: "domain-ws1",
    scanId: "scan-preparing",
    domain: "a1.example",
    report: preparingReport,
    assessedAt: preparingReport.completed_at,
  });
  ok("finalizer can complete the in-window snapshot", preparingBuild.status === "completed");
  const prepared = await call("/api/scans/scan-preparing");
  ok("bounded-poll target transitions from preparing to ready",
    prepared.data?.report_availability?.status === "report_ready");

  // 4. COMPLETED + REAL REPORT FAILURE — integrity errors beat preparing.
  seedScan("scan-broken", "ws1", "completed", "2026-07-30 08:00:00");
  const brokenReport = makeReport(
    "scan-broken",
    "domain-ws1",
    "2026-07-30T08:01:00.000Z",
  );
  store.set("reports/scan-broken.json", JSON.stringify(brokenReport));
  const brokenBuild = await snapshotModule.buildScanReportSnapshot(env, {
    workspaceId: "ws1",
    domainId: "domain-ws1",
    scanId: "scan-broken",
    domain: "a1.example",
    report: brokenReport,
    assessedAt: brokenReport.completed_at,
  });
  const brokenKey = db.prepare(
    "SELECT r2_key FROM scan_report_snapshots WHERE scan_id='scan-broken' AND status='completed'"
  ).get().r2_key;
  store.delete(brokenKey);
  ok("broken fixture had a completed snapshot before object loss",
    brokenBuild.status === "completed");
  const brokenDetail = await call("/api/scans/scan-broken");
  ok("real snapshot integrity error is terminal, never preparing",
    brokenDetail.status === 200 &&
    brokenDetail.data?.report_availability?.status === "report_unavailable" &&
    brokenDetail.data?.report_availability?.code === "report_integrity_error");
  const brokenReportRoute = await call("/api/scans/scan-broken/report");
  ok("renderer preserves terminal integrity failure",
    brokenReportRoute.status === 500 &&
    brokenReportRoute.data?.code === "report_integrity_error" &&
    brokenReportRoute.data?.report_availability?.status !== "report_preparing");
  const brokenResolved = await resolveScanReportAvailability(env, {
    id: "scan-broken",
    status: "completed",
    created_at: "2026-07-30 08:00:00",
  });
  ok("resolver gives terminal integrity errors precedence over preparing",
    brokenResolved.availability.status === "report_unavailable" &&
    brokenResolved.availability.code === "report_integrity_error");

  // Direct resolver carrier: completed alone is never ready without evidence.
  seedScan("scan-missing", "ws1", "completed", "2026-07-30 08:00:00");
  const missingResolved = await resolveScanReportAvailability(env, {
    id: "scan-missing",
    status: "completed",
    created_at: "2026-07-30 08:00:00",
  });
  ok("completed status alone never becomes report_ready",
    missingResolved.availability.status === "report_unavailable" &&
    missingResolved.availability.code === "report_not_found");

  // Failed builds are bounded. Two failures close read-triggered repair.
  seedScan("scan-failed-build", "ws1", "completed", "2026-07-30 08:00:00");
  putReport("scan-failed-build", "ws1", "2026-07-30T08:01:00.000Z");
  for (let index = 1; index <= MAX_REPORT_REPAIR_ATTEMPTS; index += 1) {
    db.prepare(
      `INSERT INTO scan_report_snapshots
         (id,workspace_id,domain_id,scan_id,status,r2_key,snapshot_schema_version,
          resolver_version,assessed_at,metadata_json,created_at)
       VALUES (?,?,?,'scan-failed-build','failed',?,'1','test',
               '2026-07-30T08:01:00.000Z',?,datetime('now'))`
    ).run(
      `snap-failed-${index}`,
      "ws1",
      "domain-ws1",
      `reports/snapshots/ws1/scan-failed-build/${index}.json`,
      JSON.stringify({ failure_reason: `injected-${index}` }),
    );
  }
  const writesBeforeBoundedFailure = writeLog.length;
  const failedBounded = await resolveScanReportAvailability(env, {
    id: "scan-failed-build",
    status: "completed",
    created_at: "2026-07-30 08:00:00",
  });
  ok("failed repair limit is an explicit terminal report error",
    failedBounded.availability.status === "report_unavailable" &&
    failedBounded.availability.reason === "repair_attempt_limit");
  ok("failed repair limit starts no further repair",
    writeLog.length === writesBeforeBoundedFailure);
  const failedBoundedRoute = await call(
    "/api/scans/scan-failed-build?retry_report=1",
  );
  ok("explicit retry cannot exceed the second failed-attempt boundary",
    failedBoundedRoute.status === 200 &&
    failedBoundedRoute.data?.report_availability?.status === "report_unavailable" &&
    failedBoundedRoute.data?.report_availability?.reason === "repair_attempt_limit" &&
    failedBoundedRoute.data?.report_availability?.manual_retry_available === false);
  ok("bounded-out explicit retry creates no snapshot work",
    writeLog.length === writesBeforeBoundedFailure);

  // A real first build failure remains visible through every passive renderer.
  // Only one explicit scan-detail customer action may spend the remaining
  // bounded repair attempt.
  seedScan("scan-repairable", "ws1", "completed", "2026-07-30 07:00:00");
  putReport("scan-repairable", "ws1", "2026-07-30T07:01:00.000Z");
  db.prepare(
    `INSERT INTO scan_report_snapshots
       (id,workspace_id,domain_id,scan_id,status,r2_key,snapshot_schema_version,
        resolver_version,assessed_at,metadata_json,created_at)
     VALUES ('snap-repairable-failed','ws1','domain-ws1','scan-repairable',
             'failed','reports/snapshots/ws1/scan-repairable/failed.json',
             '1','test','2026-07-30T07:01:00.000Z',
             '{"failure_reason":"injected"}',datetime('now'))`
  ).run();
  const writesBeforePassiveFailedReads = writeLog.length;
  const failedCountBeforePassiveReads = db.prepare(
    "SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-repairable' AND status='failed'"
  ).get().count;
  for (const pathSuffix of ["/report", "/executive-report-v2", "/snapshot", "/report/pdf"]) {
    const response = await call(`/api/scans/scan-repairable${pathSuffix}`);
    ok(`passive renderer ${pathSuffix} preserves failed report_unavailable`,
      response.status === 500 &&
      response.data?.code === "report_generation_failed" &&
      response.data?.report_availability?.status === "report_unavailable" &&
      response.data?.report_availability?.manual_retry_available === true);
    ok(`passive renderer ${pathSuffix} starts no repair work`,
      writeLog.length === writesBeforePassiveFailedReads &&
      db.prepare(
        "SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-repairable' AND status='completed'"
      ).get().count === 0);
  }
  ok("passive renderers preserve failed-attempt count",
    db.prepare(
      "SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-repairable' AND status='failed'"
    ).get().count === failedCountBeforePassiveReads);
  ok("passive renderers preserve the explicit customer retry right",
    writeLog.length === writesBeforePassiveFailedReads);
  const explicitRepair = await call(
    "/api/scans/scan-repairable?retry_report=1",
  );
  ok("explicit customer retry reuses canonical repair-on-read once",
    explicitRepair.status === 200 &&
    explicitRepair.data?.report_availability?.status === "report_ready" &&
    db.prepare(
      "SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-repairable' AND status='completed'"
    ).get().count === 1);

  // 5. UNAUTHORISED / CROSS-TENANT — same non-enumerating result, no work.
  seedScan("scan-foreign", "ws2", "completed");
  putReport("scan-foreign", "ws2", new Date().toISOString());
  const writesBeforeDenied = writeLog.length;
  const foreign = await call("/api/scans/scan-foreign?retry_report=1");
  const nonexistent = await call(
    "/api/scans/scan-does-not-exist?retry_report=1",
  );
  ok("foreign and nonexistent scan detail are non-enumerating",
    foreign.status === 403 &&
    nonexistent.status === 403 &&
    foreign.text === nonexistent.text);
  ok("cross-tenant/nonexistent reads trigger no snapshot work",
    writeLog.length === writesBeforeDenied &&
    db.prepare("SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-foreign'")
      .get().count === 0);
  const unauthenticated = await call("/api/scans/scan-preparing", null);
  ok("unauthenticated caller receives canonical 401 before availability",
    unauthenticated.status === 401 &&
    !unauthenticated.data?.report_availability);

  // 6. SOFT-DELETED WORKSPACE — inaccessible and no repair/background work.
  seedScan("scan-deleted", "wsDead", "completed");
  putReport("scan-deleted", "wsDead", new Date().toISOString());
  const writesBeforeDeleted = writeLog.length;
  const deleted = await call("/api/scans/scan-deleted?retry_report=1");
  ok("soft-deleted workspace receives no availability disclosure",
    deleted.status === 403 && !deleted.data?.report_availability);
  ok("soft-deleted workspace receives no snapshot repair",
    writeLog.length === writesBeforeDeleted &&
    db.prepare("SELECT COUNT(*) count FROM scan_report_snapshots WHERE scan_id='scan-deleted'")
      .get().count === 0);

  // 7. PREPARING EXCEEDS ITS BOUND — finite policy and honest recovery copy.
  ok("frontend recognises only explicit retryable report_preparing",
    isReportPreparing({
      status: "report_preparing",
      retryable: true,
    }) === true &&
    isReportPreparing({
      status: "report_preparing",
      retryable: false,
    }) === false);
  ok("legitimate preparing state has dedicated non-error presentation",
    reportPreparationPresentation({
      status: "report_preparing",
      retryable: true,
      message: "Preparing fixture",
    })?.title === "Your report is being prepared");
  const finiteDelays = Array.from(
    { length: REPORT_PREPARING_MAX_ATTEMPTS },
    (_, index) => nextReportPreparationDelay(index, 1000),
  );
  ok("preparation polling has one finite delay per pinned attempt",
    finiteDelays.length === REPORT_PREPARING_MAX_ATTEMPTS &&
    finiteDelays.every((delay) => Number.isFinite(delay) && delay > 0));
  ok("preparation polling stops at the configured bound",
    nextReportPreparationDelay(REPORT_PREPARING_MAX_ATTEMPTS, 1000) === null);
  const exhausted = reportPreparationPresentation(
    { status: "report_preparing", retryable: true },
    true,
  );
  ok("bounded exhaustion renders explicit recoverable unavailability",
    /taking longer than expected/i.test(exhausted?.title || "") &&
    exhausted?.canRetry === true &&
    !/failed|something went wrong/i.test(exhausted?.message || ""));

  // API compatibility: availability is additive; lifecycle and report shapes stay.
  ok("scan detail keeps existing scan and report_key fields",
    readyDetail.data?.scan?.id === "scan-ready" &&
    readyDetail.data?.report_key === "reports/scan-ready.json");
  ok("ready technical report keeps legacy report fields",
    readyTechnical.data?.scan_id === "scan-ready" &&
    readyTechnical.data?.status === "completed" &&
    "cyber_metrics_score" in readyTechnical.data);

  console.log(`\nreport-preparing: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error("report-preparing runner crashed:", error);
  process.exit(2);
});
