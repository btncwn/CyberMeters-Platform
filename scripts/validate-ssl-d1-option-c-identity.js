#!/usr/bin/env node
// SSL D1 Option C — canonical finding identity and bounded legacy compatibility.
// Node 24+ (node:sqlite). This validator is intentionally usable before the
// implementation exists so the frozen candidate carries red-before evidence.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_MODULE_PATH = path.join(ROOT, "workers", "scan-api", "src", "engines", "finding-identity.js");
const MODULE_URL = process.env.SSL_D1_IDENTITY_MODULE_URL || pathToFileURL(DEFAULT_MODULE_PATH).href;

const results = [];
function check(id, condition, detail = "") {
  const passed = Boolean(condition);
  results.push({ id, passed, detail: passed ? "" : String(detail || "contract not satisfied") });
  if (!passed) console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
}
function equal(id, actual, expected) {
  check(id, JSON.stringify(actual) === JSON.stringify(expected),
    `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`);
}

function modulePathFromUrl(value) {
  try { return fileURLToPath(new URL(value)); } catch { return null; }
}

const loadedPath = modulePathFromUrl(MODULE_URL);
let identity = null;
let moduleError = null;
if (loadedPath && fs.existsSync(loadedPath)) {
  try {
    identity = await import(`${MODULE_URL}${MODULE_URL.includes("?") ? "&" : "?"}semantic=${crypto.randomUUID()}`);
    const digest = crypto.createHash("sha256").update(fs.readFileSync(loadedPath)).digest("hex");
    console.log(`LOADED_MODULE_URL=${MODULE_URL}`);
    console.log(`LOADED_MODULE_SHA256=${digest}`);
  } catch (error) {
    moduleError = error;
  }
} else {
  moduleError = new Error(`identity module absent: ${MODULE_URL}`);
}
check("module.loaded", Boolean(identity), moduleError?.stack || moduleError?.message);

const schema = fs.readFileSync(path.join(ROOT, "database", "schema.sql"), "utf8");
const migrationPath = path.join(ROOT, "database", "migrations", "107-finding-canonical-identity.sql");
const migration = fs.existsSync(migrationPath) ? fs.readFileSync(migrationPath, "utf8") : "";
check("schema.finding_slug", /CREATE TABLE IF NOT EXISTS findings[\s\S]*?finding_slug\s+TEXT/.test(schema),
  "findings.finding_slug TEXT is absent from schema.sql");
check("migration.107.nullable_add_only",
  /^\s*ALTER TABLE findings ADD COLUMN finding_slug TEXT;\s*$/m.test(migration)
    && !/\bUPDATE\b|\bDELETE\b|\bINSERT\b|NOT\s+NULL/i.test(migration),
  "migration 107 must contain one nullable ADD COLUMN and no historical rewrite");

function makeD1(db, { failFindingSlug = null } = {}) {
  const wrap = (sql, args) => ({
    __sql: sql,
    __args: args,
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      if (failFindingSlug && args[2] === failFindingSlug) {
        throw new Error(`controlled batch failure for ${failFindingSlug}`);
      }
      const out = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: out.changes, last_row_id: Number(out.lastInsertRowid || 0) } };
    },
  });
  return {
    prepare(sql) {
      const bound = wrap(sql, []);
      bound.bind = (...args) => wrap(sql, args);
      return bound;
    },
    batch: async (statements) => {
      db.exec("BEGIN IMMEDIATE");
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* schema + ordered migrations converge */ }
  };
  apply(path.join(ROOT, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(ROOT, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(ROOT, "database", "migrations", file));
  }
  return db;
}

function seedScope(db) {
  db.prepare("INSERT INTO users (id,email,name,plan,email_verified) VALUES ('u1','one@example.test','One','professional',1)").run();
  db.prepare("INSERT INTO users (id,email,name,plan,email_verified) VALUES ('u2','two@example.test','Two','professional',1)").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws_active','u1','Active')").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name,deleted_at) VALUES ('ws_deleted','u1','Deleted','2026-08-09T00:00:00.000Z')").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws_other','u2','Other')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_active','u1','active.example')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_deleted','u1','deleted.example')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_other','u2','other.example')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_active','d_active')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_deleted','d_deleted')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_other','d_other')").run();
  db.prepare("INSERT INTO scans (id,domain_id,workspace_id,domain,status) VALUES ('scan_active','d_active','ws_active','active.example','completed')").run();
  db.prepare("INSERT INTO scans (id,domain_id,workspace_id,domain,status) VALUES ('scan_deleted','d_deleted','ws_deleted','deleted.example','completed')").run();
  db.prepare("INSERT INTO scans (id,domain_id,workspace_id,domain,status) VALUES ('scan_other','d_other','ws_other','other.example','completed')").run();
}

const exactEvidence = (domain = "active.example") => ({
  evidence_type: "https_probe",
  probe_target: `https://${domain}`,
  observed_value: "TLS handshake failed or connection refused on port 443",
  expected_value: "TLS 1.2+ handshake success with valid certificate",
  source: "cloudflare_workers_fetch",
  checked_at: "2026-08-09T09:10:11.000Z",
  manual_verification_command: `curl -sI https://${domain} | head -3`,
});

if (identity) {
  // Forward persistence and write boundaries use the real shared writer against D1.
  {
    const db = buildDb();
    seedScope(db);
    const env = { cybermeters_db: makeD1(db) };
    const historicalEvidenceBytes = JSON.stringify(exactEvidence());
    db.prepare(`INSERT INTO findings
      (id,scan_id,severity,title,recommendation,evidence_json,confidence,finding_slug,created_at)
      VALUES ('legacy_keep','scan_active','critical','Historical title','Historical recommendation',?,0.42,NULL,'2026-08-01T01:02:03.000Z')`)
      .run(historicalEvidenceBytes);
    const historicalBefore = db.prepare("SELECT * FROM findings WHERE id='legacy_keep'").get();

    await identity.persistFindingsWithIdentity(env, {
      scanId: "scan_active",
      workspaceId: "ws_active",
      findings: [{
        id: "canonical_runtime_slug", severity: "high", title: "New row", description: "d",
        evidence: "e", recommendation: "r", evidence_detail: { source: "test" }, confidence: 0.9,
      }],
    });
    const inserted = db.prepare("SELECT finding_slug FROM findings WHERE scan_id='scan_active' AND title='New row'").get();
    equal("forward.identity.persisted", inserted?.finding_slug ?? null, "canonical_runtime_slug");

    await identity.persistFindingsWithIdentity(env, {
      scanId: "scan_active", workspaceId: "ws_other",
      findings: [{
        id: "cross_tenant", severity: "critical", title: "Cross tenant",
        description: "d", evidence: { source: "test" }, confidence: 1,
      }],
    });
    equal("forward.tenant_isolation",
      db.prepare("SELECT COUNT(*) AS n FROM findings WHERE finding_slug='cross_tenant'").get().n, 0);

    await identity.persistFindingsWithIdentity(env, {
      scanId: "scan_deleted", workspaceId: "ws_deleted",
      findings: [{
        id: "deleted_write", severity: "critical", title: "Deleted write",
        description: "d", evidence: { source: "test" }, confidence: 1,
      }],
    });
    equal("forward.soft_delete",
      db.prepare("SELECT COUNT(*) AS n FROM findings WHERE finding_slug='deleted_write'").get().n, 0);

    const historicalAfter = db.prepare("SELECT * FROM findings WHERE id='legacy_keep'").get();
    equal("forward.historical_unchanged", historicalAfter, historicalBefore);
    equal("forward.historical_evidence_bytes", historicalAfter?.evidence_json, historicalEvidenceBytes);

    let missingIdentityRejected = false;
    try {
      await identity.persistFindingsWithIdentity(env, {
        scanId: "scan_active", workspaceId: "ws_active",
        findings: [
          { id: "batch_good_before_missing", severity: "low", title: "good", description: "d" },
          { id: "", severity: "low", title: "missing", description: "d" },
        ],
      });
    } catch { missingIdentityRejected = true; }
    check("forward.missing_identity_rejected", missingIdentityRejected);
    equal("forward.missing_identity_no_partial_write",
      db.prepare("SELECT COUNT(*) AS n FROM findings WHERE finding_slug='batch_good_before_missing'").get().n, 0);

    const failingEnv = { cybermeters_db: makeD1(db, { failFindingSlug: "controlled_failure" }) };
    let controlledFailureObserved = false;
    try {
      await identity.persistFindingsWithIdentity(failingEnv, {
        scanId: "scan_active", workspaceId: "ws_active",
        findings: [
          { id: "batch_first", severity: "low", title: "first", description: "d" },
          { id: "controlled_failure", severity: "low", title: "fail", description: "d" },
          { id: "batch_last", severity: "low", title: "last", description: "d" },
        ],
      });
    } catch { controlledFailureObserved = true; }
    check("forward.controlled_batch_failure_observed", controlledFailureObserved);
    equal("forward.controlled_batch_failure_no_partial_write",
      db.prepare("SELECT COUNT(*) AS n FROM findings WHERE finding_slug IN ('batch_first','controlled_failure','batch_last')").get().n, 0);
  }

  // Pure classifier oracle: no customer-visible title participates, and only exact,
  // structured historical provenance may receive compatibility treatment.
  {
    const classify = identity.isConclusiveLegacyUnprovenTlsFinding;
    check("legacy.exact.classified", classify?.({
      finding_slug: null, title: "Completely unrelated title", evidence_json: JSON.stringify(exactEvidence()), domain: "active.example",
    }) === true);
    check("legacy.new_identity_visible", classify?.({
      finding_slug: "ssl_not_available", title: "SSL unavailable", evidence_json: JSON.stringify(exactEvidence()), domain: "active.example",
    }) === false);
    check("legacy.malformed_visible", classify?.({
      finding_slug: null, title: "SSL unavailable", evidence_json: "{not-json", domain: "active.example",
    }) === false);
    check("legacy.ambiguous_visible", classify?.({
      finding_slug: null, title: "SSL unavailable", evidence_json: JSON.stringify({ ...exactEvidence(), extra_provenance: "mixed" }), domain: "active.example",
    }) === false);
    check("legacy.reused_visible", classify?.({
      finding_slug: null, title: "SSL unavailable", evidence_json: JSON.stringify({ ...exactEvidence(), observed_value: "certificate expired" }), domain: "active.example",
    }) === false);
    check("legacy.unrelated_visible", classify?.({
      finding_slug: null, title: "Unrelated critical", evidence_json: JSON.stringify({ source: "scanner", evidence_type: "open_port" }), domain: "active.example",
    }) === false);
    check("legacy.title_visible", classify?.({
      finding_slug: null, title: "SSL/TLS Not Available", evidence_json: JSON.stringify({ source: "customer_title_only" }), domain: "active.example",
    }) === false);
    for (const [name, checkedAt, expected] of [
      ["epoch_boundary", "1970-01-01T00:00:00.000Z", true],
      ["leap_day", "2024-02-29T23:59:59.999Z", true],
      ["max_year", "9999-12-31T23:59:59.999Z", true],
      ["invalid_day", "2026-02-30T00:00:00.000Z", false],
      ["missing_millis", "2026-08-09T09:10:11Z", false],
      ["timezone_offset", "2026-08-09T10:10:11.000+01:00", false],
    ]) {
      check(`legacy.date.${name}`, classify?.({
        finding_slug: null,
        evidence_json: JSON.stringify({ ...exactEvidence(), checked_at: checkedAt }),
        domain: "active.example",
      }) === expected);
    }
    const duplicateEvidence = JSON.stringify(exactEvidence()).replace(
      '"source":"cloudflare_workers_fetch"',
      '"source":"cloudflare_workers_fetch","source":"cloudflare_workers_fetch"',
    );
    check("legacy.duplicate_keys_visible", classify?.({
      finding_slug: null, evidence_json: duplicateEvidence, domain: "active.example",
    }) === false);
    check("legacy.noncanonical_json_visible", classify?.({
      finding_slug: null,
      evidence_json: JSON.stringify(exactEvidence()).replace("{", "{ "),
      domain: "active.example",
    }) === false);
  }

  // The SQL emitted for every D1 reader must implement the same bounded rule.
  {
    const db = buildDb();
    seedScope(db);
    const insert = db.prepare(`INSERT INTO findings
      (id,scan_id,severity,title,evidence_json,finding_slug) VALUES (?,?,?,?,?,?)`);
    insert.run("sql_exact", "scan_active", "critical", "Arbitrary title", JSON.stringify(exactEvidence()), null);
    insert.run("sql_ambiguous", "scan_active", "critical", "SSL/TLS Not Available", JSON.stringify({ ...exactEvidence(), extra: true }), null);
    insert.run("sql_reused", "scan_active", "critical", "SSL/TLS Not Available", JSON.stringify({ ...exactEvidence(), observed_value: "certificate expired" }), null);
    insert.run("sql_title", "scan_active", "critical", "SSL/TLS Not Available", JSON.stringify({ source: "title_only" }), null);
    insert.run("sql_new", "scan_active", "critical", "SSL/TLS Not Available", JSON.stringify(exactEvidence()), "ssl_not_available");
    insert.run("sql_duplicate", "scan_active", "critical", "SSL/TLS Not Available",
      JSON.stringify(exactEvidence()).replace('"source":"cloudflare_workers_fetch"', '"source":"cloudflare_workers_fetch","source":"cloudflare_workers_fetch"'), null);
    insert.run("sql_invalid_date", "scan_active", "critical", "SSL/TLS Not Available",
      JSON.stringify({ ...exactEvidence(), checked_at: "2026-02-30T00:00:00.000Z" }), null);
    insert.run("sql_boundary_date", "scan_active", "critical", "SSL/TLS Not Available",
      JSON.stringify({ ...exactEvidence(), checked_at: "9999-12-31T23:59:59.999Z" }), null);
    const predicate = identity.visibleFindingSql?.("f", "s");
    let visible = [];
    try {
      visible = db.prepare(`SELECT f.id FROM findings f JOIN scans s ON s.id=f.scan_id WHERE ${predicate} ORDER BY f.id`).all().map((row) => row.id);
    } catch { /* assertion below reports a bounded failure */ }
    check("legacy.sql_exact_hidden", !visible.includes("sql_exact"), visible.join(","));
    check("legacy.sql_ambiguous_visible", visible.includes("sql_ambiguous"), visible.join(","));
    check("legacy.sql_reused_visible", visible.includes("sql_reused"), visible.join(","));
    check("legacy.sql_title_visible", visible.includes("sql_title"), visible.join(","));
    check("legacy.sql_new_identity_visible", visible.includes("sql_new"), visible.join(","));
    check("legacy.sql_duplicate_visible", visible.includes("sql_duplicate"), visible.join(","));
    check("legacy.sql_invalid_date_visible", visible.includes("sql_invalid_date"), visible.join(","));
    check("legacy.sql_boundary_date_hidden", !visible.includes("sql_boundary_date"), visible.join(","));
  }

  // Persisted domain-state history has no evidence_json. Its compatibility projection
  // is therefore separately bounded by exact historic resolver versions + exact IDs.
  {
    const oldTlsOnly = {
      domain_key: "website_security", state: "issue_detected", highest_severity: "critical",
      finding_count: 1, finding_ids_json: '["ssl_not_available"]', resolver_version: "2026-07-24.4",
      summary: "A material issue was detected.",
    };
    const projected = identity.projectLegacyWebsiteDomainState?.(oldTlsOnly);
    equal("domain.exact_projected", {
      state: projected?.state,
      highest_severity: projected?.highest_severity,
      finding_count: projected?.finding_count,
      finding_ids_json: projected?.finding_ids_json,
      legacy_identity_projection: projected?.legacy_identity_projection,
    }, {
      state: "evidence_insufficient", highest_severity: null, finding_count: 0,
      finding_ids_json: "[]", legacy_identity_projection: "historical_unproven_tls",
    });
    const mixed = { ...oldTlsOnly, finding_count: 2, finding_ids_json: '["headers_missing","ssl_not_available"]' };
    equal("domain.mixed_visible", identity.projectLegacyWebsiteDomainState?.(mixed), mixed);
    const current = { ...oldTlsOnly, resolver_version: "2026-08-09.2" };
    equal("domain.resolver_bounded", identity.projectLegacyWebsiteDomainState?.(current), current);
    const malformed = { ...oldTlsOnly, finding_ids_json: "not-json" };
    equal("domain.malformed_visible", identity.projectLegacyWebsiteDomainState?.(malformed), malformed);
  }

  // JS↔SQL classifier parity: the SQL predicate must agree with the JS oracle on
  // every corpus element, and NULL/ambiguous evidence must remain VISIBLE — SQL
  // three-valued logic may never over-hide relative to the documented oracle.
  {
    const db = buildDb();
    seedScope(db);
    const corpus = [
      ["parity_epoch", "1970-01-01T00:00:00.000Z"],
      ["parity_year_zero", "0000-01-01T00:00:00.000Z"],
      ["parity_valid_leap", "2024-02-29T00:00:00.000Z"],
      ["parity_invalid_leap", "2026-02-29T00:00:00.000Z"],
      ["parity_invalid_apr31", "2026-04-31T00:00:00.000Z"],
      ["parity_hour_24", "2026-08-09T24:00:00.000Z"],
      ["parity_leap_second", "2026-08-09T23:59:60.000Z"],
      ["parity_canonical", "2026-08-09T12:00:00.000Z"],
      ["parity_max_date", "9999-12-31T23:59:59.999Z"],
      ["parity_offset", "2026-08-09T12:00:00.000+00:00"],
      ["parity_no_millis", "2026-08-09T12:00:00Z"],
      ["parity_lowercase", "2026-08-09t12:00:00.000z"],
    ];
    const insert = db.prepare(`INSERT INTO findings
      (id,scan_id,severity,title,evidence_json,finding_slug) VALUES (?,?,?,?,?,NULL)`);
    for (const [id, ts] of corpus) {
      insert.run(id, "scan_active", "critical", "SSL/TLS Not Available",
        JSON.stringify({ ...exactEvidence(), checked_at: ts }));
    }
    const srcKeyed = { ...exactEvidence() };
    delete srcKeyed.source;
    srcKeyed.src = "cloudflare_workers_fetch";
    insert.run("ambiguous_src_key", "scan_active", "critical", "SSL/TLS Not Available", JSON.stringify(srcKeyed));
    const noCheckedAt = { ...exactEvidence() };
    delete noCheckedAt.checked_at;
    noCheckedAt.checked = "2026-08-09T09:10:11.000Z";
    insert.run("ambiguous_missing_checked_at", "scan_active", "critical", "SSL/TLS Not Available", JSON.stringify(noCheckedAt));
    const predicate = identity.visibleFindingSql?.("f", "s");
    let visible = [];
    try {
      visible = db.prepare(`SELECT f.id FROM findings f JOIN scans s ON s.id=f.scan_id WHERE ${predicate} ORDER BY f.id`)
        .all().map((row) => row.id);
    } catch { /* assertions below report a bounded failure */ }
    const classify = identity.isConclusiveLegacyUnprovenTlsFinding;
    for (const [id, ts] of corpus) {
      const js = classify?.({
        finding_slug: null, domain: "active.example",
        evidence_json: JSON.stringify({ ...exactEvidence(), checked_at: ts }),
      });
      equal(`parity.${id}`,
        { js_legacy: js, sql_hidden: !visible.includes(id) },
        { js_legacy: js, sql_hidden: js === true });
    }
    check("parity.ambiguous_src_key_visible", visible.includes("ambiguous_src_key"), visible.join(","));
    check("parity.ambiguous_missing_checked_at_visible", visible.includes("ambiguous_missing_checked_at"), visible.join(","));
  }

  // Bounded legacy remediation projection: a customer-facing action disappears
  // ONLY together with its exact suppressed legacy finding, never on title alone,
  // and never when a forward-written slugged finding re-earned it.
  {
    const db = buildDb();
    seedScope(db);
    db.prepare(`INSERT INTO findings (id,scan_id,severity,title,evidence_json,finding_slug)
      VALUES ('rem_legacy_finding','scan_active','critical','HTTPS Not Available',?,NULL)`)
      .run(JSON.stringify(exactEvidence()));
    const insRem = db.prepare(`INSERT INTO remediation_items (id,scan_id,priority,title,reason,action) VALUES (?,?,?,?,?,?)`);
    insRem.run("rem_tls", "scan_active", "1", "Install a TLS Certificate", "ssl", "Enable HTTPS.");
    insRem.run("rem_tls_alt", "scan_active", "1", "Enable HTTPS with a valid certificate", "ssl", "Enable HTTPS.");
    insRem.run("rem_other", "scan_active", "2", "Create a DMARC Record", "email", "Publish DMARC.");
    db.prepare(`INSERT INTO findings (id,scan_id,severity,title,evidence_json,finding_slug)
      VALUES ('rem_nearmiss_finding','scan_other','critical','HTTPS Not Available',?,NULL)`)
      .run(JSON.stringify({ ...exactEvidence("other.example"), observed_value: "certificate expired" }));
    insRem.run("rem_nearmiss_tls", "scan_other", "1", "Install a TLS Certificate", "ssl", "Enable HTTPS.");
    const frag = identity.suppressedLegacyTlsRemediationSql?.("ri");
    const keptRows = () => {
      try {
        return db.prepare(`SELECT ri.id FROM remediation_items ri WHERE NOT ${frag} ORDER BY ri.id`)
          .all().map((row) => row.id);
      } catch { return null; }
    };
    const kept = keptRows() ?? [];
    check("remediation.legacy_tls_suppressed", !kept.includes("rem_tls"), kept.join(","));
    check("remediation.legacy_tls_alt_suppressed", !kept.includes("rem_tls_alt"), kept.join(","));
    check("remediation.unrelated_kept", kept.includes("rem_other"), kept.join(","));
    check("remediation.near_miss_kept", kept.includes("rem_nearmiss_tls"), kept.join(","));
    db.prepare(`INSERT INTO findings (id,scan_id,severity,title,evidence_json,finding_slug)
      VALUES ('rem_slugged','scan_active','critical','HTTPS Not Available','{}','ssl_not_available')`).run();
    const keptAfter = keptRows() ?? [];
    check("remediation.slugged_replacement_kept", keptAfter.includes("rem_tls"), keptAfter.join(","));
    equal("remediation.rows_untouched", db.prepare("SELECT COUNT(*) AS n FROM remediation_items").get().n, 4);
  }
} else {
  for (const id of [
    "forward.identity.persisted", "forward.tenant_isolation", "forward.soft_delete",
    "forward.historical_unchanged", "forward.historical_evidence_bytes",
    "legacy.exact.classified", "legacy.new_identity_visible", "legacy.malformed_visible",
    "legacy.ambiguous_visible", "legacy.reused_visible", "legacy.unrelated_visible", "legacy.title_visible",
    "legacy.sql_exact_hidden", "legacy.sql_ambiguous_visible", "legacy.sql_reused_visible",
    "legacy.sql_title_visible", "legacy.sql_new_identity_visible", "domain.exact_projected",
    "domain.mixed_visible", "domain.resolver_bounded", "domain.malformed_visible",
  ]) check(id, false, "identity module unavailable");
}

// Integration anchors: every D1 finding reader must use the one shared predicate.
const readerFiles = [
  "workers/scan-api/src/engines/scorecard.js",
  "workers/scan-api/src/engines/portfolio-customers.js",
  "workers/scan-api/src/routes/portfolio.js",
  "workers/scan-api/src/routes/workspace-insights.js",
  "workers/scan-api/src/routes/executive-dashboard.js",
  "workers/scan-api/src/engines/report-queries.js",
  "workers/scan-api/src/engines/business-risk.js",
  "workers/scan-api/src/routes/account.js",
  "workers/scan-api/src/routes/attack-surface.js",
];
const readerMisses = readerFiles.filter((file) => {
  const source = fs.readFileSync(path.join(ROOT, file), "utf8");
  const reads = (source.match(/\b(?:FROM|JOIN) findings\b/g) || []).length;
  const predicates = (source.match(/visibleFindingSql\("f", "s"\)/g) || []).length;
  return reads === 0 || predicates !== reads;
});
equal("readers.shared_classifier", readerMisses, []);

const scanEngine = fs.readFileSync(path.join(ROOT, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
check("writer.shared_forward_path", /persistFindingsWithIdentity\(env,\s*\{/.test(scanEngine),
  "scan-engine does not delegate finding writes to the identity layer");

const historySource = fs.readFileSync(path.join(ROOT, "workers", "scan-api", "src", "engines", "cyber-mot-state-history.js"), "utf8");
check("domain.history_shared_projection", /projectLegacyWebsiteDomainState/.test(historySource),
  "persisted Website state readers do not use the bounded projection");

// The three remediation readers compose the ONE shared suppression fragment.
for (const [file, alias] of [
  ["workers/scan-api/src/routes/executive-dashboard.js", "ri"],
  ["workers/scan-api/src/engines/report-queries.js", "r"],
  ["workers/scan-api/src/engines/scorecard.js", "remediation_items"],
]) {
  const source = fs.readFileSync(path.join(ROOT, file), "utf8");
  const anchor = "AND NOT ${suppressedLegacyTlsRemediationSql(\"" + alias + "\")}";
  check(`remediation.reader.${path.basename(file)}`, source.includes(anchor),
    `missing shared suppression composition: ${anchor}`);
}

const summary = {
  module_url: MODULE_URL,
  passed: results.filter((r) => r.passed).map((r) => r.id),
  failed: results.filter((r) => !r.passed).map((r) => r.id),
  total: results.length,
};
console.log(`SSL_D1_IDENTITY_RESULT=${JSON.stringify(summary)}`);
console.log(`\nSSL D1 Option C identity: ${summary.passed.length}/${summary.total} passed`);
if (summary.failed.length) process.exit(1);
