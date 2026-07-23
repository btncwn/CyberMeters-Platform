#!/usr/bin/env node
//
// PR-5.5 Gate 3B — atomic/repairable aggregate-report ingestion.
//
// Mutation-backed proof that:
//   • persisted detail rows fit beneath the 1,000-query D1 invocation budget;
//   • over-cap DMARC and TLS-RPT reports are rejected and audited;
//   • a mid-batch failure rolls back every report/child/rollup write, leaves a
//     failed repairable claim, and redelivery completes exactly once;
//   • nullable natural-key metadata cannot bypass the non-null claim index;
//   • observational inbound cannot suppress a later authoritative copy;
//   • content hashes are compared on a natural-key collision;
//   • invalid base64 is an audited terminal drop; and
//   • transient inbound storage failure is quarantined/audited, never silent.
//
// Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const importRepo = (relative) =>
  import(pathToFileURL(path.join(root, relative)).href);

const dmarcMod = await importRepo("workers/scan-api/src/lib/dmarc-ingest.js");
const tlsMod = await importRepo("workers/scan-api/src/lib/tlsrpt-ingest.js");
const ingestStateMod = await importRepo(
  "workers/scan-api/src/lib/aggregate-report-ingest.js",
);
const emailWorker = await importRepo("workers/email-ingest/src/index.js");

const { ingestDmarcReport } = dmarcMod;
const { ingestTlsRptReport } = tlsMod;
const {
  AGGREGATE_REPORT_D1_QUERY_BUDGET,
  AGGREGATE_REPORT_MAX_PERSISTED_ROWS,
  AGGREGATE_REPORT_MAX_TRANSACTION_STATEMENTS,
  aggregateReportCompleteSql,
  sha256Hex,
} = ingestStateMod;

let pass = 0;
let fail = 0;
function ok(name, condition) {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.error(`FAIL ${name}`);
  }
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (filename) => {
    try {
      db.exec(fs.readFileSync(filename, "utf8"));
    } catch {
      // schema.sql + historical migrations converge via tolerated duplicates.
    }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const filename of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", filename));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function buildPreGate3bDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (filename) => {
    try {
      db.exec(fs.readFileSync(filename, "utf8"));
    } catch {
      // schema.sql + historical migrations converge via tolerated duplicates.
    }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const filename of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql") &&
      name !== "100-aggregate-report-ingest-state.sql")
    .sort()) {
    apply(path.join(root, "database", "migrations", filename));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db, controls = {}) {
  controls.batchSizes ||= [];
  const wrap = (sql, args) => ({
    __sql: sql,
    __args: args,
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({
      results: db.prepare(sql).all(...args),
      success: true,
      meta: {},
    }),
    run: async () => {
      if (controls.failAuditWrites && /INSERT INTO audit_events/.test(sql)) {
        throw new Error("injected_audit_store_failure");
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
      const statement = wrap(sql, []);
      statement.bind = (...args) => wrap(sql, args);
      return statement;
    },
    async batch(statements) {
      controls.batchSizes.push(statements.length);
      db.exec("BEGIN");
      try {
        const results = [];
        for (let index = 0; index < statements.length; index += 1) {
          if (controls.failNextBatchAt === index) {
            controls.failNextBatchAt = null;
            throw new Error("injected_transient_d1_failure");
          }
          results.push(await statements[index].run());
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function seed(db, suffix = "") {
  const user = `user${suffix}`;
  const workspace = `ws${suffix}`;
  const domainId = `domain${suffix}`;
  const endpoint = `endpoint${suffix}`;
  const localpart = `cmrua_gate3b${suffix || "0"}`.toLowerCase();
  db.prepare(
    "INSERT INTO users (id,email,email_verified) VALUES (?,?,1)",
  ).run(user, `${user}@example.test`);
  db.prepare(
    "INSERT INTO workspaces (id,name,owner_user_id) VALUES (?,?,?)",
  ).run(workspace, "Gate 3B", user);
  db.prepare(
    "INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)",
  ).run(domainId, user, "victim.example");
  db.prepare(
    "INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)",
  ).run(workspace, domainId);
  db.prepare(
    `INSERT INTO dmarc_ingest_endpoints
       (id,workspace_id,domain_id,domain,token_hash,address_local,status,created_at)
     VALUES (?,?,?,?,?,?,'active',datetime('now'))`,
  ).run(endpoint, workspace, domainId, "victim.example", `hash${suffix}`, localpart);
  return { user, workspace, domainId, endpoint, localpart };
}

function envFor(db, controls = {}) {
  return {
    cybermeters_db: makeD1(db, controls),
    RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
    APP_VERSION: "gate3b-test",
    FRONTEND_URL: "https://app.cybermeters.com",
    RESEND_API_KEY: "",
  };
}

function dmarcXml(reportId, rows, {
  includeMetadata = true,
  countOffset = 0,
} = {}) {
  const metadata = includeMetadata
    ? `<org_name>Reporter</org_name><email>reports@reporter.example</email>` +
      `<report_id>${reportId}</report_id>` +
      "<date_range><begin>1784764800</begin><end>1784851200</end></date_range>"
    : `<report_id>${reportId}</report_id>`;
  const records = Array.from({ length: rows }, (_, index) => `
    <record>
      <row>
        <source_ip>192.0.${Math.floor(index / 250)}.${(index % 250) + 1}</source_ip>
        <count>${index + 1 + countOffset}</count>
        <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
      </row>
      <identifiers><header_from>victim.example</header_from></identifiers>
      <auth_results>
        <dkim><domain>victim.example</domain><selector>s1</selector><result>pass</result></dkim>
        <spf><domain>victim.example</domain><result>pass</result></spf>
      </auth_results>
    </record>`).join("");
  return `<?xml version="1.0"?><feedback>
    <report_metadata>${metadata}</report_metadata>
    <policy_published><domain>victim.example</domain><p>none</p><pct>100</pct></policy_published>
    ${records}
  </feedback>`;
}

function tlsReport(reportId, failures) {
  return JSON.stringify({
    "organization-name": "Reporter",
    "date-range": {
      "start-datetime": "2026-07-22T00:00:00Z",
      "end-datetime": "2026-07-22T23:59:59Z",
    },
    "report-id": reportId,
    policies: [{
      policy: { "policy-type": "sts", "policy-domain": "victim.example" },
      summary: {
        "total-successful-session-count": 100,
        "total-failure-session-count": failures,
      },
      "failure-details": Array.from({ length: failures }, (_, index) => ({
        "result-type": `failure-${index}`,
        "failed-session-count": 1,
      })),
    }],
  });
}

function emailMessage(localpart, bodyBase64, {
  contentType = "application/xml",
  filename = "report.xml",
} = {}) {
  const raw = new TextEncoder().encode([
    `To: ${localpart}@reports.cybermeters.com`,
    "From: attacker@example.net",
    'Content-Type: multipart/mixed; boundary="GATE3B"',
    "",
    "--GATE3B",
    `Content-Type: ${contentType}`,
    `Content-Disposition: attachment; filename="${filename}"`,
    "Content-Transfer-Encoding: base64",
    "",
    bodyBase64,
    "--GATE3B--",
    "",
  ].join("\r\n"));
  return {
    to: `${localpart}@reports.cybermeters.com`,
    from: "attacker@example.net",
    rawSize: raw.length,
    raw: new Response(raw).body,
  };
}

// ── Budget derivation + exact cap ───────────────────────────────────────────
ok("D1 budget constant matches Cloudflare paid invocation limit",
  AGGREGATE_REPORT_D1_QUERY_BUDGET === 1000);
ok("persisted row cap is 300",
  AGGREGATE_REPORT_MAX_PERSISTED_ROWS === 300);
ok("worst-case DMARC transaction preserves material D1 headroom",
  AGGREGATE_REPORT_MAX_TRANSACTION_STATEMENTS === 604 &&
  AGGREGATE_REPORT_D1_QUERY_BUDGET -
    AGGREGATE_REPORT_MAX_TRANSACTION_STATEMENTS === 396);

{
  const db = buildDb();
  const binding = seed(db, "cap");
  const controls = {};
  const result = await ingestDmarcReport(envFor(db, controls), {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    xmlString: dmarcXml("max-300", 300),
    domainId: binding.domainId,
    enforceDomainMatch: true,
  });
  ok("exactly 300 DMARC rows ingest successfully", result.ok === true);
  ok("300-row DMARC core transaction is exactly 604 statements",
    controls.batchSizes.includes(604));
  ok("300 rows and 300 source rollups persist completely",
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records").get().c === 300 &&
    db.prepare("SELECT COUNT(*) c FROM email_sender_sources").get().c === 300);
}

// ── Over-cap reports are terminal, audited, and store nothing ───────────────
{
  const db = buildDb();
  const binding = seed(db, "overd");
  const result = await ingestDmarcReport(envFor(db), {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    xmlString: dmarcXml("over-301", 301),
    domainId: binding.domainId,
    enforceDomainMatch: true,
  });
  ok("301-row DMARC report is rejected at the persistence boundary",
    result.ok === false && result.error === "report_row_limit_exceeded" &&
    result.audited === true);
  ok("over-cap DMARC stores no claim, parent, child, or rollup",
    db.prepare("SELECT COUNT(*) c FROM aggregate_report_ingest_claims").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM email_sender_sources").get().c === 0);
  ok("over-cap DMARC has an append-only rejection audit",
    db.prepare("SELECT COUNT(*) c FROM audit_events WHERE event_type='dmarc_report_rejected'").get().c === 1);
}

{
  const db = buildDb();
  const binding = seed(db, "overt");
  const result = await ingestTlsRptReport(envFor(db), {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    jsonString: tlsReport("tls-over-301", 301),
    ingestEndpointId: binding.endpoint,
    domainId: binding.domainId,
    enforceDomainMatch: true,
  });
  ok("301-detail TLS-RPT report is rejected and audited",
    result.ok === false && result.error === "report_row_limit_exceeded" &&
    result.audited === true);
  ok("over-cap TLS-RPT stores no claim, parent, or failure row",
    db.prepare("SELECT COUNT(*) c FROM aggregate_report_ingest_claims").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_failure_details").get().c === 0);
}

// ── Mid-ingest failures roll back and redelivery repairs cleanly ────────────
{
  const db = buildPreGate3bDb();
  const binding = seed(db, "legacyrepair");
  const xml = dmarcXml("legacy-partial", 2);
  const contentHash = await sha256Hex(xml);
  db.prepare(
    `INSERT INTO dmarc_aggregate_reports
       (id,workspace_id,domain,org_name,external_report_id,date_range_begin,date_range_end,
        record_count,message_count,raw_hash,source,created_at)
     VALUES ('legacy_partial',?,?,?,?,?,?,2,3,?,'inbound_email',datetime('now'))`,
  ).run(binding.workspace, "victim.example", "Reporter", "legacy-partial",
    1784764800, 1784851200, contentHash);
  db.prepare(
    `INSERT INTO dmarc_aggregate_records
       (id,report_id,workspace_id,domain,source_ip,message_count,created_at)
     VALUES ('legacy_child','legacy_partial',?,?,?,1,datetime('now'))`,
  ).run(binding.workspace, "victim.example", "192.0.0.1");
  db.exec(fs.readFileSync(
    path.join(root, "database/migrations/100-aggregate-report-ingest-state.sql"),
    "utf8",
  ));
  ok("migration 100 marks a legacy child-count mismatch as failed/repairable",
    db.prepare(
      `SELECT ingest_state s, failure_code f
       FROM aggregate_report_ingest_claims
       WHERE report_id='legacy_partial'`,
    ).get().s === "failed");
  ok("failed legacy partial evidence is hidden until repair",
    db.prepare(
      `SELECT COUNT(*) c FROM dmarc_aggregate_reports rep
       WHERE ${aggregateReportCompleteSql("rep", "dmarc")}`,
    ).get().c === 0);
  const repaired = await ingestDmarcReport(envFor(db), {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    xmlString: xml,
    ingestEndpointId: binding.endpoint,
    domainId: binding.domainId,
    enforceDomainMatch: true,
  });
  ok("redelivery atomically replaces a legacy partial parent and children",
    repaired.ok === true && repaired.repaired === true &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports WHERE id='legacy_partial'").get().c === 1 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records WHERE report_id='legacy_partial'").get().c === 2 &&
    db.prepare("SELECT ingest_state s FROM aggregate_report_ingest_claims WHERE report_id='legacy_partial'").get().s === "complete");
}

{
  const db = buildDb();
  const binding = seed(db, "repaird");
  const controls = { failNextBatchAt: 3 };
  const env = envFor(db, controls);
  const opts = {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    xmlString: dmarcXml("repair-dmarc", 2),
    ingestEndpointId: binding.endpoint,
    domainId: binding.domainId,
    enforceDomainMatch: true,
  };
  const failed = await ingestDmarcReport(env, opts);
  ok("mid-DMARC transaction failure is explicit and quarantined",
    failed.ok === false && failed.transient === true &&
    failed.quarantined === true && failed.audited === true);
  ok("failed DMARC transaction leaves no partial evidence or rollup",
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM email_sender_sources").get().c === 0);
  ok("failed DMARC claim is repairable and durably audited",
    db.prepare("SELECT ingest_state s FROM aggregate_report_ingest_claims").get().s === "failed" &&
    db.prepare("SELECT COUNT(*) c FROM audit_events WHERE event_type='dmarc_report_ingest_failed'").get().c === 1);

  const repaired = await ingestDmarcReport(env, opts);
  ok("DMARC redelivery reacquires and completes the failed claim",
    repaired.ok === true && repaired.repaired === true);
  ok("repaired DMARC is complete exactly once",
    db.prepare("SELECT ingest_state s FROM aggregate_report_ingest_claims").get().s === "complete" &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 1 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records").get().c === 2 &&
    db.prepare("SELECT COUNT(*) c FROM email_sender_sources").get().c === 2);
}

{
  const db = buildDb();
  const binding = seed(db, "repairt");
  const controls = { failNextBatchAt: 2 };
  const env = envFor(db, controls);
  const opts = {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    jsonString: tlsReport("repair-tls", 2),
    ingestEndpointId: binding.endpoint,
    domainId: binding.domainId,
    enforceDomainMatch: true,
  };
  const failed = await ingestTlsRptReport(env, opts);
  ok("mid-TLS-RPT failure is explicit and leaves no partial rows",
    failed.ok === false && failed.transient === true &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_failure_details").get().c === 0);
  const repaired = await ingestTlsRptReport(env, opts);
  ok("TLS-RPT redelivery repairs to one complete parent and two details",
    repaired.ok === true && repaired.repaired === true &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c === 1 &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_failure_details").get().c === 2 &&
    db.prepare("SELECT ingest_state s FROM aggregate_report_ingest_claims").get().s === "complete");
}

// ── Non-null atomic dedupe and source-scope separation ──────────────────────
{
  const db = buildDb();
  const binding = seed(db, "nulls");
  const env = envFor(db);
  const opts = {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    xmlString: dmarcXml("concurrent-complete-metadata", 1),
    domainId: binding.domainId,
    enforceDomainMatch: true,
  };
  const [first, second] = await Promise.all([
    ingestDmarcReport(env, opts),
    ingestDmarcReport(env, opts),
  ]);
  ok("concurrent valid deliveries cannot bypass atomic claim dedupe",
    [first, second].filter((result) => result.ok && result.imported).length === 1 &&
    db.prepare("SELECT COUNT(*) c FROM aggregate_report_ingest_claims").get().c === 1 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 1);
  const claim = db.prepare(
    `SELECT identity_org_name, identity_date_begin, identity_date_end
     FROM aggregate_report_ingest_claims`,
  ).get();
  ok("strict metadata produces non-null atomic identity fields",
    claim.identity_org_name === "Reporter" &&
    claim.identity_date_begin === "1784764800" &&
    claim.identity_date_end === "1784851200");
}

{
  const db = buildDb();
  const binding = seed(db, "scope");
  const env = envFor(db);
  const xml = dmarcXml("scope-separated", 1);
  const observational = await ingestDmarcReport(env, {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "inbound_email",
    xmlString: xml,
    domainId: binding.domainId,
    enforceDomainMatch: true,
  });
  const authoritative = await ingestDmarcReport(env, {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "manual_paste",
    xmlString: xml,
    actorUserId: binding.user,
    domainId: binding.domainId,
  });
  ok("observational arrival does not suppress later authoritative submission",
    observational.ok === true && authoritative.ok === true &&
    authoritative.promoted === true && authoritative.duplicate === false);
  ok("source-scoped claims are separate and both complete",
    db.prepare("SELECT COUNT(*) c FROM aggregate_report_ingest_claims WHERE ingest_state='complete'").get().c === 2 &&
    db.prepare("SELECT COUNT(DISTINCT source_scope) c FROM aggregate_report_ingest_claims").get().c === 2);
  ok("authoritative promotion does not double-count children or sender totals",
    db.prepare("SELECT source FROM dmarc_aggregate_reports").get().source === "manual_paste" &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records").get().c === 1 &&
    db.prepare("SELECT total_messages n FROM email_sender_sources").get().n === 1);

  const collision = await ingestDmarcReport(env, {
    workspaceId: binding.workspace,
    domain: "victim.example",
    source: "manual_paste",
    xmlString: dmarcXml("scope-separated", 1, { countOffset: 10 }),
    actorUserId: binding.user,
    domainId: binding.domainId,
  });
  ok("same-scope natural-key collision compares hash and fails closed",
    collision.ok === false &&
    collision.error === "report_identity_collision" &&
    collision.audited === true);
}

// ── Terminal invalid-base64 and transient handler outcomes ─────────────────
{
  const db = buildDb();
  const binding = seed(db, "b64");
  let escaped = false;
  try {
    await emailWorker.default.email(
      emailMessage(binding.localpart, "%%%NOT-BASE64%%%"),
      envFor(db),
      {},
    );
  } catch {
    escaped = true;
  }
  ok("invalid base64 is an audited drop and does not escape the handler",
    escaped === false &&
    db.prepare(
      `SELECT COUNT(*) c FROM audit_events
       WHERE event_type='dmarc_inbound_email_dropped'
         AND metadata_json LIKE '%invalid_base64%'`,
    ).get().c === 1);
  ok("invalid base64 stores no report evidence",
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 0 &&
    db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c === 0);
}

{
  const db = buildDb();
  const binding = seed(db, "b64auditfail");
  let escaped = false;
  try {
    await emailWorker.default.email(
      emailMessage(binding.localpart, "%%%NOT-BASE64%%%"),
      envFor(db, { failAuditWrites: true }),
      {},
    );
  } catch {
    escaped = true;
  }
  ok("invalid base64 never becomes silent success when its audit store fails",
    escaped === true);
}

{
  const db = buildDb();
  const binding = seed(db, "inboundfail");
  const controls = { failNextBatchAt: 3 };
  const env = envFor(db, controls);
  const xml = dmarcXml("inbound-transient", 2);
  const body = Buffer.from(new TextEncoder().encode(xml)).toString("base64");
  await emailWorker.default.email(
    emailMessage(binding.localpart, body),
    env,
    {},
  );
  ok("transient inbound D1 failure is quarantined and audited, not silent",
    db.prepare("SELECT ingest_state s FROM aggregate_report_ingest_claims").get().s === "failed" &&
    db.prepare("SELECT COUNT(*) c FROM audit_events WHERE event_type='dmarc_report_ingest_failed'").get().c === 1 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 0);
  await emailWorker.default.email(
    emailMessage(binding.localpart, body),
    env,
    {},
  );
  ok("redelivered inbound message repairs the quarantined claim",
    db.prepare("SELECT ingest_state s FROM aggregate_report_ingest_claims").get().s === "complete" &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_reports").get().c === 1 &&
    db.prepare("SELECT COUNT(*) c FROM dmarc_aggregate_records").get().c === 2);
}

// ── Mutation guards ─────────────────────────────────────────────────────────
const dmarcSource = fs.readFileSync(
  path.join(root, "workers/scan-api/src/lib/dmarc-ingest.js"),
  "utf8",
);
const tlsSource = fs.readFileSync(
  path.join(root, "workers/scan-api/src/lib/tlsrpt-ingest.js"),
  "utf8",
);
const inboundSource = fs.readFileSync(
  path.join(root, "workers/scan-api/src/email/inbound.js"),
  "utf8",
);
const migrationSource = fs.readFileSync(
  path.join(root, "database/migrations/100-aggregate-report-ingest-state.sql"),
  "utf8",
);

const hasStateGate = (source) =>
  source.includes(
    "transaction.push(completeAggregateReportClaimStatement(env, claim));",
  ) &&
  source.includes("failAggregateReportClaim(");
ok("state gate is present in both ingestion implementations",
  hasStateGate(dmarcSource) && hasStateGate(tlsSource));
const noDmarcStateGate = dmarcSource.replace(
  "transaction.push(completeAggregateReportClaimStatement(env, claim));",
  "/* mutant: completion gate removed */",
);
ok("mutation removing the state gate is CI-red",
  noDmarcStateGate !== dmarcSource && hasStateGate(noDmarcStateGate) === false);

const hasNonNullScopedUniqueKey = (source) =>
  /identity_org_name\s+TEXT NOT NULL/.test(source) &&
  /identity_report_id\s+TEXT NOT NULL/.test(source) &&
  /identity_date_begin\s+TEXT NOT NULL/.test(source) &&
  /identity_date_end\s+TEXT NOT NULL/.test(source) &&
  /CREATE UNIQUE INDEX[\s\S]+source_scope[\s\S]+identity_org_name/.test(source);
ok("migration uses a non-null source-scoped atomic dedupe key",
  hasNonNullScopedUniqueKey(migrationSource));
const nullableIndexMutant = migrationSource.replace(
  "identity_org_name     TEXT NOT NULL",
  "identity_org_name     TEXT",
);
ok("mutation restoring nullable-key dedupe is CI-red",
  nullableIndexMutant !== migrationSource &&
  hasNonNullScopedUniqueKey(nullableIndexMutant) === false);

const hasNoSilentOuterCatch = (source) =>
  source.includes("aggregate_report_inbound_transient_failure") &&
  /catch\s*\{\s*[\s\S]{0,180}throw e;/.test(source);
ok("outer inbound catch records or rethrows transient failure",
  hasNoSilentOuterCatch(inboundSource));
const silentCatchMutant = inboundSource.replace(
  "throw e;",
  "return; /* mutant: silent success */",
);
ok("mutation restoring the silent catch is CI-red",
  silentCatchMutant !== inboundSource &&
  hasNoSilentOuterCatch(silentCatchMutant) === false);

console.log(`\nEmail-ingest reliability: ${pass}/${pass + fail} passed`);
if (fail) {
  console.error("email-ingest reliability validation FAILED");
  process.exit(1);
}
console.log("email-ingest reliability validation passed");
