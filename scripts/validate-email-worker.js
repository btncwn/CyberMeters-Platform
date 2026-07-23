#!/usr/bin/env node
//
// Sprint 10 Stage B equivalence harness. Drives the INBOUND EMAIL handler of
// BOTH deployments — the api worker (workers/scan-api) and the standalone
// email worker (workers/email-ingest) — against two identically-seeded real
// in-memory SQLite databases (actual schema), and proves:
//   1. a real RUA email (gzip DMARC XML attachment) ingests end to end,
//   2. the duplicate natural-key dedupe still holds,
//   3. an unknown recipient is dropped safely (audit, no rows),
//   4. GOLDEN: both workers produce identical DB outcomes for the same email,
//   5. the real standalone export bounds a 121-message endpoint flood,
//   6. TLS-RPT traverses the real standalone export under the canonical limiter,
//   7. missing/removed limiter wiring is a CI-red hard failure, and
//   8. the email worker's health surface responds.
// Requires Node 24+ (node:sqlite). Exits non-zero on any failure so CI blocks.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) {
      const b = wrap(sql, []);
      b.bind = (...args) => wrap(sql, args);
      return b;
    },
    async batch(statements) {
      db.exec("BEGIN");
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

function seed(db) {
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status) VALUES (?, ?, ?, ?, ?, ?)")
    .run("userA", "a@example.com", "x", "Alice", "free", "active");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws1", "userA", "Alpha");
  db.prepare("INSERT INTO domains (id, domain, user_id) VALUES (?, ?, ?)").run("dom1", "example.com", "userA");
  db.prepare(`INSERT INTO dmarc_ingest_endpoints (id, workspace_id, domain_id, domain, token_hash, address_local, status, created_at)
              VALUES (?, ?, ?, ?, ?, ?, 'active', datetime('now'))`)
    .run("ep1", "ws1", "dom1", "example.com", "unused-hash", "cmrua_equivtest01");
}

function makeEnv(db, workerName) {
  return {
    cybermeters_db: makeD1(db),
    RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    SAFE_EMAIL_FROM: "safe@cybermeters.com", HELLO_EMAIL_FROM: "hello@cybermeters.com",
    ALERT_EMAIL_FROM: "alerts@cybermeters.com", ALERT_EMAIL_TO: "ops@example.com",
    RESEND_API_KEY: "", APP_VERSION: "test",
    ...(workerName ? { WORKER_NAME: workerName } : {}),
  };
}

// ── RUA email construction (same technique as the regression fixtures) ────────
const DMARC_XML = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>noreply-dmarc@google.com</email><report_id>RPT-EQUIV-1</report_id>
    <date_range><begin>1717200000</begin><end>1717286400</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><pct>100</pct></policy_published>
  <record><row><source_ip>209.85.220.41</source_ip><count>100</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>
</feedback>`;

const TLS_RPT_JSON = JSON.stringify({
  "organization-name": "Example Reporter",
  "date-range": {
    "start-datetime": "2026-07-22T00:00:00Z",
    "end-datetime": "2026-07-22T23:59:59Z",
  },
  "contact-info": "tls-reports@example.net",
  "report-id": "TLS-STANDALONE-1",
  policies: [{
    policy: { "policy-type": "sts", "policy-domain": "example.com" },
    summary: {
      "total-successful-session-count": 97,
      "total-failure-session-count": 3,
    },
    "failure-details": [{
      "result-type": "certificate-expired",
      "failed-session-count": 3,
    }],
  }],
});

async function gzipBytes(text) {
  const stream = new Response(new TextEncoder().encode(text)).body.pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function buildGzipReportMime(text, {
  contentType,
  filename,
  boundary,
  from,
}) {
  const gz = await gzipBytes(text);
  const b64 = Buffer.from(gz).toString("base64").replace(/(.{76})/g, "$1\r\n");
  return `From: ${from}\r\nSubject: Aggregate report for example.com\r\n` +
    `Content-Type: multipart/mixed; boundary="${boundary}"\r\n\r\n` +
    `--${boundary}\r\nContent-Type: text/plain\r\n\r\nReport attached.\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: ${contentType}; name="${filename}"\r\n` +
    `Content-Disposition: attachment; filename="${filename}"\r\n` +
    `Content-Transfer-Encoding: base64\r\n\r\n${b64}\r\n--${boundary}--\r\n`;
}

async function buildRuaMime() {
  return buildGzipReportMime(DMARC_XML, {
    contentType: "application/gzip",
    filename: "example.com!report.xml.gz",
    boundary: "EQ1",
    from: "noreply-dmarc@google.com",
  });
}

async function buildTlsRptMime() {
  return buildGzipReportMime(TLS_RPT_JSON, {
    contentType: "application/tlsrpt+gzip",
    filename: "example.com!tls-report.json.gz",
    boundary: "TLS1",
    from: "tls-reports@example.net",
  });
}

function message(to, mime) {
  const bytes = new TextEncoder().encode(mime);
  return { to, rawSize: bytes.length, raw: new Response(bytes).body };
}

function trackedMessage(to, mime) {
  const bytes = new TextEncoder().encode(mime);
  let rawRead = false;
  return {
    to,
    rawSize: bytes.length,
    get raw() {
      rawRead = true;
      return new Response(bytes).body;
    },
    rawWasRead: () => rawRead,
  };
}

// ── DB outcome snapshot for the golden comparison (stable fields only) ─────────
function snapshot(db) {
  const reports = db.prepare(
    `SELECT domain, org_name, external_report_id, date_range_begin, date_range_end, source,
            record_count, message_count, reporter_domain, auth_verdict
     FROM dmarc_aggregate_reports ORDER BY external_report_id`).all();
  const records = db.prepare(
    `SELECT source_ip, message_count, disposition, dkim_result, spf_result, header_from
     FROM dmarc_aggregate_records ORDER BY source_ip`).all();
  const senders = db.prepare(
    `SELECT domain, source_ip, total_messages FROM email_sender_sources ORDER BY source_ip`).all();
  const audits = db.prepare(
    `SELECT event_type, entity_type FROM audit_events ORDER BY event_type`).all();
  return JSON.stringify({ reports, records, senders, audits });
}

let passed = 0, failed = 0; const results = [];
function ok(name, cond) {
  if (cond) { passed++; results.push(`PASS ${name}`); }
  else      { failed++; results.push(`FAIL ${name}`); }
}

async function main() {
  const apiMod   = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);
  const emailMod = await import(pathToFileURL(path.join(root, "workers", "email-ingest", "src", "index.js")).href);
  const inboundMod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "email", "inbound.js")).href);

  const mime = await buildRuaMime();

  // ── 1-3: the standalone email worker, end to end on a real schema ──
  const dbE = buildDb(); seed(dbE);
  const envE = makeEnv(dbE, "email-ingest");
  await emailMod.default.email(message("cmrua_equivtest01@reports.cybermeters.com", mime), envE, {});
  const reportRow = dbE.prepare("SELECT org_name, external_report_id FROM dmarc_aggregate_reports").get();
  ok("email worker ingests a real RUA email (report row persisted)",
    reportRow?.org_name === "google.com" && reportRow?.external_report_id === "RPT-EQUIV-1");
  ok("record row persisted with parsed auth results",
    dbE.prepare("SELECT count(*) c FROM dmarc_aggregate_records").get().c === 1);
  ok("standalone export consumed the canonical endpoint rate limit",
    dbE.prepare("SELECT request_count FROM api_rate_limits WHERE action='rua_inbound'").get()?.request_count === 1);

  await emailMod.default.email(message("cmrua_equivtest01@reports.cybermeters.com", mime), envE, {});
  ok("DUPLICATE: same report again → still exactly one report row (natural-key dedupe)",
    dbE.prepare("SELECT count(*) c FROM dmarc_aggregate_reports").get().c === 1);
  ok("DUPLICATE: dedupe is audited (dmarc_report_duplicate event)",
    dbE.prepare("SELECT count(*) c FROM audit_events WHERE event_type='dmarc_report_duplicate'").get().c >= 1);

  const dbU = buildDb(); seed(dbU);
  await emailMod.default.email(message("nobody_here@reports.cybermeters.com", mime), makeEnv(dbU, "email-ingest"), {});
  ok("UNKNOWN recipient: no report rows written",
    dbU.prepare("SELECT count(*) c FROM dmarc_aggregate_reports").get().c === 0);
  ok("UNKNOWN recipient: dropped with a safe audit event",
    dbU.prepare("SELECT count(*) c FROM audit_events WHERE event_type='dmarc_inbound_email_dropped'").get().c === 1);

  // ── 4: GOLDEN — api worker vs email worker on identical fresh DBs ──
  const dbA = buildDb(); seed(dbA);
  const dbB = buildDb(); seed(dbB);
  await apiMod.default.email(message("cmrua_equivtest01@reports.cybermeters.com", mime), makeEnv(dbA, null), {});
  await emailMod.default.email(message("cmrua_equivtest01@reports.cybermeters.com", mime), makeEnv(dbB, "email-ingest"), {});
  const snapA = snapshot(dbA), snapB = snapshot(dbB);
  ok("GOLDEN: api worker and email worker produce IDENTICAL DB outcomes for the same email",
    snapA === snapB && snapA.includes("RPT-EQUIV-1"));

  // ── 5: real standalone export bounds a forged cross-message flood ──
  const dbFlood = buildDb(); seed(dbFlood);
  const envFlood = makeEnv(dbFlood, "email-ingest");
  for (let index = 0; index < 120; index += 1) {
    await emailMod.default.email(
      message("cmrua_equivtest01@reports.cybermeters.com", mime),
      envFlood,
      {},
    );
  }
  const blockedMessage = trackedMessage(
    "cmrua_equivtest01@reports.cybermeters.com",
    mime,
  );
  await emailMod.default.email(blockedMessage, envFlood, {});
  ok("standalone forged flood is bounded at 120 messages per endpoint/window",
    dbFlood.prepare("SELECT request_count FROM api_rate_limits WHERE action='rua_inbound'").get()?.request_count === 120);
  ok("standalone message 121 is rejected before its raw body is read",
    blockedMessage.rawWasRead() === false);
  ok("standalone rate-limit rejection is append-only audited",
    dbFlood.prepare("SELECT count(*) c FROM audit_events WHERE event_type='dmarc_inbound_email_rate_limited'").get().c === 1);

  // ── 6: TLS-RPT parity through the real standalone export ──
  const dbTls = buildDb(); seed(dbTls);
  const tlsMime = await buildTlsRptMime();
  await emailMod.default.email(
    message("cmrua_equivtest01@reports.cybermeters.com", tlsMime),
    makeEnv(dbTls, "email-ingest"),
    {},
  );
  const tlsRow = dbTls.prepare(
    `SELECT external_report_id, total_successful_sessions, total_failure_sessions
     FROM tlsrpt_aggregate_reports`,
  ).get();
  ok("standalone export routes and stores TLS-RPT under the canonical limiter",
    tlsRow?.external_report_id === "TLS-STANDALONE-1" &&
    tlsRow?.total_successful_sessions === 97 &&
    tlsRow?.total_failure_sessions === 3 &&
    dbTls.prepare("SELECT request_count FROM api_rate_limits WHERE action='rua_inbound'").get()?.request_count === 1);

  // ── 7: missing/removal wiring is CI-red, never silently unthrottled ──
  let missingWiringRejected = false;
  try {
    await inboundMod.handleInboundEmail(
      message("cmrua_equivtest01@reports.cybermeters.com", mime),
      makeEnv(buildDb(), "email-ingest"),
      {},
    );
  } catch (error) {
    missingWiringRejected = error?.message === "inbound_rate_limiter_not_wired";
  }
  ok("shared handler rejects absent limiter wiring before processing",
    missingWiringRejected === true);

  const emailEntryPath = path.join(root, "workers", "email-ingest", "src", "index.js");
  const emailEntrySource = fs.readFileSync(emailEntryPath, "utf8");
  const mandatoryInjection = (source) =>
    /handleInboundEmail\(message, env, ctx, \{ consumeApiRateLimit, rateLimitScopeId \}\)/.test(source);
  ok("standalone entry has mandatory canonical limiter injection",
    mandatoryInjection(emailEntrySource));
  const unwiredMutant = emailEntrySource.replace(
    /email:\s*\(message, env, ctx\)\s*=>\s*\n?\s*handleInboundEmail\(message, env, ctx, \{ consumeApiRateLimit, rateLimitScopeId \}\),/,
    "email: handleInboundEmail,",
  );
  ok("mutation removes standalone limiter injection",
    unwiredMutant !== emailEntrySource);
  ok("mutation removing standalone limiter injection is CI-red",
    mandatoryInjection(unwiredMutant) === false);

  // ── 8: health surface ──
  const health = await emailMod.default.fetch(new Request("https://cybermeters-email.example/health"), makeEnv(buildDb(), "email-ingest"));
  const hBody = await health.json();
  ok("email worker /health → 200 {status:ok, service:cybermeters-email}",
    health.status === 200 && hBody.status === "ok" && hBody.service === "cybermeters-email");
  const notFound = await emailMod.default.fetch(new Request("https://cybermeters-email.example/api/anything"), makeEnv(buildDb(), "email-ingest"));
  ok("email worker serves NO app routes (health-only surface) → 404", notFound.status === 404);

  for (const line of results) if (line.startsWith("FAIL")) console.error(line);
  console.log(`\nEmail-worker equivalence: ${passed}/${passed + failed} passed`);
  if (failed > 0) { console.error("email-worker validation FAILED"); process.exit(1); }
  console.log("email-worker validation passed");
}

main().catch((e) => { console.error("email-worker runner crashed:", e); process.exit(1); });
