#!/usr/bin/env node
//
// PR-5.5 Gate 5 preparation validator. Proves that the founder preflight drives
// the real production parser without mutation, that envelope diagnostics are
// present, and that the documented cutover preserves migration/deploy order,
// per-address routing, rollback capture, and Gate 1/2 containment.
//
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const preflightRelative = "scripts/preflight-real-aggregate-report.js";
const generatorRelative = "scripts/generate-gate5-forged-rua-fixture.js";
const runbookRelative =
  "docs/security/PR-5.5-GATE5-CUTOVER-RUNBOOK.md";
const inboundRelative = "workers/scan-api/src/email/inbound.js";
const wranglerRelative = "workers/email-ingest/wrangler.toml";
const workflowRelative = ".github/workflows/ci.yml";
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

const preflightSource = read(preflightRelative);
const generatorSource = read(generatorRelative);
const runbook = read(runbookRelative);
const inbound = read(inboundRelative);
const emailWrangler = read(wranglerRelative);
const workflow = read(workflowRelative);

let pass = 0;
let fail = 0;
const ok = (name, condition) => {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.error(`FAIL ${name}`);
  }
};

ok("offline preflight imports the canonical streamed MIME parser",
  /parseMimeMessageStream/.test(preflightSource) &&
  /workers\/scan-api\/src\/email\/inbound\.js/.test(preflightSource));
ok("offline preflight derives authority from the canonical source gate",
  /buildAggregateReportTrustSemantics/.test(preflightSource) &&
  /source:\s*"inbound_email"/.test(preflightSource) &&
  /automation_eligible: trust\.external_automation_eligible/.test(
    preflightSource,
  ));
ok("offline preflight has no production mutation or network primitive",
  !/\b(?:fetch|wrangler|d1 execute|send_email|cybermeters_db)\b/i.test(
    preflightSource,
  ) &&
  /production_mutated:\s*false/.test(preflightSource));
ok("preflight reports all envelope dimensions and explicit limits",
  [
    "raw_email_bytes",
    "encoded_attachment_bytes",
    "transfer_decoded_attachment_bytes",
    "decoded_report_body_bytes",
    "nested_multipart",
    "RUA_RAW_EMAIL_MAX_BYTES",
    "RUA_ENCODED_ATTACHMENT_MAX_BYTES",
    "RUA_ATTACHMENT_MAX_BYTES",
    "RUA_DECOMPRESSED_MAX_BYTES",
  ].every((term) => preflightSource.includes(term)));
ok("future successful audits persist safe envelope diagnostics",
  /raw_email_size: parsedMessage\.stats\.total_bytes/.test(inbound) &&
  /encoded_attachment_size: tlsSel\.part\.encoded_size/.test(inbound) &&
  /encoded_attachment_size: sel\.part\.encoded_size/.test(inbound) &&
  (inbound.match(/nested_multipart: parsedMessage\.stats\.max_depth > 1/g) || [])
    .length >= 2 &&
  (inbound.match(/mime_max_depth: parsedMessage\.stats\.max_depth/g) || [])
    .length >= 2);
ok("production parser exposes encoded and transfer-decoded sizes without content",
  /encoded_size: leafLength/.test(inbound) &&
  /transfer_decoded_size: bytes\.length/.test(inbound));
ok("email Worker workers.dev invariant is explicit",
  /^workers_dev = true$/m.test(emailWrangler));
ok("Email Routing contract is exact-address only and rejects catch-all guidance",
  /only exact per-address Email Routing rules may target this/.test(inbound) &&
  /Never enable catch-all routing/.test(inbound) &&
  !/should send \*@reports\.cybermeters\.com/.test(inbound));
ok("legacy nested-multipart reason is read-compatible but never live-emitted",
  /case "unsupported_nested_multipart": return "unsupported_nested_multipart"/
    .test(inbound) &&
  !/throw new Error\("unsupported_nested_multipart"\)/.test(inbound) &&
  /throw new Error\("mime_nesting_too_deep"\)/.test(inbound));

const migration = runbook.indexOf("### 1. Apply migration 100");
const scanDeploy = runbook.indexOf("### 2. Deploy `cybermeters-platform`");
const emailDeploy = runbook.indexOf("### 3. Deploy `cybermeters-email`");
ok("runbook orders migration before scan-api before email Worker",
  migration >= 0 && scanDeploy > migration && emailDeploy > scanDeploy);
ok("runbook records rollback IDs before both deployments",
  runbook.includes('SCAN_ROLLBACK_VERSION="<CURRENT_100_PERCENT_VERSION_ID>"') &&
  runbook.includes('EMAIL_ROLLBACK_VERSION="<CURRENT_100_PERCENT_VERSION_ID>"'));
ok("runbook verifies migration 099, migration 100 schema, and historical rows",
  runbook.includes("migration_099_indexes") &&
  runbook.includes("tlsrpt_source_columns") &&
  runbook.includes("dmarc_signature") &&
  runbook.includes("tlsrpt_signature") &&
  runbook.includes("dmarc_missing_claims") &&
  runbook.includes("tlsrpt_missing_claims"));
ok("runbook keeps the evidence gap as a hard pre-deploy blocker",
  runbook.includes("BLOCKED pending original `.eml`") &&
  runbook.includes("BLOCKED: no delivery path/sample") &&
  runbook.includes("not yet proven envelope-fit"));
ok("runbook live acceptance checks observational complete claims and DNS non-change",
  runbook.includes("source_scope=observational") &&
  runbook.includes("ingest_state=complete") &&
  runbook.includes("external_automation_eligible") &&
  runbook.includes("byte-for-byte unchanged"));
ok("forged fixture generator never sends and uses reserved test IPs",
  !/\b(?:fetch|send_email|smtp|nodemailer)\b/i.test(generatorSource) &&
  /sent: false/.test(generatorSource) &&
  /203\.0\.113\./.test(generatorSource));
ok("CI invokes the Gate 5 preparation validator",
  workflow.includes("node scripts/validate-gate5-cutover-prep.js"));

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "gate5-preflight-"));
try {
  const xmlPath = path.join(temp, "forged.xml");
  const generated = spawnSync(process.execPath, [
    path.join(root, generatorRelative),
    "--domain", "blackbullbarbers.co.uk",
    "--scenario", "fail",
    "--output", xmlPath,
    "--report-id", "gate5-validator-fail",
  ], { encoding: "utf8" });
  ok("forged fixture generator produces a strict local file",
    generated.status === 0 && fs.existsSync(xmlPath));

  const xml = fs.readFileSync(xmlPath, "utf8");
  const encoded = Buffer.from(xml).toString("base64");
  const boundary = "gate5-validator-boundary";
  const eml = [
    "From: founder@example.invalid",
    "To: cmrua_validator@reports.cybermeters.com",
    "Subject: Gate 5 validator",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain",
    "",
    "offline fixture",
    `--${boundary}`,
    'Content-Type: application/xml; name="report.xml"',
    'Content-Disposition: attachment; filename="report.xml"',
    "Content-Transfer-Encoding: base64",
    "",
    encoded,
    `--${boundary}--`,
    "",
  ].join("\r\n");
  const emlPath = path.join(temp, "report.eml");
  fs.writeFileSync(emlPath, eml);
  const preflight = spawnSync(process.execPath, [
    path.join(root, preflightRelative),
    "--file", emlPath,
    "--expect-domain", "blackbullbarbers.co.uk",
  ], { encoding: "utf8" });
  let result = null;
  try { result = JSON.parse(preflight.stdout); } catch { /* asserted below */ }
  ok("real production parser preflight accepts a strict captured envelope",
    preflight.status === 0 &&
    result?.outcome === "ACCEPT" &&
    result?.success === true &&
    result?.authority === "observational/non-authoritative" &&
    result?.automation_eligible === false &&
    result?.limit_hit === null);
  ok("ACCEPT reports exact raw, encoded, decoded, and nesting evidence",
    result?.raw_email_bytes === Buffer.byteLength(eml) &&
    result?.encoded_attachment_bytes === encoded.length &&
    result?.decoded_report_body_bytes === Buffer.byteLength(xml) &&
    result?.nested_multipart === "not_present" &&
    result?.exactly_one_report_attachment === true);

  const nested = [
    "Content-Type: multipart/mixed; boundary=outer",
    "",
    "--outer",
    "Content-Type: multipart/alternative; boundary=inner",
    "",
    "--inner",
    "Content-Type: text/plain",
    "",
    "human-readable branch",
    "--inner--",
    "--outer",
    'Content-Type: application/xml; name="report.xml"',
    'Content-Disposition: attachment; filename="report.xml"',
    "Content-Transfer-Encoding: base64",
    "",
    encoded,
    "--outer--",
    "",
  ].join("\r\n");
  const nestedPath = path.join(temp, "nested.eml");
  fs.writeFileSync(nestedPath, nested);
  const nestedAccepted = spawnSync(process.execPath, [
    path.join(root, preflightRelative),
    "--file", nestedPath,
    "--expect-domain", "blackbullbarbers.co.uk",
  ], { encoding: "utf8" });
  let nestedResult = null;
  try {
    nestedResult = JSON.parse(nestedAccepted.stdout);
  } catch { /* asserted below */ }
  ok("bounded nested envelope is accepted with one observational attachment",
    nestedAccepted.status === 0 &&
    nestedResult?.outcome === "ACCEPT" &&
    nestedResult?.nested_multipart === "accepted_bounded" &&
    nestedResult?.exactly_one_report_attachment === true &&
    nestedResult?.automation_eligible === false);

  const deep = [
    "Content-Type: multipart/mixed; boundary=depth-1",
    "",
  ];
  for (let level = 1; level <= 5; level += 1) {
    deep.push(
      `--depth-${level}`,
      `Content-Type: multipart/mixed; boundary=depth-${level + 1}`,
      "",
    );
  }
  deep.push(
    "--depth-6",
    "Content-Type: text/plain",
    "",
    "too deep",
    "--depth-6--",
  );
  for (let level = 5; level >= 1; level -= 1) {
    deep.push(`--depth-${level}--`);
  }
  deep.push("");
  const deepPath = path.join(temp, "over-depth.eml");
  fs.writeFileSync(deepPath, deep.join("\r\n"));
  const deepRejected = spawnSync(process.execPath, [
    path.join(root, preflightRelative),
    "--file", deepPath,
    "--expect-domain", "blackbullbarbers.co.uk",
  ], { encoding: "utf8" });
  let deepResult = null;
  try { deepResult = JSON.parse(deepRejected.stdout); } catch { /* asserted */ }
  ok("nesting beyond depth five emits only mime_nesting_too_deep",
    deepRejected.status === 2 &&
    deepResult?.outcome === "AUDITED_REJECT" &&
    deepResult?.parser_reason === "mime_nesting_too_deep" &&
    deepResult?.audited_reason === "mime_nesting_too_deep" &&
    deepResult?.nested_multipart === "present_rejected_over_depth");

  const duplicate = eml.replace(
    `--${boundary}--\r\n`,
    [
      `--${boundary}`,
      'Content-Type: application/xml; name="second.xml"',
      'Content-Disposition: attachment; filename="second.xml"',
      "Content-Transfer-Encoding: base64",
      "",
      encoded,
      `--${boundary}--`,
      "",
    ].join("\r\n"),
  );
  const duplicatePath = path.join(temp, "duplicate.eml");
  fs.writeFileSync(duplicatePath, duplicate);
  const duplicateRejected = spawnSync(process.execPath, [
    path.join(root, preflightRelative),
    "--file", duplicatePath,
    "--expect-domain", "blackbullbarbers.co.uk",
  ], { encoding: "utf8" });
  let duplicateResult = null;
  try {
    duplicateResult = JSON.parse(duplicateRejected.stdout);
  } catch { /* asserted */ }
  ok("duplicate report candidates are audited-rejected",
    duplicateRejected.status === 2 &&
    duplicateResult?.outcome === "AUDITED_REJECT" &&
    duplicateResult?.audited_reason === "multiple_dmarc_attachments");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

console.log(`\nGate 5 cutover preparation: ${pass}/${pass + fail} passed`);
if (fail) {
  console.error("Gate 5 cutover preparation validation FAILED");
  process.exit(1);
}
console.log("Gate 5 cutover preparation validation passed");
