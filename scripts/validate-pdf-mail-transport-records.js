#!/usr/bin/env node
// MTA-STS and TLS-RPT in the technical PDF: real-renderer proof that the report
// states what the scan recorded, in the same words as the mail transport card.
// The immutable snapshot does not carry these details; they come from the stored
// report the snapshot points at (read.customerModules). The contract:
//   1. positive, absent and unconcluded observations each read as themselves;
//   2. a report without the details says so, and never reads as absent;
//   3. a DNS reporting record never reads as a received TLS report;
//   4. the snapshot is only read, never changed;
//   5. the same read renders the same bytes.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { buildScanReportPdf } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "pdf.js")).href);

const EXPECTED_ASSERTIONS = 13;

let pass = 0;
let fail = 0;
const ok = (name, condition) => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}`);
};

function snapshot() {
  return {
    snapshot: {
      snapshot_id: "snap-pdf-dmarc",
      domain: "mail.example.test",
      scan_id: "scan-pdf-dmarc",
      as_of: "2026-07-25T20:00:00.000Z",
      built_at: "2026-07-25T20:00:01.000Z",
      provenance: "scan_finalize",
    },
    methodology: { snapshot_builder_version: "canonical-report-snapshot-v3" },
    overall: {
      cyber_metrics_score: null,
      score_band: null,
      assessment: {
        provisional: true,
        comparable: false,
        quality: "partial",
        message: "Assessment evidence is incomplete.",
      },
      business_risk_indicator: {},
      summary: "Assessment evidence is incomplete.",
      evidence_completeness: {},
    },
    domains: [],
    observed_findings: [],
    observations: [],
    remediation_actions: [],
    monitoring_states: {},
    limitations: [],
  };
}

const scan = { id: "scan_mail_transport", domain: "mail.example.test" };

function renderBytes(modules, snap = snapshot()) {
  return buildScanReportPdf(scan, { snapshot: snap, customerSnapshot: snap, customerModules: modules, dmarcPolicy: null });
}
// The writer wraps long lines, so the assertions read the text operators joined.
const pageText = (bytes) => [...new TextDecoder().decode(bytes).matchAll(/\(((?:\\.|[^\\)])*)\) Tj/g)]
  .map((match) => match[1].replace(/\\([()\\])/g, "$1"))
  .join(" ");
const render = (mtaSts, tlsRpt) => pageText(renderBytes(
  { email_security: { mta_sts_detail: mtaSts, tls_rpt_detail: tlsRpt } },
));

const present = render(
  { policy_found: true, mode: "enforce", observation_state: "present" },
  { record_found: true, observation_state: "present", rua: ["mailto:tls@mail.example.test"] },
);
ok("contents lists the section", present.includes("Mail transport records  ....."));
ok("enforce policy is stated", present.includes("MTA-STS: enforce policy observed; DNS activation not separately checked."));
ok("record is stated as DNS only", present.includes("TLS-RPT: reporting record observed in DNS; this does not show that TLS reports were received."));

const testing = render({ policy_found: true, mode: "testing" }, { record_found: true });
ok("testing mode is not enforcement", testing.includes("MTA-STS: testing policy observed") && !testing.includes("enforce policy observed"));

const absent = render(
  { policy_found: false, observation_state: "definitive_absent" },
  { record_found: false, observation_state: "definitive_absent" },
);
ok("absent policy is stated", absent.includes("MTA-STS: enforcement not confirmed; no policy file was confirmed."));
ok("absent record is stated", absent.includes("TLS-RPT: reporting record not found."));

const unknown = render(
  { policy_found: null, observation_state: "unavailable" },
  { record_found: null, observation_state: "unavailable" },
);
ok("unknown policy is not absent", unknown.includes("the check did not conclude") && !unknown.includes("no policy file was confirmed"));
ok("unknown record is not absent", unknown.includes("the lookup did not conclude") && !unknown.includes("reporting record not found"));

const legacy = render(undefined, { record_found: false });
ok("older false reading stays unconfirmed, not absent", legacy.includes("TLS-RPT: reporting record not confirmed.") && !legacy.includes("reporting record not found"));

const unrecorded = pageText(renderBytes({}));
ok("missing details say so", unrecorded.includes("MTA-STS: enforcement not confirmed; not recorded for this check."));
ok("missing details say so for TLS-RPT", unrecorded.includes("TLS-RPT: reporting record not confirmed; not recorded for this check."));

const frozen = snapshot();
const before = JSON.stringify(frozen);
const modules = { email_security: { mta_sts_detail: { policy_found: true, mode: "enforce" }, tls_rpt_detail: { record_found: true } } };
const first = renderBytes(modules, frozen);
ok("snapshot is unchanged", JSON.stringify(frozen) === before);
ok("rendering is deterministic", Buffer.compare(Buffer.from(first), Buffer.from(renderBytes(modules, frozen))) === 0);

if (pass + fail !== EXPECTED_ASSERTIONS) {
  console.error(`FAIL assertion count ${pass + fail}, expected ${EXPECTED_ASSERTIONS}`);
  process.exit(1);
}
if (fail) process.exit(1);
console.log(`validate-pdf-mail-transport-records: ${pass} assertions passed`);
