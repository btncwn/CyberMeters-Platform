#!/usr/bin/env node
// PDF-DMARC-OBJECT-RENDERING — real-renderer proof that the Executive PDF's
// "Observed DMARC record data" rows render the canonical customer-readable
// record string and never an internal parser object.
//
// Confirmed production defect (scan_4f100e6d-13df-4307-8f97-c98eb0493135):
// the renderer selected `record.raw ?? record.value ?? record`. `raw` is the
// original DNS answer OBJECT on the production DoH path, so nullish selection
// stopped there and String(object) printed "[object Object]" — the canonical
// `record.value` string was never reached. The contract under proof:
//   1. a string `value` is the canonical printable representation;
//   2. otherwise a string `raw` (legacy scalar shape) is printable;
//   3. otherwise the record has no customer-printable scalar → no row;
//   4. the "Observed DMARC record data" heading renders only when at least
//      one printable record exists — never as an empty section;
//   5. internal parser structure is never serialised into a customer report.
//
// Every assertion runs through the REAL buildScanReportPdf renderer — no
// copied formatter, no isolated helper return values. The assertion count is
// pinned: drift exits non-zero.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => pathToFileURL(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  name,
)).href;

const { buildScanReportPdf } = await import(engine("pdf.js"));

const EXPECTED_ASSERTIONS = 20;

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) {
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const count = (haystack, needle) => haystack.split(needle).length - 1;

// Production-shaped DMARC evidence (dmarc-policy.v2). Only raw_records and
// parsed_tags vary per fixture; everything else stays a stable current read so
// the technical appendix renders exactly as it does for a real scan.
function evidence({ raw_records, parsed_tags = [] }) {
  return {
    schema: "dmarc-policy.v2",
    methodology_version: "rfc9989-treewalk-v1",
    parser_version: "dmarcbis-policy-parser-v1",
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    author_domain: "mail.example.test",
    submitted_domain: "mail.example.test",
    observed_at: "2026-07-25T20:00:00.000Z",
    observation_state: "present_valid",
    record_validity: "valid",
    raw_records,
    parsed_tags,
    lookup_path: [{
      question: {
        name: "_dmarc.mail.example.test",
        type: "TXT",
        purpose: "policy_tree_walk",
      },
      outcome: "nodata",
      logically_used: true,
    }],
    organisational_domain: "example.test",
    organisational_domain_provenance: "psd_n",
    organisational_domain_completeness: "complete",
    policy_source_domain: "example.test",
    policy_source_kind: "exact",
    domain_existence: "exists",
    existence_completeness: "complete",
    declared_policy: "none",
    effective_requested_policy: "none",
    testing_adjustment: "none",
    effective_policy_tag: "p",
    inheritance_reason: "none",
    p: { present: true, raw: "none", normalized: "none", valid: true },
    sp: { present: false, raw: null, normalized: null, valid: true },
    np: { present: false, raw: null, normalized: null, valid: true },
    t: { present: false, raw: null, normalized: null, valid: true },
    psd: { present: false, raw: null, normalized: null, valid: true },
    legacy_pct: {
      observed: false,
      raw: null,
      numeric: null,
      applied_to_effective_policy: false,
    },
    policy_completeness: "complete",
    core_completeness: "complete",
    rua_authorisation_completeness: "complete",
    monitoring_state: "monitoring_healthy",
    provider_state: "available",
    corroboration_state: "corroborated",
    receiver_enforcement_observed: false,
    external_rua_authorisation: {
      all_destinations_authorized: null,
      destinations: [],
    },
    evidence_grade: {
      grade: "L3",
      source_type: "normative_protocol",
      basis: "Complete RFC 9989 policy discovery.",
      limits: ["Receiver enforcement is not observed."],
      repeat_confirmed: false,
    },
    evidence_fingerprint: "fixture-fingerprint",
  };
}

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

function renderPdf(records, parsed_tags = []) {
  const read = {
    status: "ok",
    snapshot: snapshot(),
    row: { id: "snap-pdf-dmarc" },
    integrity: { status: "verified" },
    dmarcPolicy: {
      status: "current",
      evidence: evidence({ raw_records: records, parsed_tags }),
    },
  };
  return new TextDecoder().decode(buildScanReportPdf(
    { id: "scan-pdf-dmarc", domain: "mail.example.test" },
    read,
  ));
}

const HEADING = "Observed DMARC record data";
const OBJECT_MARKER = "[object Object]";

// ── A. Production-shaped parsed record: raw = object, value = string ────────
const VALUE_A = "v=DMARC1; p=none; rua=mailto:record-a@example.test";
const pdfA = renderPdf(
  [{
    index: 0,
    chunks: [VALUE_A],
    value: VALUE_A,
    byte_length: VALUE_A.length,
    truncated: false,
    raw: {
      name: "_dmarc.mail.example.test",
      type: 16,
      data: "internal-dns-answer-shape-a",
    },
  }],
  [
    { name: "p", raw_value: "none" },
    { name: "rua", raw_value: "mailto:tag-line-fixture@example.test" },
  ],
);
ok("A: canonical record value renders", pdfA.includes(VALUE_A));
ok("A: no object marker", !pdfA.includes(OBJECT_MARKER));
ok("A: internal DNS answer structure is not dumped",
  !pdfA.includes("internal-dns-answer-shape-a"));

// ── B. Legacy scalar fallback: value absent, raw = string ───────────────────
const RAW_B = "v=DMARC1; p=reject";
const pdfB = renderPdf([{ raw: RAW_B }]);
ok("B: legacy scalar raw renders", pdfB.includes(RAW_B));
ok("B: no object marker", !pdfB.includes(OBJECT_MARKER));

// ── C. Unsupported object-only record ───────────────────────────────────────
const pdfC = renderPdf([{ raw: { data: "internal-shape-c" } }]);
ok("C: internal shape is not dumped", !pdfC.includes("internal-shape-c"));
ok("C: no object marker", !pdfC.includes(OBJECT_MARKER));

// ── D. All records non-printable → heading omitted, appendix intact ────────
const pdfD = renderPdf([
  { raw: { data: "internal-shape-d" } },
  { value: "", raw: {} },
]);
ok("D: record-data heading absent when nothing is printable",
  !pdfD.includes(HEADING));
ok("D: technical appendix still renders",
  pdfD.includes("Technical Appendix - DMARC Policy"));
ok("D: no object marker", !pdfD.includes(OBJECT_MARKER));

// ── E. Mixed records: one printable, one unsupported ───────────────────────
const VALUE_E = "v=DMARC1; p=quarantine; rua=mailto:record-e@example.test";
const pdfE = renderPdf([
  {
    value: VALUE_E,
    raw: { name: "_dmarc.mail.example.test", type: 16, data: "internal-shape-e" },
  },
  { raw: { data: "internal-shape-e" } },
]);
ok("E: heading renders exactly once", count(pdfE, HEADING) === 1,
  `got ${count(pdfE, HEADING)}`);
ok("E: printable record renders exactly once", count(pdfE, VALUE_E) === 1,
  `got ${count(pdfE, VALUE_E)}`);
ok("E: unsupported entry produces no output", !pdfE.includes("internal-shape-e"));
ok("E: no object marker", !pdfE.includes(OBJECT_MARKER));

// ── F. Existing appendix surfaces continue to render unchanged ─────────────
ok("F: DMARC policy section renders", pdfA.includes("DMARC Policy Evidence"));
ok("F: appendix fact line renders",
  pdfA.includes("Parser: dmarcbis-policy-parser-v1"));
ok("F: ordered lookup evidence renders",
  pdfA.includes("Ordered DNS lookup evidence"));
ok("F: lookup step line renders",
  pdfA.includes("1. TXT _dmarc.mail.example.test - nodata - used"));
ok("F: parsed tag line renders",
  pdfA.includes("Parsed tags") &&
  pdfA.includes("rua=mailto:tag-line-fixture@example.test"));

// ── Global: zero object markers across every rendered PDF ──────────────────
const totalMarkers = [pdfA, pdfB, pdfC, pdfD, pdfE]
  .reduce((total, pdf) => total + count(pdf, OBJECT_MARKER), 0);
ok("global: zero object markers across all rendered PDFs", totalMarkers === 0,
  `got ${totalMarkers}`);

const total = pass + fail;
console.log(`\nPDF-DMARC record rendering: ${pass} passed, ${fail} failed (pinned ${EXPECTED_ASSERTIONS})`);
if (total !== EXPECTED_ASSERTIONS) {
  console.error(`FAIL assertion-count drift — ran ${total}, pinned ${EXPECTED_ASSERTIONS}`);
  process.exit(1);
}
if (!fail) console.log("PDF-DMARC record rendering proof passed");
process.exit(fail ? 1 : 0);
