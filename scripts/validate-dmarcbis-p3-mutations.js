#!/usr/bin/env node
// Item 7 P3 load-bearing mutation proof.
//
// Temporary adjacent module copies retain the real import graph. Each mutant
// deliberately reintroduces a prohibited snapshot/API defect and must make the
// corresponding invariant observably false.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (condition) console.log(`ok - ${name}`);
  else console.error(`not ok - ${name}${detail ? `: ${detail}` : ""}`);
};

async function withMutant(file, from, to, run) {
  const sourcePath = path.join(engines, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = source.replace(from, to);
  ok(`${file} mutation applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    engines,
    `.${file.replace(/\.js$/, "")}.p3-mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    const module = await import(
      `${pathToFileURL(mutantPath).href}?mutation=${sequence}`
    );
    await run(module);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

const contract = await import(
  pathToFileURL(path.join(engines, "dmarcbis-contract.js")).href
);
const { DMARCBIS_IDNA_PROFILE } = await import(
  pathToFileURL(path.join(engines, "dmarcbis-idna.js")).href
);
const { DMARCBIS_PARSER_VERSION } = await import(
  pathToFileURL(path.join(engines, "dmarcbis-parser.js")).href
);
const { DMARCBIS_METHODOLOGY_VERSION } = await import(
  pathToFileURL(path.join(engines, "dmarcbis-resolver.js")).href
);

function evidence(overrides = {}) {
  return {
    schema: "dmarc-policy.v2",
    methodology_version: DMARCBIS_METHODOLOGY_VERSION,
    parser_version: DMARCBIS_PARSER_VERSION,
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    idna_profile: DMARCBIS_IDNA_PROFILE,
    author_domain: "example.test",
    submitted_domain: "example.test",
    observed_at: "2026-07-25T12:00:00.000Z",
    observation_state: "present_valid",
    record_validity: "valid",
    raw_records: [],
    parsed_tags: [],
    lookup_path: [],
    organisational_domain: "example.test",
    organisational_domain_provenance: "psd_n",
    organisational_domain_completeness: "complete",
    policy_source_domain: "example.test",
    policy_source_kind: "exact",
    domain_existence: "not_required",
    existence_completeness: "not_applicable",
    declared_policy: "reject",
    effective_requested_policy: "reject",
    effective_policy_tag: "p",
    inheritance_reason: "exact_p",
    p: null,
    sp: null,
    np: null,
    t: null,
    psd: null,
    legacy_pct: {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: [],
    ruf_destinations: [],
    policy_completeness: "complete",
    rua_authorisation_completeness: "not_applicable",
    corroboration_state: "corroborated",
    core_completeness: "complete",
    monitoring_state: "monitoring_healthy",
    provider_state: "available",
    receiver_enforcement_observed: false,
    limits: {},
    ...overrides,
  };
}

await withMutant(
  "dmarcbis-contract.js",
  `if (evidence.schema !== DMARCBIS_POLICY_EVIDENCE_SCHEMA) {
    return "unsupported_schema";
  }`,
  `if (false) {
    return "unsupported_schema";
  }`,
  async (mutant) => {
    const future = await mutant.sealDmarcPolicyEvidence(
      evidence({ schema: "dmarc-policy.v999" }),
    );
    const read = await mutant.readDmarcPolicyEvidenceFromSnapshot({
      protocol_evidence: { dmarc: future },
    });
    ok("MUTANT unknown nested schema is accepted instead of failing closed",
      read.status === "current");
  },
);

await withMutant(
  "dmarcbis-contract.js",
  `if (!ORGANISATIONAL_DOMAIN_PROVENANCE.has(
    evidence.organisational_domain_provenance,
  )) {`,
  `if (false) {`,
  async (mutant) => {
    const future = await mutant.sealDmarcPolicyEvidence(evidence({
      organisational_domain_provenance: "future_guess",
    }));
    const read = await mutant.readDmarcPolicyEvidenceFromSnapshot({
      protocol_evidence: { dmarc: future },
    });
    ok("MUTANT unknown nested enum is accepted instead of failing closed",
      read.status === "current");
  },
);

await withMutant(
  "dmarcbis-contract.js",
  "if (fingerprint !== evidence.evidence_fingerprint) {",
  "if (false) {",
  async (mutant) => {
    const sealed = await mutant.sealDmarcPolicyEvidence(evidence());
    const read = await mutant.readDmarcPolicyEvidenceFromSnapshot({
      protocol_evidence: {
        dmarc: { ...sealed, effective_requested_policy: "none" },
      },
    });
    ok("MUTANT tampered policy is served despite its stale fingerprint",
      read.status === "current");
  },
);

await withMutant(
  "dmarcbis-contract.js",
  "evidence.legacy_pct?.applied_to_effective_policy !== false",
  "evidence.legacy_pct?.applied_to_effective_policy === \"__never__\"",
  async (mutant) => {
    const sealed = await mutant.sealDmarcPolicyEvidence(evidence({
      legacy_pct: {
        observed: true,
        raw: "25",
        numeric: 25,
        semantics: "rfc7489_legacy",
        applied_to_effective_policy: true,
      },
    }));
    ok("MUTANT operative legacy pct passes the P3 contract",
      sealed.legacy_pct.applied_to_effective_policy === true);
  },
);

await withMutant(
  "dmarcbis-contract.js",
  "This report preserves the DMARC methodology and conclusions used when the scan completed.",
  "",
  async (mutant) => {
    const read = await mutant.readDmarcPolicyEvidenceFromSnapshot({});
    const api = mutant.dmarcPolicyApiProjection(read);
    ok("MUTANT historical snapshot loses the approved methodology notice",
      api.dmarc_methodology_notice === "");
  },
);

await withMutant(
  "dmarcbis-contract.js",
  "automation_status: \"suspended\",",
  "automation_status: \"active\",",
  async (mutant) => {
    const hosted = mutant.hostedDmarcReadOnlyProjection({
      status: "current",
      evidence: await contract.sealDmarcPolicyEvidence(evidence()),
    });
    ok("MUTANT Hosted-DMARC projection reactivates suspended automation",
      hosted.automation_status === "active");
  },
);

await withMutant(
  "dmarcbis-contract.js",
  "projection.dmarc_policy_evidence = read.evidence;",
  "delete projection.dmarc_policy_evidence;",
  async (mutant) => {
    const sealed = await contract.sealDmarcPolicyEvidence(evidence());
    const api = mutant.dmarcPolicyApiProjection({
      status: "current",
      evidence: sealed,
    });
    ok("MUTANT additive API drops the v2 evidence object",
      !Object.prototype.hasOwnProperty.call(api, "dmarc_policy_evidence"));
  },
);

await withMutant(
  "report-snapshot.js",
  "export const SNAPSHOT_SCHEMA_VERSION = \"1\";",
  "export const SNAPSHOT_SCHEMA_VERSION = \"2\";",
  async (mutant) => {
    ok("MUTANT P3 breaks the approved outer-v1 snapshot contract",
      mutant.SNAPSHOT_SCHEMA_VERSION === "2");
  },
);

await withMutant(
  "report-snapshot.js",
  `protocol_evidence: {
      ...(dmarcPolicyEvidence
        ? { dmarc: dmarcPolicyEvidence }
        : {}),
    },`,
  "protocol_evidence: {},",
  async (mutant) => {
    const sealed = await contract.sealDmarcPolicyEvidence(evidence());
    const snapshot = mutant.composeSnapshot({
      snapshotId: "snap",
      workspaceId: "ws",
      domainId: "dom",
      scanId: "scan",
      domain: "example.test",
      report: {
        status: "completed",
        completed_at: "2026-07-25T12:00:00.000Z",
        scan_quality: { status: "complete", modules_skipped: [] },
        monitoring_states: { signals: {} },
        modules: {},
        findings: [],
        recommendations: [],
      },
      dmarcPolicyEvidence: sealed,
      cyberEssentials: null,
      ceReadiness: null,
      caseRows: [],
      questionSetVersions: [],
      supersedesSnapshotId: null,
      builtAt: "2026-07-25T12:00:01.000Z",
    });
    ok("MUTANT new snapshot drops protocol_evidence.dmarc",
      snapshot.protocol_evidence?.dmarc == null);
  },
);

console.log(`\nDMARCbis P3 mutations: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
