#!/usr/bin/env node
// Item 9 P4 — load-bearing source mutation proof.
//
// Every mutation is applied to a temporary copy of the real engine. The
// corresponding deterministic P4 invariant must then observe the reintroduced
// defect. Checked-in sources are never modified.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const NOW = "2026-07-26T15:00:00.000Z";
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (condition) console.log(`ok - ${name}`);
  else console.error(`not ok - ${name}${detail ? `: ${detail}` : ""}`);
};

async function withMutant(file, mutate, run) {
  const sourcePath = path.join(engines, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = mutate(source);
  ok(`${file} mutation applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    engines,
    `.${file.replace(/\.js$/, "")}.item9-p4-mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    const module = await import(
      `${pathToFileURL(mutantPath).href}?mutation=${sequence}`,
    );
    await run(module);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

const healthyProviders = {
  crt_sh: { outcome: "available" },
  certspotter: { outcome: "available" },
};
const baseModules = () => ({
  ssl: {
    https_available: true,
    https_probe_executed: true,
    cert_not_after: "2026-11-30T00:00:00.000Z",
    cert_issuer: "Fixture CA",
    cert_subject: "example.com",
    cert_san_names: ["example.com"],
    cert_wildcard_san_count: 0,
    certificate_evidence: {
      live_tls: {
        leaf_certificate: {
          collection_performed: true,
          collection_complete: true,
          certificate_identity: "sha256:leaf",
          public_key_algorithm: "RSA",
          public_key_size_bits: 2048,
          signature_algorithm: "sha256WithRSAEncryption",
        },
        presented_chain: {
          collection_performed: true,
          collection_complete: true,
          presentation_state: "presented_complete",
          intermediates: [],
        },
        hostname_match: {
          assessment_performed: true,
          result: "matched",
          reference_hostname: "example.com",
        },
        trust_store_validation: {
          validation_performed: true,
          validation_result: "valid",
          certificate_identity: "sha256:leaf",
          trust_store_context: {
            name: "fixture-store",
            version: "2026-07-26",
          },
        },
        revocation_assurance: {
          assessment_performed: true,
          stapled_ocsp: true,
          response_validated: true,
          status: "good",
          certificate_identity: "sha256:leaf",
        },
      },
    },
  },
  dns: {
    caa: {
      present: true,
      records: ["0 issue \"fixture.example\""],
      issuers: ["fixture.example"],
      wildcard_issuers: [],
      iodef: [],
      error: null,
    },
    cross_checks: {
      caa: {
        primary_resolver: { status: "ok" },
        google_resolver: { status: "ok" },
        resolver_agreement_score: 100,
      },
    },
  },
  subdomains: {
    sources: {
      crt_sh: { count: 1, error: null },
      certspotter: { count: 1, error: null },
    },
  },
});
const derive = (module, modules, providerHealth = healthyProviders) =>
  module.deriveCertificateSignalCompletenessFromModules({
    modules,
    providerHealth,
    observedAt: NOW,
    engineVersion: "item9-p4-mutation",
  });

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source
    .replace(
      "completeness_state: trust.leafCollected\n        ? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY",
      "completeness_state: trust.leafCollected || selectedCtCertificate\n        ? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY",
    )
    .replace(
      "observation: trust.leafCollected\n        ? CERTIFICATE_OBSERVATION_STATES.PRESENT",
      "observation: trust.leafCollected || selectedCtCertificate\n        ? CERTIFICATE_OBSERVATION_STATES.PRESENT",
    )
    .replace(
      "value: trust.leafCollected ? { ...trust.leaf } : null,",
      "value: trust.leafCollected ? { ...trust.leaf } : { certificate_identity: ssl.cert_subject },",
    ),
  async (mutant) => {
    const modules = baseModules();
    modules.ssl.certificate_evidence.live_tls = {};
    const result = derive(mutant, modules);
    ok("MUTANT CT issuance as live leaf makes the CT-only fixture red",
      result.signals.leaf.observation === "present");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source.replace(
    `    if (!hasDeclaredTrustStoreContext(value)) {
      return "Trust-store validation requires a declared trust-store name and version.";
    }`,
    `    if (false) {
      return "Trust-store validation requires a declared trust-store name and version.";
    }`,
  ),
  async (mutant) => {
    const modules = baseModules();
    modules.ssl.certificate_evidence.live_tls
      .trust_store_validation.trust_store_context = null;
    const result = derive(mutant, modules);
    ok("MUTANT trust result without declared store makes fixture red",
      result.signals.trust_store_validation.observation === "present");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source
    .replace(
      "completeness_state: trust.leafCollected\n        ? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY",
      "completeness_state: trust.leafCollected && trust.revocationObserved\n        ? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY",
    )
    .replace(
      "observation: trust.leafCollected\n        ? CERTIFICATE_OBSERVATION_STATES.PRESENT",
      "observation: trust.leafCollected && trust.revocationObserved\n        ? CERTIFICATE_OBSERVATION_STATES.PRESENT",
    ),
  async (mutant) => {
    const modules = baseModules();
    modules.ssl.certificate_evidence.live_tls.revocation_assurance = {
      assessment_performed: false,
      response_validated: false,
      status: "unknown",
    };
    const result = derive(mutant, modules);
    ok("MUTANT missing revocation erases leaf sibling and makes fixture red",
      result.signals.leaf.observation === "unknown");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source
    .replace(
      "const caaUnavailable = Boolean(caa && cleanString(caa.error));",
      "const caaUnavailable = false;",
    )
    .replace(
      "    !cleanString(caa.error) &&\n    typeof caa.present === \"boolean\"",
      "    true &&\n    typeof caa.present === \"boolean\"",
    )
    .replace(
      `      observation: trust.caaObserved
        ? (trust.caa.present
          ? CERTIFICATE_OBSERVATION_STATES.PRESENT
          : CERTIFICATE_OBSERVATION_STATES.ABSENT)
        : CERTIFICATE_OBSERVATION_STATES.UNKNOWN,`,
      `      observation: trust.caaObserved
        ? (trust.caa.present
          ? CERTIFICATE_OBSERVATION_STATES.PRESENT
          : CERTIFICATE_OBSERVATION_STATES.ABSENT)
        : CERTIFICATE_OBSERVATION_STATES.ABSENT,`,
    ),
  async (mutant) => {
    const modules = baseModules();
    modules.dns.caa = {
      present: false,
      records: [],
      issuers: [],
      wildcard_issuers: [],
      iodef: [],
      error: "CAA lookup failed",
    };
    const result = derive(mutant, modules);
    ok("MUTANT CAA lookup failure as absence makes fixture red",
      result.signals.caa.observation === "absent");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source
    .replace(
      `  if (normalizedSignature.includes("sha1") || normalizedSignature.includes("sha-1")) {
    weaknesses.push("sha1_certificate_signature_observed");
  }`,
      `  if (normalizedSignature.includes("sha1") || normalizedSignature.includes("sha-1")) {
    void 0;
  }`,
    ),
  async (mutant) => {
    const modules = baseModules();
    modules.ssl.certificate_evidence.live_tls
      .leaf_certificate.signature_algorithm = "sha1WithRSAEncryption";
    const result = derive(mutant, modules);
    ok("MUTANT ignored SHA-1 signature makes weak-algorithm fixture red",
      result.signals.certificate_algorithm.value.status ===
        "no_known_weakness_observed");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source
    .replace("    revocation.response_validated === true &&\n", "")
    .replace(
      `    if (value.response_validated !== true) {
      return "A revocation status requires validation of the response signature and time semantics.";
    }`,
      `    if (false) {
      return "A revocation status requires validation of the response signature and time semantics.";
    }`,
    ),
  async (mutant) => {
    const modules = baseModules();
    modules.ssl.certificate_evidence.live_tls.revocation_assurance
      .response_validated = false;
    const result = derive(mutant, modules);
    ok("MUTANT unvalidated OCSP good status makes revocation fixture red",
      result.signals.revocation_assurance.value?.status === "good");
  },
);

await withMutant(
  "cert-trust-l2.js",
  (source) => source.replace(
    "  return anomalies;\n}",
    `  if (rows.length > 0) {
    anomalies.push({ type: "parallel_certificate", severity: "low" });
  }
  return anomalies;
}`,
  ),
  async (mutant) => {
    const result = mutant.buildCertificateTrustL2({
      issuer: "Current CA",
      subject: "example.com",
      expires_at: "2027-01-01T00:00:00.000Z",
    }, {
      history: [{
        issuer: "Historical CA",
        subject: "example.com",
        expires_at: "2027-02-01T00:00:00.000Z",
        evidence_json: "{}",
      }],
    });
    ok("MUTANT CT/history multiplicity as parallel live set makes fixture red",
      result.anomalies.some((row) => row.type === "parallel_certificate"));
  },
);

console.log(`\nItem 9 P4 mutations: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P4 mutation proof passed");
process.exit(fail ? 1 : 0);
