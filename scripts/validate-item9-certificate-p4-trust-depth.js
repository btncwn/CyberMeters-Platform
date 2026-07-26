#!/usr/bin/env node
// Item 9 P4 — deterministic trust-policy depth fixtures.
//
// Exercises the existing production certificate-intelligence caller with
// injected evidence objects only. No network, persistence, route or renderer is
// involved here; the faithful runScanEngine proof is separate.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CERTIFICATE_SIGNAL_CONTRACTS,
  CERTIFICATE_SIGNAL_KEYS,
} from "../workers/scan-api/src/engines/certificate-signal-completeness.js";
import { runCertificateIntelligenceModule } from "../workers/scan-api/src/engines/cert-intel.js";
import { buildCertificateTrustL2 } from "../workers/scan-api/src/engines/cert-trust-l2.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(fs.readFileSync(path.join(
  root,
  "scripts",
  "fixtures",
  "item9-p4-certificate-trust-depth.json",
), "utf8"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) =>
  ok(name, actual === expected,
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
const clone = (value) => structuredClone(value);
const run = (modules, providerHealth = fixture.provider_health) =>
  runCertificateIntelligenceModule(modules, fixture.domain, {
    providerHealth,
    observedAt: fixture.observed_at,
    engineVersion: fixture.engine_version,
  });

const expectedTrustKeys = [
  "caa",
  "hostname_match",
  "intermediate_validity",
  "certificate_algorithm",
  "trust_store_validation",
  "revocation_assurance",
];
for (const key of expectedTrustKeys) {
  ok(`${key}: additive trust signal exists`, CERTIFICATE_SIGNAL_KEYS.includes(key));
  const contract = CERTIFICATE_SIGNAL_CONTRACTS[key];
  ok(`${key}: grade contract is complete`, Boolean(
    contract?.observable_ceiling &&
    contract?.beta_target &&
    contract?.minimum_publishable &&
    contract?.degrade_behavior &&
    Array.isArray(contract?.required_corroboration)
  ));
  ok(`${key}: source type declared`, Boolean(contract?.source_type));
  ok(`${key}: cited authorities declared`, Boolean(
    contract?.authorities?.length &&
    contract.authorities.every((row) =>
      row.standard_id &&
      row.standard_version &&
      row.requirement_type &&
      row.source_type
    )
  ));
}
const authorities = Object.values(CERTIFICATE_SIGNAL_CONTRACTS)
  .flatMap((contract) => contract.authorities);
for (const standard of ["RFC 5280", "RFC 8659", "RFC 6960", "RFC 9162"]) {
  ok(`${standard}: canonical authority is cited`,
    authorities.some((row) => row.standard_id === standard));
}
ok("RFC 6844 is not cited as a current authority",
  !authorities.some((row) => row.standard_id === "RFC 6844"));
ok("TLS BR version and date are pinned",
  authorities
    .filter((row) =>
      row.standard_id === "CA/Browser Forum TLS Baseline Requirements")
    .every((row) => row.standard_version === "2.2.8 (16 June 2026)"));
ok("TLS BR access date is pinned",
  authorities
    .filter((row) =>
      row.standard_id === "CA/Browser Forum TLS Baseline Requirements")
    .every((row) => row.accessed_at === "2026-07-26"));

const complete = run(clone(fixture.base_modules));
const completeSignals = complete.signal_completeness.signals;
eq("production caller emits v2", complete.signal_completeness.model_version,
  "certificate-signal-completeness-v2");
for (const key of expectedTrustKeys) {
  eq(`${key}: complete fixture is independently complete`,
    completeSignals[key].completeness_state, "monitoring_healthy");
  eq(`${key}: complete fixture is observed`,
    completeSignals[key].observation, "present");
  ok(`${key}: result carries evidence grade contract`,
    Boolean(completeSignals[key].grade_contract?.observable_ceiling));
  ok(`${key}: result carries source and provenance`, Boolean(
    completeSignals[key].source_type &&
    completeSignals[key].provenance?.source &&
    completeSignals[key].provenance?.method &&
    completeSignals[key].provenance?.observed_at &&
    completeSignals[key].provenance?.engine_version
  ));
  ok(`${key}: result carries cited authority`,
    completeSignals[key].authorities.length > 0);
}
eq("complete chain reports its presented state",
  completeSignals.chain.value.presentation_state, "presented_complete");
eq("hostname result is scoped and matched",
  completeSignals.hostname_match.value.result, "matched");
eq("algorithm result avoids blanket compliance",
  completeSignals.certificate_algorithm.value.status,
  "no_known_weakness_observed");
eq("trust result names the declared store",
  completeSignals.trust_store_validation.value.trust_store_context.name,
  "fixture-public-root-store");
eq("validated OCSP result remains scoped good",
  completeSignals.revocation_assurance.value.status, "good");
eq("revocation family reflects only its signal",
  complete.signal_completeness.assurance_families.revocation_assurance.revocation_status,
  "good");
eq("revocation family reports observed support only when evidence exists",
  complete.signal_completeness.assurance_families.revocation_assurance.supported,
  true);
eq("external evidence never claims private-key security",
  complete.signal_completeness.assurance_families.internal_key_assurance.private_key_security,
  "unknown");

const adverseModules = clone(fixture.base_modules);
const live = adverseModules.ssl.certificate_evidence.live_tls;
adverseModules.dns.caa = {
  present: false,
  records: [],
  issuers: [],
  wildcard_issuers: [],
  iodef: [],
  error: null,
};
live.presented_chain.presentation_state = "presented_incomplete";
live.presented_chain.intermediates[0].not_after = "2026-01-01T00:00:00.000Z";
live.hostname_match.result = "mismatched";
live.leaf_certificate.public_key_size_bits = 1024;
live.leaf_certificate.signature_algorithm = "sha1WithRSAEncryption";
live.trust_store_validation.validation_result = "invalid";
live.revocation_assurance.status = "revoked";
const adverse = run(adverseModules);
const adverseSignals = adverse.signal_completeness.signals;
eq("CAA absence is a reliable scoped absence when resolvers agree",
  adverseSignals.caa.observation, "absent");
eq("hostname mismatch remains its own signal",
  adverseSignals.hostname_match.value.result, "mismatched");
eq("presented incomplete chain is a decisive observed state",
  adverseSignals.chain.value.presentation_state, "presented_incomplete");
eq("expired intermediate remains separate from leaf expiry",
  adverseSignals.intermediate_validity.value.status, "expired");
eq("weak algorithm remains separate",
  adverseSignals.certificate_algorithm.value.status, "weak");
ok("weak predicates name RSA size and SHA-1",
  adverseSignals.certificate_algorithm.value.weaknesses.includes(
    "rsa_public_key_below_2048_bits"
  ) &&
  adverseSignals.certificate_algorithm.value.weaknesses.includes(
    "sha1_certificate_signature_observed"
  ));
eq("declared-store rejection is scoped invalid",
  adverseSignals.trust_store_validation.value.validation_result, "invalid");
eq("validated revoked result is scoped to revocation",
  adverseSignals.revocation_assurance.value.status, "revoked");
eq("expired intermediate does not erase leaf",
  adverseSignals.leaf.observation, "present");
eq("revoked result does not erase active service",
  adverseSignals.active_service.observation, "present");
ok("no blanket trust verdict is manufactured",
  !["secure", "compliant", "compromised", "malicious"].includes(
    adverseSignals.trust_store_validation.value.validation_result
  ));

const noStoreModules = clone(fixture.base_modules);
noStoreModules.ssl.certificate_evidence.live_tls
  .trust_store_validation.trust_store_context = null;
const noStore = run(noStoreModules).signal_completeness.signals;
eq("trust result without declared store fails closed",
  noStore.trust_store_validation.completeness_state, "evidence_incomplete");
eq("undeclared-store result cannot claim trusted-root acceptance",
  noStore.trust_store_validation.observation, "unknown");
eq("undeclared store does not erase hostname evidence",
  noStore.hostname_match.value.result, "matched");

const noRevocationModules = clone(fixture.base_modules);
noRevocationModules.ssl.certificate_evidence.live_tls.revocation_assurance = {
  assessment_performed: false,
  stapled_ocsp: null,
  response_validated: false,
  status: "unknown",
};
const noRevocation = run(noRevocationModules).signal_completeness;
eq("missing revocation evidence degrades revocation only",
  noRevocation.signals.revocation_assurance.completeness_state,
  "evidence_incomplete");
for (const key of ["leaf", "chain", "hostname_match", "expiry", "caa", "active_service"]) {
  ok(`${key}: missing OCSP leaves sibling observed`,
    noRevocation.signals[key].observation !== "unknown");
}
eq("revocation family stays unknown when OCSP was not validated",
  noRevocation.assurance_families.revocation_assurance.revocation_status,
  "unknown");
eq("revocation family does not claim collection support without evidence",
  noRevocation.assurance_families.revocation_assurance.supported, false);

const incompleteAlgorithmModules = clone(fixture.base_modules);
incompleteAlgorithmModules.ssl.certificate_evidence.live_tls
  .leaf_certificate.public_key_size_bits = null;
const incompleteAlgorithm = run(incompleteAlgorithmModules)
  .signal_completeness.signals.certificate_algorithm;
eq("missing key size is incomplete, not a fabricated weak key",
  incompleteAlgorithm.completeness_state, "evidence_incomplete");
eq("missing key size cannot publish an algorithm verdict",
  incompleteAlgorithm.observation, "unknown");

const caaFailureModules = clone(fixture.base_modules);
caaFailureModules.dns.caa = {
  present: false,
  records: [],
  issuers: [],
  wildcard_issuers: [],
  iodef: [],
  error: "CAA lookup failed",
};
const caaFailure = run(caaFailureModules).signal_completeness.signals;
eq("CAA lookup failure is unavailable, not absent",
  caaFailure.caa.completeness_state, "signal_unavailable");
eq("CAA lookup failure cannot claim no CAA",
  caaFailure.caa.observation, "unknown");
eq("CAA failure does not erase live leaf",
  caaFailure.leaf.observation, "present");

const ctOnlyModules = clone(fixture.base_modules);
ctOnlyModules.ssl.certificate_evidence.live_tls = {
  leaf_collected: false,
  chain_collected: false,
  reason: "peer_certificate_not_exposed",
};
const ctOnly = run(ctOnlyModules).signal_completeness;
eq("CT-only evidence remains explicit",
  ctOnly.summary.ct_only, true);
eq("CT issuance does not become a live leaf",
  ctOnly.signals.leaf.observation, "unknown");
eq("CT issuance does not become hostname validation",
  ctOnly.signals.hostname_match.observation, "unknown");
eq("CT issuance does not become trust-store validation",
  ctOnly.signals.trust_store_validation.observation, "unknown");
eq("CT issuance does not become revocation assurance",
  ctOnly.signals.revocation_assurance.observation, "unknown");
eq("independent HTTPS service evidence survives CT-only scope",
  ctOnly.signals.active_service.observation, "present");

const providersUnavailable = run(
  clone(fixture.base_modules),
  {
    crt_sh: { outcome: "unavailable" },
    certspotter: { outcome: "unavailable" },
  },
).signal_completeness.signals;
eq("CT provider timeout remains scoped unavailable",
  providersUnavailable.certificate_transparency.completeness_state,
  "signal_unavailable");
eq("CT timeout does not erase CAA",
  providersUnavailable.caa.observation, "present");
eq("CT timeout does not erase live hostname result",
  providersUnavailable.hostname_match.value.result, "matched");
eq("CT timeout does not erase active service",
  providersUnavailable.active_service.observation, "present");

const historicalOnly = buildCertificateTrustL2({
  issuer: "Current CA",
  subject: fixture.domain,
  expires_at: "2027-01-01T00:00:00.000Z",
  days_until_expiry: 150,
}, {
  history: [{
    issuer: "Historical CA",
    subject: fixture.domain,
    expires_at: "2027-02-01T00:00:00.000Z",
    evidence_json: "{}",
  }],
});
ok("CT/history multiplicity cannot manufacture a parallel live set",
  !historicalOnly.anomalies.some((row) => row.type === "parallel_certificate"));

const realParallel = buildCertificateTrustL2({
  signal_completeness: {
    signals: {
      parallel_certificate_set: {
        observation: "present",
        observation_scope: "live_tls_endpoint_set",
        value: {
          observation_window: {
            started_at: "2026-07-26T15:00:00.000Z",
            ended_at: "2026-07-26T15:00:01.000Z"
          },
          observations: [
            {
              protected_hostname: fixture.domain,
              source: "fixture_endpoint_a",
              endpoint_context: "203.0.113.1:443",
              certificate_identity: "sha256:a",
              observed_at: "2026-07-26T15:00:00.000Z",
              completeness_state: "monitoring_healthy"
            },
            {
              protected_hostname: fixture.domain,
              source: "fixture_endpoint_b",
              endpoint_context: "203.0.113.2:443",
              certificate_identity: "sha256:b",
              observed_at: "2026-07-26T15:00:01.000Z",
              completeness_state: "monitoring_healthy"
            }
          ]
        }
      }
    }
  }
}, { history: [] });
eq("canonical simultaneous live set remains reportable",
  realParallel.anomalies.filter((row) => row.type === "parallel_certificate").length,
  1);
eq("parallel multiplicity carries no fault severity",
  realParallel.anomalies.find((row) => row.type === "parallel_certificate")?.severity,
  "info");

console.log(`\nItem 9 P4 trust depth fixtures: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P4 trust depth fixtures passed");
process.exit(fail ? 1 : 0);
