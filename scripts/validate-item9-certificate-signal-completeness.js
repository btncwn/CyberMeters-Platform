#!/usr/bin/env node
//
// Item 9 P1: deterministic proof for the pure per-signal certificate evidence
// contract. This deliberately does not call runScanEngine; the real engine
// traces belong to P2 onwards. Certificate facts come only from the live TLS
// leaf: stored certificate fields from an earlier scan never fill a signal.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { liveTlsSsl } from "./lib/live-tls-fixture.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const modelPath = path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "certificate-signal-completeness.js"
);
const fixture = JSON.parse(fs.readFileSync(
  path.join(root, "scripts", "fixtures", "item9-certificate-signal-completeness.json"),
  "utf8"
));
const mutation =
  process.argv.find((argument) => argument.startsWith("--mutation="))?.split("=")[1] ??
  null;

const INLINE_STATES = `const SIGNAL_MONITORING_STATES = Object.freeze({
  MONITORING_HEALTHY: "monitoring_healthy",
  MONITORING_DEGRADED: "monitoring_degraded",
  SIGNAL_UNAVAILABLE: "signal_unavailable",
  EVIDENCE_INCOMPLETE: "evidence_incomplete",
});`;

function mutateSource(source) {
  const mutations = {
    "collapse-siblings": [
      "signals[signal] = resolveOneSignal(signal, evidenceBySignal?.[signal], {",
      "signals[signal] = resolveOneSignal(signal, evidenceBySignal?.chain, {",
    ],
    "unavailable-as-absent": [
      `  ) {
    observation = CERTIFICATE_OBSERVATION_STATES.UNKNOWN;
    value = null;
  } else if (`,
      `  ) {
    observation = CERTIFICATE_OBSERVATION_STATES.ABSENT;
    value = false;
  } else if (`,
    ],
    "stored-fields-fill-issuer": [
      `    issuer: liveLeafSignal({
      collected: trust.leafCollected && Boolean(cleanString(trust.leaf.issuer)),
      value: cleanString(trust.leaf?.issuer) || null,`,
      `    issuer: liveLeafSignal({
      collected: Boolean(cleanString(trust.leaf?.issuer || ssl.cert_issuer)),
      value: cleanString(trust.leaf?.issuer || ssl.cert_issuer) || null,`,
    ],
    "wildcard-without-leaf": [
      `    wildcard: liveLeafSignal({
      collected: trust.leafCollected,`,
      `    wildcard: liveLeafSignal({
      collected: true,`,
    ],
    "history-promotes-parallel-set": [
      `    parallel_certificate_set: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      value: null,`,
      `    parallel_certificate_set: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
      observation: CERTIFICATE_OBSERVATION_STATES.PRESENT,
      value: {
        protected_hostname: "example.com",
        observation_window: {
          started_at: "2026-07-26T09:59:58.000Z",
          ended_at: "2026-07-26T10:00:02.000Z",
        },
        observations: [
          {
            protected_hostname: "example.com",
            source: "historical_observation",
            endpoint_context: "history-row-a",
            certificate_identity: "sha256:history-a",
            observed_at: "2026-07-26T10:00:00.000Z",
            completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
          },
          {
            protected_hostname: "example.com",
            source: "historical_observation",
            endpoint_context: "history-row-b",
            certificate_identity: "sha256:history-b",
            observed_at: "2026-07-26T10:00:01.000Z",
            completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
          },
        ],
      },`,
    ],
    "drop-grade-contract": [
      "minimum_publishable: contractDefinition.minimum_publishable,",
      "minimum_publishable: null,",
    ],
    "trust-without-store": [
      "    !hasDeclaredTrustStoreContext(value)",
      "    false",
    ],
    "publish-without-provenance": [
      "      !provenanceComplete(provenance)",
      "      false",
    ],
    "allow-identical-parallel-identities": [
      "  if (identities.size < 2) {",
      "  if (identities.size < 1) {",
    ],
    "unbound-parallel-window": [
      `    windowEnd < windowStart ||
    windowEnd - windowStart > MAX_PARALLEL_OBSERVATION_WINDOW_MS`,
      "    windowEnd < windowStart",
    ],
  };
  const pair = mutations[mutation];
  if (!pair) throw new Error(`unknown mutation: ${mutation}`);
  const [from, to] = pair;
  if (!source.includes(from)) throw new Error(`mutation anchor missing: ${mutation}`);
  return source.replace(from, to);
}

async function loadModel() {
  if (!mutation) return import(pathToFileURL(modelPath).href);
  // data: modules cannot resolve relative imports, so both are rewritten; a
  // missed rewrite would crash the mutant at load, which is not a kill.
  const original = fs.readFileSync(modelPath, "utf8");
  const tlsImport = 'from "./tls-evidence.js";';
  if (!original.includes(tlsImport)) throw new Error("tls-evidence import anchor missing");
  const source = original
    .replace(
      'import { SIGNAL_MONITORING_STATES } from "./signal-monitoring-state.js";',
      INLINE_STATES
    )
    .replace(tlsImport, `from "${pathToFileURL(path.join(path.dirname(modelPath), "tls-evidence.js")).href}";`);
  if (source.includes('from "./')) throw new Error("unresolved relative import in mutant");
  const mutated = mutateSource(source);
  return import(
    `data:text/javascript;base64,${Buffer.from(mutated).toString("base64")}#${mutation}`
  );
}

const model = await loadModel();
const {
  CERTIFICATE_SIGNAL_KEYS,
  CERTIFICATE_SIGNAL_CONTRACTS,
  deriveCertificateSignalCompleteness,
  deriveCertificateSignalCompletenessFromModules,
} = model;

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const derive = (evidenceBySignal) => deriveCertificateSignalCompleteness({
  evidenceBySignal,
  observedAt: fixture.observed_at,
  engineVersion: fixture.engine_version,
});

// ── The eight live/serving signals of the original P1 vocabulary remain a
// stable prefix; later Item 9 depth adds independent signals after it. ───────
const P1_SIGNAL_KEYS = CERTIFICATE_SIGNAL_KEYS.slice(0, 8);
eq("the model retains the eight original independent signals", P1_SIGNAL_KEYS.length, 8);
eq(
  "the simultaneous signal has the canonical unambiguous name",
  P1_SIGNAL_KEYS[6],
  "parallel_certificate_set"
);
ok("no signal depends on an external certificate log",
  !CERTIFICATE_SIGNAL_KEYS.includes("certificate_transparency") &&
    Object.values(CERTIFICATE_SIGNAL_CONTRACTS).every((contract) =>
      contract.observation_scope !== "ct_issuance" &&
      contract.authorities.every((authority) => authority.standard_id !== "RFC 9162")));
for (const signal of P1_SIGNAL_KEYS) {
  const contract = CERTIFICATE_SIGNAL_CONTRACTS[signal];
  ok(`${signal}: contract exists`, Boolean(contract));
  for (const field of [
    "observable_ceiling",
    "beta_target",
    "minimum_publishable",
    "degrade_behavior",
    "required_corroboration",
  ]) {
    ok(`${signal}: grade contract declares ${field}`, Boolean(contract?.[field]));
  }
  ok(`${signal}: source type declared`, Boolean(contract?.source_type));
  ok(`${signal}: assurance family declared`, Boolean(contract?.assurance_family));
  ok(`${signal}: authority provenance declared`,
    Array.isArray(contract?.authorities) &&
      contract.authorities.length > 0 &&
      contract.authorities.every((authority) =>
        authority.standard_id &&
        authority.standard_version &&
        authority.requirement_type &&
        authority.source_type
      ));
}
const cabfAuthorities = Object.values(CERTIFICATE_SIGNAL_CONTRACTS)
  .flatMap((contract) => contract.authorities)
  .filter((authority) =>
    authority.standard_id === "CA/Browser Forum TLS Baseline Requirements"
  );
ok("CA/B Forum BR is pinned to v2.2.8", cabfAuthorities.every((row) =>
  row.standard_version === "2.2.8 (16 June 2026)"
));
ok("CA/B Forum BR carries its access date", cabfAuthorities.every((row) =>
  row.accessed_at === "2026-07-26"
));

// ── Mixed evidence: one failed signal cannot erase reliable siblings ────────
const mixed = derive(fixture.mixed_independent_signals);
for (const signal of P1_SIGNAL_KEYS) {
  const gradeContract = mixed.signals[signal].grade_contract;
  for (const field of [
    "observable_ceiling",
    "beta_target",
    "minimum_publishable",
    "degrade_behavior",
    "required_corroboration",
  ]) {
    ok(`${signal}: resolved signal carries ${field}`, Boolean(gradeContract?.[field]));
  }
  ok(`${signal}: resolved signal carries source_type`,
    Boolean(mixed.signals[signal].source_type));
  ok(`${signal}: resolved signal carries complete provenance`,
    Boolean(
      mixed.signals[signal].provenance.source &&
      mixed.signals[signal].provenance.method &&
      mixed.signals[signal].provenance.observed_at &&
      mixed.signals[signal].provenance.engine_version
    ));
  ok(`${signal}: resolved signal carries authority citations`,
    mixed.signals[signal].authorities.length > 0);
}
eq("unavailable chain stays unavailable", mixed.signals.chain.completeness_state,
  "signal_unavailable");
eq("unavailable chain cannot become absent", mixed.signals.chain.observation, "unknown");
eq("unavailable chain value is removed", mixed.signals.chain.value, null);
for (const signal of ["leaf", "san", "issuer", "expiry", "wildcard", "active_service"]) {
  eq(`${signal}: reliable sibling remains complete`,
    mixed.signals[signal].completeness_state, "monitoring_healthy");
}
eq("degraded CAA remains independently degraded",
  mixed.signals.caa.completeness_state, "monitoring_degraded");
eq("degraded positive CAA evidence stays visible",
  mixed.signals.caa.observation, "present");
eq("complete wildcard absence remains an honest absence",
  mixed.signals.wildcard.observation, "absent");
eq("parallel set reports simultaneous multiplicity without a risk verdict",
  mixed.signals.parallel_certificate_set.observation, "present");
ok("parallel set has two non-identical identities",
  new Set((mixed.signals.parallel_certificate_set.value?.observations || []).map(
    (row) => row.certificate_identity
  )).size === 2
);
ok("parallel set does not manufacture a misconfiguration verdict",
  !Object.prototype.hasOwnProperty.call(mixed.signals.parallel_certificate_set, "verdict")
);

// ── External validation, internal key assurance and revocation stay separate ─
eq("external leaf observation is retained", mixed.signals.leaf.observation, "present");
eq("private-key security remains unknown",
  mixed.assurance_families.internal_key_assurance.private_key_security, "unknown");
eq("internal keystore health remains unknown",
  mixed.assurance_families.internal_key_assurance.internal_keystore_health, "unknown");
eq("complete internal inventory remains unknown",
  mixed.assurance_families.internal_key_assurance.internal_certificate_inventory, "unknown");
eq("absence of key compromise remains unknown",
  mixed.assurance_families.internal_key_assurance.absence_of_key_compromise, "unknown");
eq("missing OCSP remains isolated to revocation assurance",
  mixed.assurance_families.revocation_assurance.stapled_ocsp, "unknown");
eq("missing OCSP does not erase expiry", mixed.signals.expiry.observation, "present");
const degradedWithoutProvenance = derive({
  caa: {
    completeness_state: "monitoring_degraded",
    observation: "present",
    value: { present: true, records: ["0 issue \"ca.example\""] },
    achieved_grade: "L1"
  }
});
eq("degraded positive evidence without full provenance fails closed",
  degradedWithoutProvenance.signals.caa.completeness_state,
  "evidence_incomplete");
eq("unprovenanced positive evidence becomes unknown",
  degradedWithoutProvenance.signals.caa.observation, "unknown");

// ── Trust results fail closed without a declared trust-store context ─────────
const chainBase = {
  completeness_state: "monitoring_healthy",
  observation: "present",
  value: {
    presented_chain: ["sha256:leaf-a", "sha256:intermediate-a"],
    validation_result: "valid"
  },
  observation_scope: "live_tls",
  achieved_grade: "L4",
  source_type: "normative_protocol",
  source: "injected_tls_handshake",
  method: "rfc5280_path_validation"
};
const noTrustStore = derive({ chain: chainBase });
eq("trust result without declared store fails closed",
  noTrustStore.signals.chain.completeness_state, "evidence_incomplete");
eq("trust result without declared store becomes unknown",
  noTrustStore.signals.chain.observation, "unknown");
const declaredTrustStore = derive({
  chain: {
    ...chainBase,
    value: {
      ...chainBase.value,
      trust_store_context: {
        name: "fixture-public-root-store",
        version: "2026-07-26"
      }
    }
  }
});
eq("trust result with declared store remains complete",
  declaredTrustStore.signals.chain.completeness_state, "monitoring_healthy");

// ── Parallel set must be simultaneous, contextual and non-identical ─────────
const identicalSetInput = structuredClone(
  fixture.mixed_independent_signals.parallel_certificate_set
);
identicalSetInput.value.observations[1].certificate_identity = "sha256:leaf-a";
const identicalSet = derive({ parallel_certificate_set: identicalSetInput });
eq("identical certificate identities do not form a parallel set",
  identicalSet.signals.parallel_certificate_set.completeness_state,
  "evidence_incomplete");
eq("invalid parallel set cannot publish multiplicity",
  identicalSet.signals.parallel_certificate_set.observation, "unknown");
const unboundedWindowInput = structuredClone(
  fixture.mixed_independent_signals.parallel_certificate_set
);
unboundedWindowInput.value.observation_window.ended_at =
  "2026-07-26T10:00:10.000Z";
const unboundedWindow = derive({ parallel_certificate_set: unboundedWindowInput });
eq("parallel observations outside the SSL cap are not called simultaneous",
  unboundedWindow.signals.parallel_certificate_set.completeness_state,
  "evidence_incomplete");

// ── Stored certificate fields cannot manufacture live serving evidence ──────
const stored = deriveCertificateSignalCompletenessFromModules({
  ...fixture.stored_certificate_fields_without_live_leaf,
  observedAt: fixture.observed_at,
  engineVersion: fixture.engine_version,
});
eq("stored certificate fields cannot become a live leaf",
  stored.signals.leaf.observation, "unknown");
eq("stored modules do not contain a live chain",
  stored.signals.chain.observation, "unknown");
eq("historical parallel flags cannot complete simultaneous endpoint evidence",
  stored.signals.parallel_certificate_set.completeness_state,
  "evidence_incomplete");
eq("historical parallel flags cannot claim simultaneous multiplicity",
  stored.signals.parallel_certificate_set.observation, "unknown");
for (const signal of ["san", "issuer", "expiry", "wildcard"]) {
  eq(`stored ${signal} cannot become a live ${signal} observation`,
    stored.signals[signal].observation, "unknown");
  eq(`stored ${signal} keeps the live TLS scope`,
    stored.signals[signal].observation_scope, "live_tls");
}
eq("live HTTP-service observation stays independent of the missing leaf",
  stored.signals.active_service.observation, "present");
eq("the summary states that no live serving certificate was observed",
  stored.summary.live_serving_certificate_observed, false);

// ── A live leaf fills the certificate signals from the served certificate ────
const liveModules = (options) => ({
  modules: { ssl: liveTlsSsl({ domain: "example.com", ...options }, { https_probe_executed: true, https_available: true, tls_state: "observed_present" }) },
  observedAt: fixture.observed_at,
  engineVersion: fixture.engine_version,
});
const live = deriveCertificateSignalCompletenessFromModules(
  liveModules({ dnsNames: ["example.com", "*.example.com"], issuer: "CN=Fixture Live CA" }),
);
eq("a live leaf is a complete leaf observation", live.signals.leaf.completeness_state, "monitoring_healthy");
eq("a live leaf issuer is the served certificate's issuer",
  live.signals.issuer.value, "CN=Fixture Live CA");
eq("a wildcard SAN on the served certificate is present",
  live.signals.wildcard.observation, "present");
ok("live SANs come from the served certificate",
  JSON.stringify(live.signals.san.value) === JSON.stringify(["example.com", "*.example.com"]));
eq("the summary states the live serving certificate was observed",
  live.summary.live_serving_certificate_observed, true);
const liveWithoutWildcard = deriveCertificateSignalCompletenessFromModules(
  liveModules({ dnsNames: ["example.com"] }),
);
eq("a complete live leaf without a wildcard SAN proves wildcard absence on that certificate",
  liveWithoutWildcard.signals.wildcard.observation, "absent");
eq("live wildcard absence is complete evidence",
  liveWithoutWildcard.signals.wildcard.completeness_state, "monitoring_healthy");

console.log(
  `\nItem 9 certificate signal completeness: ${pass}/${pass + fail} assertions passed`
);
if (fail > 0) {
  console.error("Item 9 certificate signal completeness validation FAILED");
  process.exit(1);
}
console.log("Item 9 certificate signal completeness validation passed");
