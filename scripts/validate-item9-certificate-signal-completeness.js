#!/usr/bin/env node
//
// Item 9 P1: deterministic proof for the pure per-signal certificate evidence
// contract. This deliberately does not call runScanEngine: P1 has no production
// caller, and the first real engine trace belongs to P2.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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
  if (mutation === "ct-zero-becomes-wildcard") {
    const mutated = source.replaceAll(
      "ssl.cert_wildcard_san_count > 0",
      "ssl.cert_wildcard_san_count >= 0"
    );
    if (mutated === source) {
      throw new Error(`mutation anchor missing: ${mutation}`);
    }
    return mutated;
  }

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
    "ct-promotes-live-leaf": [
      `    leaf: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      observation: CERTIFICATE_OBSERVATION_STATES.UNKNOWN,
      observation_scope: "live_tls",`,
      `    leaf: evidence({
      completeness_state: ctPositiveState,
      observation: CERTIFICATE_OBSERVATION_STATES.PRESENT,
      value: { certificate_identity: ssl.cert_subject },
      observation_scope: "live_tls",`,
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
            source: "historical_ct",
            endpoint_context: "history-row-a",
            certificate_identity: "sha256:history-a",
            observed_at: "2026-07-26T10:00:00.000Z",
            completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
          },
          {
            protected_hostname: "example.com",
            source: "historical_ct",
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
  const source = fs.readFileSync(modelPath, "utf8")
    .replace(
      'import { SIGNAL_MONITORING_STATES } from "./signal-monitoring-state.js";',
      INLINE_STATES
    );
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

// ── The original nine-signal P1 vocabulary remains stable; later Item 9 depth
// adds independent signals additively after this prefix. ─────────────────────
const P1_SIGNAL_KEYS = CERTIFICATE_SIGNAL_KEYS.slice(0, 9);
eq("the model retains the nine original independent signals", P1_SIGNAL_KEYS.length, 9);
eq(
  "the simultaneous signal has the canonical unambiguous name",
  P1_SIGNAL_KEYS[7],
  "parallel_certificate_set"
);
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
eq("degraded CT remains independently degraded",
  mixed.signals.certificate_transparency.completeness_state, "monitoring_degraded");
eq("degraded positive CT evidence stays visible",
  mixed.signals.certificate_transparency.observation, "present");
eq("complete wildcard absence remains an honest absence",
  mixed.signals.wildcard.observation, "absent");
eq("parallel set reports simultaneous multiplicity without a risk verdict",
  mixed.signals.parallel_certificate_set.observation, "present");
ok("parallel set has two non-identical identities",
  new Set(mixed.signals.parallel_certificate_set.value.observations.map(
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
  certificate_transparency: {
    completeness_state: "monitoring_degraded",
    observation: "present",
    value: {
      crt_sh: "unavailable",
      certspotter: "available"
    },
    achieved_grade: "L1"
  }
});
eq("degraded positive evidence without full provenance fails closed",
  degradedWithoutProvenance.signals.certificate_transparency.completeness_state,
  "evidence_incomplete");
eq("unprovenanced positive evidence becomes unknown",
  degradedWithoutProvenance.signals.certificate_transparency.observation, "unknown");

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

// ── Existing CT/history fields cannot manufacture live serving evidence ─────
const current = deriveCertificateSignalCompletenessFromModules({
  ...fixture.current_modules_ct_only,
  observedAt: fixture.observed_at,
  engineVersion: fixture.engine_version,
});
eq("CT projection cannot become live leaf",
  current.signals.leaf.observation, "unknown");
eq("current modules do not contain a live chain",
  current.signals.chain.observation, "unknown");
eq("historical parallel flags cannot complete simultaneous endpoint evidence",
  current.signals.parallel_certificate_set.completeness_state,
  "evidence_incomplete");
eq("historical parallel flags cannot claim simultaneous multiplicity",
  current.signals.parallel_certificate_set.observation, "unknown");
eq("CT issuer is retained only as scoped issuance evidence",
  current.signals.issuer.observation_scope, "ct_issuance");
eq("live HTTP-service observation stays independent of CT-only certificate identity",
  current.signals.active_service.observation, "present");
const ctWithoutWildcardModules = structuredClone(fixture.current_modules_ct_only);
ctWithoutWildcardModules.modules.ssl.cert_wildcard_san_count = 0;
ctWithoutWildcardModules.modules.ssl.cert_san_names = ["example.com"];
const ctWithoutWildcard = deriveCertificateSignalCompletenessFromModules({
  ...ctWithoutWildcardModules,
  observedAt: fixture.observed_at,
  engineVersion: fixture.engine_version,
});
eq("zero wildcard count on one selected CT issuance does not prove wildcard absence",
  ctWithoutWildcard.signals.wildcard.completeness_state, "evidence_incomplete");
eq("zero wildcard count on one selected CT issuance remains unknown",
  ctWithoutWildcard.signals.wildcard.observation, "unknown");

const providersTimedOut = deriveCertificateSignalCompletenessFromModules({
  ...fixture.current_modules_ct_only,
  providerHealth: {
    crt_sh: { outcome: "unavailable" },
    certspotter: { outcome: "unavailable" }
  },
  observedAt: fixture.observed_at,
  engineVersion: fixture.engine_version,
});
eq("both CT providers unavailable stays signal_unavailable",
  providersTimedOut.signals.certificate_transparency.completeness_state,
  "signal_unavailable");
eq("provider timeout never becomes false CT absence",
  providersTimedOut.signals.certificate_transparency.observation, "unknown");
eq("CT provider timeout does not erase active-service evidence",
  providersTimedOut.signals.active_service.observation, "present");

console.log(
  `\nItem 9 certificate signal completeness: ${pass}/${pass + fail} assertions passed`
);
if (fail > 0) {
  console.error("Item 9 certificate signal completeness validation FAILED");
  process.exit(1);
}
console.log("Item 9 certificate signal completeness validation passed");
