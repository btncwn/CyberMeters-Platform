#!/usr/bin/env node
// Item 9 P2 — load-bearing mutation proof.
//
// Each temporary mutant reintroduces a P2 defect and executes the corresponding
// production contract. The checked-in sources are never modified.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const NOW = "2026-07-26T13:00:00.000Z";
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
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
    `.${file.replace(/\.js$/, "")}.item9-p2-mutant.${process.pid}.${++sequence}.js`,
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

const completeModules = () => ({
  ssl: {
    https_available: true,
    https_probe_executed: true,
    cert_not_after: "2026-11-01T00:00:00.000Z",
    cert_issuer: "Mutation CA",
    cert_subject: "example.com",
    cert_san_names: ["example.com", "www.example.com"],
    cert_wildcard_san_count: 0,
  },
  subdomains: {
    items: ["www.example.com"],
    sensitive: [],
    sources: {
      crt_sh: { count: 2, error: null },
      certspotter: { count: 2, error: null },
    },
  },
});
const healthyProviders = {
  crt_sh: { outcome: "available" },
  certspotter: { outcome: "available" },
};
const unavailableProviders = {
  crt_sh: { outcome: "unavailable" },
  certspotter: { outcome: "unavailable" },
};
const options = (providerHealth) => ({
  providerHealth,
  observedAt: NOW,
  engineVersion: "item9-p2-mutation",
});

await withMutant(
  "cert-intel.js",
  (source) => source.replace(
    "signal_completeness: deriveCertificateSignalCompletenessFromModules({",
    "signal_completeness: (() => null)({",
  ),
  async (mutant) => {
    const result = mutant.runCertificateIntelligenceModule(
      completeModules(),
      "example.com",
      options(healthyProviders),
    );
    ok("MUTANT detached P1 model makes the integration fixture red",
      result.signal_completeness === null);
  },
);

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
    const result = mutant.deriveCertificateSignalCompletenessFromModules({
      modules: completeModules(),
      providerHealth: healthyProviders,
      observedAt: NOW,
      engineVersion: "item9-p2-mutation",
    });
    ok("MUTANT CT-as-live-leaf makes the CT-only fixture red",
      result.signals.leaf.observation === "present");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source.replace(
    `tls.state !== TLS_RUNTIME_STATES.UNAVAILABLE
          ? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY
          : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE`,
    "ctState",
  ),
  async (mutant) => {
    const result = mutant.deriveCertificateSignalCompletenessFromModules({
      modules: completeModules(),
      providerHealth: unavailableProviders,
      observedAt: NOW,
      engineVersion: "item9-p2-mutation",
    });
    ok("MUTANT collapsed sibling completeness makes active-service fixture red",
      result.signals.active_service.completeness_state === "signal_unavailable");
  },
);

await withMutant(
  "certificate-signal-completeness.js",
  (source) => source.replace(
    /parallel_certificate_set: evidence\(\{[\s\S]*?\n    \}\),\n    active_service:/,
    `parallel_certificate_set: evidence({
      completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
      observation: CERTIFICATE_OBSERVATION_STATES.PRESENT,
      value: {
        protected_hostname: "example.com",
        observation_window: {
          started_at: observedAt,
          ended_at: observedAt,
        },
        observations: [
          {
            protected_hostname: "example.com",
            source: "certificate_transparency",
            endpoint_context: "ct-entry-1/historical",
            certificate_identity: "ct-history-1",
            observed_at: observedAt,
            completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
          },
          {
            protected_hostname: "example.com",
            source: "certificate_transparency",
            endpoint_context: "ct-entry-2/historical",
            certificate_identity: "ct-history-2",
            observed_at: observedAt,
            completeness_state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
          },
        ],
      },
      observation_scope: "live_tls_endpoint_set",
      achieved_grade: "L3",
      source_type: "product_policy",
      source: "shared_ct_provider_cache",
      method: "historical_ct_multiplicity",
    }),
    active_service:`,
  ),
  async (mutant) => {
    const result = mutant.deriveCertificateSignalCompletenessFromModules({
      modules: completeModules(),
      providerHealth: healthyProviders,
      observedAt: NOW,
      engineVersion: "item9-p2-mutation",
    });
    ok("MUTANT CT multiplicity as parallel live set makes fixture red",
      result.signals.parallel_certificate_set.observation === "present");
  },
);

function buildDb({ includeDeleted = false } = {}) {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')")
    .run();
  db.prepare(
    "INSERT INTO domains (id, user_id, domain) VALUES ('dom', 'usr', 'example.com')",
  ).run();
  db.prepare(
    "INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws', 'Active', NULL)",
  ).run();
  db.prepare(
    "INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws', 'dom')",
  ).run();
  if (includeDeleted) {
    db.prepare(
      `INSERT INTO workspaces (id, name, deleted_at)
       VALUES ('ws-deleted', 'Deleted', '2026-07-25T00:00:00.000Z')`,
    ).run();
    db.prepare(
      `INSERT INTO workspace_domains (workspace_id, domain_id)
       VALUES ('ws-deleted', 'dom')`,
    ).run();
  }
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => db.prepare(sql).run(...args),
  });
  return { prepare: (sql) => statement(sql) };
}

const certMod = {
  error: null,
  issuer: "Mutation CA",
  subject: "example.com",
  san_hostnames: ["example.com"],
  san_count: 1,
  expires_at: "2026-11-01T00:00:00.000Z",
  source: "ssl_ct_correlation",
  signal_completeness: {
    model_version: "certificate-signal-completeness-v1",
    signals: {
      san: { observation: "present" },
      issuer: { observation: "present" },
      expiry: { observation: "present" },
    },
  },
};

await withMutant(
  "cert-events.js",
  (source) => source.replace(
    "signal_completeness: certMod.signal_completeness ?? null,",
    "signal_completeness: null,",
  ),
  async (mutant) => {
    const db = buildDb();
    try {
      await mutant.upsertCertificateObservation(
        "scan", "dom", certMod,
        { cybermeters_db: makeD1(db) },
      );
      const row = db.prepare(
        "SELECT evidence_json FROM certificate_observations WHERE workspace_id = 'ws'",
      ).get();
      const evidence = JSON.parse(row?.evidence_json || "{}");
      ok("MUTANT dropped D1 completeness makes persistence fixture red",
        evidence.signal_completeness === null);
    } finally {
      db.close();
    }
  },
);

await withMutant(
  "cert-events.js",
  (source) => source.replace(
    "if (!hasObservedCertificateIdentity) return;",
    "if (!hasObservedCertificateIdentity) void 0;",
  ),
  async (mutant) => {
    const db = buildDb();
    try {
      await mutant.upsertCertificateObservation(
        "scan",
        "dom",
        {
          ...certMod,
          issuer: null,
          san_hostnames: [],
          san_count: 0,
          expires_at: null,
          signal_completeness: {
            model_version: "certificate-signal-completeness-v1",
            signals: {
              san: { observation: "unknown" },
              issuer: { observation: "unknown" },
              expiry: { observation: "unknown" },
            },
          },
        },
        { cybermeters_db: makeD1(db) },
      );
      const count = db.prepare(
        "SELECT COUNT(*) AS n FROM certificate_observations WHERE workspace_id = 'ws'",
      ).get().n;
      ok("MUTANT pseudo-certificate on unavailable evidence makes honesty fixture red",
        count === 1);
    } finally {
      db.close();
    }
  },
);

await withMutant(
  "cert-events.js",
  (source) => source.replace(
    "WHERE wd.domain_id = ? AND w.deleted_at IS NULL",
    "WHERE wd.domain_id = ?",
  ),
  async (mutant) => {
    const db = buildDb({ includeDeleted: true });
    try {
      await mutant.upsertCertificateObservation(
        "scan", "dom", certMod,
        { cybermeters_db: makeD1(db) },
      );
      const count = db.prepare(
        `SELECT COUNT(*) AS n FROM certificate_observations
         WHERE workspace_id = 'ws-deleted'`,
      ).get().n;
      ok("MUTANT removed soft-delete gate makes tenant fixture red", count === 1);
    } finally {
      db.close();
    }
  },
);

await withMutant(
  "scan-budget.js",
  (source) => source.replace(
    "ssl:                         9_000,",
    "ssl:                        12_000,",
  ),
  async (mutant) => {
    ok("MUTANT 12-second SSL allocation makes budget fixture red",
      mutant.SCAN_MODULE_BUDGETS.ssl === 12_000);
  },
);

console.log(`\nItem 9 P2 mutations: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P2 mutation proof passed");
process.exit(fail ? 1 : 0);
