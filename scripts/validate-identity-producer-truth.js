#!/usr/bin/env node
// U2 — Identity producer/carrier truth validator.
//
// The registry is the contract: every fixture invokes production code, reports
// its stable ID, and is counted mechanically. Missing U2 exports are represented
// as semantic failures on the unchanged parent, never as harness/import errors.

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runIdentityDiscoveryModule } from "../workers/scan-api/src/engines/identity-scan.js";
import { upsertIdentityAssets } from "../workers/scan-api/src/engines/asset-persistence.js";

let contract = {};
try {
  contract = await import("../workers/scan-api/src/engines/identity-evidence-contract.js");
} catch (error) {
  if (error?.code !== "ERR_MODULE_NOT_FOUND") throw error;
}

const {
  buildIdentityClaim,
  buildIdentityEvidenceProjection,
  readIdentityEvidence,
  serializeIdentityEvidence,
} = contract;

const OBSERVED_AT = "2026-08-11T09:10:11.000Z";
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ADFS_POSITIVE = [
  "adfs.corp.com",
  "sts.corp.com",
  "ADFS.Corp.com",
  "fs.adfs.corp.com",
  "adfs.corp.com.",
];
const ADFS_NEGATIVE = [
  "requests.example.com", "hosts.example.com", "lists.example.com",
  "costs.example.com", "analysts.example.com", "tests.example.com",
  "guests.example.com", "posts.example.com", "forecasts.example.com",
  "broadcasts.example.com", "readfs.example.com", "noadfs.example.com",
  "mysts.example.com", "evil-adfs.attacker.example", "sts.windows.net",
  "login.microsoftonline.com",
];

function makeD1(database) {
  return {
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async all() {
              const statement = database.prepare(sql);
              return { results: statement.all(...params) };
            },
            async run() {
              const statement = database.prepare(sql);
              const result = statement.run(...params);
              return { meta: { changes: Number(result.changes) } };
            },
          };
        },
      };
    },
  };
}

function makePersistenceFixture() {
  const database = new DatabaseSync(":memory:");
  database.exec(`
    CREATE TABLE workspace_domains (workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL);
    CREATE TABLE identity_assets (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL,
      scan_id TEXT, hostname TEXT, asset_type TEXT, identity_type TEXT,
      provider TEXT, internet_exposed INTEGER, source TEXT, risk_score INTEGER,
      evidence TEXT, first_seen TEXT, last_seen TEXT, status TEXT,
      created_at TEXT, updated_at TEXT
    );
    CREATE TABLE workspace_vendors (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, vendor_name TEXT NOT NULL,
      category TEXT NOT NULL, source TEXT, evidence TEXT, confidence,
      risk_level TEXT, first_seen TEXT, last_seen TEXT, status TEXT,
      source_module TEXT, created_at TEXT, updated_at TEXT,
      UNIQUE (workspace_id, vendor_name, category)
    );
    INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws-u2', 'domain-u2');
  `);
  return { database, env: { cybermeters_db: makeD1(database) } };
}

function entraModules() {
  return {
    subdomain_takeover: { risks: [{ cname: "login.microsoftonline.com" }] },
    email_security: { spf: { includes: ["spf.protection.outlook.com"] } },
    dns: { mx_records: [{ value: "mx1.protection.outlook.com", ttl: 300 }] },
    headers: {
      security_headers: { content_security_policy: { value: "default-src https://login.microsoftonline.com" } },
      response_headers: {},
    },
  };
}

function provider(result, name) {
  return (result?.providers ?? []).find((item) => item.provider === name) ?? null;
}

function portal(result, hostname) {
  return (result?.portals ?? []).find((item) => item.hostname === hostname) ?? null;
}

function claimFor(row) {
  return typeof buildIdentityClaim === "function" ? buildIdentityClaim(row) : null;
}

function readEvidence(raw) {
  return typeof readIdentityEvidence === "function" ? readIdentityEvidence(raw) : null;
}

function allV2Fields(items, expectedSources) {
  if (!Array.isArray(items) || items.length !== expectedSources.length) return false;
  const sources = items.map((item) => item?.source).sort();
  const expectedPrecision = { cname: "host_substring", csp: "token_substring", spf: "host_substring", mx: "host_substring" };
  const expectedProvenance = {
    cname: ["subdomain_takeover", "risks[].cname"],
    csp: ["headers", "security_headers.content_security_policy.value"],
    spf: ["email_security", "spf.includes[]"],
    mx: ["dns", "mx_records[].value"],
  };
  return JSON.stringify(sources) === JSON.stringify([...expectedSources].sort()) && items.every((item) =>
    item?.schema_version === "identity_evidence.v2" &&
    item?.provenance?.producer === "identity_discovery" &&
    item?.provenance?.module === expectedProvenance[item.source]?.[0] &&
    item?.provenance?.path === expectedProvenance[item.source]?.[1] &&
    item?.match_precision === expectedPrecision[item.source] &&
    typeof item?.name_resolution === "string" &&
    typeof item?.validation_state === "string" &&
    item?.confidence_detail?.schema_version === "identity_confidence.v1" &&
    (item?.observed_at === null || typeof item?.observed_at === "string"));
}

async function roundTrip() {
  const result = runIdentityDiscoveryModule(entraModules(), "example.com", { observedAt: OBSERVED_AT });
  const { database, env } = makePersistenceFixture();
  try {
    await upsertIdentityAssets("domain-u2", "scan-u2", result, env);
    const row = database.prepare(
      "SELECT * FROM identity_assets WHERE workspace_id = ? AND provider = ? ORDER BY id LIMIT 1",
    ).get("ws-u2", "Microsoft Entra ID");
    const adapted = row && readEvidence(row.evidence);
    const identityClaim = row && claimFor(row);
    const projection = row && typeof buildIdentityEvidenceProjection === "function"
      ? buildIdentityEvidenceProjection(row)
      : null;
    return { result, row, adapted, identityClaim, projection };
  } finally {
    database.close();
  }
}

async function persistIdentityModule(identityModule, { providerName = null, hostname = null } = {}) {
  const { database, env } = makePersistenceFixture();
  try {
    await upsertIdentityAssets("domain-u2", "scan-carrier", identityModule, env);
    const row = providerName
      ? database.prepare("SELECT * FROM identity_assets WHERE workspace_id = ? AND provider = ? ORDER BY id LIMIT 1").get("ws-u2", providerName)
      : hostname
        ? database.prepare("SELECT * FROM identity_assets WHERE workspace_id = ? AND hostname = ? ORDER BY id LIMIT 1").get("ws-u2", hostname)
        : database.prepare("SELECT * FROM identity_assets WHERE workspace_id = ? ORDER BY id LIMIT 1").get("ws-u2");
    return {
      row,
      adapted: row ? readEvidence(row.evidence) : null,
      claim: row ? claimFor(row) : null,
      projection: row && typeof buildIdentityEvidenceProjection === "function"
        ? buildIdentityEvidenceProjection(row)
        : null,
    };
  } finally {
    database.close();
  }
}

function moduleWithPortalEvidence(evidence, hostname = "login.example") {
  return {
    detected: true,
    providers: [],
    portals: [{
      asset_type: "portal",
      identity_type: "login_portal",
      provider: null,
      hostname,
      internet_exposed: true,
      risk_score: 10,
      source: "hostname_pattern",
      evidence,
      confidence: 60,
      validation_quality: "partial",
    }],
  };
}

function historicalRawProjection(raw) {
  const { database } = makePersistenceFixture();
  try {
    database.prepare(`INSERT INTO identity_assets (
      id, workspace_id, domain_id, scan_id, hostname, asset_type, identity_type,
      provider, internet_exposed, source, risk_score, evidence, first_seen,
      last_seen, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "historical-u2", "ws-u2", "domain-u2", "scan-historical", "login.example",
      "portal", "login_portal", null, 1, "hostname_pattern", 10, raw,
      OBSERVED_AT, OBSERVED_AT, "active", OBSERVED_AT, OBSERVED_AT,
    );
    const row = database.prepare("SELECT * FROM identity_assets WHERE id = ?").get("historical-u2");
    return {
      row,
      adapted: readEvidence(row.evidence),
      claim: claimFor(row),
      projection: typeof buildIdentityEvidenceProjection === "function"
        ? buildIdentityEvidenceProjection(row)
        : null,
    };
  } finally {
    database.close();
  }
}

const validDatum = {
  schema_version: "identity_evidence.v2",
  source: "cname",
  value: "adfs.example.com",
  provenance: { producer: "identity_discovery", module: "subdomain_takeover", path: "risks[].cname" },
  match_precision: "label_boundary",
  name_resolution: "not_evaluated",
  validation_state: "observed",
  confidence_detail: {
    schema_version: "identity_confidence.v1",
    subject: "provider_identification",
    level: "high",
    score: 85,
    quality: "good",
    basis: "label_boundary",
  },
  observed_at: OBSERVED_AT,
};

const FIXTURES = [
  {
    id: "U2-E01",
    run: () => {
      const item = provider(runIdentityDiscoveryModule(entraModules(), "example.com", { observedAt: OBSERVED_AT }), "Microsoft Entra ID");
      return allV2Fields(item?.evidence, ["cname", "csp", "spf", "mx"]);
    },
  },
  {
    id: "U2-E02",
    run: async () => {
      const value = await roundTrip();
      const writerSource = fs.readFileSync(path.join(ROOT, "workers/scan-api/src/engines/asset-persistence.js"), "utf8");
      return value.adapted?.status === "valid_v2" && value.adapted.valid_v2_count === 4 &&
        value.identityClaim?.reachability?.status === "not_evaluated" &&
        value.projection?.evidence_status === "valid_v2" &&
        writerSource.includes("serializeIdentityEvidence(asset.evidence)");
    },
  },
  {
    id: "U2-E03",
    run: async () => {
      const raw = '[{"source":"subdomain_hostname","value":"login.example"}]';
      const value = await persistIdentityModule(moduleWithPortalEvidence(JSON.parse(raw)));
      return value.adapted?.status === "legacy" && value.adapted.legacy_count === 1 &&
        value.adapted.items[0]?.name_resolution === "unknown_legacy" && value.row?.evidence === raw &&
        value.projection?.evidence_status === "legacy";
    },
  },
  {
    id: "U2-E04",
    run: async () => {
      const value = await persistIdentityModule(moduleWithPortalEvidence([validDatum, { source: "subdomain_hostname", value: "login.example" }, 7]));
      return value.adapted?.status === "mixed" && value.adapted.valid_v2_count === 1 &&
        value.adapted.legacy_count === 1 && value.adapted.malformed_count === 1 && value.adapted.items.length === 3 &&
        value.projection?.evidence_status === "mixed";
    },
  },
  {
    id: "U2-E05",
    run: () => {
      const value = historicalRawProjection("{not-json");
      return value.adapted?.status === "malformed" && value.claim?.reachability?.status === "not_evaluated" &&
        value.claim?.surface_classification?.status === "unknown" && value.row?.evidence === "{not-json" &&
        value.projection?.evidence_status === "malformed";
    },
  },
  {
    id: "U2-E06",
    run: async () => {
      const value = await persistIdentityModule(moduleWithPortalEvidence([]));
      const empty = value.adapted;
      const absent = readEvidence(null);
      return empty?.status === "empty" && absent?.status === "empty" &&
        value.row?.evidence === "[]" && value.claim?.reachability?.status === "not_evaluated";
    },
  },
  {
    id: "U2-E07",
    run: () => {
      const result = runIdentityDiscoveryModule({ ...entraModules(), subdomains: { items: ["login.example.com"] } }, "example.com", { observedAt: OBSERVED_AT });
      return typeof result.providers[0]?.confidence === "number" && result.providers[0].confidence === 90 &&
        typeof result.portals[0]?.confidence === "number" && result.portals[0].confidence === 60 &&
        result.providers[0]?.confidence_detail?.subject === "provider_identification" &&
        result.portals[0]?.confidence_detail?.subject === "hostname_classification";
    },
  },
  {
    id: "U2-E08",
    run: async () => {
      const cyclic = {}; cyclic.self = cyclic;
      const { database, env } = makePersistenceFixture();
      const errors = [];
      const originalError = console.error;
      console.error = (...args) => errors.push(args.map(String).join(" "));
      try {
        await upsertIdentityAssets("domain-u2", "scan-cycle", {
          detected: true,
          providers: [{
            asset_type: "provider", identity_type: "idp", provider: "Cycle IDP",
            internet_exposed: true, source: "identity_discovery", risk_score: 10,
            confidence: 90, evidence: cyclic,
          }],
          portals: [],
        }, env);
        await upsertIdentityAssets("domain-u2", "scan-non-array", {
          detected: true,
          providers: [],
          portals: [{
            asset_type: "portal", identity_type: "login_portal", hostname: "login.example",
            internet_exposed: true, source: "hostname_pattern", risk_score: 10,
            confidence: 60, evidence: undefined,
          }],
        }, env);
        const count = database.prepare("SELECT COUNT(*) AS n FROM identity_assets").get().n;
        return count === 0 && errors.length >= 2;
      } finally {
        console.error = originalError;
        database.close();
      }
    },
  },
  {
    id: "U2-B2-P01",
    run: () => ADFS_POSITIVE.every((hostname) => {
      const rows = runIdentityDiscoveryModule({ subdomain_takeover: { risks: [{ cname: hostname }] } }, "corp.com", { observedAt: OBSERVED_AT });
      const matches = (rows.providers ?? []).filter((item) => item.provider === "Microsoft ADFS");
      return matches.length === 1 && matches[0].evidence[0]?.match_precision === "label_boundary";
    }),
  },
  {
    id: "U2-B2-N01",
    run: () => ADFS_NEGATIVE.filter((hostname) => hostname !== "sts.windows.net").every((hostname) => {
      const rows = runIdentityDiscoveryModule({ subdomain_takeover: { risks: [{ cname: hostname }] } }, "example.com", { observedAt: OBSERVED_AT });
      return !(rows.providers ?? []).some((item) => item.provider === "Microsoft ADFS");
    }),
  },
  {
    id: "U2-B2-N02",
    run: () => {
      const rows = runIdentityDiscoveryModule({ subdomain_takeover: { risks: [{ cname: "sts.windows.net" }] } }, "example.com", { observedAt: OBSERVED_AT });
      return (rows.providers ?? []).filter((item) => item.provider === "Microsoft Entra ID").length === 1 &&
        !(rows.providers ?? []).some((item) => item.provider === "Microsoft ADFS");
    },
  },
  {
    id: "U2-B2-W01",
    run: () => {
      const row = provider(runIdentityDiscoveryModule({ headers: { response_headers: { server: "Okta Edge" } } }, "example.com", { observedAt: OBSERVED_AT }), "Okta");
      const claim = claimFor({ ...row, evidence: JSON.stringify(row?.evidence ?? []) });
      return row?.evidence[0]?.match_precision === "token_substring" && claim?.provider_relationship?.status === "possible";
    },
  },
  {
    id: "U2-B2-W02",
    run: () => {
      const row = provider(runIdentityDiscoveryModule({ headers: { security_headers: { content_security_policy: { value: "frame-src https://keycloak.example" } } } }, "example.com", { observedAt: OBSERVED_AT }), "Keycloak");
      const claim = claimFor({ ...row, evidence: JSON.stringify(row?.evidence ?? []) });
      return row?.evidence[0]?.match_precision === "token_substring" && claim?.provider_relationship?.status === "possible";
    },
  },
  {
    id: "U2-B2-MX01",
    run: () => {
      const row = provider(runIdentityDiscoveryModule({ dns: { mx_records: [{ value: "mx1.protection.outlook.com", ttl: 300 }] } }, "example.com", { observedAt: OBSERVED_AT }), "Microsoft Entra ID");
      return row?.evidence[0]?.value === "mx1.protection.outlook.com" && row.evidence[0]?.provenance?.path === "mx_records[].value";
    },
  },
  {
    id: "U2-B2-MX02",
    run: () => {
      const direct = provider(runIdentityDiscoveryModule({ dns: { mx_records: ["mx1.protection.outlook.com"] } }, "example.com", { observedAt: OBSERVED_AT }), "Microsoft Entra ID");
      const legacy = provider(runIdentityDiscoveryModule({ dns: { mx_records: [{ hostname: "mx1.protection.outlook.com" }] } }, "example.com", { observedAt: OBSERVED_AT }), "Microsoft Entra ID");
      return direct?.evidence[0]?.source === "mx" && legacy?.evidence[0]?.source === "mx" &&
        direct.evidence[0]?.schema_version === "identity_evidence.v2" &&
        legacy.evidence[0]?.schema_version === "identity_evidence.v2";
    },
  },
  {
    id: "U2-B3-CT01",
    run: async () => {
      const result = runIdentityDiscoveryModule({ subdomains: { items: ["admin.example.com"] } }, "example.com", { observedAt: OBSERVED_AT });
      const value = await persistIdentityModule(result, { hostname: "admin.example.com" });
      return value.adapted?.items[0]?.source === "certificate_transparency" &&
        value.claim?.name_resolution?.status === "not_evaluated" && value.claim?.name_resolution?.measured_at === null &&
        value.claim?.reachability?.status === "not_evaluated";
    },
  },
  {
    id: "U2-B3-DNS01",
    run: async () => {
      const result = runIdentityDiscoveryModule({ dns_bruteforce: { items: [{ hostname: "login.example.com", ip_addresses: ["192.0.2.10"] }] } }, "example.com", { observedAt: OBSERVED_AT });
      const value = await persistIdentityModule(result, { hostname: "login.example.com" });
      return value.adapted?.items[0]?.source === "dns_bruteforce" && value.adapted.items[0]?.name_resolution === "resolved" &&
        value.adapted.items[0]?.ip_addresses?.[0] === "192.0.2.10" && value.claim?.surface_classification?.status === "possible" &&
        value.claim?.reachability?.status === "not_evaluated";
    },
  },
  {
    id: "U2-B3-BOTH01",
    run: () => {
      const row = portal(runIdentityDiscoveryModule({
        subdomains: { items: ["login.example.com"] },
        dns_bruteforce: { items: [{ hostname: "login.example.com", ip_addresses: ["192.0.2.10"] }] },
      }, "example.com", { observedAt: OBSERVED_AT }), "login.example.com");
      return row?.evidence?.length === 2 && new Set(row.evidence.map((item) => item.source)).size === 2 &&
        row?.name_resolution?.status === "resolved";
    },
  },
  {
    id: "U2-B3-MX01",
    run: () => {
      const row = portal(runIdentityDiscoveryModule({ dns_bruteforce: { items: [{ hostname: "login.example.com", source: "dns_mx", mail_only: true }] } }, "example.com", { observedAt: OBSERVED_AT }), "login.example.com");
      const claim = claimFor({ ...row, evidence: JSON.stringify(row?.evidence ?? []) });
      return row?.evidence[0]?.source === "dns_mx" && row.evidence[0]?.name_resolution === "mx_only" &&
        claim?.reachability?.status === "not_evaluated";
    },
  },
  {
    id: "U2-B3-EMPTY01",
    run: () => {
      const row = portal(runIdentityDiscoveryModule({ dns_bruteforce: { items: [{ hostname: "login.example.com", ip_addresses: [] }] } }, "example.com", { observedAt: OBSERVED_AT }), "login.example.com");
      return row?.evidence[0]?.source === "dns_bruteforce" && row.evidence[0]?.validation_state === "source_incomplete" &&
        row.evidence[0]?.name_resolution === "not_evaluated";
    },
  },
  {
    id: "U2-B3-FAIL01",
    run: () => {
      const row = portal(runIdentityDiscoveryModule({
        subdomains: { items: ["admin.example.com"] },
        dns_bruteforce: { error: "resolver failed", items: [{ hostname: "admin.example.com", ip_addresses: ["192.0.2.10"] }] },
      }, "example.com", { observedAt: OBSERVED_AT }), "admin.example.com");
      return row?.evidence?.length === 1 && row.evidence[0]?.source === "certificate_transparency" &&
        row?.name_resolution?.status === "not_evaluated";
    },
  },
  {
    id: "U2-B3-DEAD01",
    run: () => [
      { outcome: "deadline_exceeded" }, { incomplete: true }, { executed: false },
    ].every((state) => {
      const row = portal(runIdentityDiscoveryModule({
        subdomains: { items: ["admin.example.com"] },
        dns_bruteforce: { ...state, items: [{ hostname: "admin.example.com", ip_addresses: ["192.0.2.10"] }] },
      }, "example.com", { observedAt: OBSERVED_AT }), "admin.example.com");
      return row?.evidence?.length === 1 && row.evidence[0]?.source === "certificate_transparency";
    }),
  },
  {
    id: "U2-B3-ABS01",
    run: () => {
      const row = portal(runIdentityDiscoveryModule({ subdomains: { items: ["login.example.com"] }, dns_bruteforce: { items: [] } }, "example.com", { observedAt: OBSERVED_AT }), "login.example.com");
      const forbiddenResolution = ["not", "resolved"].join("_");
      return row?.name_resolution?.status === "not_evaluated" && !JSON.stringify(row).includes(forbiddenResolution);
    },
  },
  {
    id: "U2-B3-TIME01",
    run: () => {
      const result = runIdentityDiscoveryModule({
        ...entraModules(),
        subdomains: { items: ["portal.example.com"] },
        dns_bruteforce: { items: [
          { hostname: "login.example.com", ip_addresses: ["192.0.2.10"] },
          { hostname: "admin.example.com", source: "dns_mx", mail_only: true },
        ] },
      }, "example.com", { observedAt: OBSERVED_AT });
      const data = [...result.providers.flatMap((item) => item.evidence), ...result.portals.flatMap((item) => item.evidence)];
      return data.length > 0 && data.every((item) => item.observed_at === OBSERVED_AT) &&
        result.portals.every((item) => ["resolved", "mx_only"].includes(item.name_resolution.status)
          ? item.name_resolution.measured_at === OBSERVED_AT
          : item.name_resolution.measured_at === null);
    },
  },
  {
    id: "U2-B3-TIME02",
    run: async () => {
      for (const observedAt of [undefined, "not-a-time"]) {
        const result = runIdentityDiscoveryModule({ subdomains: { items: ["login.example.com"] } }, "example.com", { observedAt });
        const value = await persistIdentityModule(result, { hostname: "login.example.com" });
        if (value.adapted?.items[0]?.observed_at !== null || value.claim?.name_resolution?.measured_at !== null) return false;
      }
      return true;
    },
  },
  {
    id: "U2-B3-NOREACH01",
    run: () => {
      const row = portal(runIdentityDiscoveryModule({ dns_bruteforce: { items: [{ hostname: "login.example.com", ip_addresses: ["192.0.2.10"] }] } }, "example.com", { observedAt: OBSERVED_AT }), "login.example.com");
      const claim = claimFor({ ...row, evidence: JSON.stringify(row?.evidence ?? []) });
      return claim?.name_resolution?.status === "resolved" && claim?.reachability?.status === "not_evaluated" &&
        claim?.reachability?.endpoint === null;
    },
  },
  {
    id: "U2-POS-01",
    control: true,
    run: () => provider(runIdentityDiscoveryModule({ subdomain_takeover: { risks: [{ cname: "login.microsoftonline.com" }] } }, "example.com"), "Microsoft Entra ID") != null,
  },
  {
    id: "U2-POS-02",
    control: true,
    run: () => portal(runIdentityDiscoveryModule({ subdomains: { items: ["login.example.com"] } }, "example.com"), "login.example.com") != null,
  },
];

let passed = 0;
const failed = [];
const controls = [];
console.log(`LOADED identity-scan.js asset-persistence.js contract=${Object.keys(contract).length > 0}`);
for (const fixture of FIXTURES) {
  let ok = false;
  let detail = "";
  try {
    ok = Boolean(await fixture.run());
  } catch (error) {
    detail = error?.message ?? String(error);
  }
  if (fixture.control) controls.push({ id: fixture.id, ok });
  if (ok) passed += 1;
  else failed.push(fixture.id);
  console.log(`${ok ? "PASS" : "FAIL"} ${fixture.id}${detail ? ` — ${detail}` : ""}`);
}

const executedIds = FIXTURES.map((fixture) => fixture.id);
console.log(`U2 fixtures executed (${executedIds.length}): ${executedIds.join(",")}`);
console.log(`U2 producer truth: ${passed}/${FIXTURES.length} fixtures passed`);
console.log(`U2 controls: ${controls.filter((item) => item.ok).length}/${controls.length} passed`);
if (new Set(executedIds).size !== FIXTURES.length || failed.length > 0) process.exit(1);
