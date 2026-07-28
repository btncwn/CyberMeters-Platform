#!/usr/bin/env node
// Business Risk Score downstream completeness: deterministic sibling evidence,
// persistence guard, and real authenticated supply-chain customer-route proof.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...parts) => path.join(root, "workers", "scan-api", "src", ...parts);
const { computeAndPersistWorkspaceBrs } = await import(
  pathToFileURL(src("engines", "business-risk.js")).href
);
const { computeSupplyChainIntelligence, upsertSupplyChainScore } = await import(
  pathToFileURL(src("engines", "supply-chain.js")).href
);
const worker = await import(pathToFileURL(src("index.js")).href);

const NOW = "2026-07-28T09:00:00.000Z";
const EXPECTED_ASSERTIONS = 31;
let passed = 0;
let failed = 0;
const only = String(process.env.BRS_DOWNSTREAM_ASSERT_ONLY || "");
const check = (name, condition, detail = "") => {
  if (only && !name.includes(only)) return;
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  check(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent overlap */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const name of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((entry) => entry.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", name));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes, last_row_id: Number(result.lastInsertRowid || 0) } };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => {
      const results = [];
      db.exec("BEGIN");
      try {
        for (const entry of statements) {
          results.push(/^\s*select/i.test(entry.__sql) ? await entry.all() : await entry.run());
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

const db = buildDb();
const reports = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: {
    get: async (key) => reports.has(String(key))
      ? { json: async () => JSON.parse(reports.get(String(key))) }
      : null,
  },
  APP_VERSION: "brs-downstream-completeness",
  ALLOWED_ORIGIN: "https://app.cybermeters.com",
  FRONTEND_URL: "https://app.cybermeters.com",
  MFA_ENCRYPTION_KEY: "brs-downstream-completeness-key",
  RESEND_API_KEY: "",
  ADMIN_EMAILS: "",
};

db.prepare(`
  INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled)
  VALUES ('user','founder@example.com','Founder','professional','active',1,0)
`).run();
db.prepare(`
  INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,current_period_end,created_at)
  VALUES ('sub','user','professional','active','2099-01-01T00:00:00.000Z',?)
`).run(NOW);

function seedWorkspace(wsId, domainId, domain) {
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES (?,?,'user')")
    .run(wsId, `${wsId} Workspace`);
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,'user','admin')")
    .run(`member-${wsId}`, wsId);
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,'user',?)").run(domainId, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)").run(wsId, domainId);
  db.prepare(`
    INSERT INTO workspace_assets
      (id,workspace_id,domain_id,hostname,asset_type,source,first_seen,last_seen,status,created_at,updated_at)
    VALUES (?,?,?,?,'subdomain','ct',?,?,'active',?,?)
  `).run(`asset-${wsId}`, wsId, domainId, `www.${domain}`, NOW, NOW, NOW, NOW);
  db.prepare(`
    INSERT INTO workspace_vendors
      (id,workspace_id,vendor_name,category,source,confidence,risk_level,status,
       source_module,first_seen,last_seen,created_at,updated_at)
    VALUES (?,?,'Identity Provider','identity_provider','scan','high','high','active',
            'vendor_risk',?,?,?,?)
  `).run(`vendor-${wsId}`, wsId, NOW, NOW, NOW, NOW);
}

function seedScan(scanId, wsId, domainId, domain, quality, createdAt) {
  db.prepare(`
    INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,score,rating,created_at)
    VALUES (?,?,?,?,'completed',?,70,'medium',?)
  `).run(scanId, wsId, domainId, domain, quality, createdAt);
}

function completeReport(scanId) {
  reports.set(`reports/${scanId}.json`, JSON.stringify({
    scan_id: scanId,
    scan_quality: { status: "complete" },
    findings: [
      { id: `${scanId}-ssl`, type: "ssl_no_certificate", finding_type: "finding", severity: "high" },
      { id: `${scanId}-dmarc`, type: "email_missing_dmarc", finding_type: "finding", severity: "high" },
      { id: `${scanId}-csp`, type: "header_missing_content_security_policy", finding_type: "finding", severity: "medium" },
    ],
  }));
}

seedWorkspace("assessed", "dom-assessed", "assessed.example");
seedWorkspace("unavailable", "dom-unavailable", "unavailable.example");

seedScan("assessed-old", "assessed", "dom-assessed", "assessed.example", "complete", "2026-07-28T08:00:00.000Z");
seedScan("assessed-current", "assessed", "dom-assessed", "assessed.example", "complete", NOW);
completeReport("assessed-current");
const assessedBrs = await computeAndPersistWorkspaceBrs(env, "assessed", {
  scanId: "assessed-current",
  scanQuality: "complete",
  assessedAt: NOW,
});

seedScan("unavailable-complete", "unavailable", "dom-unavailable", "unavailable.example", "complete", "2026-07-28T08:00:00.000Z");
completeReport("unavailable-complete");
await computeAndPersistWorkspaceBrs(env, "unavailable", {
  scanId: "unavailable-complete",
  scanQuality: "complete",
  assessedAt: "2026-07-28T08:01:00.000Z",
});
seedScan("unavailable-partial", "unavailable", "dom-unavailable", "unavailable.example", "partial", NOW);

const assessed = await computeSupplyChainIntelligence("assessed", env);
const unavailable = await computeSupplyChainIntelligence("unavailable", env);

check("assessed positive control retains a real BRS", Number.isFinite(assessedBrs.score));
eq("assessed maturity state unchanged", assessed.asm_maturity.state, "assessed");
check("assessed maturity stays numeric", Number.isFinite(assessed.asm_maturity.score));
eq("assessed composite state unchanged", assessed.supply_chain_score_state, "assessed");
check("assessed composite stays numeric", Number.isFinite(assessed.supply_chain_score));
eq("assessed compliance state unchanged", assessed.compliance_readiness.state, "assessed");
check("assessed compliance families retain levels",
  ["gdpr", "security_governance", "pci_dss"].every((key) =>
    ["low", "medium", "high"].includes(assessed.compliance_readiness[key])));

eq("unavailable BRS remains null", unavailable.brs_score, null);
eq("unavailable maturity state is incomplete", unavailable.asm_maturity.state, "incomplete");
eq("unavailable maturity score is null", unavailable.asm_maturity.score, null);
eq("unavailable maturity level is null", unavailable.asm_maturity.level, null);
check("unavailable maturity names the missing BRS component",
  unavailable.asm_maturity.missing_components.includes("business_risk_score"));
eq("unavailable composite state is incomplete", unavailable.supply_chain_score_state, "incomplete");
eq("unavailable composite score is null", unavailable.supply_chain_score, null);
eq("unavailable compliance state is incomplete", unavailable.compliance_readiness.state, "incomplete");
check("unavailable compliance families are not low numbers or verdicts",
  ["gdpr", "security_governance", "pci_dss"].every((key) =>
    unavailable.compliance_readiness[key] === null));
check("unavailable compliance coverage identifies the missing BRS",
  Object.values(unavailable.compliance_readiness.coverage).every((family) =>
    family.state === "incomplete" && family.missing_components.includes("business_risk_score")));
check("independent compliance observations remain present",
  unavailable.compliance_readiness.coverage.gdpr.observed_signals.has_identity_provider === true);

const assessedSiblingComponents = assessed.asm_maturity.observed_components
  .filter((component) => component.component !== "business_risk_score");
eq("identical sibling evidence produces identical observed maturity components",
  JSON.stringify(unavailable.asm_maturity.observed_components),
  JSON.stringify(assessedSiblingComponents));
eq("trustworthy vendor evidence remains represented",
  unavailable.vendor_summary.active, assessed.vendor_summary.active);
eq("trustworthy operational resilience remains represented",
  unavailable.operational_resilience_score, assessed.operational_resilience_score);
eq("trustworthy concentration remains represented",
  unavailable.concentration_level, assessed.concentration_level);

db.prepare(`
  INSERT INTO workspace_supply_chain_scores
    (id,workspace_id,supply_chain_score,resilience_score,concentration_level,
     critical_vendor_count,tier1_count,tier2_count,tier3_count,spof_count,
     payload_json,calculated_at,created_at,updated_at)
  VALUES ('legacy-sc','unavailable',91,82,'medium',1,1,0,0,1,
          '{"supply_chain_score":91,"asm_maturity":{"score":10,"level":"initial"}}',?,?,?)
`).run(NOW, NOW, NOW);
await upsertSupplyChainScore("unavailable", unavailable, env);
eq("incomplete persistence cannot overwrite legacy storage with a fabricated zero",
  db.prepare("SELECT supply_chain_score FROM workspace_supply_chain_scores WHERE workspace_id='unavailable'").get().supply_chain_score,
  91);
eq("incomplete persistence appends no numeric history",
  db.prepare("SELECT COUNT(*) n FROM workspace_supply_chain_history WHERE workspace_id='unavailable'").get().n,
  0);

const token = "brs-downstream-route-token";
db.prepare(`
  INSERT INTO user_sessions (id,user_id,token_hash,expires_at)
  VALUES ('session','user',?,'2099-01-01T00:00:00.000Z')
`).run(await worker.hashToken(token));
const response = await worker.default.fetch(new Request(
  "https://api.cybermeters.com/api/workspaces/unavailable/supply-chain",
  { headers: { Authorization: `Bearer ${token}` } },
), env, { waitUntil: () => {}, passThroughOnException: () => {} });
const body = await response.json();

eq("real authenticated supply-chain route returns 200", response.status, 200);
eq("real route masks the persisted numeric composite", body.supply_chain_score, null);
eq("real route publishes incomplete composite state", body.supply_chain_score_state, "incomplete");
eq("real route masks numeric ASM maturity", body.asm_maturity.score, null);
eq("real route publishes incomplete ASM maturity", body.asm_maturity.state, "incomplete");
check("real route preserves independently trustworthy sibling evidence",
  body.vendor_summary.active === 1 && Number.isFinite(body.operational_resilience_score));
check("real route does not expose low compliance from missing BRS",
  body.compliance_readiness.gdpr === null
  && body.compliance_readiness.security_governance === null
  && body.compliance_readiness.pci_dss === null);

if (!only && passed + failed !== EXPECTED_ASSERTIONS) {
  failed += 1;
  console.error(`FAIL pinned assertion count — got ${passed + failed - 1} want ${EXPECTED_ASSERTIONS}`);
}
console.log(`BRS downstream completeness: ${passed}/${passed + failed} assertions passed`);
if (failed > 0 || (!only && passed !== EXPECTED_ASSERTIONS)) process.exit(1);
console.log("BRS downstream completeness passed");
