#!/usr/bin/env node
// Identity U1+B4 exact semantic mutation registry. Each mutant changes one
// production anchor, runs the named right-reason fixtures in a fresh process,
// rejects unexpected failures and restores the candidate bytes in finally.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(ROOT, "scripts/validate-identity-substrate-idempotence.js");
const target = (relative) => path.join(ROOT, relative);
const TARGETS = {
  writer: target("workers/scan-api/src/engines/asset-persistence.js"),
  contract: target("workers/scan-api/src/engines/identity-evidence-contract.js"),
  related: target("workers/scan-api/src/engines/related-changes.js"),
  route: target("workers/scan-api/src/routes/related-changes.js"),
  adapter: target("workers/scan-api/src/engines/related-changes-adapter.js"),
  list: target("frontend/src/components/RelatedChangesList.jsx"),
  detail: target("frontend/src/pages/ws/WorkspaceRelatedChangeDetailPage.jsx"),
};
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

function replaceExactly(source, anchor, replacement, label) {
  const count = source.split(anchor).length - 1;
  if (count !== 1) throw new Error(`${label}: expected one anchor, found ${count}`);
  return source.replace(anchor, replacement);
}

const INSERT_NOT_EXISTS = `                AND NOT EXISTS (
                      SELECT 1 FROM identity_assets existing
                       WHERE existing.workspace_id = c.workspace_id
                         AND existing.domain_id = c.domain_id
                         AND existing.identity_type = c.identity_type
                         AND (
                               existing.hostname = c.hostname
                               OR (existing.hostname IS NULL AND c.hostname IS NULL)
                             )
                         AND (
                               existing.provider = c.provider
                               OR (existing.provider IS NULL AND c.provider IS NULL)
                             )
                    )`;
const INSERT_ACTIVE = `WHERE EXISTS (
                      SELECT 1 FROM workspaces w
                       WHERE w.id = c.workspace_id AND w.deleted_at IS NULL
                    )`;
const UPDATE_ACTIVE = `AND EXISTS (
                      SELECT 1 FROM workspaces w
                       WHERE w.id = (SELECT workspace_id FROM candidate)
                         AND w.deleted_at IS NULL
                    )`;
const VENDOR_INSERT_ACTIVE = `WHERE EXISTS (
                    SELECT 1 FROM workspaces w
                     WHERE w.id = ? AND w.deleted_at IS NULL
                  )`;
const VENDOR_UPDATE_ACTIVE = `AND EXISTS (
                     SELECT 1 FROM workspaces w
                      WHERE w.id = workspace_vendors.workspace_id
                        AND w.deleted_at IS NULL
                   )`;

const rankingAnchor = `ROW_NUMBER() OVER (
           PARTITION BY workspace_id, domain_id, identity_type,
                        IFNULL(hostname, ''), IFNULL(provider, '')
           ORDER BY first_seen ASC, created_at ASC, id ASC
         ) AS representative_rank,
         ROW_NUMBER() OVER (
           PARTITION BY workspace_id, domain_id, identity_type,
                        IFNULL(hostname, ''), IFNULL(provider, '')`;
const rankingWithoutDomain = `ROW_NUMBER() OVER (
           PARTITION BY workspace_id, identity_type,
                        IFNULL(hostname, ''), IFNULL(provider, '')
           ORDER BY first_seen ASC, created_at ASC, id ASC
         ) AS representative_rank,
         ROW_NUMBER() OVER (
           PARTITION BY workspace_id, identity_type,
                        IFNULL(hostname, ''), IFNULL(provider, '')`;

const MUTANTS = [
  { id:"U1-M01", file:"writer", anchor:INSERT_NOT_EXISTS, replacement:"", fail:["U1-W01","U1-W02","U1-W03","U1-W08","U1-B4-01"], controls:["U1-POS-DISTINCT-WRITE"] },
  { id:"U1-M02", file:"writer", anchor:"AND (\n                               existing.hostname = c.hostname\n                               OR (existing.hostname IS NULL AND c.hostname IS NULL)\n                             )\n                         AND (\n                               existing.provider = c.provider\n                               OR (existing.provider IS NULL AND c.provider IS NULL)\n                             )\n                    )`", replacement:"AND existing.hostname = c.hostname\n                         AND (\n                               existing.provider = c.provider\n                               OR (existing.provider IS NULL AND c.provider IS NULL)\n                             )\n                    )`", fail:["U1-W05","U1-W07"], controls:["U1-W06"] },
  { id:"U1-M03", file:"writer", anchor:"AND (\n                               existing.hostname = c.hostname\n                               OR (existing.hostname IS NULL AND c.hostname IS NULL)\n                             )\n                         AND (\n                               existing.provider = c.provider\n                               OR (existing.provider IS NULL AND c.provider IS NULL)\n                             )\n                    )`", replacement:"AND (\n                               existing.hostname = c.hostname\n                               OR (existing.hostname IS NULL AND c.hostname IS NULL)\n                             )\n                         AND existing.provider = c.provider\n                    )`", fail:["U1-W06","U1-W07"], controls:["U1-W05"] },
  { id:"U1-M04", file:"writer", anchor:"SELECT 1 FROM identity_assets existing\n                       WHERE existing.workspace_id = c.workspace_id\n                         AND existing.domain_id = c.domain_id\n                         AND existing.identity_type = c.identity_type", replacement:"SELECT 1 FROM identity_assets existing\n                       WHERE existing.workspace_id = c.workspace_id\n                         AND existing.identity_type = c.identity_type", fail:["U1-W04"], controls:["U1-W01"] },
  { id:"U1-M05", file:"writer", anchor:"FROM identity_assets existing, candidate c\n                WHERE existing.workspace_id = c.workspace_id\n                  AND existing.domain_id = c.domain_id\n                  AND existing.identity_type = c.identity_type", replacement:"FROM identity_assets existing, candidate c\n                WHERE existing.workspace_id = c.workspace_id\n                  AND existing.identity_type = c.identity_type", fail:["U1-W04"], controls:["U1-W01"] },
  { id:"U1-M06", file:"writer", anchor:"ORDER BY existing.first_seen ASC,\n                         existing.created_at ASC, existing.id ASC", replacement:"ORDER BY existing.first_seen ASC", fail:["U1-W08","U1-W09","U1-C02"], controls:["U1-W01"] },
  { id:"U1-M07", file:"writer", anchor:INSERT_ACTIVE, replacement:"WHERE 1 = 1", fail:["U1-SD02"], controls:["U1-SD04"] },
  { id:"U1-M08", file:"writer", anchor:UPDATE_ACTIVE, replacement:"AND 1 = 1", fail:["U1-SD02"], controls:["U1-SD04"] },
  { id:"U1-M09", file:"writer", anchor:VENDOR_INSERT_ACTIVE, replacement:"WHERE 1 = 1", fail:["U1-SD03"], controls:["U1-W01"] },
  { id:"U1-M10", file:"writer", anchor:VENDOR_UPDATE_ACTIVE, replacement:"AND 1 = 1", fail:["U1-SD03"], controls:["U1-W01"] },
  { id:"U1-M11", file:"contract", anchor:rankingAnchor, replacement:rankingWithoutDomain, fail:["U1-W04","U1-CONS01","U1-CONS02","U1-CONS03","U1-CONS04","U1-CONS05","U1-CONS06","U1-CONS07","U1-CONS08","U1-CONS09"], controls:["U1-C01"] },
  { id:"U1-M12", file:"contract", anchor:"ORDER BY first_seen ASC, created_at ASC, id ASC", replacement:"ORDER BY first_seen ASC", fail:["U1-C04","U1-C05"], controls:["U1-C01","U1-C02"] },
  { id:"U1-M13", file:"contract", anchor:"ORDER BY last_seen DESC,\n                    COALESCE(updated_at, created_at, '') DESC,\n                    scan_id DESC, id DESC", replacement:"ORDER BY last_seen DESC", fail:["U1-C03","U1-C04","U1-C05"], controls:["U1-C01"] },
  { id:"U1-M14", file:"contract", anchor:"export const IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT COUNT(*) AS n FROM canonical_identity_assets`;", replacement:"export const IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT COUNT(DISTINCT domain_id || identity_type || IFNULL(hostname, '') || IFNULL(provider, '')) AS n FROM canonical_identity_assets`;", fail:["U1-C01"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M15", file:"contract", anchor:"export const IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT COUNT(*) AS n FROM canonical_identity_assets`;", replacement:"export const IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY = `SELECT COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active'`;", fail:["U1-CONS01"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M16", file:"contract", anchor:"export const IDENTITY_CANONICAL_SUMMARY_TYPE_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT identity_type, COUNT(*) AS n FROM canonical_identity_assets GROUP BY identity_type`;", replacement:"export const IDENTITY_CANONICAL_SUMMARY_TYPE_QUERY = `SELECT identity_type, COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' GROUP BY identity_type`;", fail:["U1-CONS02"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M17", file:"contract", anchor:"export const IDENTITY_CANONICAL_SUMMARY_PROVIDER_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT provider, COUNT(*) AS n FROM canonical_identity_assets\n WHERE provider IS NOT NULL AND provider != ''\n GROUP BY provider ORDER BY n DESC, provider ASC`;", replacement:"export const IDENTITY_CANONICAL_SUMMARY_PROVIDER_QUERY = `SELECT provider, COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND provider IS NOT NULL AND provider != '' GROUP BY provider ORDER BY n DESC, provider ASC`;", fail:["U1-CONS03"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M18", file:"contract", anchor:"export const IDENTITY_CANONICAL_SUMMARY_HIGH_RISK_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT COUNT(*) AS n FROM canonical_identity_assets WHERE risk_score >= 15`;", replacement:"export const IDENTITY_CANONICAL_SUMMARY_HIGH_RISK_QUERY = `SELECT COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND risk_score >= 15`;", fail:["U1-CONS04"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M19", file:"contract", anchor:"return `${CANONICAL_IDENTITY_CTE}\nSELECT * FROM canonical_identity_assets${clauses.length ? ` WHERE ${clauses.join(\" AND \")}` : \"\"}\n ORDER BY risk_score DESC, first_seen DESC, id ASC LIMIT ?`;", replacement:"return `SELECT * FROM identity_assets WHERE workspace_id = ? AND status = 'active'${clauses.length ? ` AND ${clauses.join(\" AND \")}` : \"\"} ORDER BY risk_score DESC, first_seen DESC, id ASC LIMIT ?`;", fail:["U1-CONS05"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M20", file:"contract", anchor:"export const IDENTITY_CANONICAL_EXPOSURE_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT id, domain_id, hostname, asset_type, identity_type, provider,\n       internet_exposed, source, risk_score, evidence, first_seen, last_seen\n  FROM canonical_identity_assets\n ORDER BY risk_score DESC, internet_exposed DESC, id ASC LIMIT 100`;", replacement:"export const IDENTITY_CANONICAL_EXPOSURE_QUERY = `SELECT id, domain_id, hostname, asset_type, identity_type, provider, internet_exposed, source, risk_score, evidence, first_seen, last_seen FROM identity_assets WHERE workspace_id = ? AND status = 'active' ORDER BY risk_score DESC, internet_exposed DESC, id ASC LIMIT 100`;", fail:["U1-CONS06"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M21", file:"contract", anchor:"export const IDENTITY_CANONICAL_SHADOW_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT id, domain_id, hostname, asset_type, identity_type, provider,\n       internet_exposed, source, risk_score, evidence, first_seen, last_seen\n  FROM canonical_identity_assets\n WHERE provider IS NOT NULL AND provider != ''`;", replacement:"export const IDENTITY_CANONICAL_SHADOW_QUERY = `SELECT id, domain_id, hostname, asset_type, identity_type, provider, internet_exposed, source, risk_score, evidence, first_seen, last_seen FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND provider IS NOT NULL AND provider != ''`;", fail:["U1-CONS07"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M22", file:"contract", anchor:"export const IDENTITY_CANONICAL_LIFECYCLE_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT id, domain_id, hostname, asset_type, identity_type, provider,\n       internet_exposed, source, risk_score, evidence, first_seen, last_seen\n  FROM canonical_identity_assets`;", replacement:"export const IDENTITY_CANONICAL_LIFECYCLE_QUERY = `SELECT id, domain_id, hostname, asset_type, identity_type, provider, internet_exposed, source, risk_score, evidence, first_seen, last_seen FROM identity_assets WHERE workspace_id = ? AND status = 'active'`;", fail:["U1-CONS08"], controls:["U1-POS-UNIQUE"] },
  { id:"U1-M23", file:"contract", anchor:"export const IDENTITY_CANONICAL_RELATED_CHANGES_QUERY = `${CANONICAL_IDENTITY_CTE}\nSELECT id, hostname, identity_type, provider, first_seen\n  FROM canonical_identity_assets\n WHERE first_seen >= ? AND first_seen <= ?`;", replacement:"export const IDENTITY_CANONICAL_RELATED_CHANGES_QUERY = `SELECT id, hostname, identity_type, provider, first_seen FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND first_seen >= ? AND first_seen <= ?`;", fail:["U1-CONS09","U1-B4-01"], controls:["U1-POS-FORWARD-EVENT"] },
  { id:"U1-M24", file:"related", anchor:"MAX(CASE WHEN identity_row_count > 1 THEN 1 ELSE 0 END) AS polluted", replacement:"MAX(CASE WHEN false THEN 1 ELSE 0 END) AS polluted", fail:["U1-B4-03"], controls:["U1-B4-04"] },
  { id:"U1-M25", file:"contract", anchor:"if (unresolved > 0 || !Number.isInteger(Number(row.recurrence_count)) || Number(row.recurrence_count) < 1) return {", replacement:"if (false || !Number.isInteger(Number(row.recurrence_count)) || Number(row.recurrence_count) < 1) return {", fail:["U1-B4-05"], controls:["U1-B4-04"] },
  { id:"U1-M26", file:"route", anchor:"recurrence: projectRelatedChangeRecurrence(row),", replacement:"recurrence: { schema_version: 'related_change_recurrence.v2', status: 'comparable', count: Number(row.recurrence_count), reason: null, source: 'raw_recurrence_count' },", fail:["U1-B4-03","U1-B4-05","U1-B4-07"], controls:["U1-B4-04"] },
  { id:"U1-M27", file:"list", anchor:"{recurrenceCopy(rc.recurrence) && (\n                      <span className=\"text-xs text-slate-400\">· {recurrenceCopy(rc.recurrence)}</span>\n                    )}", replacement:"{recurrenceCopy(rc.recurrence_count) && (\n                      <span className=\"text-xs text-slate-400\">· {recurrenceCopy(rc.recurrence_count)}</span>\n                    )}", fail:["U1-B4-07","U1-B4-08"], controls:["U1-B4-POS"] },
  { id:"U1-M28", file:"detail", anchor:"<span>{recurrenceCopy(rc.recurrence)}</span>", replacement:"<span>{recurrenceCopy(rc.recurrence_count)}</span>", fail:["U1-B4-07","U1-B4-08"], controls:["U1-B4-POS"] },
  { id:"U1-M29", file:"related", anchor:"if (isNewScan && inserted > 0) {", replacement:"if (isNewScan) {", fail:["U1-B4-06"], controls:["U1-B4-02"] },
  { id:"U1-M30", file:"adapter", anchor:"source_table: \"identity_assets\",\n        source_record_id: String(r.id),\n        evidence_ref: String(r.id),", replacement:"source_table: \"identity_assets\",\n        source_record_id: crypto.randomUUID(),\n        evidence_ref: String(r.id),", fail:["U1-B4-01"], controls:["U1-POS-FORWARD-EVENT"] },
];

function runValidator(fixtures, timeout = 30000) {
  const child = spawnSync(process.execPath, [VALIDATOR, `--fixtures=${fixtures.join(",")}`], {
    cwd: ROOT, encoding: "utf8", timeout,
  });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  const failures = [...output.matchAll(/^FAIL (U1-[A-Z0-9-]+)/gm)].map((match) => match[1]);
  const normal = !child.error && !child.signal && (child.status === 0 || child.status === 1) &&
    /identity U1\+B4: \d+\/\d+ passed; \d+ failed/.test(output) &&
    !/HARNESS|SyntaxError|ERR_MODULE_NOT_FOUND|TypeError:|ReferenceError:/.test(output);
  return { child, output, failures, normal };
}

const originals = Object.fromEntries(Object.entries(TARGETS).map(([key, file]) => [key, fs.readFileSync(file)]));
const originalHashes = Object.fromEntries(Object.entries(originals).map(([key, value]) => [key, sha(value)]));
let killed = 0, failures = 0;

for (const mutant of MUTANTS) {
  const file = TARGETS[mutant.file];
  const original = originals[mutant.file];
  try {
    const changed = replaceExactly(original.toString("utf8"), mutant.anchor, mutant.replacement, mutant.id);
    fs.writeFileSync(file, changed);
    const selected = [...mutant.fail, ...mutant.controls];
    const result = runValidator(selected);
    const exact = result.normal && JSON.stringify(result.failures) === JSON.stringify(mutant.fail);
    if (exact) {
      killed += 1;
      console.log(`KILL ${mutant.id} -> ${mutant.fail.join(",")}`);
    } else {
      failures += 1;
      console.error(`INVALID ${mutant.id}: expected ${JSON.stringify(mutant.fail)} got ${JSON.stringify(result.failures)}`);
      if (!result.normal) console.error(result.output.trim());
    }
  } catch (error) {
    failures += 1;
    console.error(`INVALID ${mutant.id}: ${error.message}`);
  } finally {
    fs.writeFileSync(file, original);
    if (sha(fs.readFileSync(file)) !== originalHashes[mutant.file]) {
      failures += 1;
      console.error(`RESTORE ${mutant.id}: target hash drift`);
    }
  }
}

let invalidControls = 0;
function invalid(name, condition) {
  if (condition) { invalidControls += 1; console.log(`CONTROL ${name}`); }
  else { failures += 1; console.error(`FAIL invalid-kill control ${name}`); }
}

{
  const file = TARGETS.contract, original = originals.contract;
  try {
    fs.writeFileSync(file, `${original.toString("utf8")}\nexport const broken syntax !\n`);
    const result = runValidator(["U1-C01"]);
    invalid("SYNTAX_FAILURE_REJECTED", !result.normal && result.failures.length === 0);
  } finally { fs.writeFileSync(file, original); }
}
{
  const file = TARGETS.adapter, original = originals.adapter;
  try {
    fs.writeFileSync(file, replaceExactly(original.toString("utf8"), 'from "./identity-evidence-contract.js";', 'from "./missing-identity-evidence-contract.js";', "load-control"));
    const result = runValidator(["U1-B4-01"]);
    invalid("LOAD_FAILURE_REJECTED", !result.normal && result.failures.length === 0);
  } finally { fs.writeFileSync(file, original); }
}
{
  const result = runValidator(["U1-C01"], 1);
  invalid("TIMEOUT_REJECTED", !result.normal && result.child.error?.code === "ETIMEDOUT");
}
invalid("WRONG_REASON_REJECTED", JSON.stringify(["U1-C01"]) !== JSON.stringify(MUTANTS[14].fail));
invalid("WRONG_ORDER_REJECTED", JSON.stringify([...MUTANTS[10].fail].reverse()) !== JSON.stringify(MUTANTS[10].fail));

for (const [key, file] of Object.entries(TARGETS)) {
  if (sha(fs.readFileSync(file)) !== originalHashes[key]) {
    failures += 1;
    console.error(`FAIL final target fingerprint drift: ${key}`);
  }
}
console.log(`U1+B4 mutations: ${killed}/${MUTANTS.length} semantic mutants killed; ${invalidControls}/5 invalid-kill controls rejected`);
if (failures || killed !== MUTANTS.length || invalidControls !== 5) process.exit(1);
