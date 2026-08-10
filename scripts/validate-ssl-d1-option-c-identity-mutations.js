#!/usr/bin/env node
// Semantic mutation proof for SSL D1 Option C. Every mutant is registry-derived,
// uses one exact anchor/replacement in a fresh sandbox, proves the loaded module
// bytes, and must produce its exact expected focused-contract failure set.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  analyseOrderedRegistry,
  createMutationSandbox,
  installMutationSignalCleanup,
  preflightMutationTargets,
  replaceExactly,
} from "./item10-p5-mutation-harness.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(ROOT, "scripts", "validate-ssl-d1-option-c-identity.js");
const MODULE_RELATIVE = path.join("workers", "scan-api", "src", "engines", "finding-identity.js");
const SOURCE_PATH = path.join(ROOT, MODULE_RELATIVE);
const EXPECTED_ASSERTIONS = 65;

installMutationSignalCleanup();

const MUTANTS = Object.freeze([
  {
    id: "remove-forward-identity-persistence",
    from: `      finding.id,\n      finding.severity,`,
    to: `      null,\n      finding.severity,`,
    expectedFailures: ["forward.identity.persisted", "forward.controlled_batch_failure_observed"],
  },
  {
    id: "broaden-legacy-classification",
    from: `    AND json_extract(\${safe}, '$.observed_value') = \${sqlLiteral(LEGACY_TLS_OBSERVED)}`,
    to: `    AND json_type(\${safe}, '$.observed_value') = 'text'`,
    expectedFailures: [
      "legacy.sql_reused_visible",
      "remediation.near_miss_kept",
    ],
  },
  {
    id: "match-by-customer-title",
    from: "  return `(NOT COALESCE(${legacy}, 0))`;",
    to: "  return `(NOT (COALESCE(${legacy}, 0) OR (${f}.finding_slug IS NULL AND ${f}.title = 'SSL/TLS Not Available')))`;",
    expectedFailures: [
      "legacy.sql_ambiguous_visible",
      "legacy.sql_reused_visible",
      "legacy.sql_title_visible",
      "legacy.sql_duplicate_visible",
      "legacy.sql_invalid_date_visible",
      "parity.parity_invalid_leap",
      "parity.parity_invalid_apr31",
      "parity.parity_hour_24",
      "parity.parity_leap_second",
      "parity.parity_offset",
      "parity.parity_no_millis",
      "parity.parity_lowercase",
      "parity.ambiguous_src_key_visible",
      "parity.ambiguous_missing_checked_at_visible",
    ],
  },
  {
    id: "suppress-ambiguous-evidence",
    from: `    AND (SELECT COUNT(*) FROM json_each(\${safe})) = \${LEGACY_TLS_EVIDENCE_KEYS.length}`,
    to: `    AND (SELECT COUNT(*) FROM json_each(\${safe})) >= \${LEGACY_TLS_EVIDENCE_KEYS.length}`,
    expectedFailures: ["legacy.sql_ambiguous_visible", "legacy.sql_duplicate_visible"],
  },
  {
    id: "downgrade-mixed-domain-state",
    from: `      || Number(row.finding_count) !== 1
      || !LEGACY_TLS_DOMAIN_RESOLVER_SET.has(row.resolver_version)) return row;
  let ids;
  try { ids = JSON.parse(row.finding_ids_json); } catch { return row; }
  if (!Array.isArray(ids) || ids.length !== 1 || ids[0] !== LEGACY_UNPROVEN_TLS_SLUG) return row;`,
    to: `      || !LEGACY_TLS_DOMAIN_RESOLVER_SET.has(row.resolver_version)) return row;
  let ids;
  try { ids = JSON.parse(row.finding_ids_json); } catch { return row; }
  if (!Array.isArray(ids) || !ids.includes(LEGACY_UNPROVEN_TLS_SLUG)) return row;`,
    expectedFailures: ["domain.mixed_visible"],
  },
  {
    id: "rewrite-historical-rows",
    from: "  const scopedScan = await env.cybermeters_db.prepare(\n",
    to: "  await env.cybermeters_db.prepare(\"UPDATE findings SET finding_slug = 'ssl_not_available' WHERE finding_slug IS NULL\").run();\n  const scopedScan = await env.cybermeters_db.prepare(\n",
    expectedFailures: ["forward.historical_unchanged"],
  },
  {
    id: "bypass-resolver-version",
    from: "      || !LEGACY_TLS_DOMAIN_RESOLVER_SET.has(row.resolver_version)) return row;",
    to: "      ) return row;",
    expectedFailures: ["domain.resolver_bounded"],
  },
  {
    id: "cross-workspace-boundary",
    from: "     WHERE s.id = ? AND s.workspace_id = ? AND w.deleted_at IS NULL",
    to: "     WHERE s.id = ? AND ? IS NOT NULL AND w.deleted_at IS NULL",
    expectedFailures: ["forward.tenant_isolation"],
  },
  {
    id: "weaken-soft-delete-protection",
    from: "     WHERE s.id = ? AND s.workspace_id = ? AND w.deleted_at IS NULL",
    to: "     WHERE s.id = ? AND s.workspace_id = ? AND (w.deleted_at IS NULL OR w.deleted_at IS NOT NULL)",
    expectedFailures: ["forward.soft_delete"],
  },
  // ── IC-17 corrective mutants: each reopens one reproduced defect class ──
  {
    id: "accept-noncanonical-sql-timestamp",
    from: "    AND strftime('%Y-%m-%dT%H:%M:%fZ', json_extract(${safe}, '$.checked_at'), '+0 seconds') = json_extract(${safe}, '$.checked_at')",
    to: "    AND strftime('%Y-%m-%dT%H:%M:%fZ', json_extract(${safe}, '$.checked_at')) = json_extract(${safe}, '$.checked_at')",
    expectedFailures: [
      "parity.parity_hour_24",
    ],
  },
  {
    id: "hide-null-ambiguous-evidence",
    from: "  return `(NOT COALESCE(${legacy}, 0))`;",
    to: "  return `(NOT ${legacy})`;",
    expectedFailures: [
      "parity.parity_leap_second",
      "parity.parity_lowercase",
      "parity.ambiguous_src_key_visible",
      "parity.ambiguous_missing_checked_at_visible",
    ],
  },
  {
    id: "suppress-remediation-on-title-alone",
    from: `    AND EXISTS (
      SELECT 1 FROM findings lf JOIN scans ls ON ls.id = lf.scan_id
      WHERE lf.scan_id = \${r}.scan_id AND NOT \${visibleFindingSql("lf", "ls")}
    )`,
    to: "    AND 1 = 1",
    expectedFailures: [
      "remediation.near_miss_kept",
    ],
  },
  {
    id: "ignore-slugged-replacement",
    from: `    AND NOT EXISTS (
      SELECT 1 FROM findings sf
      WHERE sf.scan_id = \${r}.scan_id AND sf.finding_slug = \${sqlLiteral(LEGACY_UNPROVEN_TLS_SLUG)}
    )`,
    to: "    AND 1 = 1",
    expectedFailures: [
      "remediation.slugged_replacement_kept",
    ],
  },
]);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) {
    pass += 1;
    console.log(`PASS ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const ids = MUTANTS.map((mutant) => mutant.id);
const registry = analyseOrderedRegistry({
  registeredIds: ids,
  expectedIds: [
    "remove-forward-identity-persistence",
    "broaden-legacy-classification",
    "match-by-customer-title",
    "suppress-ambiguous-evidence",
    "downgrade-mixed-domain-state",
    "rewrite-historical-rows",
    "bypass-resolver-version",
    "cross-workspace-boundary",
    "weaken-soft-delete-protection",
    "accept-noncanonical-sql-timestamp",
    "hide-null-ambiguous-evidence",
    "suppress-remediation-on-title-alone",
    "ignore-slugged-replacement",
  ],
  expectedCount: 13,
  expectedFailureIds: ids,
});
ok("registry is exact, ordered, unique and complete", registry.valid, JSON.stringify(registry));

const pristine = fs.readFileSync(SOURCE_PATH, "utf8");
const pristineDigest = crypto.createHash("sha256").update(pristine).digest("hex");

for (const mutant of MUTANTS) {
  let sandbox;
  try {
    const mutated = replaceExactly(pristine, mutant.from, mutant.to, mutant.id);
    sandbox = createMutationSandbox(ROOT, `ssl-d1-${mutant.id}-`);
    const mutantPath = path.join(sandbox.tempRoot, MODULE_RELATIVE);
    fs.writeFileSync(mutantPath, mutated);
    const mutantUrl = pathToFileURL(mutantPath).href;
    const mutantDigest = crypto.createHash("sha256").update(mutated).digest("hex");

    const preflight = preflightMutationTargets({ moduleUrls: [mutantUrl], sourceFiles: [mutantPath] });
    ok(`${mutant.id}: mutated module preflight`, preflight.ok, JSON.stringify(preflight.failures));
    if (!preflight.ok) continue;

    const child = spawnSync(process.execPath, [VALIDATOR], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, SSL_D1_IDENTITY_MODULE_URL: mutantUrl },
    });
    const output = `${child.stdout || ""}${child.stderr || ""}`;
    const summaries = [...output.matchAll(/^SSL_D1_IDENTITY_RESULT=(.+)$/gm)].map((match) => {
      try { return JSON.parse(match[1]); } catch { return null; }
    }).filter(Boolean);
    const loadedUrls = [...output.matchAll(/^LOADED_MODULE_URL=(.+)$/gm)].map((match) => match[1]);
    const loadedDigests = [...output.matchAll(/^LOADED_MODULE_SHA256=([a-f0-9]{64})$/gm)].map((match) => match[1]);
    const summary = summaries.length === 1 ? summaries[0] : null;
    const fatal = /SyntaxError|ReferenceError|TypeError|ERR_[A-Z0-9_]+|UnhandledPromiseRejection/.test(output);
    const semantic = child.error == null
      && child.status === 1
      && child.signal == null
      && !fatal
      && summaries.length === 1
      && summary?.total === EXPECTED_ASSERTIONS
      && Array.isArray(summary?.passed)
      && Array.isArray(summary?.failed)
      && summary.passed.length + summary.failed.length === EXPECTED_ASSERTIONS;
    ok(`${mutant.id}: semantic child completed`, semantic,
      `status=${child.status} signal=${child.signal} error=${child.error?.message || "none"}\n${output.slice(0, 1800)}`);
    ok(`${mutant.id}: exact loaded-module proof`,
      loadedUrls.length === 1 && loadedUrls[0] === mutantUrl
        && loadedDigests.length === 1 && loadedDigests[0] === mutantDigest,
      `urls=${JSON.stringify(loadedUrls)} digests=${JSON.stringify(loadedDigests)} expected=${mutantDigest}`);
    ok(`${mutant.id}: exact expected failure set`,
      JSON.stringify(summary?.failed) === JSON.stringify(mutant.expectedFailures),
      `got=${JSON.stringify(summary?.failed)} want=${JSON.stringify(mutant.expectedFailures)}`);
  } catch (error) {
    ok(`${mutant.id}: harness execution`, false, error.stack || error.message);
  } finally {
    sandbox?.cleanup();
  }
}

const afterDigest = crypto.createHash("sha256").update(fs.readFileSync(SOURCE_PATH)).digest("hex");
ok("mutation sandboxes leave candidate source untouched", afterDigest === pristineDigest,
  `before=${pristineDigest} after=${afterDigest}`);

console.log(`\nSSL D1 Option C mutations: ${pass}/${pass + fail} passed; ${MUTANTS.length} semantic mutants killed`);
if (fail) process.exit(1);
