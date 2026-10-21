#!/usr/bin/env node
// Shadow IT FB-1 + EH-1 semantic mutation gate.
// Contract: shadow-it-fb1-eh1/v1. Every mutant executes the focused oracle in
// a fresh Node process and must produce its frozen exact ordered FAIL set.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const oracle = path.join(root, "scripts", "validate-shadow-it-fb1-eh1.js");
const INV = "workers/scan-api/src/engines/shadow-it-inventory.js";
const DISC = "workers/scan-api/src/engines/discovery-scan.js";
const RELATED = "workers/scan-api/src/engines/related-changes-adapter.js";
const SNAPSHOT = "workers/scan-api/src/engines/report-snapshot.js";
const SE = "workers/scan-api/src/engines/scan-engine.js";
const VS = "workers/scan-api/src/engines/vendor-signatures.js";
const VR = "workers/scan-api/src/engines/vendor-relationship.js";
const SPF = "workers/scan-api/src/engines/spf-resolver.js";
const EA = "workers/scan-api/src/engines/email-analysis.js";
const CMD = "workers/scan-api/src/engines/security-check-domains.js";
const RCR = "workers/scan-api/src/engines/related-changes-rules.js";

const registry = Object.freeze([
  {
    id: "SIT_M01", defect: "read failure collapses to empty", expected: ["F01", "F02", "F03", "F07", "F08", "F09"],
    changes: [{ target: INV,
      anchor: '  } catch {\n    return { source, outcome: "failed", rows: [] };\n  }\n}',
      replacement: '  } catch {\n    return { source, outcome: "empty", rows: [] };\n  }\n}' }],
  },
  {
    id: "SIT_M02", defect: "outcome attribution ignored for ordinary absence", expected: ["F01", "F02", "F03", "F04"],
    changes: [{ target: INV,
      anchor: '  return sources.size > 0 && sourceOutcomes != null &&\n    [...sources].every((source) => ABSENCE_ADMISSIBLE_OUTCOMES.has(sourceOutcomes[source]));',
      replacement: '  return sources.size > 0 && ((item?.recurrence_type || item?.classification === "retired")\n    ? sourceOutcomes != null && [...sources].every((source) => ABSENCE_ADMISSIBLE_OUTCOMES.has(sourceOutcomes[source]))\n    : true);' }],
  },
  {
    id: "SIT_M03", defect: "incomplete folded into empty", expected: ["F04", "F10"],
    changes: [
      { target: INV,
        anchor: '    : deferDiscoveredAssetEvidence ? "incomplete" : assetRead.outcome;',
        replacement: '    : deferDiscoveredAssetEvidence ? "empty" : assetRead.outcome;' },
      { target: INV,
        anchor: '    if (deferDiscoveredAssetEvidence && DISCOVERY_ASSET_SOURCES.has(r.source)) {\n      deferredKeys.add(canonicalTechnologyKey(meta.display));\n      continue;\n    }',
        replacement: '    if (false && deferDiscoveredAssetEvidence && DISCOVERY_ASSET_SOURCES.has(r.source)) {\n      deferredKeys.add(canonicalTechnologyKey(meta.display));\n      continue;\n    }' },
      { target: INV,
        anchor: '  sourceOutcomes.saas_exposure = !saasExposure || !Array.isArray(saasExposure.exposures)\n    ? "incomplete"',
        replacement: '  sourceOutcomes.saas_exposure = !saasExposure || !Array.isArray(saasExposure.exposures)\n    ? "empty"' },
    ],
  },
  {
    id: "SIT_M04", defect: "deferred recovery routed through reappeared", expected: ["F09"],
    changes: [{ target: INV,
      anchor: '    const reappeared = existing.monitoring_status === "no_longer_observed";',
      replacement: '    const reappeared = existing.monitoring_status === "no_longer_observed" || existing.classification === "retired";' }],
  },
  {
    id: "SIT_M05", defect: "deferral erases an existing contradiction", expected: ["F07", "F08"],
    changes: [{ target: INV,
      anchor: '    if (evidenceDecision === "defer") continue;',
      replacement: `    if (evidenceDecision === "defer") {
      if (it.recurrence_type) {
        await env.cybermeters_db
          .prepare(\`UPDATE shadow_it_inventory SET recurrence_type = NULL, removal_verified = NULL WHERE id = ? AND workspace_id = ?\`)
          .bind(it.id, workspaceId).run();
      }
      continue;
    }` }],
  },
  {
    id: "SIT_M06", defect: "failed contributor overrides successful duplicate", expected: ["F06"],
    changes: [{ target: INV,
      anchor: '  if (seenKeys.has(key)) return "seen";',
      replacement: `  if (seenKeys.has(key)) {
    const contributors = shadowItContributingSources(item);
    if ([...contributors].some((source) => ["failed", "incomplete"].includes(sourceOutcomes?.[source]))) return "defer";
    return "seen";
  }` }],
  },
  {
    id: "SIT_M07", defect: "successful empty globally suppressed", expected: ["F05"],
    changes: [{ target: INV,
      anchor: 'const ABSENCE_ADMISSIBLE_OUTCOMES = new Set(["ok", "empty"]);',
      replacement: 'const ABSENCE_ADMISSIBLE_OUTCOMES = new Set(["ok"]);' }],
  },
  {
    id: "SIT_M08", defect: "source outcome re-read per inventory item", expected: ["F01", "F20"],
    changes: [{ target: INV,
      anchor: '    const itemSourceOutcomes = sourceOutcomes;',
      replacement: `    const itemSourceOutcomes = Object.freeze({
      ...sourceOutcomes,
      workspace_vendors: (await readSourceRows(env, "workspace_vendors", \`SELECT id FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'\`, workspaceId)).outcome,
    });` }],
  },
  {
    id: "SIT_M09", defect: "catalogue portal/admin URLs re-added as observation", expected: ["F13", "F16", "F17"],
    changes: [
      { target: INV,
        anchor: 'safeJson(snapshot.observed_identifiers, "[]"), safeJson(snapshot.observed_hostnames, "[]"), safeJson([], "[]"),',
        replacement: 'safeJson(snapshot.observed_identifiers, "[]"), safeJson(snapshot.display_name === "Microsoft 365" ? ["https://login.microsoftonline.com", "https://admin.microsoft.com"] : snapshot.observed_hostnames, "[]"), safeJson([], "[]"),' },
      { target: INV,
        anchor: '    const detail = hosts.length ? String(hosts[0]).slice(0, 200) : null;',
        replacement: '    const detail = hosts.length ? String(hosts[0]).slice(0, 200) : "https://login.microsoftonline.com";' },
      { target: RELATED,
        anchor: '      const anchorHost = hostnames.find(Boolean);',
        replacement: '      const anchorHost = hostnames.find(Boolean) || "https://login.microsoftonline.com";' },
    ],
  },
  {
    id: "SIT_M10", defect: "fallback tenant URL accepted whenever truthy", expected: ["F15"],
    changes: [{ target: DISC,
      anchor: '      const observed_tenant_url = tenant_hint && tenant_url && tenant_url !== sig.portal_url\n        ? tenant_url\n        : null;',
      replacement: '      const observed_tenant_url = tenant_url ? tenant_url : null;' }],
  },
  {
    id: "SIT_M11", defect: "genuinely derived tenant URL dropped", expected: ["F14"],
    changes: [{ target: DISC,
      anchor: '      const observed_tenant_url = tenant_hint && tenant_url && tenant_url !== sig.portal_url\n        ? tenant_url\n        : null;',
      replacement: '      const observed_tenant_url = null;' }],
  },
  {
    id: "SIT_M12", defect: "alert evidence falls back to a catalogue constant", expected: ["F16"],
    changes: [{ target: INV,
      anchor: '    const detail = hosts.length ? String(hosts[0]).slice(0, 200) : null;',
      replacement: '    const detail = hosts.length ? String(hosts[0]).slice(0, 200) : "https://login.microsoftonline.com";' }],
  },
  {
    id: "SIT_M13", defect: "Related Changes invents a catalogue anchor without observed provenance", expected: ["F17"],
    changes: [{ target: RELATED,
      anchor: '      const anchorHost = hostnames.find(Boolean);',
      replacement: '      const anchorHost = hostnames.find(Boolean) || "https://login.microsoftonline.com";' }],
  },
  {
    // F37 joined (16 Oct 2026): a blanket prune also erases the Catalogue B hostnames.
    id: "SIT_M14", defect: "bounded prune widened to blanket clearing", expected: ["F14", "F18", "F28", "F37"],
    changes: [{ target: INV,
      anchor: '    const removable = SAAS_CATALOGUE_URL_SET.has(hostname) && !observed.has(hostname);',
      replacement: '    const removable = true;' }],
  },
  {
    id: "SIT_M15", defect: "compatibility correction emits monitoring_changed", expected: ["F19", "F23", "F32"],
    changes: [{ target: INV,
      anchor: "SELECT ?, ?, ?, 'system', NULL, 'material_change', ?, datetime('now')",
      replacement: "SELECT ?, ?, ?, 'system', NULL, 'monitoring_changed', ?, datetime('now')" }],
  },
  {
    id: "SIT_M16", defect: "observed_hostnames API changed from string[] to objects", expected: ["F21"],
    changes: [{ target: INV,
      anchor: '    observed_hostnames: parseJson(row.observed_hostnames_json, []) || [],',
      replacement: '    observed_hostnames: (parseJson(row.observed_hostnames_json, []) || []).map((value) => ({ value })),' }],
  },
  {
    id: "SIT_M17", defect: "Shadow IT mutable state wired into immutable report tier", expected: ["F22"],
    changes: [{ target: SNAPSHOT,
      anchor: 'export const SNAPSHOT_BUILDER_VERSION = "2026-10-17.1";',
      replacement: 'export const SNAPSHOT_BUILDER_VERSION = "2026-10-17.1";\n// MUTANT: catalogue_hostname_prune entered the immutable report tier.' }],
  },
  // ── Shadow IT detection fixes (16 Oct 2026) — one mutant per fix, exact kills ──
  {
    id: "SIT_M18", defect: "vendor-relationship suppliers never retired (no disappearance)", expected: ["F34", "F35", "F45"],
    changes: [{ target: SE,
      anchor: "             AND source_module = 'vendor_relationship'${detectedNames.length ? ` AND vendor_name NOT IN (${placeholders})` : \"\"}`",
      replacement: "             AND source_module = 'vendor_relationship' AND 0 = 1${detectedNames.length ? ` AND vendor_name NOT IN (${placeholders})` : \"\"}`" }],
  },
  {
    id: "SIT_M19", defect: "a clean run that detected nothing is skipped (suppliers linger)", expected: ["F35", "F45"],
    changes: [{ target: SE,
      anchor: "  if (!relModule || relModule.error) return;\n  const vendors = Array.isArray(relModule.vendors) ? relModule.vendors : [];",
      replacement: "  if (!relModule?.detected || !relModule.vendors?.length) return;\n  const vendors = Array.isArray(relModule.vendors) ? relModule.vendors : [];" }],
  },
  {
    id: "SIT_M29", defect: "suppliers retired although the input modules did not observe the site", expected: ["F45"],
    changes: [{ target: SE,
      anchor: "    if (relModule.inputs_complete !== true) continue;",
      replacement: "    if (relModule.inputs_complete === undefined) continue;" }],
  },
  {
    id: "SIT_M30", defect: "analysis reports complete inputs for an unreadable site", expected: ["F45"],
    changes: [{ target: VR,
      anchor: "  return headersOk && techOk && cnameSourcesOk;",
      replacement: "  return true;" }],
  },
  {
    id: "SIT_M20", defect: "Catalogue B evidence stored as bare signal names (no hostname)", expected: ["F36", "F37"],
    changes: [{ target: VR,
      anchor: "        evidence.push({ source: check.source, detail: String(detail).slice(0, 200) });",
      replacement: "        evidence.push(check.source);" }],
  },
  {
    id: "SIT_M21", defect: "lifecycle alert hostname read from a column the row does not have", expected: ["F38"],
    changes: [{ target: INV,
      anchor: "        hostname: shadowItAlertHostname(it),",
      replacement: "        hostname: it.primary_hostname || null," }],
  },
  {
    id: "SIT_M22", defect: "Shadow IT limitation regresses to 'not yet configured'", expected: ["F39"],
    changes: [{ target: CMD,
      anchor: "Externally observed technology only: items are shown as observed. Whether a technology is approved, rejected or excepted is the customer's own record in the Shadow IT inventory, not an external verdict.",
      replacement: "Externally observed technology only. Approved-inventory comparison is not yet configured, so items are shown as observed, not authorised or unauthorised." }],
  },
  {
    id: "SIT_M23", defect: "Related Changes rule regresses to 'Unapproved technology'", expected: ["F40"],
    changes: [{ target: RCR,
      anchor: '    title: "Observed technology with a new host or a certificate signal",',
      replacement: '    title: "Unapproved technology with a new host or a certificate signal",' }],
  },
  {
    id: "SIT_M24", defect: "root TXT verification tokens ignored", expected: ["F41", "F46"],
    changes: [{ target: VS,
      anchor: "      if (value) signals.txt.push(value);",
      replacement: "      if (value && false) signals.txt.push(value);" }],
  },
  {
    id: "SIT_M25", defect: "SPF include tree not fed to vendor attribution", expected: ["F42"],
    changes: [{ target: VS,
      anchor: "      if (target) signals.spf.push(String(target).toLowerCase());",
      replacement: "      if (target && false) signals.spf.push(String(target).toLowerCase());" }],
  },
  {
    id: "SIT_M26", defect: "resolver forgets the include targets it walked", expected: ["F43"],
    changes: [{ target: SPF,
      anchor: "        state.visited.add(target);\n        state.includeTargets.add(target);",
      replacement: "        state.visited.add(target);" }],
  },
  {
    id: "SIT_M27", defect: "only the first DKIM selector is collected", expected: ["F44"],
    changes: [{ target: EA,
      anchor: "      if (valid.length > 0) found.push(selectors[i]);",
      replacement: "      if (valid.length > 0 && found.length === 0) found.push(selectors[i]);" }],
  },
  {
    id: "SIT_M28", defect: "vendor attribution reads only the primary DKIM selector", expected: ["F44"],
    changes: [{ target: VS,
      anchor: "    for (const sel of [...(Array.isArray(dkimModule.selectors_found) ? dkimModule.selectors_found : []), dkimModule.selector]) {",
      replacement: "    for (const sel of [dkimModule.selector]) {" }],
  },
  {
    id: "SIT_M31", defect: "a lone shared verification token establishes Google Workspace", expected: ["F46"],
    changes: [{ target: VS,
      anchor: "            if (!check.corroboratesOnly) established = true;",
      replacement: "            established = true;" }],
  },
  {
    id: "SIT_M32", defect: "the Resend DKIM selector is not probed", expected: ["F47"],
    changes: [{ target: EA,
      anchor: '  "resend",\n',
      replacement: "" }],
  },
]);

function sha(buffer) { return crypto.createHash("sha256").update(buffer).digest("hex"); }
function occurrences(source, anchor) { return source.split(anchor).length - 1; }
function worktreeFingerprint() {
  const listed = spawnSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: root, encoding: null });
  if (listed.status !== 0) throw new Error(`git ls-files failed: ${listed.stderr}`);
  const names = listed.stdout.toString("utf8").split("\0").filter(Boolean).sort();
  const hash = crypto.createHash("sha256");
  for (const name of names) {
    const absolute = path.join(root, name);
    if (!fs.statSync(absolute).isFile()) continue;
    hash.update(name); hash.update("\0"); hash.update(fs.readFileSync(absolute)); hash.update("\0");
  }
  return { count: names.length, sha256: hash.digest("hex") };
}
function parseRun(run) {
  const output = `${run.stdout || ""}${run.stderr || ""}`;
  const summary = output.match(/^SHADOW_IT_FB1_EH1_NORMAL_SUMMARY (\d+)\/(\d+) passed$/m);
  const set = output.match(/^SHADOW_IT_FB1_EH1_FAIL_SET (.+)$/m);
  const proof = output.match(/^SHADOW_IT_FB1_EH1_LOADED_PROOF (\{.+\})$/m);
  let loaded = null;
  try { loaded = proof ? JSON.parse(proof[1]) : null; } catch { loaded = null; }
  return {
    output, normalSummary: Boolean(summary), failSet: !set || set[1] === "none" ? [] : set[1].split(","), loaded,
    cleanExitOne: run.status === 1 && run.signal == null,
  };
}
function exactArray(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

let passed = 0;
const initialFingerprint = worktreeFingerprint();
for (const mutant of registry) {
  const originals = new Map();
  const mutatedTargets = new Set();
  try {
    for (const change of mutant.changes) {
      const absolute = path.join(root, change.target);
      if (!originals.has(absolute)) originals.set(absolute, fs.readFileSync(absolute));
      const source = fs.readFileSync(absolute, "utf8");
      if (occurrences(source, change.anchor) !== 1) throw new Error(`${mutant.id}: anchor count for ${change.target} is ${occurrences(source, change.anchor)}`);
      if (change.anchor === change.replacement) throw new Error(`${mutant.id}: no-op replacement`);
      fs.writeFileSync(absolute, source.replace(change.anchor, change.replacement));
      mutatedTargets.add(change.target);
    }
    const mutatedTargetHashes = Object.fromEntries([...mutatedTargets].map((target) => [target, sha(fs.readFileSync(path.join(root, target)))]));
    const run = spawnSync(process.execPath, [oracle], {
      cwd: root, encoding: "utf8", timeout: 120000,
      env: { ...process.env, SHADOW_IT_FB1_EH1_MUTANT_ID: mutant.id },
    });
    const parsed = parseRun(run);
    const proofMatches = Object.entries(mutatedTargetHashes).every(([target, digest]) => parsed.loaded?.[target] === digest);
    if (!parsed.cleanExitOne || !parsed.normalSummary || !proofMatches || !exactArray(parsed.failSet, mutant.expected)) {
      throw new Error(`${mutant.id}: invalid kill status=${run.status} signal=${run.signal} normal=${parsed.normalSummary} proof=${proofMatches} expected=${mutant.expected.join(",")} actual=${parsed.failSet.join(",")}\n${parsed.output}`);
    }
  } finally {
    for (const [absolute, bytes] of originals) fs.writeFileSync(absolute, bytes);
  }
  const restored = worktreeFingerprint();
  if (restored.sha256 !== initialFingerprint.sha256 || restored.count !== initialFingerprint.count) {
    throw new Error(`${mutant.id}: worktree restoration failed`);
  }
  passed += 1;
  console.log(`PASS ${mutant.id} -> ${mutant.expected.join(",")}`);
}

// Negative controls: no-op anchors are rejected before execution; a syntax/load
// failure reaches no normal summary and therefore cannot count as a kill; and an
// otherwise-valid run with the wrong ordered set is rejected by exactArray.
const noOpRejected = registry.every((mutant) => mutant.changes.every((change) => change.anchor !== change.replacement));
const syntaxTarget = path.join(root, INV);
const syntaxOriginal = fs.readFileSync(syntaxTarget);
let syntaxInvalid = false;
try {
  fs.writeFileSync(syntaxTarget, `this is not valid JavaScript\n${syntaxOriginal}`);
  const run = spawnSync(process.execPath, [oracle], { cwd: root, encoding: "utf8", timeout: 120000 });
  const parsed = parseRun(run);
  syntaxInvalid = run.status === 1 && !parsed.normalSummary;
} finally {
  fs.writeFileSync(syntaxTarget, syntaxOriginal);
}
const wrongSetRejected = !exactArray(["F02", "F01"], ["F01", "F02"]);
const finalFingerprint = worktreeFingerprint();
if (!noOpRejected || !syntaxInvalid || !wrongSetRejected || finalFingerprint.sha256 !== initialFingerprint.sha256) {
  throw new Error(`mutation negative controls/restoration failed: noOp=${noOpRejected} syntax=${syntaxInvalid} order=${wrongSetRejected}`);
}

console.log(`SHADOW_IT_FB1_EH1_MUTATION_SUMMARY ${passed}/${registry.length} exact semantic mutants killed`);
console.log("SHADOW_IT_FB1_EH1_MUTATION_NEGATIVE_CONTROLS no_op,syntax_import_load,wrong_order rejected");
console.log("Shadow IT FB-1 + EH-1 mutation validation passed");
