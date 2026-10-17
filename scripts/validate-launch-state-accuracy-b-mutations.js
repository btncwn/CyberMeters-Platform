#!/usr/bin/env node
// Each correction is removed in turn; its named fixture must then fail.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const suite = path.join(root, "scripts/validate-launch-state-accuracy-b.js");
const cases = [
  {
    name: "CM-P1-003 live decision omitted from JSON",
    file: "workers/scan-api/src/engines/email-scan.js",
    from: 'value: dmarcEvidence.dmarc_state,\n    enumerable: true,',
    to: 'value: dmarcEvidence.dmarc_state,\n    enumerable: false,',
    failure: "CM-P1-003 decision survives JSON storage",
  },
  {
    name: "CM-P1-003 projected decision omitted from JSON",
    file: "workers/scan-api/src/engines/email-scan.js",
    from: 'value: compatibilityState,\n    enumerable: true,',
    to: 'value: compatibilityState,\n    enumerable: false,',
    failure: "CM-P1-003 projected decision survives JSON storage",
  },
  {
    name: "CM-P1-003 legacy report credited as healthy",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    from: 'if (!dmarcState && moduleAssessed(report, "email_security", skippedSet)) {',
    to: 'if (false && !dmarcState && moduleAssessed(report, "email_security", skippedSet)) {',
    failure: "CM-P1-003 legacy missing decision is insufficient",
  },
  {
    name: "CM-P1-006 unvalidated candidate scored as threat",
    file: "workers/scan-api/src/engines/scoring.js",
    from: '    if (brandMod?.candidates_validated === false && !openAbuseCase) continue;\n',
    to: "",
    failure: "CM-P1-006 unvalidated candidate is not a scored threat",
  },
  // CM-P1-007: ignoring the enrichment state must break the brand decision.
  {
    name: "CM-P1-007 enrichment rows ignored when deriving the brand decision",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '    const row = rowByCandidate.get(key) || null;',
    to: '    const row = null;',
    failure: "CM-P1-007 live high-risk candidate is a scored finding",
  },
  {
    name: "CM-P1-007 unchecked candidates scored as live",
    file: "workers/scan-api/src/engines/scoring.js",
    from: '    if (!brandCandidateIsLive(c)) continue;\n',
    to: "",
    failure: "CM-P1-007 inactive critical candidate is not a finding",
  },
  {
    name: "CM-P1-007 DNS result ignored by the live test",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '  return triState(candidate.dns_resolves) === 1;',
    to: '  return true;',
    failure: "CM-P1-007 inactive critical candidate is not a finding",
  },
  {
    name: "CM-P1-007 unchecked watchlist declared validated",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '    candidates_validated: checked > 0 || openAbuseCandidates.length > 0,',
    to: '    candidates_validated: true,',
    failure: "CM-P1-007 unchecked watchlist stays unvalidated",
  },
  {
    name: "CM-P1-007 unfinished checks read as a clean watchlist",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    from: '    if (brandValidation && brandPendingChecks > 0) {',
    to: '    if (false && brandValidation && brandPendingChecks > 0) {',
    failure: "CM-P1-007 partially validated watchlist stays provisional",
  },
  {
    name: "CM-P1-007 open confirmed-abuse cases ignored",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '  for (const row of caseRows) {',
    to: '  for (const row of []) {',
    failure: "CM-P1-007 open confirmed-abuse case is a finding",
  },
  {
    name: "CM-P1-007 customer-closed candidate scored",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '  if (BRAND_CLOSED_CLASSIFICATIONS.includes(String(candidate.classification || ""))) return false;',
    to: '',
    failure: "CM-P1-007 customer-closed live candidate is not a finding",
  },
  {
    name: "CM-P1-007 unreadable enrichment state trusted",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '    return deriveBrandValidation(brandModule, { checkedAt, unavailable: true, reason: "enrichment_state_read_failed" });',
    to: '    return deriveBrandValidation(brandModule, { checkedAt });',
    failure: "CM-P1-007 read failure, missing database and missing workspace all fail closed",
  },
  {
    name: "CM-P1-007 case-only entries persisted as generated candidates",
    file: "workers/scan-api/src/engines/asset-persistence.js",
    from: '      if (c?.generated_this_scan === false) continue;\n',
    to: "",
    failure: "CM-P1-007 case-only entries are never re-persisted as generated candidates",
  },
  {
    name: "CM-P1-007 scan no longer merges the enrichment state",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: '    modules.brand_monitoring = await loadBrandValidationState(env, {',
    to: '    modules.brand_monitoring_enriched = await loadBrandValidationState(env, {',
    failure: "CM-P1-007 scan merges enrichment state before scoring and before the report freezes",
  },
  {
    name: "CM-P1-006 unvalidated domain declared healthy",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    from: '    if (brandUnvalidated) {',
    to: '    if (false && brandUnvalidated) {',
    failure: "CM-P1-006 dashboard marks watchlist provisional",
  },
  {
    name: "CM-P1-006 absent validation decision credited as a brand finding",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    from: '    if (brandValidationUnknown) {',
    to: '    if (false && brandValidationUnknown) {',
    failure: "CM-P1-006 missing candidate validation is insufficient",
  },
  {
    name: "CM-P1-006 stored report presents candidate as threat",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: 'if (!report || report?.modules?.brand_monitoring?.candidates_validated === true) return report;',
    to: 'if (true || report?.modules?.brand_monitoring?.candidates_validated === true) return report;',
    failure: "CM-P1-006 raw report candidate presented as observation",
  },
  {
    name: "CM-P1-006 stored snapshot retains candidate action",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: 'if (candidateValidation === true) return snapshot;',
    to: 'if (true || candidateValidation === true) return snapshot;',
    failure: "CM-P1-006 frozen snapshot candidate demoted without changing raw bytes",
  },
  {
    name: "CM-P1-006 repaired snapshot preserves a scored guess",
    file: "workers/scan-api/src/engines/report-snapshot.js",
    from: 'const brandScoreUnreliable = hasUnvalidatedBrandFinding(report);',
    to: 'const brandScoreUnreliable = false;',
    failure: "CM-P1-006 new snapshot withholds old candidate score",
  },
  {
    name: "CM-P1-006 old snapshot score survives the customer projection",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '...((!sourceReport || (sourceUnavailable && converted.length > 0) || hasUnvalidatedBrandFinding(sourceReport)) ? {',
    to: '...(false ? {',
    failure: "CM-P1-006 frozen snapshot candidate demoted without changing raw bytes",
  },
  {
    name: "CM-P1-006 missing report leaves a frozen candidate threat visible",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '  const candidateValidation = sourceReport?.modules?.brand_monitoring?.candidates_validated;',
    to: '  const candidateValidation = sourceReport ? sourceReport?.modules?.brand_monitoring?.candidates_validated : true;',
    failure: "CM-P1-006 unavailable source cannot publish old candidate threat",
  },
  {
    name: "CM-P1-006 incomplete source trusted as validated",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '  const sourceUnavailable = candidateValidation !== true && candidateValidation !== false;',
    to: '  const sourceUnavailable = false;',
    failure: "CM-P1-006 incomplete source cannot publish old candidate threat",
  },
  {
    name: "CM-P1-006 historical scan row retains candidate score",
    file: "workers/scan-api/src/engines/phase5-evidence.js",
    from: '      brand_score_unreliable: hasUnvalidatedBrandFinding(report),',
    to: '      brand_score_unreliable: false,',
    failure: "CM-P1-006 historical candidate score withheld across scan rows",
  },
  {
    name: "CM-P1-006 missing validation decision trusted for scan score",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '  return report?.modules?.brand_monitoring?.candidates_validated !== true &&',
    to: '  return report?.modules?.brand_monitoring?.candidates_validated === false &&',
    failure: "CM-P1-006 historical row without validation withholds score",
  },
  {
    name: "Shadow IT CNAME inputs excluded from absence gate",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '  return headersOk && techOk && cnameSourcesOk;',
    to: '  return headersOk && techOk;',
    failure: "Shadow IT subdomain_takeover absent preserves CNAME supplier",
  },
  {
    name: "Shadow IT partial DNS lookup credited as complete",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '          !(source.not_asked > 0 || source.lookup_failed > 0)) &&',
    to: '          true) &&',
    failure: "Shadow IT dns_bruteforce partial coverage preserves CNAME supplier",
  },
  {
    name: "Shadow IT capped exposure credited as complete",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '          !(source.probe_coverage?.cap_reached === true || source.probe_coverage?.dropped_count > 0));',
    to: '          true);',
    failure: "Shadow IT asset_exposure partial coverage preserves CNAME supplier",
  },
  {
    name: "Shadow IT takeover CNAME observations ignored",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '    for (const observation of (modules?.subdomain_takeover?.cname_observations || [])) {\n      if (observation?.cname) cnames.push(observation.cname.toLowerCase());\n    }\n',
    to: '',
    failure: "Shadow IT takeover CNAME observation preserves supplier detection",
  },
  {
    name: "Shadow IT discovered CNAME chain ignored",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '      for (const hop of (item?.dns?.cname_chain || [])) {\n        if (hop?.target) cnames.push(hop.target.toLowerCase());\n      }\n',
    to: '',
    failure: "Shadow IT discovered DNS CNAME chain preserves supplier detection",
  },
];

function run() {
  try {
    return { passed: true, output: execFileSync(process.execPath, [suite], {
      cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    }) };
  } catch (error) {
    return { passed: false, output: String(error.stdout ?? "") + String(error.stderr ?? "") };
  }
}
const baseline = run();
if (!baseline.passed) {
  console.error("Baseline fixture failed:\n" + baseline.output);
  process.exit(1);
}
let killed = 0;
for (const mutant of cases) {
  const filename = path.join(root, mutant.file);
  const original = fs.readFileSync(filename, "utf8");
  const matches = original.split(mutant.from).length - 1;
  if (matches !== 1) {
    console.error(`ANCHOR FAILURE ${mutant.name}: ${matches} matches`);
    continue;
  }
  let result;
  try {
    fs.writeFileSync(filename, original.replace(mutant.from, mutant.to));
    result = run();
  } finally {
    fs.writeFileSync(filename, original);
  }
  const namedFailure = result.output.split("\n").some((line) => line.startsWith(`FAIL ${mutant.failure}`));
  const complete = /Launch state accuracy fixtures: \d+\/\d+ passed/.test(result.output);
  const success = !result.passed && namedFailure && complete && fs.readFileSync(filename, "utf8") === original;
  console.log(`${success ? "KILLED" : "SURVIVED"} ${mutant.name}`);
  if (!success) console.error(result.output.slice(-1200));
  if (success) killed++;
}
console.log(`Launch state accuracy mutations: ${killed}/${cases.length} killed`);
if (killed !== cases.length) process.exit(1);
