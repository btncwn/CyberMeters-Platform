#!/usr/bin/env node
// U3 semantic mutation harness. Every mutant edits exact production bytes,
// launches the 45-fixture validator in a fresh process, requires the exact FAIL
// set, and restores both target bytes and the candidate-worktree fingerprint.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(ROOT, "scripts", "validate-identity-truth-projection.js");
const TARGETS = Object.freeze({
  contract: "workers/scan-api/src/engines/identity-evidence-contract.js",
  lifecycle: "workers/scan-api/src/engines/identity-lifecycle.js",
  business: "workers/scan-api/src/engines/business-risk.js",
  domains: "workers/scan-api/src/engines/cyber-mot-domains.js",
  shadow: "workers/scan-api/src/engines/shadow-it-inventory.js",
  vendor: "workers/scan-api/src/engines/vendor-risk.js",
  scorecard: "workers/scan-api/src/engines/scorecard.js",
  supply: "workers/scan-api/src/engines/supply-chain.js",
  rules: "workers/scan-api/src/engines/related-changes-rules.js",
  pdf: "workers/scan-api/src/engines/pdf.js",
  academy: "frontend/src/data/academy.js",
  registry: "workers/scan-api/src/engines/remediation-registry.js",
  phase5: "workers/scan-api/src/engines/phase5-evidence.js",
  snapshot: "workers/scan-api/src/engines/report-snapshot.js",
  scans: "workers/scan-api/src/routes/scans.js",
  exposure: "workers/scan-api/src/engines/identity-exposure.js",
  workspacePage: "frontend/src/pages/ws/WorkspaceIdentityPage.jsx",
  card: "frontend/src/components/IdentityExposureCard.jsx",
  managedPage: "frontend/src/pages/ws/IdentityExposurePage.jsx",
  landing: "frontend/src/pages/PublicLandingPage.jsx",
  dashboard: "frontend/src/pages/Dashboard.jsx",
  capabilities: "docs/CAPABILITIES.md",
  methodology: "docs/risk-methodology-v1.md",
});
const absolute = (target) => path.join(ROOT, TARGETS[target]);
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");

function git(args) { return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }); }
function worktreeFingerprint() {
  const status = git(["status", "--porcelain=v1", "-z"]);
  const entries = status.split("\0").filter(Boolean);
  const hash = crypto.createHash("sha256").update(status);
  for (const entry of entries) {
    const relative = entry.slice(3);
    const file = path.join(ROOT, relative);
    hash.update(relative).update("\0");
    if (fs.existsSync(file) && fs.statSync(file).isFile()) hash.update(fs.readFileSync(file));
    hash.update("\0");
  }
  return hash.digest("hex");
}
function replaceExactly(value, from, to, label) {
  const count = value.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return value.replace(from, to);
}
function mutate(value, replacements, label) {
  return replacements.reduce((current, replacement, index) =>
    replaceExactly(current, replacement.from, replacement.to, `${label}.${index + 1}`), value);
}
function failureIds(output) {
  return String(output).split(/\r?\n/).filter((line) => line.startsWith("FAIL U3-"))
    .map((line) => line.split(" — ")[0].slice(5));
}
function runValidator() {
  const child = spawnSync(process.execPath, [VALIDATOR], { cwd: ROOT, encoding: "utf8", timeout: 120_000 });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  const failures = failureIds(output);
  const summary = String(child.stdout || "").match(/U3 identity truth projection: (\d+)\/(\d+) fixtures passed/);
  const controls = String(child.stdout || "").match(/U3 controls: (\d+)\/(\d+) passed/);
  const loaded = String(child.stdout || "").includes("LOADED identity truth contract=true lifecycle=true");
  const normal = child.error == null && child.signal == null && child.status === 1 && loaded &&
    summary != null && Number(summary[2]) === 45 && Number(summary[1]) + failures.length === 45 &&
    controls != null;
  return { child, output, failures, normal };
}

const MUTANTS = [
  { id: "U3-M01", target: "contract", expected: ["U3-P02"], controls: ["U3-P01"], replacements: [{ from: '  if (providerItems.some((item) => ["host_substring", "token_substring"].includes(item.match_precision))) return "possible";', to: '  if (providerItems.some((item) => ["host_substring", "token_substring"].includes(item.match_precision))) return "observed";' }] },
  { id: "U3-M02", target: "contract", expected: ["U3-P01", "U3-P03", "U3-P04", "U3-P05", "U3-ITEM11-01"], controls: ["U3-POS-01"], replacements: [{ from: '      status: "not_evaluated",', to: '      status: row.internet_exposed ? "reachable" : "not_evaluated",' }] },
  { id: "U3-M03", target: "contract", expected: ["U3-API-01", "U3-FE-01"], controls: ["U3-COMPAT-01"], replacements: [{ from: '  const projection = buildIdentityEvidenceProjection(row);\n  const candidate = projection.identity_claim?.surface_classification?.status === "possible" && row.hostname;', to: '  const baseProjection = buildIdentityEvidenceProjection(row);\n  const projection = { ...baseProjection, identity_claim: { ...baseProjection.identity_claim, reachability: { status: "reachable", endpoint: null, method: null, measured_at: null, confidence_detail: null } } };\n  const candidate = projection.identity_claim?.surface_classification?.status === "possible" && row.hostname;' }] },
  { id: "U3-M04", target: "lifecycle", expected: ["U3-LIFE-01", "U3-ALERT-01"], controls: ["U3-POS-01"], replacements: [{ from: '    else if (measuredIdentityClaim && admin && stillObserved && cls !== "expected")', to: '    else if (admin && stillObserved && cls !== "expected")' }] },
  { id: "U3-M05", target: "contract", expected: ["U3-API-02", "U3-API-03", "U3-LIFE-03"], controls: ["U3-LIFE-02"], replacements: [{ from: '  return isMeasuredIdentityClaim(identityClaim)\n    ? [...NEUTRAL_IDENTITY_ACTIONS, ...MEASURED_IDENTITY_ACTIONS]\n    : [...NEUTRAL_IDENTITY_ACTIONS];', to: '  return [...NEUTRAL_IDENTITY_ACTIONS, ...MEASURED_IDENTITY_ACTIONS];' }] },
  { id: "U3-M06", target: "lifecycle", expected: ["U3-API-03"], controls: ["U3-API-02"], replacements: [{ from: '  if (!allowedActions.includes(action)) return { ok: false, code: "action_not_allowed", allowed_actions: allowedActions };', to: '  if (!IDENTITY_WORKFLOW_ACTIONS.includes(action)) return { ok: false, code: "invalid_action" };' }] },
  // Kill set widened by I11B: this mutant reintroduces the deprecated
  // high_risk_count into the BRS deduction - precisely the defect F-51
  // documents - so the methodology doc-parity fixture U3-CS-06 correctly
  // fails alongside U3-BRI-01. Widened deliberately, not to dodge a clash.
  { id: "U3-M07", target: "business", expected: ["U3-BRI-01", "U3-CS-06"], controls: ["U3-BRI-02"], replacements: [{ from: '  attackDed += Math.min(20, identityReachableSurfaceCount * 7);', to: '  attackDed += Math.min(20, (identityHighRiskCount || identityReachableSurfaceCount) * 7);' }] },
  { id: "U3-M08", target: "domains", expected: ["U3-DOM-01"], controls: ["U3-DOM-02"], replacements: [{ from: '      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;\n      base.coverage = requiredAssessedAll ? "partial" : quality;\n      base.summary = "Identity reachability was not evaluated — no supported reachability producer is implemented. Provider relationships and possible hostnames remain visible for review.";', to: '      base.state = CYBER_MOT_STATES.ASSESSED_HEALTHY;\n      base.coverage = "complete";\n      base.summary = "Assessed — no material issue observed.";' }] },
  { id: "U3-M09", target: "shadow", expected: ["U3-XD-01"], controls: ["U3-XD-02"], replacements: [{ from: '    confidence: detail?.level && detail.level !== "unknown" ? detail.level : "low",', to: '    confidence: (row.risk_score || 0) >= 20 ? "high" : "medium",' }] },
  { id: "U3-M10", target: "vendor", expected: ["U3-VR-01"], controls: ["U3-VR-02"], replacements: [{ from: '  return identityOnly ? "relationship_only" : "independent_risk_evidence";', to: '  return "independent_risk_evidence";' }] },
  { id: "U3-M11", target: "scorecard", expected: ["U3-VR-01"], controls: ["U3-VR-02"], replacements: [{ from: "           AND COALESCE(source_module, '') != 'identity_discovery'\n", to: "" }] },
  { id: "U3-M12", target: "supply", expected: ["U3-SC-01"], controls: ["U3-VR-02"], replacements: [{ from: "  const idpVendors = enrichedVendors.filter(v => v.category === 'identity_provider' && v.status === 'active' && v.relationship_only !== true);", to: "  const idpVendors = enrichedVendors.filter(v => v.category === 'identity_provider' && v.status === 'active');" }] },
  { id: "U3-M13", target: "rules", expected: ["U3-RC-01", "U3-RC-02"], controls: ["U3-DOM-02"], replacements: [{ from: '    title: "New host with a possible identity-facing hostname",', to: '    title: "New host with a login or identity surface",' }, { from: '    summary: "A new host and a possible identity-facing hostname were observed on the same registrable domain in the same period. This correlation does not establish endpoint reachability.",', to: '    summary: "A new host appeared and a login or identity-provider surface was observed on the same registrable domain in the same period.",' }, { from: '    title: "Possible identity-facing hostname with a certificate signal",', to: '    title: "Login or admin surface with a certificate signal",' }, { from: '    summary: "A possible identity-facing hostname and a certificate signal were observed on the same registrable domain in the same period. Neither observation establishes endpoint reachability.",', to: '    summary: "A login or admin surface and a certificate signal were observed on the same registrable domain in the same period.",' }] },
  { id: "U3-M14", target: "pdf", expected: ["U3-RC-01", "U3-RC-02"], controls: ["U3-SNAP-RAW-01"], replacements: [{ from: '  new_host_with_identity: "New host with a possible identity-facing hostname",', to: '  new_host_with_identity: "New host with a login or identity surface",' }, { from: '  identity_with_cert: "Possible identity-facing hostname with a certificate signal",', to: '  identity_with_cert: "Login or admin surface with a certificate signal",' }] },
  { id: "U3-M15", target: "academy", expected: ["U3-A02", "U3-FE-04"], controls: ["U3-A01"], replacements: [{ from: "        heading: 'What CyberMeters can observe',", to: "        heading: 'What CyberMeters Detects'," }, { from: "          p('Provider configuration and sign-in controls must be verified in the Microsoft administration tools. A later CyberMeters scan may refresh provider or hostname evidence, but it cannot verify tenant policy or endpoint reachability.'),", to: "          p('Re-scan in CyberMeters — M365 identity exposure findings will reflect updated configuration.')," }] },
  { id: "U3-M16", target: "registry", expected: ["U3-A03"], controls: ["U3-A01"], replacements: [{ from: '    remediation_id: "identity.m365.harden",\n    domain_key: "identity_exposure",\n    finding_types: ["identity_microsoft_365_detected"],\n    status: "deprecated",', to: '    remediation_id: "identity.m365.harden",\n    domain_key: "identity_exposure",\n    finding_types: ["identity_microsoft_365_detected"],\n    status: "active",' }, { from: '    remediation_id: "identity.legacy_auth",\n    domain_key: "identity_exposure",\n    finding_types: ["identity_legacy_auth_exposed"],\n    status: "deprecated",', to: '    remediation_id: "identity.legacy_auth",\n    domain_key: "identity_exposure",\n    finding_types: ["identity_legacy_auth_exposed"],\n    status: "active",' }, { from: '    remediation_id: "identity.autodiscover",\n    domain_key: "identity_exposure",\n    finding_types: ["identity_autodiscover_exposed"],\n    status: "deprecated",', to: '    remediation_id: "identity.autodiscover",\n    domain_key: "identity_exposure",\n    finding_types: ["identity_autodiscover_exposed"],\n    status: "active",' }] },
  { id: "U3-M17", target: "phase5", expected: ["U3-SNAP-LIVE-01"], controls: ["U3-SNAP-LIVE-02", "U3-SNAP-RAW-01"], replacements: [{ from: '  const legacyBriAffected = !projectionAlreadyHonest && !hasTypedReachability && Number(identityModule?.high_risk_count || 0) > 0;\n  const legacyHealthyAffected = !projectionAlreadyHonest && identityDomain?.state === "assessed_healthy" && !hasTypedReachability;', to: '  const legacyBriAffected = false;\n  const legacyHealthyAffected = false;' }] },
  { id: "U3-M18", target: "snapshot", expected: ["U3-SNAP-RAW-01"], controls: ["U3-SNAP-LIVE-01"], replacements: [{ from: '  const customerSnapshot = projectDmarcSnapshotForCustomer(\n    projectPhase5SnapshotForCustomer(snapshot, sourceModules),\n    dmarcPolicy.evidence,\n  );', to: '  const customerSnapshot = projectDmarcSnapshotForCustomer(\n    projectPhase5SnapshotForCustomer(snapshot, sourceModules),\n    dmarcPolicy.evidence,\n  );\n  snapshot.overall = customerSnapshot.overall;' }] },
  { id: "U3-M19", target: "scans", expected: ["U3-SNAP-LIVE-01"], controls: ["U3-SNAP-LIVE-02"], replacements: [{ from: '          snapshot: read.snapshot,', to: '          snapshot: customerSnapshot,' }] },
  { id: "U3-M20", target: "exposure", expected: ["U3-API-01", "U3-FE-02"], controls: ["U3-XD-02"], replacements: [{ from: '    internet_facing: claimCounts.reachable_surface_count,', to: '    internet_facing: projectedLoginRows.filter((row) => row.internet_exposed).length,' }] },
  { id: "U3-M21", target: "workspacePage", expected: ["U3-FE-01"], controls: ["U3-COMPAT-01"], replacements: [{ from: '  const claim = asset.identity_claim\n', to: '  const legacyExposure = asset.internet_exposed\n  const claim = asset.identity_claim\n' }] },
  { id: "U3-M22", target: "card", expected: ["U3-FE-02"], controls: ["U3-DOM-02"], replacements: [{ from: "'Endpoint reachability not evaluated'", to: "'None exposed'" }] },
  { id: "U3-M23", target: "managedPage", expected: ["U3-API-02", "U3-FE-03"], controls: ["U3-LIFE-02"], replacements: [{ from: '  const can = (item, action) => Array.isArray(item?.allowed_actions) && item.allowed_actions.includes(action)', to: '  const can = (_item, action) => (data?.actions || []).includes(action)' }, { from: '{confidenceDetailLabel(it.confidence_detail)} · reachability {it.identity_claim?.reachability?.status?.replace(/_/g, \' \') || \'not evaluated\'}', to: '{it.confidence || \'confidence unknown\'}' }] },
  { id: "U3-M24", target: "lifecycle", expected: ["U3-ALERT-01"], controls: ["U3-POS-01"], replacements: [{ from: '    const alertEligible = measuredIdentityClaim || recurrence_type === "provider_change";', to: '    const alertEligible = true;' }] },
  { id: "U3-M25", target: "contract", expected: ["U3-DOM-01", "U3-ITEM11-01"], controls: ["U3-DOM-02"], replacements: [{ from: 'export const IDENTITY_REACHABILITY_PRODUCERS = Object.freeze([]);', to: 'export const IDENTITY_REACHABILITY_PRODUCERS = Object.freeze(["unimplemented_reachability"]);' }] },
  // ── I11B F-50/F-51 — claim-surface mutants (repo-owned, right-reason) ──
  // Each restores one exact pre-fix wording and must fail ONLY its own fixture.
  // Wording is the claim, so the claim-surface guard earns the same mutation
  // discipline as every other U3 assertion.
  { id: "U3-M26", target: "landing", expected: ["U3-CS-01"], controls: ["U3-CS-03"], replacements: [{ from: "'Identity-provider relationships and identity-facing hostnames observed from public DNS, certificate transparency and response metadata. Endpoint reachability testing is on the roadmap and is not performed today. No breach, credential or dark-web claims.'", to: "'Public login surfaces and identity-facing entry points, without unsupported breach or dark-web claims.'" }] },
  { id: "U3-M27", target: "landing", expected: ["U3-CS-01"], controls: ["U3-CS-02"], replacements: [{ from: "'Reachability: roadmap'", to: "'IdP exposure'" }] },
  { id: "U3-M28", target: "dashboard", expected: ["U3-CS-03"], controls: ["U3-CS-01"], replacements: [{ from: 'fallback="Review observed identity-provider relationships and identity-facing hostnames. Endpoint reachability is not measured."', to: 'fallback="Review public login surfaces and identity-facing entry points."' }] },
  { id: "U3-M29", target: "capabilities", expected: ["U3-CS-04"], controls: ["U3-CS-05"], replacements: [{ from: "- **Observes:** identity-provider relationships and identity-facing hostname candidates, derived from public DNS, certificate transparency and HTTP response metadata.", to: "- **Observes:** public login surfaces and identity-facing entry points." }] },
  { id: "U3-M30", target: "methodology", expected: ["U3-CS-05", "U3-CS-06"], controls: ["U3-CS-04"], replacements: [{ from: "| Identity exposure (measured reachable surfaces × 7, capped at −20) — requires a registered reachability producer; none is registered today, so this contributes 0. The deprecated `high_risk_count` heuristic is deliberately ignored by the current implementation. | Up to −20 |", to: "| Identity exposure (high_risk_count × 7, capped at −20) | Up to −20 |" }] },
];

let killed = 0;
let failures = 0;
const initialFingerprint = worktreeFingerprint();
for (const mutant of MUTANTS) {
  const target = absolute(mutant.target);
  const original = fs.readFileSync(target);
  const originalHash = digest(original);
  try {
    const changed = mutate(original.toString("utf8"), mutant.replacements, mutant.id);
    fs.writeFileSync(target, changed);
    const result = runValidator();
    const exact = JSON.stringify(result.failures) === JSON.stringify(mutant.expected);
    if (result.normal && exact) {
      killed += 1;
      console.log(`PASS ${mutant.id} exact FAIL set ${JSON.stringify(result.failures)} controls=${JSON.stringify(mutant.controls)} fresh=true`);
    } else {
      failures += 1;
      console.error(`FAIL ${mutant.id} expected=${JSON.stringify(mutant.expected)} actual=${JSON.stringify(result.failures)} normal=${result.normal} status=${result.child.status}\n${result.output}`);
    }
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${mutant.id} — ${error?.message || error}`);
  } finally {
    fs.writeFileSync(target, original);
    if (digest(fs.readFileSync(target)) !== originalHash) throw new Error(`${mutant.id}: restoration hash mismatch`);
  }
}
const finalFingerprint = worktreeFingerprint();
if (finalFingerprint !== initialFingerprint) {
  failures += 1;
  console.error(`FAIL U3-RESTORE expected=${initialFingerprint} actual=${finalFingerprint}`);
} else {
  console.log(`PASS U3-RESTORE worktree_fingerprint=${finalFingerprint}`);
}
console.log(`U3 mutants: ${killed}/${MUTANTS.length} killed with exact right-reason sets`);
if (MUTANTS.length !== 30 || failures > 0 || killed !== MUTANTS.length) process.exit(1);
