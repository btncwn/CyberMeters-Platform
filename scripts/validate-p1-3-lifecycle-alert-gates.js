#!/usr/bin/env node
// P1.3 focused proof: both ISSUE directions and the final alert eligibility floor.
// Every mutation is restored in-process; no product state survives the harness.
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const root = new URL("..", import.meta.url).pathname;
const eng = (name) => `${root}workers/scan-api/src/engines/${name}`;
let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => { condition ? pass++ : fail++; console.log(`${condition ? "PASS" : "FAIL"} ${name}${condition ? "" : ` — ${detail}`}`); };

const { buildPostureDiffEvents } = await import(pathToFileURL(eng("posture-events.js")).href);
const { mayIssueFromModule } = await import(pathToFileURL(eng("website-security-lifecycle.js")).href);
const { isAlertEvidenceEligible } = await import(pathToFileURL(eng("managed-alerts.js")).href);

const service = { hostname: "admin.example", product: "Admin", severity: "high" };
const previous = { admin_surface_detection: { services: [] } };
const unavailable = { admin_surface_detection: { services: [service], evidence_status: "unavailable" } };
const unassessed = { admin_surface_detection: { services: [service], evidence_status: "not_assessed" } };
const assessed = { admin_surface_detection: { services: [service], evidence_status: "issue_detected" } };
ok("posture unassessed + new service emits no issue", buildPostureDiffEvents("example.com", previous, unassessed, { includeSpf: false }).length === 0);
ok("posture unavailable + new service emits no issue", buildPostureDiffEvents("example.com", previous, unavailable, { includeSpf: false }).length === 0);
ok("posture issue_detected + new service emits issue", buildPostureDiffEvents("example.com", previous, assessed, { includeSpf: false }).some((e) => e.event_type === "exposed_service_detected"));
ok("website shaped serviceability false suppresses ISSUE", mayIssueFromModule({ headers: { serviceability: { serviceable: false, conclusion_class: "evidence_insufficient" } } }, "headers") === false);
ok("website shaped serviceability true preserves ISSUE", mayIssueFromModule({ headers: { serviceability: { serviceable: true, conclusion_class: "conclusive" } } }, "headers") === true);
ok("website ssl invalid redirect envelope suppresses ISSUE", mayIssueFromModule({ ssl: { http_redirect_chain: { http_redirect_validated: false } } }, "ssl") === false);
ok("website ssl valid serviceable envelope preserves ISSUE", mayIssueFromModule({ ssl: { http_redirect_chain: { http_redirect_validated: true } } }, "ssl") === true);

ok("alert shaped false is ineligible", isAlertEvidenceEligible({ evidence_eligible: false } ) === false);
ok("alert shaped true is eligible", isAlertEvidenceEligible({ evidence_eligible: true } ) === true);
ok("alert evidence_insufficient is ineligible", isAlertEvidenceEligible({ evidence_state: "evidence_insufficient" }) === false);
ok("alert absent metadata preserves legacy eligibility", isAlertEvidenceEligible({}) === true);

const mutateAndProbe = (file, from, to, probe, name) => {
  const original = fs.readFileSync(file, "utf8");
  let mutated;
  try {
    if (!original.includes(from)) throw new Error(`anchor missing: ${name}`);
    mutated = original.replace(from, to);
    fs.writeFileSync(file, mutated);
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", probe], { encoding: "utf8" });
    ok(`${name} mutant dies by named assertion`, child.status !== 0, child.stderr || child.stdout);
  } finally { fs.writeFileSync(file, original); }
};

mutateAndProbe(eng("website-security-lifecycle.js"),
  "if (evidence?.serviceability && !maySupportDefectConclusion(evidence.serviceability)) return false;",
  "if (false) return false;",
  `import { mayIssueFromModule } from ${JSON.stringify(pathToFileURL(eng("website-security-lifecycle.js")).href + "?m=website" )}; if (mayIssueFromModule({headers:{serviceability:{serviceable:false,conclusion_class:"evidence_insufficient"}}},"headers") !== false) process.exit(1);`,
  "website ISSUE serviceability gate removed");

mutateAndProbe(eng("posture-events.js"),
  "if (!currentAdminIssueAssessed) continue;",
  "if (false) continue;",
  `import { buildPostureDiffEvents } from ${JSON.stringify(pathToFileURL(eng("posture-events.js")).href + "?m=posture" )}; const p={admin_surface_detection:{services:[]}}, c={admin_surface_detection:{services:[${JSON.stringify(service)}],evidence_status:"unavailable"}}; if (buildPostureDiffEvents("example.com",p,c,{includeSpf:false}).length !== 0) process.exit(1);`,
  "posture ISSUE evidence gate removed");

mutateAndProbe(eng("managed-alerts.js"),
  "return metadata?.evidence_eligible !== false\n    && evidenceState !== \"evidence_insufficient\"\n    && !(serviceability?.serviceable !== undefined && serviceability?.serviceable !== true);",
  "return true;",
  `import { isAlertEvidenceEligible } from ${JSON.stringify(pathToFileURL(eng("managed-alerts.js")).href + "?m=alert" )}; if (isAlertEvidenceEligible({evidence_state:"evidence_insufficient"}) !== false) process.exit(1);`,
  "alert eligibility floor removed");

console.log(`\nP1.3 lifecycle/alert gates: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
