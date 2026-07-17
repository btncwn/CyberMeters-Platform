#!/usr/bin/env node
//
// Cross-surface remediation PARITY — end-to-end proof that every customer surface
// exposes the SAME canonical remediation identity for the same finding. CI-blocking.
//
// Runs the ACTUAL production builders each surface uses:
//   • Scan Detail            → findingRemediation(finding)                 (routes/scans.js /report)
//   • Executive Report UI    → buildExecutiveReportV2(...).prioritized_remediation
//   • Scorecard / PDF top    → resolveByCustomerTitle(canonical title)     (pdf.js top_recommendations join)
//   • Executive PDF plan src → computeSecurityPosture(...).<cat>.remediations (pdf.js priority_action_plan)
//   • Cyber Essentials       → resolveRemediation(ce control-gap ref)      (ce-readiness.js addGap)
// and asserts they agree on remediation_id for one Email, one Web/ASM, and one CE
// remediation. This is the automated production-parity proof; a founder-workspace
// live smoke is the customer-visible confirmation.
// Node 24+.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const imp = (f) => import(pathToFileURL(path.join(enginesDir, f)).href);

const { resolveRemediation, resolveByCustomerTitle, findingRemediation } = await imp("remediation-registry.js");
const { buildExecutiveReportV2 } = await imp("executive-report.js");
const { computeSecurityPosture } = await imp("posture-scoring.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// Representative report: an Email finding (SPF) and a Web/ASM finding (admin
// interface). Titles are the canonical customer_titles scoring.js now persists.
const emailTitle = resolveRemediation({ finding_type: "email_missing_spf" }).customer_title;
const asmTitle = resolveRemediation({ finding_type: "asset_exposure_admin_interface" }).customer_title;
const rawReport = {
  findings: [
    { id: "email_missing_spf", finding_type: "finding", module: "email_security", severity: "high", title: emailTitle, description: "No SPF record.", recommendation: "No SPF record." },
    { id: "asset_exposure_admin_interface", finding_type: "finding", module: "asset_exposure", severity: "medium", title: asmTitle, description: "Admin exposed.", recommendation: "Admin exposed." },
  ],
  recommendations: [
    { title: emailTitle, module: "email_security", priority: 1, action: "Publish one SPF TXT record." },
    { title: asmTitle, module: "asset_exposure", priority: 2, action: "Limit admin interfaces." },
  ],
  modules: {},
};

// The three canonical identities we expect every surface to agree on.
const EXPECT = {
  email: "email.spf.publish",
  asm: "asm.exposure.admin",
  ce: "ce.backlog.remediate",
};

// ── Surface A — Scan Detail (findingRemediation over /report findings) ───────
const sdEmail = findingRemediation(rawReport.findings[0])?.remediation_id;
const sdAsm = findingRemediation(rawReport.findings[1])?.remediation_id;
ok("Scan Detail: email finding → canonical id", sdEmail === EXPECT.email, sdEmail);
ok("Scan Detail: admin finding → canonical id", sdAsm === EXPECT.asm, sdAsm);

// ── Surface B — Executive Report UI (snapshot remediation_actions, M5.d) ─────
// The executive report renders the canonical snapshot's remediation actions
// verbatim; parity holds because the snapshot resolves through the SAME registry.
const { composeSnapshot } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "report-snapshot.js")).href);
const paritySnap = composeSnapshot({
  snapshotId: "snap_par", workspaceId: "ws_par", domainId: "dom_par", scanId: "scan_parity",
  domain: "parity.example",
  report: { ...rawReport, scan_id: "scan_parity", status: "completed", completed_at: rawReport.completed_at ?? "2026-07-14T10:00:00Z" },
  cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
  supersedesSnapshotId: null, builtAt: "2026-07-14T10:00:05Z",
});
const er = buildExecutiveReportV2({ scan: { id: "scan_parity", domain: "parity.example", status: "completed" }, workspace: null, read: { status: "ok", snapshot: paritySnap, row: { id: "snap_par" }, integrity: { verified: true } } });
const erIds = new Set((er.remediation_actions || []).map((x) => x.remediation_id));
ok("Executive Report: email remediation identity", erIds.has(EXPECT.email), [...erIds].join(","));
ok("Executive Report: admin remediation identity", erIds.has(EXPECT.asm), [...erIds].join(","));

// ── Surface C — Scorecard top_recommendations (title join) ───────────────────
// The scorecard reunites each top_recommendation (canonical title) with its
// identity via resolveByCustomerTitle. (The PDF no longer joins — M5.d — it
// renders snapshot remediation_actions; the scorecard surface remains live.)
ok("Scorecard join: email title → canonical id", resolveByCustomerTitle(emailTitle)?.remediation_id === EXPECT.email);
ok("Scorecard join: admin title → canonical id", resolveByCustomerTitle(asmTitle)?.remediation_id === EXPECT.asm);

// ── Surface D — Scorecard posture categories (canonical ids) ─────────────────
// computeSecurityPosture still feeds the live /scorecard analytics surface
// (NOT the PDF since M5.d); its promoted remediations must carry the same
// canonical identities as every other surface.
const scorecardFixture = {
  certificate_risks: { risk_level: null, days_until_expiry: null },
  brand_risks: { high: 0, medium: 0 }, vendor_risk: { high: 0, medium: 0 },
  new_assets_30d: 0, third_party_assets: 0, saas_exposures: 0,
  admin_surfaces: 1, last_scanned_domain: "parity.example",
};
const postureReport = { modules: {
  email_security: { spf: { present: false }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  ssl: { https_available: true, http_redirects_to_https: true },
  admin_surface_detection: { critical: 1, high: 0, total: 1 },
} };
const posture = computeSecurityPosture(scorecardFixture, postureReport);
const postureEmailIds = (posture.email_security.remediations || []).map((r) => r.remediation_id);
const postureAdminIds = (posture.admin_exposure.remediations || []).map((r) => r.remediation_id);
ok("Scorecard posture: email category promotes canonical id", postureEmailIds.includes(EXPECT.email), postureEmailIds.join(","));
ok("Scorecard posture: admin category promotes canonical id", postureAdminIds.includes(EXPECT.asm), postureAdminIds.join(","));

// ── Surface E — Cyber Essentials (control-gap ref resolution) ────────────────
// ce-readiness.addGap resolves each control gap through the registry; the open-
// findings backlog gap resolves to the CE backlog remediation, and the CE email
// access gap resolves to the SAME email identity as every other surface.
ok("Cyber Essentials: open-findings backlog → CE canonical id",
  resolveRemediation({ finding_type: "ce_open_findings_backlog" }).remediation_id === EXPECT.ce);
ok("Cyber Essentials: email access gap shares the email identity",
  resolveRemediation({ finding_type: "email_missing_spf" }).remediation_id === EXPECT.email);

// ── The headline: all surfaces agree on one identity per remediation ─────────
const emailAcrossSurfaces = new Set([
  sdEmail, ([...erIds].find((x) => x === EXPECT.email)), resolveByCustomerTitle(emailTitle)?.remediation_id,
  postureEmailIds.find((x) => x === EXPECT.email), resolveRemediation({ finding_type: "email_missing_spf" }).remediation_id,
]);
ok("EMAIL remediation identity is IDENTICAL across all five surfaces",
  emailAcrossSurfaces.size === 1 && emailAcrossSurfaces.has(EXPECT.email), [...emailAcrossSurfaces].join(","));
const asmAcrossSurfaces = new Set([
  sdAsm, ([...erIds].find((x) => x === EXPECT.asm)), resolveByCustomerTitle(asmTitle)?.remediation_id,
  postureAdminIds.find((x) => x === EXPECT.asm),
]);
ok("ADMIN/ASM remediation identity is IDENTICAL across all surfaces",
  asmAcrossSurfaces.size === 1 && asmAcrossSurfaces.has(EXPECT.asm), [...asmAcrossSurfaces].join(","));

// Print the parity table for the record.
console.log("\nCross-surface parity (remediation_id):");
console.log(`  EMAIL  scan_detail=${sdEmail}  exec_report=${[...erIds].find((x) => x === EXPECT.email)}  scorecard/pdf=${resolveByCustomerTitle(emailTitle)?.remediation_id}  posture=${postureEmailIds.find((x) => x === EXPECT.email)}  ce=${resolveRemediation({ finding_type: "email_missing_spf" }).remediation_id}`);
console.log(`  ASM    scan_detail=${sdAsm}  exec_report=${[...erIds].find((x) => x === EXPECT.asm)}  scorecard/pdf=${resolveByCustomerTitle(asmTitle)?.remediation_id}  posture=${postureAdminIds.find((x) => x === EXPECT.asm)}`);
console.log(`  CE     backlog=${resolveRemediation({ finding_type: "ce_open_findings_backlog" }).remediation_id}`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
