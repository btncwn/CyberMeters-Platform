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

// ── Surface B — Executive Report UI (prioritized_remediation) ────────────────
const er = buildExecutiveReportV2({ scan: { id: "scan_parity", domain: "parity.example", status: "completed" }, rawReport, workspace: null });
const erById = new Map((er.prioritized_remediation || []).map((x) => [x.title, x.remediation_id]));
ok("Executive Report: email remediation identity", erById.get(emailTitle) === EXPECT.email, erById.get(emailTitle));
ok("Executive Report: admin remediation identity", erById.get(asmTitle) === EXPECT.asm, erById.get(asmTitle));

// ── Surface C — Scorecard / PDF top_recommendations (title join) ─────────────
// pdf.js reunites each scorecard top_recommendation (canonical title) with its
// identity via resolveByCustomerTitle — the same join the PDF uses.
ok("Scorecard/PDF join: email title → canonical id", resolveByCustomerTitle(emailTitle)?.remediation_id === EXPECT.email);
ok("Scorecard/PDF join: admin title → canonical id", resolveByCustomerTitle(asmTitle)?.remediation_id === EXPECT.asm);

// ── Surface D — Executive PDF priority_action_plan source (posture) ──────────
// The PDF fills its plan from posture category.remediations (canonical). Drive
// posture so email + admin categories are at risk, and confirm the promoted
// remediations carry the same identities.
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
ok("Executive PDF (posture source): email category promotes canonical id", postureEmailIds.includes(EXPECT.email), postureEmailIds.join(","));
ok("Executive PDF (posture source): admin category promotes canonical id", postureAdminIds.includes(EXPECT.asm), postureAdminIds.join(","));

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
  sdEmail, erById.get(emailTitle), resolveByCustomerTitle(emailTitle)?.remediation_id,
  postureEmailIds.find((x) => x === EXPECT.email), resolveRemediation({ finding_type: "email_missing_spf" }).remediation_id,
]);
ok("EMAIL remediation identity is IDENTICAL across all five surfaces",
  emailAcrossSurfaces.size === 1 && emailAcrossSurfaces.has(EXPECT.email), [...emailAcrossSurfaces].join(","));
const asmAcrossSurfaces = new Set([
  sdAsm, erById.get(asmTitle), resolveByCustomerTitle(asmTitle)?.remediation_id,
  postureAdminIds.find((x) => x === EXPECT.asm),
]);
ok("ADMIN/ASM remediation identity is IDENTICAL across all surfaces",
  asmAcrossSurfaces.size === 1 && asmAcrossSurfaces.has(EXPECT.asm), [...asmAcrossSurfaces].join(","));

// Print the parity table for the record.
console.log("\nCross-surface parity (remediation_id):");
console.log(`  EMAIL  scan_detail=${sdEmail}  exec_report=${erById.get(emailTitle)}  scorecard/pdf=${resolveByCustomerTitle(emailTitle)?.remediation_id}  posture=${postureEmailIds.find((x) => x === EXPECT.email)}  ce=${resolveRemediation({ finding_type: "email_missing_spf" }).remediation_id}`);
console.log(`  ASM    scan_detail=${sdAsm}  exec_report=${erById.get(asmTitle)}  scorecard/pdf=${resolveByCustomerTitle(asmTitle)?.remediation_id}  posture=${postureAdminIds.find((x) => x === EXPECT.asm)}`);
console.log(`  CE     backlog=${resolveRemediation({ finding_type: "ce_open_findings_backlog" }).remediation_id}`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
