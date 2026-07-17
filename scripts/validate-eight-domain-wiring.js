#!/usr/bin/env node
//
// Eight-domain Cyber MOT wiring contract — proves the canonical resolver is wired
// into all four primary surfaces (Main Dashboard, Scan Detail, Executive Report UI,
// Executive PDF) with no logic duplicated in the frontend, that the Dashboard no
// longer defaults absent evidence to "good", and that the Executive PDF actually
// renders all eight domain names + state labels with white-label branding intact.
// Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// ── Backend wiring (snapshot-native, M5.d) ──────────────────────────────────
{
  const scans = read("workers/scan-api/src/routes/scans.js");
  ok("scan /report serves cyber_mot_domains from the canonical SNAPSHOT (no live resolver)",
    /readScanReportSnapshot/.test(scans) && /cyber_mot_domains:\s*snap\.domains/.test(scans) &&
    !/resolveCyberMotDomainStates/.test(scans));
  ok("executive-report-v2 is built from the snapshot read",
    /buildExecutiveReportV2\(\{ scan, workspace, read \}\)/.test(scans));
  const er = read("workers/scan-api/src/engines/executive-report.js");
  ok("executive report exposes the snapshot's eight domains verbatim",
    /cyber_mot_domains:\s*snap\.domains/.test(er) && !/INTELLIGENCE_ENGINE_REGISTRY/.test(er));
  const pdf = read("workers/scan-api/src/engines/pdf.js");
  ok("PDF module owns no calculation brain (no resolver/scorecard/posture/BRS imports)",
    !/resolveCyberMotDomainStates|buildScorecardData|computeSecurityPosture|latestScanBusinessRisk|buildCyberEssentialsReadiness/.test(pdf));
  ok("workspace executive PDF renders the snapshot domains section",
    /buildWorkspaceExecutivePdf/.test(pdf) && /sectionDomains/.test(pdf));
}

// ── Frontend wiring (renders the server states; no resolver logic duplicated) ──
{
  const comp = read("frontend/src/components/CyberMotDomains.jsx");
  ok("shared presentation component exists and does not import/call the resolver", /export default function CyberMotDomains/.test(comp) && !/from ['"].*cyber-mot-domains/.test(comp) && !/resolveCyberMotDomainStates\(/.test(comp));
  ok("Main Dashboard renders CyberMotDomains", /<CyberMotDomains[\s>]/.test(read("frontend/src/pages/Dashboard.jsx")));
  ok("Scan Detail renders CyberMotDomains", /<CyberMotDomains[\s>]/.test(read("frontend/src/pages/ScanDetail.jsx")));
  ok("Executive Report UI renders CyberMotDomains", /<CyberMotDomains[\s>]/.test(read("frontend/src/components/ExecutiveReportV2.jsx")));
  // Dashboard no longer defaults absent evidence to green.
  ok("Dashboard no longer defaults missing evidence to 'good'",
    !/completed\.length > 0 \? 'good'/.test(read("frontend/src/pages/Dashboard.jsx")));
  ok("no resolver logic duplicated in the frontend",
    !/resolveCyberMotDomainStates/.test(read("frontend/src/pages/Dashboard.jsx")) &&
    !/resolveCyberMotDomainStates/.test(read("frontend/src/pages/ScanDetail.jsx")));
}

// ── PDF behavioural — all eight domain names + state labels + white-label ─────
{
  const pdfMod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "pdf.js")).href);
  const rsMod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "report-snapshot.js")).href);
  const report = {
    scan_id: "scan_x", domain_id: "dom_x", domain: "wiring.example", status: "completed",
    cyber_metrics_score: 82, risk_level: "good",
    started_at: "2026-07-14T09:55:00Z", completed_at: "2026-07-14T10:00:00Z",
    scan_quality: { status: "complete", modules_skipped: [] },
    modules: { email_security: {}, dns: {}, ssl: {}, headers: {}, subdomains: { count: 2 }, certificate_intelligence: {}, identity_discovery: {}, saas_exposure: { count: 1 }, brand_monitoring: {} },
    findings: [{ id: "email_dmarc_missing", title: "DMARC missing", severity: "high", module: "email_security", finding_type: "finding" }],
    recommendations: [],
  };
  const snapshot = rsMod.composeSnapshot({
    snapshotId: "snap_w", workspaceId: "ws_w", domainId: "dom_x", scanId: "scan_x",
    domain: "wiring.example", report, cyberEssentials: null, ceReadiness: null,
    caseRows: [], questionSetVersions: [], supersedesSnapshotId: null,
    builtAt: "2026-07-14T10:00:05Z",
  });
  const readObj = { status: "ok", snapshot, row: { id: "snap_w" }, integrity: { verified: true } };
  const bytes = pdfMod.buildScanReportPdf({ id: "scan_x", domain: "wiring.example" }, readObj, null, null);
  const txt = Buffer.from(bytes).toString("latin1");
  const names = ["Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust", "Cyber Essentials Readiness", "Website Security", "Identity Exposure", "Shadow IT"];
  ok("scan PDF renders all eight domain names", names.every((n) => txt.includes(n)), names.filter((n) => !txt.includes(n)).join(","));
  ok("scan PDF renders a state label (Issue detected)", txt.includes("Issue detected"));
  ok("scan PDF renders the assessment date, not a render-time clock", txt.includes("14 July 2026"));
  ok("scan PDF default footer intact", txt.includes("Generated by CyberMeters | app.cybermeters.com"));
  // White-label: only branding changes; all eight domains survive.
  const branded = pdfMod.buildScanReportPdf({ id: "scan_x", domain: "wiring.example" }, readObj, { company_name: "Acme MSP", accent: "#1568C7" }, null);
  const btxt = Buffer.from(branded).toString("latin1");
  ok("white-label changes only branding, all eight domains still present",
     btxt.includes("Acme MSP") && names.every((n) => btxt.includes(n)));
  // Workspace executive PDF renders the same snapshot facts.
  const wbytes = pdfMod.buildWorkspaceExecutivePdf({ workspaceName: "Test WS", reads: [{ status: "ok", snapshot, row: { id: "snap_w" } }], branding: null, generatedAt: "2026-07-14T10:01:00Z" });
  const wtxt = Buffer.from(wbytes).toString("latin1");
  ok("workspace executive PDF renders all eight domain names", names.every((n) => wtxt.includes(n)));
  ok("workspace executive PDF headlines the snapshot's assessment date", wtxt.includes("14 July 2026"));
}

console.log(`\neight-domain-wiring: ${pass} passed, ${fail} failed`);
if (fail) { console.error("eight-domain-wiring validation FAILED"); process.exit(1); }
console.log("eight-domain-wiring validation passed");
