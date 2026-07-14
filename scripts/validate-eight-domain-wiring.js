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

// ── Backend wiring ───────────────────────────────────────────────────────────
{
  const scans = read("workers/scan-api/src/routes/scans.js");
  ok("scan /report returns cyber_mot_domains from the canonical resolver",
    /resolveCyberMotDomainStates/.test(scans) && /cyber_mot_domains:\s*cyberMotDomains/.test(scans));
  ok("executive-report-v2 attaches cyber_mot_domains",
    /execReport\.cyber_mot_domains = resolveCyberMotDomainStates/.test(scans));
  const pdf = read("workers/scan-api/src/engines/pdf.js");
  ok("collectPdfData computes cyber_mot_domains over the authoritative scan",
    /resolveCyberMotDomainStates\(authReport/.test(pdf) && /cyber_mot_domains:\s*cyberMotDomains/.test(pdf));
  ok("executive PDF has 12 pages and an eight-domain summary page",
    /const NP\s*=\s*12/.test(pdf) && /Eight-Domain Cyber MOT Coverage Summary/.test(pdf) && /pdfData\.cyber_mot_domains/.test(pdf));
}

// ── Frontend wiring (renders the server states; no resolver logic duplicated) ──
{
  const comp = read("frontend/src/components/CyberMotDomains.jsx");
  ok("shared presentation component exists and does not import/call the resolver", /export default function CyberMotDomains/.test(comp) && !/from ['"].*cyber-mot-domains/.test(comp) && !/resolveCyberMotDomainStates\(/.test(comp));
  ok("Main Dashboard renders CyberMotDomains", /<CyberMotDomains /.test(read("frontend/src/pages/Dashboard.jsx")));
  ok("Scan Detail renders CyberMotDomains", /<CyberMotDomains /.test(read("frontend/src/pages/ScanDetail.jsx")));
  ok("Executive Report UI renders CyberMotDomains", /<CyberMotDomains /.test(read("frontend/src/components/ExecutiveReportV2.jsx")));
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
  const { resolveCyberMotDomainStates } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "cyber-mot-domains.js")).href);
  const report = {
    scan_quality: { status: "complete", modules_skipped: [] },
    modules: { email_security: {}, dns: {}, ssl: {}, headers: {}, subdomains: { count: 2 }, certificate_intelligence: {}, identity_discovery: {}, saas_exposure: { count: 1 } },
    findings: [{ id: "email_dmarc_missing", severity: "high", module: "email_security" }],
    completed_at: "2026-07-14T10:00:00Z",
  };
  const domains = resolveCyberMotDomainStates(report, { scanId: "scan_x" });
  const bytes = pdfMod.buildExecutivePdf({ workspace: { id: "w", name: "Test WS" }, generated_at: "2026-07-14T10:00:00Z", overall_score: 82, risk_rating: "good", cyber_mot_domains: domains });
  const txt = Buffer.from(bytes).toString("latin1");
  const names = ["Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust", "Cyber Essentials Readiness", "Website Security", "Identity Exposure", "Shadow IT"];
  ok("PDF renders all eight domain names", names.every((n) => txt.includes(n)), names.filter((n) => !txt.includes(n)).join(","));
  ok("PDF renders a state label (Issue detected)", txt.includes("Issue detected"));
  ok("PDF is version v2.3", txt.includes("v2.3"));
  ok("PDF white-label footer intact", txt.includes("CyberMeters Platform"));
  // With a custom white-label footer, only presentation changes.
  const branded = pdfMod.buildExecutivePdf({ workspace: { id: "w", name: "Test WS" }, overall_score: 82, risk_rating: "good", cyber_mot_domains: domains, white_label: { footer_text: "Acme MSP" } });
  const btxt = Buffer.from(branded).toString("latin1");
  ok("white-label changes only branding, all eight domains still present", btxt.includes("Acme MSP") && names.every((n) => btxt.includes(n)));
}

console.log(`\neight-domain-wiring: ${pass} passed, ${fail} failed`);
if (fail) { console.error("eight-domain-wiring validation FAILED"); process.exit(1); }
console.log("eight-domain-wiring validation passed");
