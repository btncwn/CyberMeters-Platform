#!/usr/bin/env node
//
// A5 Executive Security Report — PDF quality + honesty guard. CI-blocking.
//
// Pins the founder A5 acceptance corrections to workers/scan-api/src/engines/pdf.js
// (buildWorkspaceExecutivePdf, snapshot-native). Behaviour-level: it RENDERS the real
// PDF from controlled snapshot inputs and asserts the rendered bytes. The renderer
// emits ASCII content streams, so page text is read directly from the `(…) Tj` ops.
//
//   A  Evidence-honest risk narrative — when the snapshot's own frozen evidence is
//      incomplete (partial quality / skipped module / domains needing evidence), the
//      report must NOT print the unqualified "No major gaps detected" and MUST print an
//      evidence-bounded statement. When coverage is complete, the frozen explanation is
//      kept verbatim. No score/band recomputation — frozen facts only.
//   B  Controlled page breaks — a domain limitation NEVER splits across a page boundary
//      (the "No" | "internal-network…" defect); every limitation renders within one page.
//   D  Branded cover — canonical CyberMeters wordmark + report title + workspace/date block.
//   E  No visible internal version identifiers (Resolver/Score/Risk-indicator methodology).
//   Preserved: all eight domain names, workspace + domain + dates, provisional wording,
//   missing evidence never shown healthy, no Scotist Ltd, no certification claim, valid PDF.
//
// Node 24+.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { buildWorkspaceExecutivePdf, buildScanReportPdf } = await eng("pdf.js");
const { CYBERMETERS_LOGO_DATA_URI, CYBERMETERS_LOGO_SHA256, CYBERMETERS_LOGO_DIMENSIONS } = await eng("brand-logo.js");
const { prepareLogoXObject } = await eng("pdf-image.js");
const { loadBrandingLogoDataUri, cyberMetersDescriptor } = await eng("report-branding-v2.js");
const { CYBER_MOT_DOMAINS } = await eng("cyber-mot-domains.js");
const fs = await import("node:fs");
const crypto = await import("node:crypto");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const DOMAINS = ["Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust",
  "Cyber Essentials Readiness", "Website Security", "Identity Exposure", "Shadow IT & Unmanaged Technology"];

const SHADOW_LIMIT = "CyberMeters observes only externally visible technology signals. It has no internal-network, endpoint, CASB or EDR visibility, so unmanaged software that leaves no external trace cannot be seen.";

// Build a snapshot in the exact shape the renderer reads. `opts` toggles coverage.
function mkSnap({ complete = false, weakEmpty = true, pad = 0 } = {}) {
  return {
    snapshot: { domain: "cybermeters.com", as_of: "2026-07-19 20:30:00", built_at: "2026-07-19 20:37:32", provenance: "canonical" },
    overall: {
      cyber_metrics_score: 78, score_band: "B",
      assessment: { provisional: !complete, message: complete ? null : "Provisional score - evidence incomplete." },
      summary: "Two issues detected across the assessed domains.",
      business_risk_indicator: {
        band: "Low Business Risk",
        explanation: weakEmpty
          ? "Business risk posture is low risk. No major gaps detected across email security, website trust, operational continuity, attack surface, or brand protection."
          : "Business risk posture is low risk. Primary concerns are in email security and website trust.",
      },
      evidence_completeness: complete
        ? { scan_quality: "complete", modules_skipped: [] }
        : { scan_quality: "partial", modules_skipped: ["asset_exposure"] },
      not_fully_assessed: complete ? [] : [1, 2, 3, 4, 5, 6].map((i) => ({ domain_key: "d" + i })),
    },
    domains: DOMAINS.map((n, i) => ({
      domain_key: "d" + i, display_name: n,
      state: i < 2 ? "issue_detected" : (complete ? "assessed_healthy" : "evidence_insufficient"),
      // Pad early domains with filler limitations to push later blocks near page boundaries.
      limitations: n.startsWith("Shadow IT")
        ? [SHADOW_LIMIT]
        : (pad && i < 4 ? Array.from({ length: pad }, (_, k) => `Filler limitation ${i}.${k}: this domain check is externally scoped and does not inspect internal systems, so absence of a finding is not proof of absence of risk.`) : []),
    })),
    observed_findings: [], observations: [],
    remediation_actions: [{ priority: "high", title: "Publish a DMARC reject policy", action: "Move your DMARC policy to p=reject after a monitoring period." }],
    limitations: ["This snapshot records what CyberMeters externally observed at the assessment time shown; it is not a certification."],
    methodology: { cyber_mot_resolver_version: "2026-07-16.2", cyber_metrics_score_methodology_version: "2026-07-16.1", business_risk_methodology_version: "2026-07-16.1" },
  };
}
const readOf = (snap) => ({ status: "ok", snapshot: snap, row: { id: "s1" }, integrity: {} });
// Prepared canonical logo (flattened over white, like the production route).
const LOGO_IMAGE = await prepareLogoXObject(CYBERMETERS_LOGO_DATA_URI, "#FFFFFF");
const render = (snap, extra = {}) => buildWorkspaceExecutivePdf({
  workspaceName: "A4 Managed Case Test", reads: [readOf(snap)],
  branding: { mode: "cybermeters", accent: "#1568C7" }, generatedAt: "2026-07-19 20:37:32", ...extra,
});
const latin1 = (bytes) => Buffer.from(bytes).toString("latin1");
// Per-page visible text: split content streams, pull each page's `(…) Tj` fragments.
function pageTexts(bytes) {
  const s = latin1(bytes);
  const streams = [...s.matchAll(/stream\n([\s\S]*?)\nendstream/g)].map((m) => m[1]);
  return streams.map((st) => [...st.matchAll(/\(((?:\\.|[^()\\])*)\) Tj/g)].map((m) => m[1]).join(" "));
}
const norm = (s) => s.replace(/\s+/g, " ").trim();

// ── A. Evidence-honest narrative — incomplete coverage ────────────────────────
{
  const bytes = render(mkSnap({ complete: false }));
  const t = latin1(bytes);
  ok("A incomplete: valid PDF", t.startsWith("%PDF-1.4") && t.trimEnd().endsWith("%%EOF"));
  ok("A incomplete: unqualified 'No major gaps detected' is NOT printed", !t.includes("No major gaps detected"));
  ok("A incomplete: evidence-bounded narrative is printed",
     t.includes("No major gaps were identified in the evidence available"));
  ok("A incomplete: narrative states coverage is incomplete / not confirmation",
     t.includes("Coverage is incomplete") && t.includes("material gaps exist"));
  ok("A incomplete: provisional wording preserved", t.includes("Provisional") || t.includes("provisional"));
  // Missing evidence never healthy: at least one domain reads 'Evidence insufficient', none of the
  // not-fully-assessed domains reads 'no material issue observed'.
  ok("A incomplete: missing evidence rendered as insufficient, never healthy",
     t.includes("Evidence insufficient") && !t.includes("Shadow IT & Unmanaged Technology: Assessed - no material issue"));
}

// ── A. Complete coverage keeps the frozen honest explanation verbatim ─────────
{
  const t = latin1(render(mkSnap({ complete: true })));
  ok("A complete: frozen 'No major gaps detected' explanation IS shown when coverage is complete",
     t.includes("No major gaps detected"));
  ok("A complete: does not force the incomplete-coverage caveat",
     !t.includes("No major gaps were identified in the evidence available"));
}

// ── B. Controlled page breaks — no limitation splits across a page boundary ───
{
  // Padded fixture spans multiple pages and pushes limitations near boundaries.
  const bytes = render(mkSnap({ complete: false, pad: 6 }));
  const pages = pageTexts(bytes).map(norm);
  ok("B: report spans multiple pages (pagination actually exercised)", pages.length >= 2);
  // Every domain limitation must be fully contained within a single page.
  const allLimits = [SHADOW_LIMIT];
  let allWhole = true;
  for (const lim of allLimits) {
    const whole = pages.some((p) => p.includes(norm(`Limitation: ${lim}`)));
    if (!whole) allWhole = false;
  }
  ok("B: the Shadow IT limitation renders as ONE unsplit block on a single page", allWhole);
  // Specifically the founder defect: 'No' must not be the last word of a page with
  // 'internal-network' opening the next.
  const splitAfterNo = pages.some((p, i) => i + 1 < pages.length && /\bIt has no\s*$/.test(p) && /^internal-network/.test(pages[i + 1]));
  ok("B: no page ends on 'It has no' with the next page continuing 'internal-network'", !splitAfterNo);
  // Copy correction: lowercase 'no' mid-sentence (the fixture grammar the founder flagged).
  ok("B: Shadow IT limitation uses lowercase 'it has no internal-network'",
     pages.some((p) => p.includes("It has no internal-network")) && !pages.some((p) => p.includes("It has No internal-network")));
}

// ── D. Branded cover ──────────────────────────────────────────────────────────
{
  const t = latin1(render(mkSnap({ complete: false })));
  ok("D: canonical CyberMeters wordmark present", t.includes("CyberMeters"));
  ok("D: report title present", t.includes("Executive Security Report"));
  ok("D: workspace label present", t.includes("Workspace:  A4 Managed Case Test") || t.includes("A4 Managed Case Test"));
  ok("D: primary domain present", t.includes("cybermeters.com"));
  ok("D: report-generated timestamp present", t.includes("Report generated:") || t.includes("Generated"));
}

// ── E. No visible internal version identifiers ────────────────────────────────
{
  const t = latin1(render(mkSnap({ complete: false })));
  ok("E: no 'Resolver 2026-' version string", !/Resolver 2026-/.test(t));
  ok("E: no 'Score methodology 2026-' version string", !/Score methodology 2026-/.test(t));
  ok("E: no 'Risk indicator methodology 2026-' version string", !/Risk indicator methodology 2026-/.test(t));
}

// ── Preserved good behaviour ──────────────────────────────────────────────────
{
  const t = latin1(render(mkSnap({ complete: false })));
  ok("preserved: all eight canonical domain names present", DOMAINS.every((d) => t.includes(d)));
  ok("preserved: no Scotist Ltd", !/Scotist/i.test(t));
  // Banned over-reassuring absolutes / positive certification CLAIMS. The honest
  // disclaimer "it is not a certification" is required and must NOT be flagged.
  ok("preserved: no over-reassuring absolute / certification claim",
     !/fully secure|all clear|no risks|is certified|certification (?:achieved|passed|granted)/i.test(t));
  ok("preserved: honest 'not a certification' disclaimer present", /not a certification/i.test(t));
  ok("preserved: assessment date present", t.includes("Assessment date:") || t.includes("Assessed"));
  // Scan PDF (shared sections) is not broken by the shared-section changes.
  const scan = latin1(buildScanReportPdf({ domain: "cybermeters.com" }, readOf(mkSnap({ complete: false })), { mode: "cybermeters", accent: "#1568C7" }, null));
  ok("regression: scan PDF still valid + carries wordmark + all eight domains",
     scan.startsWith("%PDF-1.4") && scan.trimEnd().endsWith("%%EOF") && scan.includes("CyberMeters") && DOMAINS.every((d) => scan.includes(d)));
  ok("regression: scan PDF also omits the version string", !/Resolver 2026-/.test(scan));
}

// ── D2. Canonical logo embedded on the cover ─────────────────────────────────
{
  const bytes = render(mkSnap({ complete: false }), { logoImage: LOGO_IMAGE });
  const t = latin1(bytes);
  ok("D2: generated PDF contains a logo image XObject", t.includes("/Subtype /Image"));
  ok("D2: the cover draws the embedded logo (/Im0 Do)", t.includes("/Im0 Do"));
  ok("D2: valid PDF with the image embedded", t.startsWith("%PDF-1.4") && t.trimEnd().endsWith("%%EOF"));
  // Logo image is the canonical asset at its committed dimensions (not cropped/stretched).
  ok("D2: embedded image is the canonical asset dimensions",
     t.includes(`/Width ${CYBERMETERS_LOGO_DIMENSIONS.width} /Height ${CYBERMETERS_LOGO_DIMENSIONS.height}`));
  // Logo stays within the cover bounds: uniform scale, capped at 300x70pt, inside the
  // 504pt content width — assert the cm matrix width/height are within the cap.
  const cm = t.match(/q (\d+) 0 0 (\d+) \d+ \d+ cm \/Im0 Do Q/);
  ok("D2: logo drawn with a uniform-scaled matrix within the cover cap (<=300x70pt)",
     !!cm && Number(cm[1]) <= 300 && Number(cm[2]) <= 70 && Number(cm[1]) >= 1 && Number(cm[2]) >= 1);
  // Aspect preserved (no distortion): drawn ratio ~= source ratio.
  const srcRatio = CYBERMETERS_LOGO_DIMENSIONS.width / CYBERMETERS_LOGO_DIMENSIONS.height;
  ok("D2: logo aspect ratio preserved (not stretched)",
     !!cm && Math.abs((Number(cm[1]) / Number(cm[2])) - srcRatio) < 0.15);
}

// ── D3. Default CyberMeters branding → canonical logo (executive route contract) ─
{
  const descriptor = cyberMetersDescriptor();
  ok("D3: default descriptor is mode 'cybermeters' with no customer R2 logo key",
     descriptor.mode === "cybermeters" && !descriptor.logo_r2_key);
  // The executive routes inject the embedded house logo exactly when the branding
  // has no customer logo AND mode is cybermeters. Replicate that resolution:
  let dataUri = await loadBrandingLogoDataUri(null, descriptor); // null for the house descriptor
  if (!dataUri && descriptor.mode === "cybermeters") dataUri = CYBERMETERS_LOGO_DATA_URI;
  ok("D3: default branding resolves to the canonical logo data URI",
     dataUri === CYBERMETERS_LOGO_DATA_URI && /^data:image\/png;base64,/.test(dataUri || ""));
  const img = await prepareLogoXObject(dataUri, "#FFFFFF");
  ok("D3: the canonical logo prepares to a DeviceRGB image at committed dimensions",
     !!img && img.width === CYBERMETERS_LOGO_DIMENSIONS.width && img.height === CYBERMETERS_LOGO_DIMENSIONS.height && img.colorSpace === "DeviceRGB");
}

// ── D4. Text wordmark fallback when logo preparation fails ────────────────────
{
  // No prepared logo (image decode/prep failed) → the cover falls back to the
  // CyberMeters text wordmark, never a blank identity slot.
  const t = latin1(render(mkSnap({ complete: false }))); // render() passes no logoImage
  ok("D4: fallback path draws no image XObject", !t.includes("/Im0 Do"));
  ok("D4: fallback shows the CyberMeters text wordmark", t.includes("CyberMeters"));
  ok("D4: fallback PDF is still valid", t.startsWith("%PDF-1.4") && t.trimEnd().endsWith("%%EOF"));
}

// ── Asset integrity: the embedded data URI is the exact committed PNG ─────────
{
  const pngPath = path.join(root, "workers", "scan-api", "src", "assets", "cybermeters-logo-full-pdf@2x.png");
  ok("asset: committed canonical PNG exists at the Worker asset path", fs.existsSync(pngPath));
  const b64 = String(CYBERMETERS_LOGO_DATA_URI).replace(/^data:image\/png;base64,/, "");
  const fromUri = Buffer.from(b64, "base64");
  const fromFile = fs.readFileSync(pngPath);
  const shaUri = crypto.createHash("sha256").update(fromUri).digest("hex");
  ok("asset: embedded data URI decodes to the exact committed PNG (no drift)", fromUri.equals(fromFile));
  ok("asset: data URI sha256 matches the module's declared CYBERMETERS_LOGO_SHA256", shaUri === CYBERMETERS_LOGO_SHA256);
}

// ── No retired weekly-PDF content ─────────────────────────────────────────────
{
  const t = latin1(render(mkSnap({ complete: false }), { logoImage: LOGO_IMAGE }));
  const RETIRED = ["Vendor Risk", "Supply Chain", "supply-chain posture", "Five-Pillar", "five-category", "cybermeters.io", "Report ID", "customer logo placeholder"];
  for (const s of RETIRED) ok(`no-retired: '${s}' does not appear`, !t.includes(s));
  ok("no-retired: footer domain is app.cybermeters.com (not cybermeters.io)", t.includes("app.cybermeters.com") && !t.includes("cybermeters.io"));
}

// ── Copy correction: limitation punctuation renders correctly (no dash-loss) ──
// The ASCII-only PDF renderer strips a non-ASCII em-dash to a space, so a source
// "only — no" rendered as a malformed "only  no". The canonical limitation copy in
// cyber-mot-domains.js must use ASCII punctuation (a semicolon) so it renders clean.
{
  // Source-level: the two flagged domain limitations are ASCII with a semicolon.
  const allLimits = CYBER_MOT_DOMAINS.flatMap((d) => d.limitations || []);
  const extObs = allLimits.find((l) => l.startsWith("External observation only"));
  const passive = allLimits.find((l) => l.startsWith("Passive external check only"));
  ok("copy: canonical Attack-Surface limitation is ASCII with a semicolon",
     extObs === "External observation only; no internal-network discovery. Subdomain coverage depends on public Certificate Transparency logs.");
  ok("copy: canonical Website-Security limitation is ASCII with a semicolon",
     passive === "Passive external check only; no active, authenticated or intrusive testing.");
  ok("copy: no non-ASCII in either flagged limitation (no em/en dash to strip)",
     !/[^\x00-\x7F]/.test(extObs || "x") && !/[^\x00-\x7F]/.test(passive || "x"));

  // Rendered: the corrected sentences appear in the Executive PDF; the malformed
  // double-space variants are absent. Render a fixture carrying the REAL limitations.
  const snap = mkSnap({ complete: false });
  snap.domains[2].limitations = [extObs];   // Attack Surface
  snap.domains[5].limitations = [passive];  // Website Security
  const pages = pageTexts(render(snap, { logoImage: LOGO_IMAGE })).map(norm);
  const joined = pages.join(" ");
  ok("copy: corrected 'External observation only; no internal-network discovery' in PDF",
     joined.includes("External observation only; no internal-network discovery"));
  ok("copy: corrected 'Passive external check only; no active, authenticated or intrusive testing' in PDF",
     joined.includes("Passive external check only; no active, authenticated or intrusive testing"));
  ok("copy: malformed double-space 'External observation only  no' absent",
     !/External observation only\s{2,}no/.test(joined) && !joined.includes("External observation only  no"));
  ok("copy: malformed double-space 'Passive external check only  no' absent",
     !/Passive external check only\s{2,}no/.test(joined) && !joined.includes("Passive external check only  no"));
  // Regressions still hold with the real limitations present.
  const t = latin1(render(snap, { logoImage: LOGO_IMAGE }));
  ok("copy: all eight domains still present", DOMAINS.every((d) => t.includes(d)));
  ok("copy: canonical logo image still embedded", t.includes("/Subtype /Image") && t.includes("/Im0 Do"));
  ok("copy: two-page fixture remains balanced", (t.match(/\/Type \/Page \/Parent/g) || []).length === 2);
}

console.log(`\nvalidate-a5-executive-report: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
