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
//      evidence-bounded statement. Frozen conclusions remain in the per-area view;
//      no score/band recomputation or combined workspace verdict.
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
const { buildWorkspaceExecutivePdf, buildScanReportPdf, pdfEsc } = await eng("pdf.js");
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
     t.includes("A missing check is not a clean result"));
  ok("A incomplete: narrative states coverage is incomplete / not confirmation",
     t.includes("Coverage is incomplete") && t.includes("limited to the evidence available"));
  ok("A incomplete: provisional wording preserved", t.includes("Provisional") || t.includes("provisional"));
  // Missing evidence never healthy: at least one domain reads 'Evidence insufficient', none of the
  // not-fully-assessed domains reads 'no material issue observed'.
  ok("A incomplete: missing evidence rendered as insufficient, never healthy",
     t.includes("Evidence insufficient") && !t.includes("Shadow IT & Unmanaged Technology: Assessed - no material issue"));
}

// ── A. Complete coverage keeps the frozen honest explanation verbatim ─────────
{
  const t = latin1(render(mkSnap({ complete: true })));
  ok("A complete: brief describes recorded evidence without claiming risk absence",
     t.includes("Recorded coverage") && t.includes("does not establish an absence of risk"));
  ok("A complete: does not force the incomplete-coverage caveat",
     !t.includes("No major gaps were identified in the evidence available"));
}

// ── B. Concise executive scope; full limitations remain in technical PDF ──
{
  const snap = mkSnap({ complete: false, pad: 6 });
  const pages = pageTexts(render(snap)).map(norm);
  ok("B: ordinary single-website brief has two pages", pages.length === 2);
  ok("B: brief directs readers to the complete technical evidence",
     pages.join(" ").includes("download the technical PDF") && pages.join(" ").includes("no internal-network assessment or penetration test"));
  const technical = pageTexts(buildScanReportPdf({ domain: "cybermeters.com" }, readOf(snap))).map(norm);
  ok("B: Shadow IT limitation stays whole in the full technical report",
     technical.some((p) => p.includes(norm(`Limits: ${SHADOW_LIMIT}`))));
  ok("B: long technical limitations do not inflate the executive brief",
     !pages.join(" ").includes("Filler limitation"));
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
  const pages = pageTexts(buildScanReportPdf({ domain: "cybermeters.com" }, readOf(snap), null, LOGO_IMAGE)).map(norm);
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
  ok("copy: executive brief stays two pages while technical copy remains complete",
     (t.match(/\/Type \/Page \/Parent/g) || []).length === 2);
}

// ── Typographic punctuation → ASCII (trust-closure episode) ──────────────────
// The ASCII stream encoder used to strip EVERY non-ASCII byte to a space, so
// "scan — not enough to assess" rendered "scan   not enough" — punctuation
// vanished, leaving a malformed double space (the class behind the certificate
// evidence-insufficient and DMARC could-not-be-observed sentences). pdfEsc now
// transliterates the common typographic characters; these pins keep the class
// closed for every current and future sentence.
{
  ok("pdfEsc: em dash transliterates, no double space",
     pdfEsc("scan — not enough to assess.") === "scan - not enough to assess.");
  ok("pdfEsc: the DMARC could-not-be-observed sentence renders intact",
     pdfEsc("DMARC could not be observed this scan (the DNS lookup did not complete) — not enough to assess.")
       === "DMARC could not be observed this scan \\(the DNS lookup did not complete\\) - not enough to assess.");
  ok("pdfEsc: en dash, curly quotes and ellipsis transliterate",
     pdfEsc("2–3 ‘quoted’ “words”…") === `2-3 'quoted' "words"...`);
  ok("pdfEsc: arrows and comparators transliterate", pdfEsc("a → b ≠ c") === "a -> b != c");
  ok("pdfEsc: unmapped non-ASCII still falls back to a space (never dropped)", pdfEsc("a☃b") === "a b");
  ok("pdfEsc: PDF escaping is preserved after transliteration",
     pdfEsc("(x) \\ y") === "\\(x\\) \\\\ y");
  ok("pdfEsc: no transliterated sentence produces a double space",
     !/\s{2}/.test(pdfEsc("Required evidence (certificate_chain) could not be collected this scan — not enough to assess.")));
}

// ── Decision brief: exact executive bytes, projection and adverse inputs ──
{
  // Captured from accepted executive commit c32ad27b. The subsequent authorized
  // technical-report redesign must not rewrite the executive decision brief.
  const executiveGolden = {
    false: "ce31f504991d594d67db4db639be159e25b6849cb2fff25f4fe0cf6dde704227",
    true: "bcc8a0fbe59e47311cdc96e3cace8f889a7f95a529038cfc93b0478e22cf4949",
  };
  for (const complete of [false, true]) {
    const bytes = render(mkSnap({ complete }));
    ok(`executive byte golden: complete=${complete}`,
      crypto.createHash("sha256").update(bytes).digest("hex") === executiveGolden[complete]);
  }
  const snap = mkSnap({ complete: false });
  snap.snapshot.scan_id = "scan-decision-fixture";
  snap.observed_findings = [
    { finding_id: "medium", severity: "medium", domain_keys: ["d2"] },
    { finding_id: "urgent", severity: "critical", domain_keys: ["d0"] },
  ];
  snap.observations = [{ finding_id: "observation-only", severity: "critical" }];
  snap.remediation_actions = [
    { priority: "low", title: "Low action", action: "Keep this in the full technical report." },
    { priority: "medium", title: "Medium action" },
    { priority: "high", title: "High action" },
    { priority: "critical", title: "Critical action last in input", verification_ceiling: "External verification only." },
  ];
  snap.domains[2] = { ...snap.domains[2], state: "issue_detected", finding_count: 1,
    coverage: "partial", summary: "Verified DNS absence. HTTP was not tested; no healthy web-service conclusion is made." };
  snap.domains[6].summary = "Identity reachability was not evaluated — no supported reachability producer is implemented. Provider relationships and possible hostnames remain visible for review.";
  const before = JSON.stringify(snap);
  const rendered = render(snap), text = latin1(rendered);
  const visible = pageTexts(rendered).map(norm).join(" ");
  ok("brief determinism and input immutability", Buffer.from(rendered).equals(Buffer.from(render(snap))) && JSON.stringify(snap) === before);
  ok("brief urgent priority survives adverse input order", text.indexOf("Critical action last in input") < text.indexOf("High action") && text.indexOf("High action") < text.indexOf("Medium action") && !text.includes("Low action"));
  ok("brief explicitly declares remaining actions", text.includes("1 further recorded action"));
  ok("brief finding and observation counts remain separate", visible.includes("2 Recorded findings 1 High / critical findings 1 Observation"));
  ok("brief retains action verification ceiling", text.includes("External verification only."));
  ok("brief translates Unicode-dash implementation copy without changing the snapshot",
    visible.includes("Sign-in endpoint reachability was not assessed; provider relationships and possible hostnames remain visible for review.") &&
    !visible.includes("producer is implemented") && snap.domains[6].summary.includes("producer is implemented"));
  ok("brief retains DNS absence and no-HTTP limitation", visible.includes(snap.domains[2].summary));
  ok("brief medium issue uses amber, not critical red", text.includes("0.60 0.36 0.08 rg"));
  ok("brief source reference and correct website scope", text.includes("scan-decision-fixture") && text.includes("Latest assessed website") && !text.includes("Workspace risk score"));
  ok("brief has no technical appendices or internal methodology strings", !text.includes("Technical Appendix") && !text.includes("Cited authorities:") && !text.includes("2026-07-16.2"));
  const projected = structuredClone(snap);
  projected.overall.cyber_metrics_score = null;
  projected.overall.score_band = null;
  const projectedText = latin1(render(snap, { reads: [{ ...readOf(snap), customerSnapshot: projected }] }));
  ok("brief uses customer projection, never revives raw score", !projectedText.includes("78 / 100") && projectedText.includes("Coverage is incomplete"));
  const complete = mkSnap({ complete: true });
  ok("brief does not invent incomplete coverage from absent legacy per-area coverage", !latin1(render(complete)).includes("Coverage is incomplete"));
  const missing = structuredClone(complete);
  delete missing.overall.evidence_completeness;
  missing.domains.pop();
  const missingText = latin1(render(missing));
  ok("brief missing evidence is explicit with all eight areas", missingText.includes("Coverage is incomplete") && missingText.includes("Not assessed - no recorded area evidence") && DOMAINS.every((name) => missingText.includes(name)));
  const old = structuredClone(snap);old.snapshot.domain = "older.example";old.snapshot.as_of = "2026-07-18T12:00:00Z";
  const multi = latin1(render(snap, { reads: [readOf(old), { status: "integrity_error", domain_id: "unavailable.example" }, readOf(snap), { status: "building", domain_id: "pending.example" }] }));
  ok("brief latest assessment selected independently of input order", multi.indexOf("cybermeters.com") < multi.indexOf("older.example"));
  ok("brief never omits another supplied website or unavailable entry", ["older.example", "unavailable.example", "pending.example", "still being prepared", "not available"].every((name) => multi.includes(name)));
  ok("brief additional sites retain their own areas without duplicating the workspace summary", (multi.match(/Eight-Domain Cyber MOT/g) || []).length === 2 && (multi.match(/Recorded findings/g) || []).length === 1);
  const newestQuiet = mkSnap({ complete: true });
  newestQuiet.snapshot.domain = "latest-quiet.example";
  newestQuiet.remediation_actions = [{ priority: "low", title: "Routine latest action" }];
  const olderUrgent = structuredClone(old);
  olderUrgent.remediation_actions = [{ priority: "critical", title: "Urgent older website action", action: "Protect the exposed service." }];
  const portfolioPages = pageTexts(render(snap, { reads: [readOf(newestQuiet), readOf(olderUrgent)] })).map(norm);
  ok("brief non-leading website critical action is on page one with its origin", portfolioPages[0].includes("Urgent older website action") && portfolioPages[0].includes("Website: older.example") && portfolioPages[0].indexOf("Urgent older website action") < portfolioPages[0].indexOf("Routine latest action"));
  ok("brief two websites use one overview plus two area pages", portfolioPages.length === 3);
  ok("brief cross-site counts are explicitly limited to included assessments", portfolioPages[0].includes("Recorded across the assessments below") && portfolioPages[0].includes("not a complete asset inventory"));
  const d1Date = structuredClone(old), isoDate = structuredClone(old);
  d1Date.snapshot.domain = "actually-later.example";d1Date.snapshot.as_of = "2026-10-08 22:00:00";
  isoDate.snapshot.domain = "earlier-iso.example";isoDate.snapshot.as_of = "2026-10-08T21:00:00Z";
  const mixedDates = pageTexts(render(snap, { reads: [readOf(isoDate), readOf(d1Date)] })).map(norm).join(" ");
  ok("brief latest website compares D1 UTC and ISO dates chronologically", mixedDates.includes("Latest assessed website: actually-later.example") && mixedDates.indexOf("actually-later.example") < mixedDates.indexOf("earlier-iso.example"));
  const noData = pageTexts(render(snap, { reads: [] })).map(norm).join(" ");
  ok("brief empty workspace has no security verdict", noData.includes("No security conclusion") && !noData.includes("78 / 100"));
  const changeText = pageTexts(render(snap, { relatedChanges: { items: [
    { rule_id: "new_host_with_cert", affected_domain: "elsewhere.example", last_seen: "2026-07-20T10:00:00Z" },
    { rule_id: "new_host_with_identity", affected_domain: "old-change.example", last_seen: "2026-07-18T10:00:00Z" },
  ] } })).map(norm).join(" ");
  ok("brief changes retain workspace scope and most-recent affected website", changeText.includes("2 related changes recorded across the workspace") && changeText.includes("elsewhere.example") && changeText.includes("change is not proof of compromise"));
  const verbose = mkSnap({ complete: false });
  verbose.domains[7].summary = "Recorded evidence. ".repeat(180) + "IMPORTANT_FINAL_LIMIT";
  const verboseText = latin1(render(verbose));
  ok("brief exceptional long evidence continues without silent clipping", verboseText.includes("IMPORTANT_FINAL_LIMIT") && (verboseText.match(/\/Type \/Page \/Parent/g) || []).length > 2);
}

console.log(`\nvalidate-a5-executive-report: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
