// ── PDF generation engine (snapshot-native, M5.d) ──
// Raw-PDF (no library) generation. Since M5.d every PDF renders the canonical
// immutable reporting snapshot (engines/report-snapshot.js) — this module owns
// NO calculation brain: no score, band, BRI, CE, domain-state, taxonomy,
// remediation or trend derivation happens here. It formats frozen facts.
//
// The legacy builders and their recalculation imports (posture scoring,
// scorecard, live resolvers, scan-path risk re-derivation, registry-by-title
// joins, five-category posture, four-service palette) are DELETED, not merely
// unreferenced — the M5.c defect class was renderers re-deriving truth, and
// dead brains drift back to life.
//
// Determinism: rendering a given snapshot twice yields identical bytes. The
// only permitted live inputs are presentation metadata under the documented
// frozen-vs-live policy — white-label branding (logo/company name/accent) and
// the workspace display name. No clock is read here; every date printed comes
// from the snapshot (as_of / built_at) or an explicit caller argument.

function pdfEsc(v) {
  return String(v == null ? "" : v)
    .replace(/[^\x20-\x7E]/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

/** Return [r, g, b] as 0-1 floats from a #RRGGBB string. */
function hexToRgbF(hex) {
  const h = hex.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16) / 255,
    parseInt(h.slice(2, 4), 16) / 255,
    parseInt(h.slice(4, 6), 16) / 255,
  ];
}

/**
 * Assemble a PDF 1.4 document from an array of content-stream strings.
 *
 * Fixed object layout (1-indexed):
 *   1  = Catalog
 *   2  = Pages tree
 *   3  = /F1  Helvetica        (regular)
 *   4  = /F2  Helvetica-Bold   (bold)
 *   For page i (0-based):
 *     5 + i*2     = content stream object
 *     5 + i*2 + 1 = page object
 *
 * All stream content must be ASCII-only (guaranteed by pdfEsc) so
 * stream.length === byte length and TextEncoder output is identical.
 */
export function assemblePdf(streams) {
  const n   = streams.length;
  const cId = (i) => 5 + i * 2;       // content stream object id
  const pId = (i) => 5 + i * 2 + 1;  // page object id
  const totalObjs = 4 + n * 2;

  let out      = "%PDF-1.4\n";
  const offsets = {};

  const addObj = (id, data) => {
    offsets[id] = out.length;
    out += `${id} 0 obj\n${data}\nendobj\n`;
  };

  addObj(1, "<< /Type /Catalog /Pages 2 0 R >>");
  addObj(
    2,
    `<< /Type /Pages /Kids [${Array.from({ length: n }, (_, i) => `${pId(i)} 0 R`).join(" ")}] /Count ${n} >>`
  );
  addObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
  addObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");

  for (let i = 0; i < n; i++) {
    const s = streams[i];
    addObj(cId(i), `<< /Length ${s.length} >>\nstream\n${s}\nendstream`);
    addObj(
      pId(i),
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
      `/Contents ${cId(i)} 0 R ` +
      `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>`
    );
  }

  // Cross-reference table — each entry is exactly 20 bytes
  const xrefPos = out.length;
  out += `xref\n0 ${totalObjs + 1}\n`;
  out += "0000000000 65535 f \n";
  for (let i = 1; i <= totalObjs; i++) {
    out += (offsets[i] || 0).toString().padStart(10, "0") + " 00000 n \n";
  }
  out +=
    `trailer\n<< /Size ${totalObjs + 1} /Root 1 0 R >>\n` +
    `startxref\n${xrefPos}\n%%EOF`;

  return out;
}

/**
 * Binary variant of assemblePdf that embeds a single Image XObject (/Im0) and
 * references it from every page's /Resources. Used only when a white-label logo
 * is present — the text-only path stays on assemblePdf. Content streams remain
 * ASCII (the image is a separate binary object), so offsets are byte-exact.
 *
 * `image` = { width, height, colorSpace, bitsPerComponent, filter, bytes:Uint8Array }.
 * Returns a Uint8Array.
 */
export function assemblePdfWithImage(streams, image) {
  const enc = new TextEncoder();
  const chunks = [];
  let len = 0;
  const push = (chunk) => { const u = typeof chunk === "string" ? enc.encode(chunk) : chunk; chunks.push(u); len += u.length; };

  const n = streams.length;
  const cId = (i) => 5 + i * 2;
  const pId = (i) => 5 + i * 2 + 1;
  const imgId = 4 + n * 2 + 1;          // first object after the pages
  const totalObjs = 4 + n * 2 + 1;      // + the image
  const offsets = {};
  const addObj = (id, data) => { offsets[id] = len; push(`${id} 0 obj\n${data}\nendobj\n`); };

  push("%PDF-1.4\n");
  addObj(1, "<< /Type /Catalog /Pages 2 0 R >>");
  addObj(2, `<< /Type /Pages /Kids [${Array.from({ length: n }, (_, i) => `${pId(i)} 0 R`).join(" ")}] /Count ${n} >>`);
  addObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
  addObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");

  for (let i = 0; i < n; i++) {
    const s = streams[i];
    addObj(cId(i), `<< /Length ${enc.encode(s).length} >>\nstream\n${s}\nendstream`);
    addObj(
      pId(i),
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
      `/Contents ${cId(i)} 0 R ` +
      `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> /XObject << /Im0 ${imgId} 0 R >> >> >>`
    );
  }

  // Binary image XObject.
  offsets[imgId] = len;
  push(
    `${imgId} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${image.width} /Height ${image.height} ` +
    `/ColorSpace /${image.colorSpace} /BitsPerComponent ${image.bitsPerComponent} ` +
    `/Filter /${image.filter} /Length ${image.bytes.length} >>\nstream\n`
  );
  push(image.bytes);
  push("\nendstream\nendobj\n");

  const xrefPos = len;
  let xref = `xref\n0 ${totalObjs + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= totalObjs; i++) xref += (offsets[i] || 0).toString().padStart(10, "0") + " 00000 n \n";
  push(xref);
  push(`trailer\n<< /Size ${totalObjs + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF`);

  const out = new Uint8Array(len);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/**
 * pdfUtcDate(value, withTime) — shared timestamp formatter for every PDF
 * builder. D1 timestamps ("YYYY-MM-DD HH:MM:SS") carry no zone marker but are
 * UTC; interpret them as such, and always label rendered times explicitly so a
 * reader in any timezone knows the reference. British date style, ASCII-only
 * (the hand-rolled PDF engine's fonts are ASCII-safe).
 *   pdfUtcDate("2026-07-06 14:12:48")        → "6 July 2026"
 *   pdfUtcDate("2026-07-06 14:12:48", true)  → "6 July 2026, 14:12 UTC"
 */
export function pdfUtcDate(value, withTime = false) {
  if (!value) return "";
  const s = String(value);
  const d = new Date(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(s) ? s.replace(" ", "T") + "Z" : s);
  if (Number.isNaN(d.getTime())) return s.slice(0, 10);
  const MONTHS = ["January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"];
  const date = `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
  if (!withTime) return date;
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${date}, ${hh}:${mm} UTC`;
}

// ── Shared layout writer ─────────────────────────────────────────────────────
// A tiny paginating text writer over the ASCII content-stream model: tracks the
// cursor, auto page-breaks, and keeps every draw call one-line simple. Purely
// presentational — no data interpretation.
const PAGE_W = 612, PAGE_H = 792, MARGIN = 54, FOOT = 60;
const BRAND_HEX = "#1568C7";

const DEFAULT_FOOTER = "Generated by CyberMeters | app.cybermeters.com";
function makeWriter({ accentHex = BRAND_HEX, footerText = DEFAULT_FOOTER } = {}) {
  const [ar, ag, ab] = hexToRgbF(accentHex);
  const pages = [];
  let buf = "";
  let y = 0;

  const footer = () =>
    `BT /F1 8 Tf 0.45 0.5 0.55 rg ${MARGIN} 30 Td (${pdfEsc(footerText)}) Tj ET\n`;
  const newPage = () => {
    if (buf) pages.push(buf + footer());
    buf = "";
    y = PAGE_H - MARGIN;
  };
  newPage();

  const ensure = (h) => { if (y - h < FOOT) newPage(); };
  const text = (str, { size = 10, bold = false, color = "0.10 0.12 0.16", indent = 0, gap = 4 } = {}) => {
    const line = String(str ?? "");
    ensure(size + gap);
    y -= size + gap;
    buf += `BT /${bold ? "F2" : "F1"} ${size} Tf ${color} rg ${MARGIN + indent} ${y} Td (${pdfEsc(line)}) Tj ET\n`;
  };
  // Wrap prose at ~92 chars for 10pt Helvetica in the content width.
  const prose = (str, opts = {}) => {
    const width = opts.width ?? 92;
    const words = String(str ?? "").split(/\s+/);
    let line = "";
    for (const w of words) {
      if ((line + " " + w).trim().length > width) { text(line.trim(), opts); line = w; }
      else line = `${line} ${w}`;
    }
    if (line.trim()) text(line.trim(), opts);
  };
  const heading = (str) => {
    ensure(26);
    y -= 22;
    buf += `${ar} ${ag} ${ab} rg ${MARGIN} ${y - 4} ${PAGE_W - 2 * MARGIN} 1.5 re f\n`;
    buf += `BT /F2 13 Tf 0.08 0.10 0.14 rg ${MARGIN} ${y} Td (${pdfEsc(str)}) Tj ET\n`;
    y -= 6;
  };
  const gap = (h = 8) => { ensure(h); y -= h; };
  // Raw content-stream ops (logo XObject drawing) — presentation only.
  const raw = (op) => { buf += op; };
  const finish = () => { if (buf) { pages.push(buf + footer()); buf = ""; } return pages; };
  return { text, prose, heading, gap, newPage, finish, raw };
}

// Customer-safe state labels for the canonical domain states. Display mapping
// only — the STATE ITSELF is the snapshot's frozen fact.
const STATE_LABEL = {
  assessed_healthy: "Assessed - no material issue observed",
  issue_detected: "Issue detected",
  provisional: "Provisional",
  degraded: "Degraded",
  unavailable: "Unavailable",
  not_configured: "Not configured",
  customer_input_required: "Customer input required",
  monitoring_only: "Monitoring only",
  not_yet_assessed: "Not yet assessed",
  evidence_insufficient: "Evidence insufficient",
};
const stateLabel = (s) => STATE_LABEL[s] || "Unknown";

// ── Shared snapshot sections ─────────────────────────────────────────────────
// One implementation of each report section, consumed by BOTH PDF builders so
// the scan PDF and the workspace executive PDF can never disagree on meaning.

function sectionOverall(w, snap) {
  const o = snap.overall || {};
  const scoreText = o.cyber_metrics_score == null
    ? "Not available for this assessment"
    : `${o.cyber_metrics_score} / 100`;
  w.text(`${o.assessment?.provisional ? "Provisional Score" : "Cyber Metrics Score"}: ${scoreText}`, { size: 14, bold: true });
  if (o.score_band) w.text(`Security rating: ${o.score_band}`, { size: 11 });
  if (o.assessment?.message) w.prose(o.assessment.message, { size: 9, color: "0.45 0.35 0.10" });
  w.gap(4);
  const bri = o.business_risk_indicator || {};
  if (bri.band) {
    // An indicator: band + explanation. Never a second numeric score.
    w.text(`Business Risk Indicator: ${String(bri.band).toUpperCase()}`, { size: 11, bold: true });
    if (bri.explanation) w.prose(bri.explanation, { size: 9 });
  }
  if (o.summary) { w.gap(2); w.prose(o.summary, { size: 10 }); }
  const ec = o.evidence_completeness || {};
  if (ec.scan_quality && ec.scan_quality !== "complete") {
    w.prose(`Evidence completeness: ${ec.scan_quality}` +
      (ec.modules_skipped?.length ? ` (skipped: ${ec.modules_skipped.join(", ")})` : ""),
      { size: 9, color: "0.45 0.35 0.10" });
  }
}

function sectionDomains(w, snap) {
  w.heading("Eight-Domain Cyber MOT");
  for (const d of snap.domains || []) {
    w.text(`${d.display_name}: ${stateLabel(d.state)}`, { size: 10, bold: true });
    if (d.state_reason) w.prose(d.state_reason, { size: 9, indent: 10, color: "0.25 0.28 0.33" });
    // Honest-scope limitations travel with each domain (e.g. Certificates &
    // Trust: chain/root/OCSP/revocation are NOT checked) — frozen snapshot
    // facts, never softened at render time.
    for (const l of d.limitations || []) w.prose(`Limitation: ${l}`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    const ceStmt = d.cyber_essentials?.external_coverage_statement;
    if (ceStmt) w.prose(ceStmt, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
  }
}

function sectionFindings(w, snap) {
  const findings = snap.observed_findings || [];
  const observations = snap.observations || [];
  w.heading(`Observed Findings (${findings.length})`);
  if (!findings.length) w.text("No material findings were observed in this assessment.", { size: 10 });
  for (const f of findings) {
    w.text(`[${String(f.severity || "").toUpperCase()}] ${f.title}`, { size: 10, bold: true });
    if (f.explanation) w.prose(f.explanation, { size: 9, indent: 10, color: "0.25 0.28 0.33" });
  }
  w.heading(`Observations (${observations.length})`);
  if (!observations.length) w.text("No additional observations.", { size: 10 });
  for (const f of observations) {
    w.text(`${f.title}`, { size: 10 });
    if (f.explanation) w.prose(f.explanation, { size: 9, indent: 10, color: "0.25 0.28 0.33" });
  }
}

function sectionRemediation(w, snap) {
  const actions = snap.remediation_actions || [];
  w.heading(`Recommended Actions (${actions.length})`);
  if (!actions.length) w.text("No canonical remediation actions for this assessment.", { size: 10 });
  for (const a of actions) {
    w.text(`${a.priority ? `[${String(a.priority).toUpperCase()}] ` : ""}${a.title}`, { size: 10, bold: true });
    if (a.action) w.prose(a.action, { size: 9, indent: 10 });
    if (a.finding_ids?.length > 1) {
      w.text(`Resolves ${a.finding_ids.length} related findings.`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
    if (a.verification_ceiling) {
      w.text(`Verification: ${a.verification_ceiling}`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
  }
  const unmapped = snap.unmapped_finding_types || [];
  if (unmapped.length) {
    w.gap(4);
    w.prose(`${unmapped.length} finding type(s) have no canonical remediation registered and are listed without invented advice: ${unmapped.join(", ")}.`, { size: 8, color: "0.35 0.38 0.44" });
  }
}

function sectionMethodology(w, snap) {
  const m = snap.methodology || {};
  const s = snap.snapshot || {};
  w.heading("Methodology & Limitations");
  w.text(`Assessed on ${pdfUtcDate(s.as_of, true)}`, { size: 10, bold: true });
  if (s.provenance === "reconstructed_on_demand") {
    w.prose(`This report was reconstructed on ${pdfUtcDate(s.built_at, true)} from the immutable evidence recorded at assessment time.`, { size: 9, color: "0.45 0.35 0.10" });
  }
  w.text(`Resolver ${m.cyber_mot_resolver_version || "-"} - Score methodology ${m.cyber_metrics_score_methodology_version || "-"} - Risk indicator methodology ${m.business_risk_methodology_version || "-"}`, { size: 8, color: "0.35 0.38 0.44" });
  const ce = (snap.domains || []).find((d) => d.domain_key === "cyber_essentials_readiness")?.cyber_essentials;
  if (ce?.external_coverage_statement) w.prose(ce.external_coverage_statement, { size: 8, color: "0.35 0.38 0.44" });
  w.gap(2);
  for (const l of snap.limitations || []) w.prose(`- ${l}`, { size: 8, color: "0.35 0.38 0.44" });
}

function footerFor(branding) {
  return branding?.company_name
    ? `Prepared by ${branding.company_name} | Powered by CyberMeters`
    : DEFAULT_FOOTER;
}

function brandingHeader(w, branding, title, subtitle, logoImage = null) {
  if (logoImage?.width && logoImage?.height) {
    // The logo replaces the text wordmark (white-label contract). Drawn at the
    // top-right of the first page, aspect-preserved, capped at 96x40pt.
    const maxW = 96, maxH = 40;
    const scale = Math.min(maxW / logoImage.width, maxH / logoImage.height, 1);
    const lw = Math.max(1, Math.round(logoImage.width * scale));
    const lh = Math.max(1, Math.round(logoImage.height * scale));
    w.raw(`q ${lw} 0 0 ${lh} ${PAGE_W - MARGIN - lw} ${PAGE_H - MARGIN - lh} cm /Im0 Do Q\n`);
  } else {
    w.text(branding?.company_name || "CyberMeters", { size: 16, bold: true, color: "0.05 0.30 0.62" });
  }
  w.text(title, { size: 13, bold: true });
  if (subtitle) w.text(subtitle, { size: 10, color: "0.35 0.38 0.44" });
  w.gap(6);
}

/**
 * buildScanReportPdf(scan, read, branding) — the per-scan PDF, rendered from a
 * verified canonical snapshot read ({ snapshot } from readScanReportSnapshot).
 * Returns a Uint8Array. Deterministic for a given snapshot + branding.
 */
export function buildScanReportPdf(scan, read, branding = null, logoImage = null) {
  const snap = read.snapshot;
  const s = snap.snapshot || {};
  const w = makeWriter({
    accentHex: branding?.accent || BRAND_HEX,
    footerText: footerFor(branding),
  });
  brandingHeader(w, branding, "External Security Assessment", `${s.domain || scan?.domain || ""} - assessed ${pdfUtcDate(s.as_of, true)}`, logoImage);
  sectionOverall(w, snap);
  sectionDomains(w, snap);
  sectionFindings(w, snap);
  sectionRemediation(w, snap);
  sectionMethodology(w, snap);
  const streams = w.finish();
  if (logoImage) return assemblePdfWithImage(streams, logoImage);
  return new TextEncoder().encode(assemblePdf(streams));
}

/**
 * buildWorkspaceExecutivePdf({ workspaceName, reads, branding, generatedAt }) —
 * the workspace executive PDF: a period-framed rendering over the latest
 * completed canonical snapshot per domain (founder package: renderings over
 * canonical snapshots, never separate brains). First-two-pages rule: cover +
 * eight-domain scorecard lead. Domains with no snapshot appear as an HONEST
 * "no canonical assessment" row — never recalculated, never healthy.
 *
 * `reads` = array from readLatestWorkspaceSnapshots (ok + non-ok entries).
 * `generatedAt` is the caller's artefact timestamp (claim time for stored
 * PDFs) — deterministic per artefact, never read from the clock here.
 */
export function buildWorkspaceExecutivePdf({ workspaceName, reads = [], branding = null, generatedAt = null, logoImage = null }) {
  const ok = reads.filter((r) => r.status === "ok");
  const unavailable = reads.filter((r) => r.status !== "ok");
  // Presentation rule (documented): the cover headlines the most recently
  // assessed domain's snapshot; every domain is listed beneath it.
  const lead = ok.slice().sort((a, b) => String(b.snapshot.snapshot.as_of).localeCompare(String(a.snapshot.snapshot.as_of)))[0] || null;

  const w = makeWriter({
    accentHex: branding?.accent || BRAND_HEX,
    footerText: footerFor(branding),
  });
  brandingHeader(w, branding, "Executive Security Report", workspaceName ? `Workspace: ${workspaceName}` : null, logoImage);
  if (generatedAt) w.text(`Generated ${pdfUtcDate(generatedAt, true)}`, { size: 9, color: "0.35 0.38 0.44" });
  w.gap(4);

  if (!ok.length) {
    w.prose("No canonical assessment snapshot is available for this workspace yet. Reports are produced from completed Cyber MOT assessments; run a scan to establish the first one.", { size: 10 });
  } else {
    w.text(`Latest assessment: ${lead.snapshot.snapshot.domain} - ${pdfUtcDate(lead.snapshot.snapshot.as_of, true)}`, { size: 10, bold: true });
    w.gap(2);
    sectionOverall(w, lead.snapshot);
    for (const r of ok) {
      w.newPage();
      w.text(`Domain: ${r.snapshot.snapshot.domain}`, { size: 12, bold: true });
      w.text(`Assessed ${pdfUtcDate(r.snapshot.snapshot.as_of, true)}`, { size: 9, color: "0.35 0.38 0.44" });
      sectionOverall(w, r.snapshot);
      sectionDomains(w, r.snapshot);
      sectionRemediation(w, r.snapshot);
      sectionMethodology(w, r.snapshot);
    }
  }
  if (unavailable.length) {
    w.gap(6);
    w.heading("Not yet available");
    for (const u of unavailable) {
      w.text(`A canonical assessment for one domain is ${u.status === "building" ? "still being prepared" : "not available"}.`, { size: 9 });
    }
  }
  const streams = w.finish();
  if (logoImage) return assemblePdfWithImage(streams, logoImage);
  return new TextEncoder().encode(assemblePdf(streams));
}
