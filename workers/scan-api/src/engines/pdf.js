// ── PDF generation engine ──
// Raw-PDF (no library) generation: PDF primitives + escaping, the shared service palette,
// scan-report + executive PDF builders, and workspace PDF data collection. Extracted verbatim
// from index.js (monolith decomposition, Phase 1c). pdfEsc/hexToRgbF/PDF_SERVICE are internal.
import { POSTURE_WEIGHTS } from "./scoring-config.js";
import { resolveAssessmentPresentation } from "./assessment-presentation.js";
import { LATEST_COMPLETED_SCAN_SCOPE } from "./report-queries.js";
import { buildCyberEssentialsReadiness, getCyberEssentialsSnapshot } from "./ce-readiness.js";
import { buildScorecardData } from "./scorecard.js";
import { getCurrentPosturePresentation } from "./current-posture.js";
import { resolveCyberMotDomainStates } from "./cyber-mot-domains.js";
import { latestScanBusinessRisk } from "./business-risk.js";
import { resolveByCustomerTitle } from "./remediation-registry.js";

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

// ── Ocean & Ice service palette (shared by every PDF builder) ────────────────
// The four CyberMeters services each own a colour, matched 1:1 to the product
// sidebar so a report reads as the same product. Any data that belongs to a
// service is tinted with that service's colour; `tint` is the pale background
// used behind service headers/blocks. hex is consumed directly by hexToRgbF.
const PDF_SERVICE = {
  email:   { name: 'Email Protection',     hex: '#1568C7', tint: '#EAF2FC' }, // Glacial Blue
  surface: { name: 'Attack Surface',       hex: '#0DA08D', tint: '#E6F6F3' }, // Teal / Emerald
  brand:   { name: 'Brand Protection',     hex: '#10B9D1', tint: '#E3F7FA' }, // Turquoise / Aqua
  certs:   { name: 'Certificates & Trust', hex: '#0A8CBE', tint: '#E6F4FA' }, // Deep Cyan
};

/**
 * buildScanReportPdf(scan, report) — a focused, single-scan PDF built from the
 * stored V1 report. Uses the same low-level primitives (assemblePdf, pdfEsc,
 * hexToRgbF) as the workspace executive PDF. Returns a Uint8Array. Never leaks
 * internals; degrades gracefully when fields are absent. Auto page-breaks.
 */
export function buildScanReportPdf(scan, report, branding = null) {
  const PW = 612, PH = 792, ML = 50, MR = 50, MB = 55, CW = PW - ML - MR;
  // White-label: when the account has branding on, lead with their name + accent.
  // pdf.js is text-only (no image XObjects), so the PDF carries a text wordmark;
  // the shareable HTML report carries the logo image.
  const wl = branding && branding.company_name ? branding : null;
  const HEXRE = /^#[0-9a-fA-F]{6}$/;
  const BRAND = wl && HEXRE.test(wl.accent || "") ? wl.accent : "#00876A";
  const WORDMARK = wl ? String(wl.company_name).slice(0, 40) : "CyberMeters";
  // Prepared logo Image-XObject (from prepareLogoXObject, resolved async in the
  // route). Present → drawn in the header in place of the text wordmark, and the
  // PDF is assembled with the binary image assembler.
  const logoImg = wl && wl.logoImage && wl.logoImage.bytes ? wl.logoImage : null;
  const FOOTER_TEXT = wl
    ? `Prepared by ${String(wl.company_name).slice(0, 40)} | Powered by CyberMeters`
    : "Generated by CyberMeters | app.cybermeters.com";
  const DK = "#1F2937", GRAY = "#555555", LGRAY = "#888888", XGRAY = "#CCCCCC", BG = "#F3F4F6";
  const SEVHEX = { critical: "#991B1B", high: "#B45309", medium: "#1D4ED8", low: "#6B7280", info: "#6B7280" };

  const streams = [];
  let s = "", y = 50;
  const op = (t) => { s += t + "\n"; };
  const txt = (x, yTop, str, font, sz, hex = "#000000") => {
    if (str == null || str === "") return;
    const [r, g, b] = hexToRgbF(hex);
    op("BT"); op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg`);
    op(`/F${font} ${sz} Tf`); op(`1 0 0 1 ${x} ${PH - yTop} Tm`);
    op(`(${pdfEsc(str)}) Tj`); op("ET");
  };
  const rect = (x, yTop, w, h, hex) => {
    const [r, g, b] = hexToRgbF(hex);
    op("q"); op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg`);
    op(`${x} ${PH - yTop - h} ${w} ${h} re f`); op("Q");
  };
  const hline = (x1, x2, yTop, hex = "#DDDDDD") => {
    const [r, g, b] = hexToRgbF(hex);
    op("q"); op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} RG`); op("0.5 w");
    op(`${x1} ${PH - yTop} m ${x2} ${PH - yTop} l S`); op("Q");
  };
  const wrap = (text, sz, maxW = CW) => {
    const maxC = Math.max(1, Math.floor(maxW / (sz * 0.52)));
    const words = String(text ?? "").split(/\s+/).filter(Boolean);
    if (!words.length) return [];
    const lines = []; let cur = "";
    for (const w of words) {
      if (!cur) { cur = w; }
      else if (cur.length + 1 + w.length <= maxC) { cur += " " + w; }
      else { lines.push(cur); cur = w; }
    }
    if (cur) lines.push(cur);
    return lines;
  };
  const footer = () => {
    hline(ML, PW - MR, PH - MB + 8, XGRAY);
    txt(ML, PH - MB + 22, FOOTER_TEXT, 1, 7, LGRAY);
    txt(PW - MR - 42, PH - MB + 22, `Page ${streams.length + 1}`, 1, 7, LGRAY);
  };
  const endPage = () => { footer(); streams.push(s); s = ""; y = 50; };
  const ensure = (h) => { if (y + h > PH - MB) endPage(); };
  const para = (text, x, sz, hex, maxW, gap = 12) => {
    for (const ln of wrap(text, sz, maxW)) { ensure(gap); txt(x, y, ln, 1, sz, hex); y += gap; }
  };

  const domain = scan.domain || report.domain || "domain";
  const score = report.cyber_metrics_score ?? scan.score;
  // Completeness-aware presentation — a partial/degraded/unknown assessment shows a
  // provisional score with NO final rating + a coverage caveat (partial-scan honesty).
  const assessment = resolveAssessmentPresentation({
    score, scanQuality: report.scan_quality?.status, status: report.status || scan.status,
  });
  const rating = assessment.display_rating || "";
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const isObs = (f) => (f.finding_type || (Number(f.score_impact) < 0 ? "finding" : "observation")) === "observation";
  const actionable = findings.filter((f) => !isObs(f));
  const observations = findings.filter(isObs);
  const br = report.business_risk || null;

  // ── Header band + score ──
  rect(0, 0, PW, 92, BRAND);
  if (logoImg) {
    // Draw the logo XObject where the wordmark would go. Image space is a unit
    // square, so the cm matrix scales it to w2×h2 at (ML, yBottom) in native
    // (bottom-left origin) coordinates. Aspect ratio preserved.
    const maxH = 38, maxW = 190;
    let h2 = maxH, w2 = h2 * (logoImg.width / logoImg.height);
    if (w2 > maxW) { w2 = maxW; h2 = w2 * (logoImg.height / logoImg.width); }
    const yBottom = (PH - 16) - h2;
    op("q");
    op(`${w2.toFixed(2)} 0 0 ${h2.toFixed(2)} ${ML} ${yBottom.toFixed(2)} cm`);
    op("/Im0 Do");
    op("Q");
  } else {
    txt(ML, 40, WORDMARK, 2, 20, "#FFFFFF");
  }
  txt(ML, 62, "External Security Scan Report", 1, 11, "#DCFCE7");
  txt(PW - MR - 150, 40, domain, 2, 13, "#FFFFFF");
  const created = pdfUtcDate(scan.created_at, true);
  txt(PW - MR - 150, 60, created ? `Scan date: ${created}` : "", 1, 9, "#DCFCE7");
  y = 122;

  rect(ML, y, CW, 60, BG);
  txt(ML + 16, y + 24, assessment.provisional ? "Provisional Score" : "Cyber Metrics Score", 1, 9, GRAY);
  txt(ML + 16, y + 48, `${score ?? "-"} / 100`, 2, 22, DK);
  txt(ML + 170, y + 24, "Security Rating", 1, 9, GRAY);
  // A final rating shows only for a complete assessment; otherwise "Provisional".
  txt(ML + 170, y + 46, rating ? rating.charAt(0).toUpperCase() + rating.slice(1) : (assessment.provisional ? "Provisional" : "-"), 2, 15, BRAND);
  txt(ML + 330, y + 24, "Business Risk", 1, 9, GRAY);
  txt(ML + 330, y + 46, br && br.score != null ? `${br.score} / 100` : "-", 2, 15, DK);
  // band already reads like "Low Business Risk" — show as-is, no suffix
  txt(ML + 330, y + 60, br && br.band ? String(br.band) : "", 1, 8, GRAY);
  y += 78;
  // Coverage caveat banner — an incomplete assessment is never a final clean result.
  if (assessment.message) {
    txt(ML, y, assessment.message, 1, 9, "#B45309");
    y += 18;
  }
  txt(ML, y, `${actionable.length} finding${actionable.length === 1 ? "" : "s"} to act on`, 2, 11, DK);
  txt(ML + 200, y, `${observations.length} observation${observations.length === 1 ? "" : "s"}`, 1, 11, GRAY);
  y += 24;

  // ── Findings ──
  ensure(24); hline(ML, PW - MR, y, XGRAY); y += 6;
  txt(ML, y, "Findings", 2, 14, DK); y += 22;
  if (actionable.length === 0) {
    para("No actionable findings — this domain passed the checks that impact the score.", ML, 9.5, GRAY, CW);
    y += 4;
  }
  for (const f of actionable) {
    ensure(46);
    const sev = String(f.severity || "info").toLowerCase();
    const hex = SEVHEX[sev] || SEVHEX.info;
    rect(ML, y - 8, 3, 14, hex);
    txt(ML + 10, y, (f.title || "Finding").slice(0, 90), 2, 10.5, DK);
    txt(PW - MR - 60, y, sev.toUpperCase(), 2, 8, hex);
    y += 15;
    if (f.description) para(f.description, ML + 10, 8.5, GRAY, CW - 10, 11);
    if (f.recommendation) { para(`Recommended: ${f.recommendation}`, ML + 10, 8.5, BRAND, CW - 10, 11); }
    y += 8;
  }

  // ── Observations ──
  if (observations.length) {
    ensure(30); hline(ML, PW - MR, y, XGRAY); y += 6;
    txt(ML, y, "Observations", 2, 14, DK); y += 20;
    for (const o of observations) {
      ensure(24);
      txt(ML + 10, y, (o.title || "Observation").slice(0, 95), 2, 9.5, GRAY); y += 13;
      if (o.description) para(o.description, ML + 10, 8.5, LGRAY, CW - 10, 11);
      y += 5;
    }
  }

  // ── External posture, grouped and colour-coded by service ──
  // Each block carries its CyberMeters service colour, so the reader sees at a
  // glance which of the four services each signal belongs to.
  const es = (report.modules && report.modules.email_security) || {};
  const ssl = (report.modules && report.modules.ssl) || {};
  const hdr = (report.modules && report.modules.headers) || {};
  const yn = (v) => (v === true ? "Yes" : v === false ? "No" : "-");
  ensure(34); hline(ML, PW - MR, y, XGRAY); y += 8;
  txt(ML, y, "External posture by service", 2, 14, DK); y += 22;

  const postureGroups = [
    { svc: PDF_SERVICE.email, rows: [
      ["SPF", yn(es.spf && es.spf.present)],
      ["DMARC policy", es.dmarc && es.dmarc.present ? `p=${es.dmarc.policy || "?"}` : "Not present"],
      ["DKIM", es.dkim && es.dkim.present ? "Detected" : "Not detected via common selectors"],
    ] },
    { svc: PDF_SERVICE.certs, rows: [
      ["HTTPS available", yn(ssl.https_available)],
      ["Certificate expiry", ssl.cert_expiry_days != null ? `${ssl.cert_expiry_days} days` : "-"],
    ] },
    { svc: PDF_SERVICE.surface, rows: [
      ["HSTS present", hdr.values && hdr.values["strict-transport-security"] ? "Yes" : "-"],
    ] },
  ];
  for (const grp of postureGroups) {
    ensure(24 + grp.rows.length * 15);
    // Service header: pale tint band + a solid accent tab + service-coloured label.
    rect(ML, y - 3, CW, 17, grp.svc.tint);
    rect(ML, y - 3, 3, 17, grp.svc.hex);
    txt(ML + 11, y + 9, grp.svc.name, 2, 9, grp.svc.hex);
    y += 24;
    for (const [k, v] of grp.rows) {
      ensure(15);
      txt(ML + 14, y, k, 1, 9, GRAY);
      txt(ML + 210, y, String(v), 2, 9, DK);
      y += 15;
    }
    y += 8;
  }

  endPage();
  if (logoImg) return assemblePdfWithImage(streams, logoImg);
  return new TextEncoder().encode(assemblePdf(streams));
}

/**
 * Build PDF content streams for a workspace executive report.
 * Returns an array of strings (one per page) for assemblePdf().
 *
 * Pages:
 *   1  Cover — score, workspace name, date
 *   2  Executive Summary + Domain Inventory
 *   3  Security Findings (may overflow to additional pages automatically)
 *   last  Recommendations + Historical Trend
 */
export function buildPdfStreams({ workspace, stats, domains, findings, recommendations, trend }) {
  const PW = 612, PH = 792;   // page width/height (pts, US Letter)
  const ML = 50;               // left margin
  const MR = 50;               // right margin
  const MT = 50;               // top margin for content
  const MB = 55;               // bottom margin (footer zone)
  const CW = PW - ML - MR;    // content width

  // Brand palette
  const BRAND   = "#00876A";
  const GRAY    = "#555555";
  const LGRAY   = "#888888";
  const XGRAY   = "#CCCCCC";
  const BG1     = "#F8F9FA";
  const BG2     = "#F3F4F6";

  const streams  = [];
  let   curStream = "";
  let   curY      = MT;        // y from top of page

  // ── Low-level drawing ops (all coordinates are "y from top") ─────────────

  const op = (s) => { curStream += s + "\n"; };

  // Draw text at absolute position.  fontId: 1=regular 2=bold.
  const txt = (x, yTop, str, fontId, sz, hex = "#000000") => {
    if (!str) return;
    const [r, g, b] = hexToRgbF(hex);
    const pdfY      = PH - yTop;
    op("BT");
    op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg`);
    op(`/F${fontId} ${sz} Tf`);
    op(`1 0 0 1 ${x} ${pdfY} Tm`);
    op(`(${pdfEsc(str)}) Tj`);
    op("ET");
  };

  // Filled rectangle.  yTop = distance from page top to top edge of rect.
  const fillRect = (x, yTop, w, h, hex) => {
    const [r, g, b] = hexToRgbF(hex);
    const pdfY      = PH - yTop - h;   // PDF y = bottom-left of rect
    op("q");
    op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg`);
    op(`${x} ${pdfY} ${w} ${h} re f`);
    op("Q");
  };

  // Horizontal rule.
  const hline = (x1, x2, yTop, lw = 0.5, hex = "#DDDDDD") => {
    const [r, g, b] = hexToRgbF(hex);
    const pdfY      = PH - yTop;
    op("q");
    op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} RG`);
    op(`${lw} w`);
    op(`${x1} ${pdfY} m ${x2} ${pdfY} l S`);
    op("Q");
  };

  // ── Page management ───────────────────────────────────────────────────────

  const addFooter = () => {
    const pageNum = streams.length + 1;
    hline(ML, PW - MR, PH - MB + 8, 0.5, XGRAY);
    txt(ML, PH - MB + 22, "Generated by CyberMeters | app.cybermeters.com", 1, 7, LGRAY);
    txt(PW - MR - 40, PH - MB + 22, `Page ${pageNum}`, 1, 7, LGRAY);
  };

  const endPage = () => {
    addFooter();
    streams.push(curStream);
    curStream = "";
    curY      = MT;
  };

  // Start a new page if the next block of `needed` pts would overflow.
  const checkBreak = (needed) => {
    if (curY + needed > PH - MB) endPage();
  };

  // Coloured section header bar.
  const sectionBar = (label) => {
    checkBreak(30);
    fillRect(ML, curY, CW, 20, BRAND);
    txt(ML + 8, curY + 14, label, 2, 10, "#FFFFFF");
    curY += 26;
  };

  // ── Rating helpers ────────────────────────────────────────────────────────

  const scoreToRating = (s) =>
    s == null  ? "N/A"       :
    s >= 90    ? "Excellent" :
    s >= 75    ? "Good"      :
    s >= 50    ? "Moderate"  :
    s >= 25    ? "Poor"      : "Critical";

  const scoreToColor = (s) =>
    s == null ? LGRAY :
    s >= 75   ? BRAND :
    s >= 50   ? "#F59E0B" : "#EF4444";

  // ── Derived values ────────────────────────────────────────────────────────

  const avgScore = stats.cyber_score_average != null
    ? Math.round(stats.cyber_score_average)
    : null;

  // ── Completeness-aware headline posture (partial-scan honesty) ─────────────
  // The cover "Cyber Score" and the summary row present the AUTHORITATIVE posture
  // (latest complete scan). When no complete assessment exists the score/rating
  // are withheld and a provisional caveat is shown — a partial-only workspace must
  // never render a clean rating such as "Excellent".
  const postureEstablished = stats.posture_established === true && stats.posture_score != null;
  const postureScore  = postureEstablished ? Math.round(stats.posture_score) : null;
  const postureRating = postureEstablished && stats.posture_rating
    ? stats.posture_rating.charAt(0).toUpperCase() + stats.posture_rating.slice(1)
    : null;
  const postureMsg = stats.posture_message || "Current posture not yet established";

  const genDate = pdfUtcDate(new Date().toISOString(), true);

  const latestDate = stats.latest_scan
    ? pdfUtcDate(stats.latest_scan.created_at, true)
    : "N/A";

  // ═══════════════════════════════════════════════════════════════════════════
  // PAGE 1 — COVER
  // ═══════════════════════════════════════════════════════════════════════════

  // Header banner
  fillRect(0, 0, PW, 64, BRAND);
  txt(ML, 22,  "CYBERMETERS",                 2, 18, "#FFFFFF");
  txt(ML, 44,  "Attack Surface Management",   1, 10, "#B2DFDB");
  txt(PW - MR - 160, 44, genDate,             1,  9, "#B2DFDB");

  curY = 106;

  txt(ML, curY, "EXECUTIVE SECURITY REPORT", 2, 9, BRAND);
  curY += 26;

  // Workspace name
  txt(ML, curY, (workspace.name || "Workspace").slice(0, 50), 2, 26, "#111111");
  curY += 44;

  hline(ML, PW - MR, curY, 1, "#E0E0E0");
  curY += 20;

  // Three KPI boxes
  const BOX_H = 82;
  const boxes = [
    { label: "CYBER SCORE",        value: postureEstablished ? String(postureScore) : "N/A", sub: postureRating || "Not yet established", valueHex: scoreToColor(postureEstablished ? postureScore : null), x: ML },
    { label: "DOMAINS MONITORED",  value: String(stats.total_domains  || 0), sub: "In workspace",      valueHex: "#111111", x: ML + 186 },
    { label: "TOTAL SCANS",        value: String(stats.total_scans    || 0), sub: "Completed",         valueHex: "#111111", x: ML + 372 },
  ];
  for (const box of boxes) {
    fillRect(box.x, curY, 166, BOX_H, BG1);
    txt(box.x + 10, curY + 18, box.label,    2,  8, LGRAY);
    txt(box.x + 10, curY + 52, box.value,    2, 30, box.valueHex);
    txt(box.x + 10, curY + 70, box.sub,      1,  8, GRAY);
  }
  curY += BOX_H + 20;

  hline(ML, PW - MR, curY, 0.5, "#E0E0E0");
  curY += 16;

  txt(ML, curY, "CONFIDENTIAL — For authorised distribution only.", 2, 8, LGRAY);
  curY += 14;
  txt(ML, curY, "This document contains sensitive information about your external attack surface.", 1, 8, LGRAY);

  endPage();   // page 1 done

  // ═══════════════════════════════════════════════════════════════════════════
  // PAGE 2 — EXECUTIVE SUMMARY + DOMAIN INVENTORY
  // ═══════════════════════════════════════════════════════════════════════════

  sectionBar("EXECUTIVE SUMMARY");

  const summaryRows = [
    ["Total Domains",       String(stats.total_domains  || 0)],
    ["Total Scans",         String(stats.total_scans    || 0)],
    ["Cyber Posture", postureEstablished ? `${postureScore} / 100 — ${postureRating}` : postureMsg],
    ["Latest Assessment",   latestDate],
    ["Report Generated",    genDate],
  ];
  for (const [label, value] of summaryRows) {
    checkBreak(20);
    txt(ML,       curY, label + ":", 2,  9, GRAY);
    txt(ML + 180, curY, value,       1,  9, "#111111");
    curY += 18;
  }

  curY += 14;
  sectionBar("DOMAIN INVENTORY");

  // Table header row
  const DC = [ML, ML + 222, ML + 292, ML + 380];   // column x positions
  fillRect(ML, curY, CW, 18, BG2);
  txt(DC[0] + 4, curY + 13, "Domain",    2, 8, "#333333");
  txt(DC[1] + 4, curY + 13, "Score",     2, 8, "#333333");
  txt(DC[2] + 4, curY + 13, "Rating",    2, 8, "#333333");
  txt(DC[3] + 4, curY + 13, "Last Scan", 2, 8, "#333333");
  curY += 20;

  for (const d of (domains || [])) {
    checkBreak(17);
    const ds = d.latest_score;
    // A clean rating shows only when the domain's latest scan is COMPLETE; a
    // partial/degraded/unknown latest scan is provisional and never rated.
    const domComplete = d.latest_quality === "complete";
    const domScore  = ds != null ? String(ds) : "—";
    const domRating = ds != null ? (domComplete ? scoreToRating(ds) : "Provisional") : "N/A";
    const domDate   = d.last_scanned_at
      ? new Date((d.last_scanned_at || "").replace(" ", "T") + "Z")
          .toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
      : "Never";

    hline(ML, PW - MR, curY, 0.3, "#EEEEEE");
    txt(DC[0] + 4, curY + 12, d.domain,  1, 8, "#111111");
    txt(DC[1] + 4, curY + 12, domScore,  1, 8, scoreToColor(ds));
    txt(DC[2] + 4, curY + 12, domRating, 1, 8, GRAY);
    txt(DC[3] + 4, curY + 12, domDate,   1, 8, GRAY);
    curY += 16;
  }
  if (!(domains || []).length) {
    txt(ML + 4, curY + 12, "No domains in this workspace.", 1, 8, LGRAY);
    curY += 16;
  }

  endPage();   // page 2 done

  // ═══════════════════════════════════════════════════════════════════════════
  // PAGE 3 — SECURITY FINDINGS (may overflow to extra pages)
  // ═══════════════════════════════════════════════════════════════════════════

  sectionBar("SECURITY FINDINGS");

  const SEV_ORDER  = ["critical", "high", "medium", "low"];
  const SEV_LABEL  = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
  const SEV_COLOR  = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6" };
  const SEV_BGCOL  = { critical: "#FEE2E2", high: "#FFF0E6", medium: "#FFFBEB", low: "#EFF6FF" };

  const grouped = {};
  for (const sev of SEV_ORDER) grouped[sev] = [];
  for (const f of (findings || [])) {
    const s = (f.severity || "low").toLowerCase();
    if (grouped[s]) grouped[s].push(f);
  }

  let findingNum = 1;
  for (const sev of SEV_ORDER) {
    const items = grouped[sev];
    if (!items.length) continue;

    checkBreak(30);
    fillRect(ML, curY, CW, 18, SEV_BGCOL[sev]);
    txt(ML + 6, curY + 13, `${SEV_LABEL[sev]}  (${items.length})`, 2, 9, SEV_COLOR[sev]);
    curY += 22;

    for (const f of items) {
      checkBreak(44);

      // Finding title + domain on same line
      txt(ML + 8, curY, `${findingNum}.  ${(f.title || "Untitled").slice(0, 68)}`, 2, 9, "#111111");
      txt(PW - MR - 110, curY, (f.domain || "").slice(0, 28), 1, 7, LGRAY);
      curY += 14;

      // Description (truncated to fit one line ~95 chars)
      const desc = (f.recommendation || "").slice(0, 100);
      if (desc) {
        txt(ML + 14, curY, desc, 1, 8, GRAY);
        curY += 13;
      }

      hline(ML + 6, PW - MR, curY, 0.3, "#EEEEEE");
      curY += 7;
      findingNum++;
    }
    curY += 6;
  }

  if (!(findings || []).length) {
    txt(ML, curY, "No findings recorded for this workspace.", 1, 9, LGRAY);
    curY += 16;
  }

  endPage();   // findings page(s) done

  // ═══════════════════════════════════════════════════════════════════════════
  // FINAL PAGE — RECOMMENDATIONS + HISTORICAL TREND
  // ═══════════════════════════════════════════════════════════════════════════

  sectionBar("RECOMMENDATIONS");

  const recs = (recommendations || []).slice(0, 10);
  if (recs.length) {
    for (let i = 0; i < recs.length; i++) {
      const r = recs[i];
      checkBreak(52);

      // Priority badge
      fillRect(ML, curY, 20, 20, BRAND);
      txt(ML + 5, curY + 14, String(r.priority || i + 1), 2, 9, "#FFFFFF");

      txt(ML + 28, curY + 14, (r.title || "Action Required").slice(0, 70), 2, 9, "#111111");
      curY += 22;

      const action = (r.action || "").slice(0, 110);
      if (action) {
        txt(ML + 28, curY, action, 1, 8, GRAY);
        curY += 13;
      }
      if (r.domain) {
        txt(ML + 28, curY, `Domain: ${r.domain}`, 1, 7, LGRAY);
        curY += 12;
      }
      hline(ML, PW - MR, curY + 2, 0.3, "#EEEEEE");
      curY += 10;
    }
  } else {
    txt(ML, curY, "No recommendations available.", 1, 9, LGRAY);
    curY += 16;
  }

  curY += 14;
  checkBreak(80);
  sectionBar("HISTORICAL TREND");

  // Trend table header
  const TC = [ML, ML + 150, ML + 250, ML + 340, ML + 430];
  fillRect(ML, curY, CW, 18, BG2);
  txt(TC[0] + 4, curY + 13, "Domain",         2, 8, "#333333");
  txt(TC[1] + 4, curY + 13, "Date",           2, 8, "#333333");
  txt(TC[2] + 4, curY + 13, "Previous",       2, 8, "#333333");
  txt(TC[3] + 4, curY + 13, "Current",        2, 8, "#333333");
  txt(TC[4] + 4, curY + 13, "Change",         2, 8, "#333333");
  curY += 20;

  for (const t of (trend || [])) {
    checkBreak(17);
    const change      = t.score_change != null
      ? (t.score_change >= 0 ? `+${t.score_change}` : String(t.score_change))
      : "—";
    const changeColor = t.score_change == null  ? GRAY
      : t.score_change > 0  ? BRAND
      : t.score_change < 0  ? "#EF4444" : GRAY;

    hline(ML, PW - MR, curY, 0.3, "#EEEEEE");
    txt(TC[0] + 4, curY + 12, (t.domain           || "—").slice(0, 25), 1, 8, "#111111");
    txt(TC[1] + 4, curY + 12, (t.date             || "—"),               1, 8, GRAY);
    txt(TC[2] + 4, curY + 12, t.previous_score != null ? String(t.previous_score) : "—", 1, 8, GRAY);
    txt(TC[3] + 4, curY + 12, t.current_score  != null ? String(t.current_score)  : "—", 1, 8, GRAY);
    txt(TC[4] + 4, curY + 12, change, 2, 8, changeColor);
    curY += 16;
  }

  if (!(trend || []).length) {
    txt(ML, curY, "No trend data yet. Run multiple scans per domain to populate this section.", 1, 8, LGRAY);
    curY += 14;
  }

  endPage();   // final page done

  return streams;
}

// ── PDF Generation Engine v1 ──────────────────────────────────────────────────
// Builds a US-Letter (612 × 792 pt) PDF from the pdf-data JSON payload.
// Uses PDF 1.4 built-in Type1 fonts (Helvetica, Helvetica-Bold) — no embedding.
// Pure JS — no external dependencies, Cloudflare Worker compatible.

export function buildExecutivePdf(pdfData) {
  const W = 612, H = 792, ML = 50, MR = 50, CW = W - ML - MR;

  // Colours [R, G, B] in 0–1 range
  const C = {
    green:   [0.000, 0.529, 0.416],
    dkgreen: [0.024, 0.306, 0.231],
    white:   [1.000, 1.000, 1.000],
    dkgray:  [0.122, 0.161, 0.216],
    mgray:   [0.420, 0.447, 0.502],
    lgray:   [0.953, 0.957, 0.965],
    red:     [0.600, 0.110, 0.110],
    amber:   [0.854, 0.467, 0.024],
    blue:    [0.114, 0.306, 0.847],
    teal:    [0.820, 0.980, 0.910],
    // Ocean & Ice service palette (mirrors PDF_SERVICE / the product sidebar) —
    // any data belonging to a service is tinted with its colour; *Bg = pale band.
    svcEmail:     hexToRgbF(PDF_SERVICE.email.hex),
    svcSurface:   hexToRgbF(PDF_SERVICE.surface.hex),
    svcBrand:     hexToRgbF(PDF_SERVICE.brand.hex),
    svcCerts:     hexToRgbF(PDF_SERVICE.certs.hex),
    svcEmailBg:   hexToRgbF(PDF_SERVICE.email.tint),
    svcSurfaceBg: hexToRgbF(PDF_SERVICE.surface.tint),
    svcBrandBg:   hexToRgbF(PDF_SERVICE.brand.tint),
    svcCertsBg:   hexToRgbF(PDF_SERVICE.certs.tint),
  };
  function rgb(c) { return c.map(v => v.toFixed(3)).join(' '); }
  function sevColor(s) {
    return { critical: C.red, high: C.amber, medium: C.blue, low: C.mgray }[s] ?? C.mgray;
  }
  // Map a control-area / posture label to its owning service colour so every
  // data row reads in the colour of the service it belongs to.
  function svcColorFor(label) {
    const t = String(label || '').toLowerCase();
    if (/dmarc|spf|dkim|email|sender|spoof|bec|mail/.test(t))            return C.svcEmail;
    if (/ssl|tls|certificate|https|expiry|trust|cipher|hsts/.test(t))    return C.svcCerts;
    if (/brand|lookalike|typosquat|impersonation|homoglyph/.test(t))     return C.svcBrand;
    if (/attack surface|subdomain|admin|exposure|asset|cloud|port|dns|third|vendor|supply|resilience/.test(t)) return C.svcSurface;
    return C.dkgray;
  }

  // Escape text for PDF string literals — strict ASCII 0x20–0x7E only
  const REMAP = {
    '–':'-','—':'-','‘':"'",'’':"'",
    '“':'"','”':'"','•':'*','…':'...',
    '£':'GBP','€':'EUR',' ':' ',
  };
  function esc(v) {
    return String(v ?? '')
      .replace(/[^\x20-\x7E]/g, c => REMAP[c] ?? ' ')
      .replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)');
  }

  // Word-wrap: split text into lines that fit within maxW pts at given size.
  // Helvetica average char width ≈ 0.55 × fontSize.
  function wrap(text, maxW, size) {
    const maxC  = Math.max(1, Math.floor(maxW / (size * 0.55)));
    const words = String(text ?? '').split(/\s+/).filter(Boolean);
    if (!words.length) return [''];
    const lines = [];
    let cur = '';
    for (const w of words) {
      if (!cur) { cur = w; continue; }
      if (cur.length + 1 + w.length <= maxC) { cur += ' ' + w; }
      else { lines.push(cur); cur = w; }
    }
    if (cur) lines.push(cur);
    return lines;
  }

  function drawWrapped(pg, text, x, y, maxW, size = 8, font = 'R', col = C.dkgray, maxLines = 3, lineGap = 11) {
    const lines = wrap(text, maxW, size).slice(0, maxLines);
    for (const line of lines) {
      pg.text(line, x, y, size, font, col);
      y -= lineGap;
    }
    return y;
  }

  // ── PDF object store ─────────────────────────────────────────────────────
  // IDs 1–4 are reserved (catalog, pages, F1, F2) and injected at assembly.
  const _objs = [];
  let _nextId = 5;
  function addObj(body) { const id = _nextId++; _objs.push({ id, body }); return id; }

  // ── Page builder ─────────────────────────────────────────────────────────
  const _pageIds = [];
  function newPage() {
    const ops  = [];
    const emit = (...a) => ops.push(a.join(' '));
    const ctx  = {
      fillRect(x, y, w, h, col) {
        emit(rgb(col), `rg ${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re f`);
        emit('0 0 0 rg');
      },
      strokeRect(x, y, w, h, col, lw = 0.5) {
        emit(`${lw} w`, rgb(col), `RG ${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re S`);
        emit('0 0 0 RG 0.5 w');
      },
      hline(x, y, w, col = C.lgray, lw = 0.5) {
        emit(`${lw} w`, rgb(col), `RG ${x.toFixed(1)} ${y.toFixed(1)} m ${(x+w).toFixed(1)} ${y.toFixed(1)} l S`);
        emit('0 0 0 RG 0.5 w');
      },
      text(str, x, y, size, font = 'R', col = C.dkgray) {
        const f = font === 'B' ? 'F2' : 'F1';
        emit(`BT /${f} ${size} Tf`, rgb(col), `rg ${x.toFixed(1)} ${y.toFixed(1)} Td (${esc(str)}) Tj ET`);
        emit('0 0 0 rg');
      },
      flush() {
        const stream = ops.join('\n');
        const csId   = addObj(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
        const pgId   = addObj(
          `<< /Type /Page /Parent 2 0 R\n` +
          `/MediaBox [0 0 ${W} ${H}]\n` +
          `/Contents ${csId} 0 R\n` +
          `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >>\n>>`
        );
        _pageIds.push(pgId);
      },
    };
    return ctx;
  }

  // ── Shared layout helpers ─────────────────────────────────────────────────
  function pgBanner(pg, section) {
    pg.fillRect(0, H - 28, W, 28, C.dkgreen);
    pg.text('CYBERMETERS', ML, H - 17, 9, 'B', C.white);
    pg.text('EXECUTIVE SECURITY REPORT', ML + 90, H - 17, 8, 'R', C.teal);
    if (section) pg.text(section.toUpperCase(), W - 60 - section.length * 4.5, H - 17, 7.5, 'R', C.teal);
  }
  function pgFooter(pg, n, total) {
    pg.hline(ML, 32, CW, C.mgray, 0.3);
    pg.text(`${whiteLabelFooter}  |  ${classification} - Prepared for ${String(ws.name ?? 'workspace').slice(0, 42)}`, ML, 20, 7.5, 'R', C.mgray);
    pg.text(`Page ${n} of ${total}`, W - 80, 20, 7.5, 'R', C.mgray);
  }
  function secBar(pg, title, y, barCol = C.green) {
    pg.fillRect(ML, y - 2, CW, 19, barCol);
    pg.text(title, ML + 8, y + 3, 9.5, 'B', C.white);
    return y - 22;
  }

  // ── Extract fields ────────────────────────────────────────────────────────
  const ws   = pdfData.workspace            ?? {};
  const gd   = pdfUtcDate(pdfData.generated_at, true) || pdfUtcDate(new Date().toISOString(), true);
  const reportId = pdfData.report_id ?? pdfData.report?.id ?? null;
  const reportVersion = pdfData.report_version ?? 'Executive PDF v2.3';
  const classificationRaw = String(pdfData.report_classification ?? 'Confidential').toLowerCase();
  const classification = classificationRaw === 'public' ? 'Public'
    : classificationRaw === 'internal' ? 'Internal'
    : 'Confidential';
  const whiteLabelFooter = pdfData.white_label?.footer_text
    || pdfData.msp?.footer_text
    || 'CyberMeters Platform';
  const sp   = pdfData.security_posture     ?? {};
  const es   = pdfData.executive_summary    ?? {};
  const fs   = pdfData.findings_summary     ?? {};
  const ai   = pdfData.asset_inventory      ?? {};
  const vr   = pdfData.vendor_risk          ?? {};
  const bm   = pdfData.brand_monitoring     ?? {};
  const ci   = pdfData.certificate_intelligence ?? {};
  const brs  = pdfData.business_risk        ?? {};
  const scn  = pdfData.supply_chain         ?? {};
  const ce   = pdfData.cyber_essentials     ?? {};
  const hist = pdfData.historical_analysis  ?? {};
  const atk  = pdfData.attack_surface       ?? {};
  const plan = pdfData.priority_action_plan ?? [];
  const topR = pdfData.top_risks            ?? [];
  const topC = pdfData.top_recommendations  ?? [];
  const trnd = pdfData.risk_trend           ?? [];
  const ovr  = pdfData.overall_score;
  const rtng = String(pdfData.risk_rating   ?? 'Unknown');
  const NP   = 12;  // total pages (v2.3: +1 Eight-Domain Cyber MOT Coverage Summary)

  // ── PAGE 1: COVER ─────────────────────────────────────────────────────────
  {
    const pg = newPage();
    pg.fillRect(0, 0, W, H, C.lgray);
    pg.fillRect(0, 0, 190, H, C.dkgreen);

    pg.text('CYBERMETERS', 16, H - 50, 14, 'B', C.white);
    pg.text('Platform',    16, H - 66,  9, 'R', C.teal);

    const scoreStr = ovr != null ? String(ovr) : '--';
    pg.fillRect(12, H/2 - 85, 166, 115, C.green);
    pg.text('SECURITY SCORE', 22, H/2 + 16, 7.5, 'B', C.white);
    const sX = scoreStr.length >= 3 ? 50 : scoreStr.length === 2 ? 65 : 80;
    pg.text(scoreStr, sX, H/2 - 38, 50, 'B', C.white);
    pg.text('/ 100', 60, H/2 - 60, 10, 'R', C.teal);
    pg.text('RISK RATING', 22, H/2 - 103, 7.5, 'B', C.teal);
    pg.text(rtng.toUpperCase(), 22, H/2 - 119, 12, 'B', C.white);
    pg.text('Generated:', 22, 85, 7.5, 'R', C.teal);
    pg.text(gd,           22, 71, 8.5, 'B', C.white);

    pg.fillRect(190, H - 120, W - 190, 120, C.green);
    pg.text('EXECUTIVE',       208, H - 55,  22, 'B', C.white);
    pg.text('SECURITY REPORT', 208, H - 80,  22, 'B', C.white);
    pg.text(`${classification} - For authorised recipients only`, 208, H - 100, 8, 'R', C.teal);
    pg.strokeRect(W - 150, H - 92, 110, 48, C.teal, 0.8);
    pg.text('CUSTOMER LOGO', W - 132, H - 64, 8, 'B', C.white);
    pg.text('PLACEHOLDER', W - 126, H - 78, 7, 'R', C.teal);

    let ry = H - 148;
    pg.text('Workspace',    208, ry, 8, 'R', C.mgray);
    pg.text(String(ws.name ?? 'Unknown'), 295, ry, 11, 'B', C.dkgray); ry -= 20;
    pg.text('Report Date',  208, ry, 8, 'R', C.mgray);
    pg.text(gd,             295, ry,  9, 'R', C.dkgray); ry -= 20;
    pg.text('Report ID',    208, ry, 8, 'R', C.mgray);
    pg.text(String(reportId ?? 'Not archived'), 295, ry, 8.5, 'R', C.dkgray); ry -= 20;
    pg.text('Report Version', 208, ry, 8, 'R', C.mgray);
    pg.text(String(reportVersion), 295, ry, 8.5, 'R', C.dkgray); ry -= 20;
    pg.text('Generated By',  208, ry, 8, 'R', C.mgray);
    pg.text('CyberMeters',   295, ry, 9, 'R', C.dkgray); ry -= 20;
    pg.text('Classification', 208, ry, 8, 'R', C.mgray);
    pg.text(`${classification} - Prepared for ${String(ws.name ?? 'workspace').slice(0, 32)}`, 295, ry, 8, 'R', C.dkgray); ry -= 20;
    pg.text('Coverage',     208, ry, 8, 'R', C.mgray);
    pg.text('Last 30 days', 295, ry,  9, 'R', C.dkgray); ry -= 12;
    pg.hline(208, ry, W - 220, C.lgray, 0.8); ry -= 18;

    pg.text('SECURITY POSTURE OVERVIEW', 208, ry, 8, 'B', C.green); ry -= 15;
    for (const [name, cat] of [
      ['Email Security',     sp.email_security],
      ['SSL & Certificates', sp.ssl_certificates],
      ['Attack Surface',     sp.attack_surface],
      ['Third-Party Risk',   sp.third_party_risk],
      ['Admin Exposure',     sp.admin_exposure],
    ]) {
      const cs = cat?.score  ?? null;
      const st = cat?.status ?? 'unknown';
      const bc = st === 'good' ? C.green : st === 'fair' ? C.blue : st === 'warning' ? C.amber : st === 'critical' ? C.red : C.mgray;
      // Category name in its service colour (which service); bar/score in status
      // colour (how healthy) — the two axes stay visually distinct.
      pg.fillRect(203, ry - 2, 2.4, 9, svcColorFor(name));
      pg.text(name, 208, ry, 8.5, 'B', svcColorFor(name));
      pg.fillRect(315, ry - 2, 88, 9, C.lgray);
      if (cs != null) pg.fillRect(315, ry - 2, Math.max(1, Math.round(88 * cs / 100)), 9, bc);
      pg.text(cs != null ? String(cs) : '-', 408, ry, 8.5, 'B', bc);
      ry -= 15;
    }
    pg.hline(208, ry, W - 220, C.lgray, 0.5); ry -= 14;
    pg.text('BUSINESS RISK', 208, ry, 8, 'B', C.green); ry -= 14;
    pg.text(`BRS: ${brs.business_risk_score ?? '-'} / 100`, 208, ry, 10, 'B', C.dkgray);
    pg.text(`Band: ${String(brs.risk_band ?? 'unknown').toUpperCase()}`, 315, ry, 9, 'R', C.mgray);
    ry -= 18;
    pg.text(`Supply Chain: ${scn.supply_chain_score ?? '-'} / 100`, 208, ry, 9, 'R', C.dkgray);
    pg.text(`CE Alignment: ${ce.score ?? '-'} ${ce.grade ? `(${ce.grade})` : ''}`, 315, ry, 9, 'R', C.dkgray);
    ry -= 18;
    pg.text('FINDINGS SNAPSHOT', 208, ry, 8, 'B', C.green); ry -= 14;
    let fx = 208;
    for (const [lbl, cnt, col] of [['Critical', fs.critical ?? 0, C.red], ['High', fs.high ?? 0, C.amber], ['Medium', fs.medium ?? 0, C.blue], ['Low', fs.low ?? 0, C.mgray]]) {
      pg.fillRect(fx, ry - 24, 82, 30, col);
      pg.text(String(cnt), fx + (cnt >= 10 ? 24 : 30), ry - 7, 14, 'B', C.white);
      pg.text(lbl, fx + 5, ry - 23, 7, 'R', C.white);
      fx += 83;
    }
    pg.flush();
  }

  // ── PAGE 2: EXECUTIVE SUMMARY ─────────────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Executive Summary');
    pgFooter(pg, 2, NP);
    let y = H - 45;

    y = secBar(pg, 'Executive Summary', y); y -= 6;

    const status = String(pdfData.executive_status ?? rtng ?? 'unknown');
    const businessNarrative = pdfData.business_impact_narrative
      ?? 'CyberMeters translates external security signals into business risk guidance for executive decision-making.';
    pg.text(`Overall risk status: ${status.toUpperCase()}`, ML + 8, y - 10, 10, 'B', C.dkgray); y -= 16;
    y = drawWrapped(pg, businessNarrative, ML + 8, y - 8, CW - 16, 8.5, 'R', C.mgray, 3, 12);
    y -= 8;

    const observations = pdfData.top_observations ?? [];
    pg.text('Top observations', ML + 8, y - 8, 9, 'B', C.green); y -= 18;
    for (const obs of observations.slice(0, 3)) {
      y = drawWrapped(pg, `* ${obs}`, ML + 12, y - 4, CW - 24, 8.3, 'R', C.dkgray, 2, 11);
    }
    y -= 8;

    // Strengths
    pg.fillRect(ML, y - 18, CW, 18, [0.216, 0.580, 0.416]);
    pg.text('STRENGTHS', ML + 8, y - 12, 9, 'B', C.white); y -= 22;
    const strengths = es.strengths ?? [];
    if (!strengths.length) { pg.text('Security monitoring is active.', ML + 8, y - 10, 8.5, 'R', C.mgray); y -= 14; }
    for (const s of strengths.slice(0, 4)) {
      for (const ln of wrap(s, CW - 20, 8.5)) { if (y < 90) break; pg.text('* ' + ln, ML + 8, y - 10, 8.5, 'R', C.dkgray); y -= 13; }
    }
    y -= 6;

    // Weaknesses
    pg.fillRect(ML, y - 18, CW, 18, C.red);
    pg.text('WEAKNESSES', ML + 8, y - 12, 9, 'B', C.white); y -= 22;
    const weaknesses = es.weaknesses ?? [];
    if (!weaknesses.length) { pg.text('No significant weaknesses identified.', ML + 8, y - 10, 8.5, 'R', C.mgray); y -= 14; }
    for (const w of weaknesses.slice(0, 4)) {
      for (const ln of wrap(w, CW - 20, 8.5)) { if (y < 90) break; pg.text('* ' + ln, ML + 8, y - 10, 8.5, 'R', C.dkgray); y -= 13; }
    }
    y -= 6;

    // Priority actions
    pg.fillRect(ML, y - 18, CW, 18, C.amber);
    pg.text('PRIORITY ACTIONS', ML + 8, y - 12, 9, 'B', C.white); y -= 22;
    const actions = es.priority_actions ?? [];
    if (!actions.length) { pg.text('No priority actions at this time.', ML + 8, y - 10, 8.5, 'R', C.mgray); y -= 14; }
    for (let i = 0; i < actions.length && y > 90; i++) {
      pg.fillRect(ML + 6, y - 15, 16, 14, C.green);
      pg.text(String(i + 1), ML + 11, y - 10, 8, 'B', C.white);
      for (const ln of wrap(actions[i], CW - 36, 8.5)) {
        if (y < 90) break;
        pg.text(ln, ML + 28, y - 10, 8.5, 'R', C.dkgray); y -= 13;
      }
      y -= 4;
    }
    y -= 10;

    // Findings summary
    if (y > 120) {
      y = secBar(pg, 'Findings Summary', y); y -= 10;
      const bw2 = Math.floor(CW / 5);
      let sx = ML;
      for (const [lbl, cnt, col] of [['Critical', fs.critical ?? 0, C.red], ['High', fs.high ?? 0, C.amber], ['Medium', fs.medium ?? 0, C.blue], ['Low', fs.low ?? 0, C.mgray], ['Info', fs.info ?? 0, [0.6, 0.6, 0.6]]]) {
        pg.fillRect(sx, y - 42, bw2 - 3, 42, col);
        const ns = String(cnt);
        pg.text(ns, sx + Math.max(4, Math.floor((bw2 - 3) / 2) - ns.length * 7), y - 16, 20, 'B', C.white);
        pg.text(lbl, sx + 6, y - 40, 7.5, 'R', C.white);
        sx += bw2;
      }
      y -= 50;
      pg.text(`Total findings: ${fs.total ?? 0}`, ML, y - 8, 9, 'B', C.dkgray);
    }

    // ── Phase 7 — Trust quality overview (Sprint 9F) ──────────────────────
    // Compute confidence tiers from topR entries enriched with R2 trust data.
    // Only rendered when at least one finding has a confidence value.
    const _trustFindings  = topR.filter(r => r.confidence != null);
    if (_trustFindings.length > 0 && y > 90) {
      const _verified9F   = _trustFindings.filter(r => r.confidence >= 90).length;
      const _strong9F     = _trustFindings.filter(r => r.confidence >= 80 && r.confidence < 90).length;
      const _review9F     = _trustFindings.filter(r => r.confidence < 70).length;
      y -= 14;
      y = secBar(pg, 'Findings Quality Overview', y); y -= 8;
      const _tqNote = `Based on ${_trustFindings.length} of ${topR.length} top finding${topR.length === 1 ? '' : 's'} with evidence data.`;
      y = drawWrapped(pg, _tqNote, ML + 8, y, CW - 16, 7.5, 'R', C.mgray, 1, 10);
      y -= 4;
      const _tqCols = Math.floor(CW / 3);
      const _tqItems = [
        ['Verified (>=90)', _verified9F, C.green],
        ['Strong evidence (80-89)', _strong9F, [0.024, 0.502, 0.376]],
        ['Needs review (<70)', _review9F, C.amber],
      ];
      let _tqX = ML;
      for (const [_lbl, _cnt, _col] of _tqItems) {
        pg.fillRect(_tqX, y - 34, _tqCols - 4, 34, C.lgray);
        pg.text(String(_cnt), _tqX + 8, y - 10, 16, 'B', _col);
        pg.text(_lbl, _tqX + 6, y - 32, 6.5, 'R', C.mgray);
        _tqX += _tqCols;
      }
      y -= 42;
    }

    pg.flush();
  }

  // ── PAGE 3: BUSINESS RISK SCORE ──────────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Business Risk');
    pgFooter(pg, 3, NP);
    let y = H - 45;

    y = secBar(pg, 'Business Risk Score', y); y -= 8;
    const brsScore = brs.business_risk_score ?? brs.score ?? null;
    const brsBand  = String(brs.risk_band ?? brs.band ?? 'unknown');
    const brsColor = brsScore == null ? C.mgray : brsScore >= 75 ? C.green : brsScore >= 50 ? C.amber : C.red;

    // Large BRS score display
    pg.fillRect(ML, y - 80, CW, 80, C.lgray);
    pg.text('BUSINESS RISK SCORE', ML + 10, y - 14, 8, 'B', C.mgray);
    const brsStr = brsScore != null ? String(brsScore) : '--';
    pg.text(brsStr, ML + 10, y - 55, 36, 'B', brsColor);
    pg.text('/ 100', ML + 10 + brsStr.length * 22, y - 50, 11, 'R', C.mgray);
    const bandColors = { low: C.green, medium: C.amber, high: C.amber, critical: C.red };
    const bandColor  = bandColors[brsBand] ?? C.mgray;
    pg.fillRect(ML + CW - 180, y - 72, 170, 62, bandColor);
    pg.text('RISK BAND', ML + CW - 170, y - 24, 8, 'B', C.white);
    pg.text(brsBand.toUpperCase(), ML + CW - 170, y - 48, 20, 'B', C.white);
    pg.text(brsBand === 'low'      ? 'Posture is well-controlled'
          : brsBand === 'medium'   ? 'Some exposure — monitor closely'
          : brsBand === 'high'     ? 'Elevated — remediation required'
          : brsBand === 'critical' ? 'Critical — immediate action needed'
          : 'Risk band not yet computed', ML + CW - 170, y - 62, 7, 'R', [1,1,1,0.85]);
    y -= 90;

    y = drawWrapped(pg, brs.summary || 'Business Risk Score (BRS) converts technical security signals and vendor dependency exposure into a single executive risk indicator on a 0-100 scale. Higher scores indicate better-controlled risk.', ML, y, CW, 8.5, 'R', C.mgray, 3, 12);
    y -= 14;

    pg.text('Risk drivers', ML, y, 9, 'B', C.green); y -= 14;
    const driverEntries = Object.entries(brs.drivers ?? {}).slice(0, 5);
    if (!driverEntries.length) {
      pg.text('No major business risk drivers available. Run scans to build BRS data.', ML + 8, y, 8.5, 'R', C.mgray);
      y -= 14;
    }
    for (const [key, val] of driverEntries) {
      const driverColor = String(val) === 'critical' || String(val) === 'elevated' ? C.red
                        : String(val) === 'high'   ? C.amber : C.dkgray;
      pg.fillRect(ML, y - 15, CW, 18, driverEntries.indexOf([key, val]) % 2 === 0 ? C.lgray : C.white);
      pg.text(key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), ML + 8, y - 6, 8.5, 'B', C.dkgray);
      pg.text(String(val).toUpperCase(), ML + CW - 90, y - 6, 8.5, 'B', driverColor);
      y -= 20;
    }
    y -= 8;

    if (y > 110) {
      pg.text('Executive recommendations', ML, y, 9, 'B', C.green); y -= 14;
      const brsRecs = brs.recommendations ?? [];
      for (const rec of brsRecs.slice(0, 4)) {
        if (y < 90) break;
        y = drawWrapped(pg, `* ${rec}`, ML + 8, y, CW - 16, 8.2, 'R', C.dkgray, 2, 11);
      }
      if (!brsRecs.length) {
        pg.text('No BRS recommendations available. Run a scan to generate business risk analysis.', ML + 8, y, 8.5, 'R', C.mgray);
      }
    }
    pg.flush();
  }

  // ── PAGE 4: TOP 5 REMEDIATION CARDS ──────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Remediation Plan');
    pgFooter(pg, 4, NP);
    let y = H - 45;

    y = secBar(pg, 'Top 5 Remediation Cards', y); y -= 8;
    const rawActions = plan.length ? plan : (topC ?? []).map(r => ({
      remediation_id: r.remediation_id ?? null,
      title: r.title,
      action: r.description,
      recommended_action: r.description,
      impact: r.business_impact || 'Reduces business exposure and improves executive risk posture.',
      business_impact: r.business_impact || 'Reduces business exposure and improves executive risk posture.',
      effort_estimate: 'Medium',
    }));
    // Dedupe near-identical cards (e.g. two "Strengthen DMARC Policy" entries
    // from different engines) by the core recommended action with the title
    // prefix stripped — while keeping distinct gaps that share a title
    // (e.g. several "Improve Cyber Essentials alignment" cards).
    const _seenRem = new Set();
    const actions = [];
    for (const a of rawActions) {
      const title = String(a.title || '').trim();
      let act = String(a.recommended_action || a.action || title).trim();
      if (title && act.toLowerCase().startsWith(title.toLowerCase())) {
        act = act.slice(title.length).replace(/^\s*[-–:]\s*/, '');
      }
      const key = act.toLowerCase().replace(/\s+/g, ' ').replace(/\.+$/, '');
      if (!key || _seenRem.has(key)) continue;
      _seenRem.add(key);
      actions.push(a);
    }
    if (!actions.length) {
      pg.text('No priority remediation actions at this time. Run additional scans to generate recommendations.', ML + 8, y - 10, 9, 'R', C.mgray);
      y -= 24;
    }
    for (let i = 0; i < Math.min(actions.length, 5) && y > 95; i++) {
      const action = actions[i];
      const rowH = 82;
      pg.fillRect(ML, y - rowH, CW, rowH, i % 2 === 0 ? C.lgray : C.white);
      pg.strokeRect(ML, y - rowH, CW, rowH, C.mgray, 0.25);
      pg.fillRect(ML + 7, y - 28, 26, 22, C.green);
      pg.text(String(i + 1), ML + 17, y - 20, 11, 'B', C.white);
      pg.text(String(action.title || 'Priority remediation').slice(0, 72), ML + 42, y - 12, 9.5, 'B', C.dkgray);
      pg.text(`Effort: ${String(action.effort_estimate || action.effort || 'Medium')}`, ML + CW - 95, y - 12, 7.5, 'B', C.mgray);
      pg.text('Business impact', ML + 42, y - 27, 7.2, 'B', C.green);
      y = drawWrapped(pg, action.business_impact || action.impact || 'Reduces business exposure and improves executive risk posture.', ML + 42, y - 38, CW - 56, 7.5, 'R', C.dkgray, 2, 9);
      pg.text('Recommended action', ML + 42, y - 3, 7.2, 'B', C.green);
      y = drawWrapped(pg, action.recommended_action || action.action || action.title || '', ML + 42, y - 14, CW - 56, 7.5, 'R', C.dkgray, 2, 9);
      y -= rowH - 66;
    }
    pg.flush();
  }

  // ── PAGE 5: TOP SECURITY FINDINGS (Sprint 9F — Trust Layer) ──────────────
  // Renders topR with trust badges, evidence summary, verification commands,
  // and low-confidence warnings. Trust fields come from R2 enrichment in
  // collectPdfData(). Gracefully handles findings with no trust data.
  {
    const pg = newPage();
    pgBanner(pg, 'Top Security Findings');
    pgFooter(pg, 5, NP);
    let y = H - 45;

    y = secBar(pg, 'Top Security Findings', y); y -= 6;

    // Sprint 9F helper: confidence tier label and color
    function _pdfConfLabel(conf) {
      if (conf == null) return null;
      if (conf >= 90) return { label: 'Verified', col: C.green };
      if (conf >= 80) return { label: 'Strong', col: [0.024, 0.502, 0.376] };
      if (conf >= 70) return { label: 'Probable', col: C.amber };
      return { label: 'Weak signal', col: C.mgray };
    }
    // Sprint 9F helper: quality pill color
    function _pdfQualityCol(q) {
      return q === 'excellent' ? C.green
        : q === 'good'        ? [0.024, 0.502, 0.376]
        : q === 'partial'     ? C.amber
        : C.mgray;
    }

    if (!topR.length) {
      pg.text('No findings recorded for this workspace yet. Run scans to populate this section.', ML + 8, y - 14, 9, 'R', C.mgray);
      y -= 28;
    }

    for (let _fi = 0; _fi < topR.length && y > 90; _fi++) {
      const _f    = topR[_fi];
      const _conf = typeof _f.confidence === 'number' ? _f.confidence : null;
      const _vq   = _f.validation_quality ?? null;
      const _eq   = _f.evidence_quality   ?? null;
      const _ev   = Array.isArray(_f.evidence) ? _f.evidence : [];
      const _isLow = _conf != null && _conf < 70;

      // ── Phase 6: Low-confidence warning banner ─────────────────────────
      if (_isLow) {
        pg.fillRect(ML, y - 14, CW, 14, C.amber);
        pg.text('NEEDS VERIFICATION — low-confidence finding. Manually confirm before acting.', ML + 6, y - 5, 7, 'B', C.white);
        y -= 16;
      }

      // ── Finding header row ─────────────────────────────────────────────
      const _sevC = sevColor(_f.severity);
      pg.fillRect(ML, y - 18, CW, 18, C.lgray);
      pg.fillRect(ML, y - 18, 6, 18, _sevC);
      pg.text(esc((_f.title ?? 'Unknown finding').slice(0, 70)), ML + 12, y - 8, 8.5, 'B', C.dkgray);
      if (_f.domain) pg.text(esc(_f.domain.slice(0, 40)), ML + CW - 180, y - 8, 7.5, 'R', C.mgray);
      if (_f.date)   pg.text(_f.date, ML + CW - 55, y - 8, 7, 'R', C.mgray);
      y -= 20;

      // ── Phase 3: Trust badge row ───────────────────────────────────────
      let _bx = ML + 4;
      const _sevLabel = (_f.severity ?? 'medium').toUpperCase();
      pg.fillRect(_bx, y - 13, _sevLabel.length * 5 + 10, 13, _sevC);
      pg.text(_sevLabel, _bx + 5, y - 5, 6.5, 'B', C.white);
      _bx += _sevLabel.length * 5 + 16;

      if (_conf != null) {
        const _ct = _pdfConfLabel(_conf);
        pg.fillRect(_bx, y - 13, 76, 13, C.lgray);
        pg.text(`${_conf}`, _bx + 4, y - 5, 6.5, 'B', _ct.col);
        pg.text(_ct.label, _bx + 22, y - 5, 6.5, 'R', _ct.col);
        _bx += 82;
      }
      if (_vq) {
        const _vqC = _pdfQualityCol(_vq);
        pg.fillRect(_bx, y - 13, 80, 13, C.lgray);
        pg.text(`VQ: ${_vq}`, _bx + 4, y - 5, 6.5, 'R', _vqC);
        _bx += 86;
      }
      if (_eq) {
        const _eqC = _pdfQualityCol(_eq);
        pg.fillRect(_bx, y - 13, 70, 13, C.lgray);
        pg.text(`EQ: ${_eq}`, _bx + 4, y - 5, 6.5, 'R', _eqC);
      }
      y -= 16;

      // ── Recommendation line ────────────────────────────────────────────
      if (_f.recommendation) {
        y = drawWrapped(pg, _f.recommendation, ML + 8, y, CW - 16, 7.5, 'R', C.mgray, 2, 10);
      }

      // ── Phase 4: Evidence summary (max 3 items) ────────────────────────
      if (_ev.length > 0) {
        pg.text('Evidence:', ML + 8, y - 4, 7, 'B', C.green); y -= 14;
        for (let _ei = 0; _ei < Math.min(_ev.length, 3) && y > 90; _ei++) {
          const _e = _ev[_ei];
          const _evType  = String(_e.type  ?? _e.evidence_type  ?? 'probe');
          const _evLabel = String(_e.label ?? _e.probe_target   ?? _e.queried_hostname ?? _e.target ?? '');
          const _evVal   = _e.value ?? _e.observed_value ?? _e.returned_records ?? _e.observed_headers ?? null;
          const _evLine  = _evLabel
            ? `${_evType}: ${_evLabel}${_evVal != null ? ' = ' + String(_evVal).slice(0, 40) : ''}`
            : `${_evType}${_evVal != null ? ': ' + String(_evVal).slice(0, 50) : ''}`;
          pg.text('*', ML + 12, y - 4, 7, 'R', C.mgray);
          y = drawWrapped(pg, _evLine, ML + 20, y, CW - 32, 7, 'R', C.dkgray, 1, 10);
          y -= 1;
        }
        y -= 3;
      }

      // ── Phase 5: Verification command (first evidence item with command) ─
      const _cmdEv = _ev.find(e => e.manual_verification_command);
      if (_cmdEv?.manual_verification_command && y > 90) {
        const _cmd = String(_cmdEv.manual_verification_command).slice(0, 80);
        pg.fillRect(ML + 8, y - 16, CW - 16, 16, [0.949, 0.953, 0.965]);
        pg.text(_cmd, ML + 12, y - 6, 6.5, 'R', C.dkgray);
        y -= 19;
      }

      // Row separator
      if (y > 90) { pg.hline(ML, y, CW, C.lgray, 0.4); y -= 6; }
    }
    pg.flush();
  }

  // ── PAGE 6: ATTACK SURFACE SUMMARY ───────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Attack Surface');
    pgFooter(pg, 6, NP);
    let y = H - 45;

    y = secBar(pg, 'Attack Surface Summary', y, C.svcSurface); y -= 8;
    const atkItems = [
      ['Exposed Assets',         atk.exposed_assets ?? ai.assets?.current ?? '-'],
      ['SSL/TLS Posture',        atk.ssl_tls_posture ?? sp.ssl_certificates?.status ?? 'unknown'],
      ['Email Security Posture', atk.email_security_posture ?? sp.email_security?.status ?? 'unknown'],
      ['Security Headers',       atk.security_headers ?? 'unknown'],
      ['Critical Findings',      fs.critical ?? 0],
      ['High Findings',          fs.high ?? 0],
    ];
    let ax = ML, ay = y - 12;
    const c2 = Math.floor(CW / 2) - 5;
    for (let i = 0; i < atkItems.length; i++) {
      const [label, value] = atkItems[i];
      const val = String(value);
      const vc = val === 'good' || val === '0' ? C.green
        : val === 'critical' || (label.includes('Critical') && Number(value) > 0) ? C.red
        : val === 'warning' || (label.includes('High') && Number(value) > 0) ? C.amber
        : C.dkgray;
      const _svc = svcColorFor(label);
      pg.fillRect(ax, ay - 28, c2, 34, i % 4 < 2 ? C.lgray : C.white);
      pg.fillRect(ax, ay - 28, 2.6, 34, _svc);
      pg.text(label, ax + 10, ay - 6, 8, 'B', _svc);
      pg.text(val.toUpperCase().slice(0, 28), ax + 10, ay - 22, 12, 'B', vc);
      if (ax === ML) ax = ML + c2 + 10;
      else { ax = ML; ay -= 40; }
    }
    y = ay - 22;

    y = secBar(pg, 'Observed Control Posture', y); y -= 8;
    for (const [name, cat] of [
      ['SSL and certificate configuration', sp.ssl_certificates],
      ['Email authentication controls',     sp.email_security],
      ['External attack surface controls',  sp.attack_surface],
      ['Public admin exposure',             sp.admin_exposure],
    ]) {
      if (y < 95) break;
      const score = cat?.score ?? null;
      const status = cat?.status ?? 'unknown';
      const col = status === 'good' ? C.green : status === 'fair' ? C.blue : status === 'warning' ? C.amber : status === 'critical' ? C.red : C.mgray;
      const svc = svcColorFor(name);
      pg.fillRect(ML, y - 22, CW, 24, C.lgray);
      pg.fillRect(ML, y - 22, 3, 24, svc);
      pg.text(name, ML + 11, y - 8, 8.5, 'B', svc);
      pg.text(score != null ? `${score}/100` : status.toUpperCase(), ML + CW - 82, y - 8, 8.5, 'B', col);
      y -= 28;
    }
    pg.flush();
  }

  // ── PAGE 7: VENDOR RISK ──────────────────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Vendor Risk');
    pgFooter(pg, 7, NP);
    let y = H - 45;

    y = secBar(pg, 'Vendor Risk Summary', y); y -= 8;
    const vendorNarrative = vr.high > 0
      ? `${vr.high} high-risk vendor relationship${vr.high === 1 ? '' : 's'} should be reviewed for business dependency and resilience exposure.`
      : vr.total > 0
        ? `${vr.total} vendor relationship${vr.total === 1 ? '' : 's'} were identified from observable external signals. No high-risk vendor concentration is currently highlighted.`
        : 'No vendor relationships have been identified yet. Run scans to populate vendor dependency analysis.';
    y = drawWrapped(pg, vendorNarrative, ML, y, CW, 8.5, 'R', C.mgray, 3, 12);
    y -= 12;

    const c3 = Math.floor(CW / 4) - 4;
    let vx = ML;
    for (const [k, v, col] of [
      ['Total Vendors', vr.total ?? '-', C.dkgray],
      ['High Risk',     vr.high ?? '-',  Number(vr.high ?? 0) > 0 ? C.red : C.green],
      ['Medium Risk',   vr.medium ?? '-', C.amber],
      ['Concentration', scn.concentration_level ?? 'unknown', C.blue],
    ]) {
      pg.fillRect(vx, y - 44, c3, 44, C.lgray);
      pg.text(k, vx + 6, y - 10, 7.5, 'R', C.mgray);
      pg.text(String(v).toUpperCase(), vx + 6, y - 31, 12, 'B', col);
      vx += c3 + 6;
    }
    y -= 58;

    y = secBar(pg, 'Top 5 Vendor Dependencies', y); y -= 8;
    const topVendors = scn.top_vendor_dependencies ?? [];
    if (!topVendors.length) {
      pg.text('No detailed vendor dependency list is available yet.', ML + 8, y - 10, 9, 'R', C.mgray);
      y -= 24;
    } else {
      const VCOLS = [190, 120, 100, 102];
      const VHDRS = ['Vendor', 'Category', 'Risk Level', 'Confidence'];
      pg.fillRect(ML, y - 17, CW, 17, C.dkgray);
      let hx = ML;
      for (let i = 0; i < VHDRS.length; i++) {
        pg.text(VHDRS[i], hx + 4, y - 11, 7.5, 'B', C.white); hx += VCOLS[i];
      }
      y -= 19;
      for (let i = 0; i < Math.min(topVendors.length, 5) && y > 90; i++) {
        const v = topVendors[i];
        const rl = String(v.risk_level ?? 'unknown').toLowerCase();
        const rlC = rl === 'critical' ? C.red : rl === 'high' ? C.amber : rl === 'medium' ? C.blue : C.mgray;
        pg.fillRect(ML, y - 18, CW, 18, i % 2 === 0 ? C.lgray : C.white);
        let x = ML;
        pg.text(String(v.name ?? v.vendor_name ?? '-').slice(0, 30), x + 4, y - 11, 8, 'R', C.dkgray); x += VCOLS[0];
        pg.text(String(v.category ?? '-').slice(0, 18), x + 4, y - 11, 8, 'R', C.mgray); x += VCOLS[1];
        pg.fillRect(x + 4, y - 15, VCOLS[2] - 10, 12, rlC);
        pg.text(rl.toUpperCase(), x + 7, y - 10, 6.5, 'B', C.white); x += VCOLS[2];
        pg.text(String(v.confidence ?? '-'), x + 4, y - 11, 8, 'R', C.mgray);
        y -= 19;
      }
    }
    pg.flush();
  }

  // ── PAGE 8: SUPPLY CHAIN & RESILIENCE ────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Supply Chain');
    pgFooter(pg, 8, NP);
    let y = H - 45;

    y = secBar(pg, 'Supply Chain & Operational Resilience', y); y -= 8;

    // Score cards
    const scCards = [
      ['Supply Chain Score',   scn.supply_chain_score              ?? null, '/100'],
      ['Resilience Score',     scn.resilience_score ?? scn.operational_resilience_score ?? null, '/100'],
      ['Concentration Level',  scn.concentration_level             ?? 'unknown', ''],
      ['Single Points of Failure', scn.spof_count                 ?? 0, ' detected'],
    ];
    let scX = ML;
    for (const [label, value, suffix] of scCards) {
      const valStr = value != null ? String(value) : '-';
      const valCol = label === 'Concentration Level'
        ? (String(value) === 'critical' ? C.red : String(value) === 'high' ? C.amber : String(value) === 'medium' ? C.blue : C.green)
        : label.includes('Failure') && Number(value) > 0 ? C.amber
        : value != null && Number(value) < 50 ? C.amber : C.dkgray;
      pg.fillRect(scX, y - 52, 124, 52, C.lgray);
      pg.strokeRect(scX, y - 52, 124, 52, C.mgray, 0.3);
      pg.text(label, scX + 6, y - 10, 7, 'R', C.mgray);
      pg.text(valStr, scX + 6, y - 38, 18, 'B', valCol);
      if (suffix) pg.text(suffix, scX + 6 + valStr.length * 11, y - 38, 9, 'R', C.mgray);
      scX += 129;
    }
    y -= 62;

    y = drawWrapped(pg, scn.narrative || 'Supply chain intelligence identifies vendor dependencies, concentration risk, and operational resilience based on detected third-party services and vendor relationships.', ML, y, CW, 8.5, 'R', C.mgray, 3, 12);
    y -= 12;

    // Top vendor dependencies
    const topVendors = scn.top_vendor_dependencies ?? [];
    if (topVendors.length > 0) {
      pg.text('Top vendor dependencies', ML, y, 9, 'B', C.green); y -= 14;
      const VCOLS = [190, 130, 100, 92];
      const VHDRS = ['Vendor Name', 'Category', 'Risk Level', 'Confidence'];
      pg.fillRect(ML, y - 17, CW, 17, C.dkgray);
      let vhX = ML;
      for (let i = 0; i < VHDRS.length; i++) {
        pg.text(VHDRS[i], vhX + 4, y - 11, 7.5, 'B', C.white); vhX += VCOLS[i];
      }
      y -= 19;
      for (let vi = 0; vi < Math.min(topVendors.length, 5) && y > 90; vi++) {
        const v   = topVendors[vi];
        const rl  = String(v.risk_level ?? 'unknown').toLowerCase();
        const rlC = rl === 'critical' ? C.red : rl === 'high' ? C.amber : rl === 'medium' ? C.blue : C.mgray;
        pg.fillRect(ML, y - 16, CW, 16, vi % 2 === 0 ? C.lgray : C.white);
        let vrX = ML;
        pg.text(String(v.name ?? v.vendor_name ?? '-').slice(0, 30), vrX + 4, y - 10, 8, 'R', C.dkgray); vrX += VCOLS[0];
        pg.text(String(v.category ?? '-').slice(0, 20), vrX + 4, y - 10, 8, 'R', C.mgray);              vrX += VCOLS[1];
        pg.fillRect(vrX + 4, y - 14, VCOLS[2] - 10, 11, rlC);
        pg.text(rl.toUpperCase(), vrX + 7, y - 9, 6.5, 'B', C.white);                                   vrX += VCOLS[2];
        pg.text(String(v.confidence ?? '-'), vrX + 4, y - 10, 8, 'R', C.mgray);
        pg.hline(ML, y - 16, CW, C.lgray, 0.2);
        y -= 17;
      }
      y -= 8;
    }

    // Cascading risks
    if (y > 100) {
      const cascades = scn.cascading_risks ?? [];
      if (cascades.length) {
        pg.text('Cascading risk scenarios', ML, y, 9, 'B', C.green); y -= 14;
        for (const item of cascades.slice(0, 4)) {
          if (y < 90) break;
          const text = item.scenario || item.message || String(item);
          y = drawWrapped(pg, `* ${text}`, ML + 8, y, CW - 16, 8.2, 'R', C.dkgray, 2, 11);
        }
      } else {
        pg.text('No cascading risk scenarios identified from current supply chain data.', ML + 8, y, 8.5, 'R', C.mgray);
      }
    }
    pg.flush();
  }

  // ── PAGE 9: HISTORICAL TRENDS ────────────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Historical Trends');
    pgFooter(pg, 9, NP);
    let y = H - 45;

    y = secBar(pg, 'Historical Trends', y); y -= 8;
    for (const [label, value, count] of [
      ['CyberMeters Score',      hist.cyber_score,         hist.cyber_score_snapshots],
      ['Business Risk Score',    hist.business_risk_score, hist.business_risk_score_snapshots],
      ['Supply Chain Score',     hist.supply_chain_score,  hist.supply_chain_score_snapshots],
    ]) {
      const hasData = Number(count ?? 0) >= 2;
      const display = hasData ? String(value ?? 'stable') : 'Insufficient historical data available.';
      const col = display === 'improving' ? C.green : display === 'deteriorating' ? C.red : display === 'stable' ? C.blue : C.mgray;
      pg.fillRect(ML, y - 44, CW, 44, C.lgray);
      pg.text(label, ML + 10, y - 13, 9, 'B', C.dkgray);
      pg.text(display.toUpperCase(), ML + 10, y - 31, 10, 'B', col);
      pg.text(`Snapshots reviewed: ${count ?? 0}`, ML + CW - 132, y - 13, 7.5, 'R', C.mgray);
      y -= 52;
    }
    y -= 8;

    y = secBar(pg, 'Recent Security Score Snapshots', y); y -= 4;
    if ((trnd || []).length < 2) {
      pg.text('Insufficient historical data available.', ML + 8, y - 14, 9, 'R', C.mgray);
      y -= 28;
    } else {
      const TCOLS = [100, 110, 110, 110, 82];
      const THDRS = ['Date', 'Avg Score', 'Low Score', 'High Score', 'Assets'];
      pg.fillRect(ML, y - 17, CW, 17, C.dkgray);
      let tx = ML;
      for (let i = 0; i < THDRS.length; i++) {
        pg.text(THDRS[i], tx + 4, y - 12, 7.5, 'B', C.white); tx += TCOLS[i];
      }
      y -= 19;
      for (let ti = 0; ti < Math.min(trnd.length, 12) && y > 90; ti++) {
        const t = trnd[ti];
        const avg = t.average_score;
        const ac = avg == null ? C.dkgray : Number(avg) >= 80 ? C.green : Number(avg) >= 60 ? C.amber : C.red;
        pg.fillRect(ML, y - 16, CW, 16, ti % 2 === 0 ? C.lgray : C.white);
        const vals = [t.date ?? '-', avg ?? '-', t.lowest_score ?? '-', t.highest_score ?? '-', t.asset_count ?? '-'];
        let x = ML;
        for (let i = 0; i < vals.length; i++) {
          pg.text(String(vals[i]), x + 4, y - 11, 8, i === 1 ? 'B' : 'R', i === 1 ? ac : C.dkgray);
          x += TCOLS[i];
        }
        y -= 17;
      }
    }
    pg.flush();
  }

  // ── PAGE 10: CYBER ESSENTIALS ALIGNMENT SUMMARY ──────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Cyber Essentials');
    pgFooter(pg, 10, NP);
    let y = H - 45;

    y = secBar(pg, 'Cyber Essentials Alignment Summary', y); y -= 10;

    // Score and grade display
    const ceScore = ce.score ?? null;
    const ceGrade = ce.grade ?? null;
    const ceColor = ceScore == null ? C.mgray : ceScore >= 80 ? C.green : ceScore >= 60 ? C.blue : ceScore >= 40 ? C.amber : C.red;
    pg.fillRect(ML, y - 68, CW, 68, C.lgray);
    pg.text('ALIGNMENT INDICATOR', ML + 10, y - 14, 8, 'B', C.mgray);
    const ceStr = ceScore != null ? String(ceScore) : '--';
    pg.text(ceStr, ML + 10, y - 52, 30, 'B', ceColor);
    pg.text('/ 100', ML + 10 + ceStr.length * 19, y - 48, 10, 'R', C.mgray);
    if (ceGrade) {
      pg.fillRect(ML + CW - 150, y - 60, 140, 50, ceColor);
      pg.text('ALIGNMENT GRADE', ML + CW - 140, y - 22, 8, 'B', C.white);
      pg.text(ceGrade, ML + CW - 140, y - 48, 22, 'B', C.white);
    }
    y -= 78;

    y = drawWrapped(pg, ce.summary || 'Cyber Essentials alignment is estimated from external attack surface signals only. This indicative assessment reflects observed controls, not formal assurance.', ML, y, CW, 8.5, 'R', C.mgray, 3, 12);
    y -= 8;

    pg.fillRect(ML, y - 18, CW, 18, C.amber);
    pg.text('This assessment provides an indicative alignment review against Cyber Essentials control areas and does not constitute certification.', ML + 8, y - 12, 7.2, 'R', C.white);
    y -= 26;

    // Category breakdown
    y = secBar(pg, 'Observed Control Area Breakdown', y); y -= 8;

    const ceCategories = Array.isArray(ce.categories) ? ce.categories : [];
    const catDisplay = [
      ['Boundary Protection',       'boundary_protection'],
      ['Secure Configuration',      'secure_configuration'],
      ['Access Control',            'access_control'],
      ['Phishing & Malware Exposure','malware_protection'],
      ['Patch & Update Management', 'patch_management_readiness'],
    ];
    for (const [catLabel, catKey] of catDisplay) {
      if (y < 90) break;
      const catData  = ceCategories.find(c => c.key === catKey) ?? null;
      const catScore = catData?.score ?? null;
      // Derive status from score: >=80 good, >=60 fair, >=40 warning, else critical
      const catStatus= catScore == null ? 'unknown'
                     : catScore >= 80 ? 'good' : catScore >= 60 ? 'fair'
                     : catScore >= 40 ? 'warning' : 'critical';
      const catColor = catStatus === 'good' ? C.green : catStatus === 'fair' ? C.blue : catStatus === 'warning' ? C.amber : catStatus === 'critical' ? C.red : C.mgray;
      const catBg    = catStatus === 'good' ? [0.93, 0.99, 0.97] : catStatus === 'fair' ? [0.93, 0.94, 0.99] : catStatus === 'warning' ? [0.99, 0.95, 0.86] : catStatus === 'critical' ? [0.99, 0.88, 0.88] : C.lgray;
      pg.fillRect(ML, y - 26, CW, 26, catBg);
      pg.strokeRect(ML, y - 26, CW, 26, catColor, 0.3);
      pg.text(catLabel, ML + 8, y - 11, 8.5, 'R', C.dkgray);
      const barW = CW - 205;
      pg.fillRect(ML + 192, y - 20, barW, 8, C.white);
      if (catScore != null) {
        pg.fillRect(ML + 192, y - 20, Math.max(2, Math.round(barW * catScore / 100)), 8, catColor);
        pg.text(`${catScore}/100`, ML + 192 + barW + 6, y - 14, 8, 'B', catColor);
      } else {
        pg.text('No data', ML + CW - 55, y - 14, 8, 'R', C.mgray);
      }
      y -= 28;
    }
    y -= 8;

    // Top gaps
    const topGaps = Array.isArray(ce.top_gaps) ? ce.top_gaps : [];
    if (topGaps.length && y > 120) {
      pg.text('Key alignment gaps', ML, y, 9, 'B', C.green); y -= 14;
      for (const gap of topGaps.slice(0, 5)) {
        if (y < 90) break;
        y = drawWrapped(pg, `* ${gap}`, ML + 8, y, CW - 16, 8.2, 'R', C.dkgray, 2, 11);
      }
    }

    if (y > 80) {
      pg.hline(ML, y, CW, C.mgray, 0.3); y -= 10;
      pg.text('CyberMeters estimates Cyber Essentials alignment from observed external controls only. No legal assurance is provided.', ML, y, 7.5, 'R', C.mgray);
    }
    pg.flush();
  }

  // ── PAGE 11: METHODOLOGY + APPENDIX SUMMARY ──────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Methodology');
    pgFooter(pg, 11, NP);
    let y = H - 45;

    y = secBar(pg, 'Methodology Summary', y); y -= 8;
    const methodology = [
      `Domains assessed: ${pdfData.last_scanned_domain ?? 'workspace domains detected by CyberMeters'}.`,
      `Assets reviewed: ${ai.assets?.current ?? 0} active asset${(ai.assets?.current ?? 0) === 1 ? '' : 's'} and ${ai.asset_events_30d ?? 0} recent asset event${(ai.asset_events_30d ?? 0) === 1 ? '' : 's'}.`,
      `Vendors identified: ${vr.total ?? 0} third-party vendor relationship${(vr.total ?? 0) === 1 ? '' : 's'} from DNS, headers, certificates, scripts, and CSP signals where available.`,
      `Findings analyzed: ${fs.total ?? 0} current finding${(fs.total ?? 0) === 1 ? '' : 's'}, including ${fs.critical ?? 0} critical and ${fs.high ?? 0} high-severity issue${(fs.high ?? 0) === 1 ? '' : 's'}.`,
      'Scoring is based on observed external signals only.',
      'No active exploitation was performed.',
      'No certification or legal assurance is provided.',
    ];
    for (const item of methodology) {
      if (y < 120) break;
      y = drawWrapped(pg, `* ${item}`, ML + 8, y, CW - 16, 8.3, 'R', C.dkgray, 2, 11);
    }
    y -= 8;

    y = secBar(pg, 'Appendix Summary', y); y -= 8;
    const appendixItems = [
      `Brand monitoring candidates: ${bm.total_candidates ?? 0}; active risks: ${bm.active_risks ?? 0}.`,
      `Certificate intelligence signals: ${ci.signals ?? 0}; status: ${ci.status ?? 'unknown'}.`,
      `Detailed vendor evidence is retained in CyberMeters workspace intelligence views and is summarized here at executive level.`,
      `Report ID: ${reportId ?? 'Not archived'}; version: ${reportVersion}; classification: ${classification}.`,
    ];
    for (const item of appendixItems) {
      if (y < 95) break;
      y = drawWrapped(pg, `* ${item}`, ML + 8, y, CW - 16, 8.3, 'R', C.dkgray, 2, 11);
    }
    y -= 8;

    if (y > 80) {
      pg.hline(ML, y, CW, C.mgray, 0.3); y -= 14;
      pg.text(`This report was generated automatically by ${whiteLabelFooter} - ${reportVersion}.`, ML, y, 8, 'R', C.mgray); y -= 12;
      pg.text(`${classification} - Prepared for ${ws.name ?? 'workspace'}. For authorised recipients only.`, ML, y, 8, 'B', C.mgray);
    }
    pg.flush();
  }

  // ── PAGE 12: EIGHT-DOMAIN CYBER MOT COVERAGE SUMMARY ─────────────────────
  // Every one of the eight Cyber MOT domains appears with one explicit honest
  // state. Missing evidence never renders as healthy; Identity and Shadow IT are
  // shown within their honest current scopes.
  {
    const pg = newPage();
    pgBanner(pg, 'Cyber MOT');
    pgFooter(pg, 12, NP);
    let y = H - 45;
    y = secBar(pg, 'Eight-Domain Cyber MOT Coverage Summary', y); y -= 6;
    y = drawWrapped(pg, 'Every domain of your Cyber MOT and its current honest coverage state. "Provisional" or "Evidence insufficient" means this scan could not fully assess the domain — absence of a finding is never presented as healthy.', ML + 2, y, CW - 4, 8, 'R', C.mgray, 2, 11);
    y -= 8;

    const STATE_LABEL = {
      assessed_healthy: ['Healthy', C.green], issue_detected: ['Issue detected', C.red],
      provisional: ['Provisional', C.amber], degraded: ['Degraded', C.amber],
      unavailable: ['Unavailable', C.mgray], not_configured: ['Not configured', C.mgray],
      customer_input_required: ['Input required', C.blue], monitoring_only: ['Monitoring', C.blue],
      not_yet_assessed: ['Not assessed', C.mgray], evidence_insufficient: ['Evidence insufficient', C.amber],
    };
    const domains = Array.isArray(pdfData.cyber_mot_domains) ? pdfData.cyber_mot_domains : [];
    for (const dm of domains) {
      if (y < 70) break;
      const [label, col] = STATE_LABEL[dm.state] || [String(dm.state || 'unknown'), C.mgray];
      pg.text(String(dm.display_name || dm.domain_key || ''), ML, y, 9.5, 'B', C.dkgreen);
      const chipW = Math.max(52, label.length * 5.2 + 12);
      pg.fillRect(W - MR - chipW, y - 3, chipW, 13, col);
      pg.text(label, W - MR - chipW + 6, y, 7.5, 'B', C.white);
      y -= 15;
      y = drawWrapped(pg, String(dm.summary || dm.description || ''), ML + 8, y, CW - 16, 7.8, 'R', C.dkgray, 2, 10);
      // Honesty limitation for the two scope-sensitive domains.
      if ((dm.domain_key === 'identity_exposure' || dm.domain_key === 'shadow_it_unmanaged_technology') && Array.isArray(dm.limitations) && dm.limitations[0]) {
        y -= 2;
        y = drawWrapped(pg, dm.limitations[0], ML + 8, y, CW - 16, 7.2, 'R', C.mgray, 1, 9);
      }
      y -= 9;
    }
    pg.flush();
  }

  // ── Assemble PDF bytes ────────────────────────────────────────────────────
  const kidsStr = _pageIds.map(id => `${id} 0 R`).join(' ');
  const allObjs = [
    { id: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' },
    { id: 2, body: `<< /Type /Pages /Kids [${kidsStr}] /Count ${_pageIds.length} >>` },
    { id: 3, body: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>' },
    { id: 4, body: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>' },
    ..._objs,
  ].sort((a, b) => a.id - b.id);

  const enc    = new TextEncoder();
  const chunks = [];
  let bPos     = 0;
  const xmap   = new Map();
  function wrt(s) { const b = enc.encode(s); chunks.push(b); bPos += b.length; }

  wrt('%PDF-1.4\n');
  for (const o of allObjs) {
    xmap.set(o.id, bPos);
    wrt(`${o.id} 0 obj\n${o.body}\nendobj\n\n`);
  }

  const xrefPos = bPos;
  const maxId   = allObjs[allObjs.length - 1].id;
  wrt('xref\n');
  wrt(`0 ${maxId + 1}\n`);
  wrt('0000000000 65535 f \n');
  for (let id = 1; id <= maxId; id++) {
    if (xmap.has(id)) wrt(`${String(xmap.get(id)).padStart(10, '0')} 00000 n \n`);
    else               wrt('0000000000 65535 f \n');
  }
  wrt('trailer\n');
  wrt(`<< /Size ${maxId + 1} /Root 1 0 R >>\n`);
  wrt('startxref\n');
  wrt(`${xrefPos}\n`);
  wrt('%%EOF\n');

  const total = chunks.reduce((s, b) => s + b.length, 0);
  const out   = new Uint8Array(total);
  let pos     = 0;
  for (const b of chunks) { out.set(b, pos); pos += b.length; }
  return out;
}

// ── collectPdfData ────────────────────────────────────────────────────────────
// Shared data layer for both /scorecard/pdf-data (JSON) and /scorecard/pdf (PDF).
// Returns the full data object on success, null if workspace not found.
// Throws on database or scorecard errors.

export async function collectPdfData(wsId, env) {
  const ws = await env.cybermeters_db
    .prepare('SELECT id, name, created_at FROM workspaces WHERE id = ?')
    .bind(wsId).first();
  if (!ws) return null;

  const generatedAt = new Date().toISOString();
  const now30dAgo   = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

  const sc = await buildScorecardData(wsId, env);
  if (!sc) throw new Error('buildScorecardData returned null');

  const [trendR, topRisksR, infoCntR, assetDeltaR, vendorDeltaR] = await Promise.allSettled([
    env.cybermeters_db.prepare(
      `SELECT s.domain, s.score, s.created_at
       FROM scans s
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = d.id
       WHERE wd.workspace_id = ? AND s.status = 'completed'
         AND s.score IS NOT NULL AND s.created_at >= ?
       ORDER BY s.domain, s.created_at DESC
       LIMIT 1000`
    ).bind(wsId, now30dAgo).all(),

    env.cybermeters_db.prepare(
      `SELECT f.title, f.severity, f.recommendation, s.domain, s.created_at
       FROM findings f
       JOIN scans s ON s.id = f.scan_id
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = d.id
       WHERE wd.workspace_id = ?
         -- Only the latest COMPLETE scan per domain (canonical shared scope), so
         -- findings resolved by a newer scan never linger and a partial scan never
         -- fabricates current findings. Same constant the report/dashboard/insights use.
         AND ${LATEST_COMPLETED_SCAN_SCOPE}
       ORDER BY CASE f.severity
         WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5 END,
         s.created_at DESC
       LIMIT 200`
    ).bind(wsId, wsId).all(),

    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS n FROM findings f
       JOIN scans s ON s.id = f.scan_id
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = d.id
       WHERE wd.workspace_id = ? AND f.severity = 'info'`
    ).bind(wsId).first(),

    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS n FROM workspace_assets
       WHERE workspace_id = ? AND status = 'active' AND first_seen < ?`
    ).bind(wsId, now30dAgo).first(),

    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS n FROM workspace_vendors
       WHERE workspace_id = ? AND status = 'active' AND first_seen < ?`
    ).bind(wsId, now30dAgo).first(),
  ]);

  const [
    brsCurrentR,
    brsHistoryR,
    supplyCurrentR,
    supplyHistoryR,
    topVendorR,
    cyberEssentialsR,
  ] = await Promise.allSettled([
    env.cybermeters_db.prepare(
      `SELECT score, risk_band, calculated_at
       FROM workspace_brs_scores
       WHERE workspace_id = ?
       ORDER BY calculated_at DESC LIMIT 1`
    ).bind(wsId).first(),

    env.cybermeters_db.prepare(
      `SELECT score, risk_band, calculated_at
       FROM workspace_brs_score_history
       WHERE workspace_id = ?
       ORDER BY calculated_at ASC LIMIT 30`
    ).bind(wsId).all(),

    env.cybermeters_db.prepare(
      `SELECT supply_chain_score, resilience_score, concentration_level,
              critical_vendor_count, spof_count, payload_json, calculated_at
       FROM workspace_supply_chain_scores
       WHERE workspace_id = ?
       ORDER BY calculated_at DESC LIMIT 1`
    ).bind(wsId).first(),

    env.cybermeters_db.prepare(
      `SELECT supply_chain_score, resilience_score, concentration_level,
              critical_vendor_count, spof_count, calculated_at
       FROM workspace_supply_chain_history
       WHERE workspace_id = ?
       ORDER BY calculated_at ASC LIMIT 30`
    ).bind(wsId).all(),

    env.cybermeters_db.prepare(
      `SELECT wv.vendor_name, wv.category, wv.risk_level, wv.confidence,
              vrs.score, vrs.concentration_penalty
       FROM workspace_vendors wv
       LEFT JOIN vendor_risk_scores vrs
         ON vrs.vendor_id = wv.id
        AND vrs.workspace_id = wv.workspace_id
       WHERE wv.workspace_id = ?
         AND wv.status = 'active'
       ORDER BY COALESCE(vrs.score, 0) DESC, wv.vendor_name
       LIMIT 10`
    ).bind(wsId).all(),

    buildCyberEssentialsReadiness(wsId, env),
  ]);

  // Risk trend — deduplicate to latest per (domain, date), then aggregate by date
  const trendRows     = (trendR.status === 'fulfilled' ? trendR.value?.results : null) ?? [];
  const _domainDayMap = new Map();
  for (const r of trendRows) {
    if (!r.created_at || r.score == null) continue;
    const date = r.created_at.slice(0, 10);
    const key  = `${r.domain ?? ''}|${date}`;
    if (!_domainDayMap.has(key)) {
      _domainDayMap.set(key, { date, domain: r.domain ?? null, score: Number(r.score) });
    }
  }
  const _dateAgg = new Map();
  for (const { date, domain, score } of _domainDayMap.values()) {
    if (!_dateAgg.has(date)) _dateAgg.set(date, { scores: [], domains: new Set() });
    const bucket = _dateAgg.get(date);
    bucket.scores.push(score);
    bucket.domains.add(domain ?? '');
  }
  const risk_trend = [..._dateAgg.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, { scores, domains }]) => ({
      date,
      average_score: Math.round(scores.reduce((s, n) => s + n, 0) / scores.length),
      lowest_score:  Math.min(...scores),
      highest_score: Math.max(...scores),
      asset_count:   domains.size,
    }));

  function trendLabel(rows, key, threshold = 3) {
    const nums = (rows || [])
      .map((r) => Number(r?.[key]))
      .filter((n) => Number.isFinite(n));
    if (nums.length < 2) return 'stable';
    const delta = nums[nums.length - 1] - nums[0];
    if (delta > threshold) return 'improving';
    if (delta < -threshold) return 'deteriorating';
    return 'stable';
  }

  // Top risks — deduplicate, sort by severity, cap at 10
  const SEVERITY_ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
  const topRisksRows   = (topRisksR.status === 'fulfilled' ? topRisksR.value?.results : null) ?? [];
  const _seenRisks     = new Set();
  const top_risks      = topRisksRows
    .reduce((acc, r) => {
      const key = `${r.title ?? ''}|${r.domain ?? ''}|${r.recommendation ?? ''}`;
      if (!_seenRisks.has(key)) {
        _seenRisks.add(key);
        acc.push({
          title:          r.title          ?? '',
          severity:       r.severity       ?? 'medium',
          recommendation: r.recommendation ?? '',
          domain:         r.domain         ?? null,
          date:           typeof r.created_at === 'string' ? r.created_at.slice(0, 10) : null,
        });
      }
      return acc;
    }, [])
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
    .slice(0, 10);

  // Sprint 9F: enrich top_risks with trust fields from R2 scan reports.
  // The findings D1 table has no trust columns; confidence/validation_quality/
  // evidence_quality/evidence live only in the scan report JSON in R2.
  // Strategy: for each unique domain in top_risks, fetch latest scan ID from D1,
  // then fetch that scan's R2 report in parallel, build a title→trust lookup,
  // and merge trust fields onto the matching top_risks entry.
  try {
    const _trustDomains = [...new Set(top_risks.map(r => r.domain).filter(Boolean))];
    if (_trustDomains.length > 0) {
      // 1. Resolve latest completed scan ID per domain (parallel D1 lookups)
      const _scanIdResults = await Promise.allSettled(
        _trustDomains.map(domain =>
          env.cybermeters_db
            .prepare(
              `SELECT s.id FROM scans s
               JOIN domains d ON d.id = s.domain_id
               WHERE d.name = ? AND s.status = 'completed'
               ORDER BY s.created_at DESC LIMIT 1`
            )
            .bind(domain)
            .first()
        )
      );
      // 2. Build domain → scanId map
      const _domainScanIds = new Map();
      for (let _di = 0; _di < _trustDomains.length; _di++) {
        const _r = _scanIdResults[_di];
        if (_r.status === 'fulfilled' && _r.value?.id) {
          _domainScanIds.set(_trustDomains[_di], _r.value.id);
        }
      }
      // 3. Fetch R2 scan report JSONs in parallel
      const _domainEntries = [..._domainScanIds.entries()];
      const _r2Results = await Promise.allSettled(
        _domainEntries.map(async ([_domain, _scanId]) => {
          const _obj = await env.cybermeters_reports.get(`reports/${_scanId}.json`);
          const _report = _obj ? await _obj.json() : null;
          return { domain: _domain, findings: _report?.findings ?? [] };
        })
      );
      // 4. Build trust lookup: domain → Map<title_lc, trust fields>
      const _trustMap = new Map();
      for (const _r of _r2Results) {
        if (_r.status !== 'fulfilled') continue;
        const { domain: _d, findings: _findings } = _r.value;
        const _dMap = new Map();
        for (const _f of _findings) {
          if (!_f.title) continue;
          _dMap.set(_f.title.toLowerCase(), {
            confidence:          _f.confidence          ?? null,
            validation_quality:  _f.validation_quality  ?? null,
            evidence_quality:    _f.evidence_quality    ?? null,
            evidence:            Array.isArray(_f.evidence) ? _f.evidence.slice(0, 3) : null,
          });
        }
        _trustMap.set(_d, _dMap);
      }
      // 5. Merge trust fields onto top_risks entries
      for (const _risk of top_risks) {
        const _dMap = _trustMap.get(_risk.domain);
        if (!_dMap) continue;
        const _trust = _dMap.get((_risk.title ?? '').toLowerCase());
        if (!_trust) continue;
        _risk.confidence         = _trust.confidence;
        _risk.validation_quality = _trust.validation_quality;
        _risk.evidence_quality   = _trust.evidence_quality;
        _risk.evidence           = _trust.evidence;
      }
    }
  } catch (_trustErr) {
    // Non-fatal: trust enrichment failure must never break PDF generation
  }

  // Findings summary
  const infoCount        = (infoCntR.status === 'fulfilled' ? infoCntR.value?.n : null) ?? 0;
  const findings_summary = {
    critical: sc.critical_findings ?? 0,
    high:     sc.high_findings     ?? 0,
    medium:   sc.medium_findings   ?? 0,
    low:      sc.low_findings      ?? 0,
    info:     infoCount,
    total:    (sc.critical_findings ?? 0) + (sc.high_findings ?? 0) +
              (sc.medium_findings   ?? 0) + (sc.low_findings   ?? 0) + infoCount,
  };

  // Asset inventory with 30d deltas
  const assetsOld  = (assetDeltaR.status  === 'fulfilled' ? assetDeltaR.value?.n  : null) ?? null;
  const vendorsOld = (vendorDeltaR.status === 'fulfilled' ? vendorDeltaR.value?.n : null) ?? null;
  const asset_inventory = {
    assets:               { current: sc.active_assets   ?? 0, delta_30d: assetsOld  !== null ? (sc.active_assets    ?? 0) - assetsOld  : null },
    vendors:              { current: sc.vendors_detected ?? 0, delta_30d: vendorsOld !== null ? (sc.vendors_detected ?? 0) - vendorsOld : null },
    brand_candidates:     { current: sc.brand_risks?.total  ?? 0, delta_30d: null },
    third_party_services: { current: sc.third_party_assets  ?? 0, delta_30d: null },
    saas_exposures:       { current: sc.saas_exposures      ?? 0, delta_30d: null },
    new_assets_30d:   sc.new_assets_30d   ?? 0,
    asset_events_30d: sc.asset_events_30d ?? 0,
  };

  // Executive summary — strengths, weaknesses, priority actions
  const sp2 = sc.security_posture ?? null;
  const strengths = [], weaknesses = [], priority_actions = [];

  if ((sc.critical_findings ?? 0) === 0 && (sc.high_findings ?? 0) === 0)
    strengths.push('No critical or high-severity security findings detected.');
  if ((sc.brand_risks?.high ?? 0) === 0 && (sc.brand_risks?.active ?? 0) === 0)
    strengths.push('No active brand impersonation or typosquat domains detected.');
  if ((sc.admin_surfaces ?? 0) === 0)
    strengths.push('No exposed admin or management interfaces found.');
  if (sp2?.email_security?.status === 'good')
    strengths.push('Email security posture is strong - SPF, DMARC, and DKIM are in place.');
  // "fully validated" was a claim this product cannot support. sslScore (posture-scoring.js)
  // starts at 100 and only ever deducts for HTTPS availability, HTTP→HTTPS redirect and
  // expiry, so `good` means exactly those three things were observed — chain validity, root
  // trust, OCSP and revocation are NEVER checked and the Certificates & Trust domain already
  // declares them "unknown" (cyber-mot-domains.js). The old copy contradicted our own
  // limitation on the one artifact customers forward to insurers and boards.
  if (sp2?.ssl_certificates?.status === 'good')
    strengths.push('HTTPS is enabled and the certificate is in date. Chain validity, root trust, OCSP and revocation are not checked.');
  if ((sc.vendors_detected ?? 0) > 0 && (sc.vendor_risk?.high ?? 0) === 0)
    strengths.push(`${sc.vendors_detected} third-party vendors detected - none rated high-risk.`);
  if (strengths.length === 0)
    strengths.push('Security monitoring is active - run additional scans to build baseline.');

  if ((sc.critical_findings ?? 0) > 0)
    weaknesses.push(`${sc.critical_findings} critical finding${sc.critical_findings !== 1 ? 's' : ''} require immediate remediation.`);
  if ((sc.high_findings ?? 0) > 0)
    weaknesses.push(`${sc.high_findings} high-severity finding${sc.high_findings !== 1 ? 's' : ''} should be addressed urgently.`);
  if (sp2?.email_security?.score != null && sp2.email_security.score < 70)
    weaknesses.push('Email security posture is weak - spoofing risk remains elevated.');
  if ((sc.brand_risks?.high ?? 0) > 0)
    weaknesses.push(`${sc.brand_risks.high} high-risk typosquat domain${sc.brand_risks.high !== 1 ? 's' : ''} are actively resolving (phishing risk).`);
  if ((sc.admin_surfaces ?? 0) > 0)
    weaknesses.push(`${sc.admin_surfaces} admin surface${sc.admin_surfaces !== 1 ? 's' : ''} exposed to the public internet.`);
  if ((sc.vendor_risk?.high ?? 0) > 0)
    weaknesses.push(`${sc.vendor_risk.high} high-risk vendor${sc.vendor_risk.high !== 1 ? 's' : ''} in the supply chain.`);
  if (weaknesses.length === 0 && (sc.medium_findings ?? 0) > 0)
    weaknesses.push(`${sc.medium_findings} medium-severity finding${sc.medium_findings !== 1 ? 's' : ''} noted - review and remediate.`);

  for (const r of (sc.top_recommendations ?? []).slice(0, 3))
    priority_actions.push(r.title + (r.description ? ` - ${r.description}` : ''));
  // Promote a canonical remediation from at-risk posture categories — NEVER the
  // raw risk reason (which is a diagnosis, not an action). A category with no
  // canonical remediation (e.g. surface-expansion only) contributes nothing here.
  if (sp2) {
    for (const catKey of ['email_security', 'ssl_certificates', 'admin_exposure']) {
      const cat = sp2[catKey];
      const rem = cat?.remediations?.[0];
      if ((cat?.status === 'critical' || cat?.status === 'warning') && rem && priority_actions.length < 5)
        priority_actions.push(`${rem.customer_title} - ${rem.recommended_action}`);
    }
  }

  const executive_summary = {
    strengths:        strengths.slice(0, 5),
    weaknesses:       weaknesses.slice(0, 5),
    priority_actions: priority_actions.slice(0, 5),
  };

  // Top recommendations. The scorecard rows already carry the canonical
  // customer_title/action (scoring.js sources them from the registry); reunite
  // each with its canonical remediation identity + business impact by title.
  const top_recommendations = (sc.top_recommendations ?? []).map(r => {
    const canon = resolveByCustomerTitle(r.title);
    return {
      title:          r.title       ?? '',
      description:    r.description ?? '',
      priority:       r.priority    ?? 3,
      remediation_id: canon?.remediation_id ?? null,
      business_impact: canon?.business_impact ?? null,
    };
  });
  // Fill remaining slots from at-risk posture categories using their CANONICAL
  // remediations — never a fabricated "Improve {category}" title from a raw
  // reason. Categories whose signals have no canonical remediation add nothing.
  if (sp2 && top_recommendations.length < 10) {
    for (const catKey of Object.keys(POSTURE_WEIGHTS)) {
      const cat = sp2[catKey];
      if (!cat || cat.score === null || (cat.score ?? 100) >= 90) continue;
      for (const rem of (cat.remediations ?? [])) {
        if (top_recommendations.length >= 10) break;
        if (top_recommendations.some((t) => t.remediation_id === rem.remediation_id)) continue;
        top_recommendations.push({
          title:          rem.customer_title,
          description:    rem.recommended_action,
          priority:       cat.status === 'critical' ? 1 : cat.status === 'warning' ? 2 : 3,
          remediation_id: rem.remediation_id,
          business_impact: rem.business_impact ?? null,
        });
      }
      if (top_recommendations.length >= 10) break;
    }
  }

  // Vendor risk, brand monitoring, certificate intelligence
  const vendor_risk = {
    total:  sc.vendors_detected    ?? 0,
    high:   sc.vendor_risk?.high   ?? 0,
    medium: sc.vendor_risk?.medium ?? 0,
    low:    sc.vendor_risk?.low    ?? 0,
  };
  const brand_monitoring = {
    total_candidates: sc.brand_risks?.total  ?? 0,
    active_risks:     sc.brand_risks?.active ?? 0,
    high:             sc.brand_risks?.high   ?? 0,
    medium:           sc.brand_risks?.medium ?? 0,
    low:              sc.brand_risks?.low    ?? 0,
  };
  const certR = sc.certificate_risks ?? {};
  const certificate_intelligence = {
    risk_level:        certR.risk_level        ?? null,
    signals:           certR.signals           ?? 0,
    days_until_expiry: certR.days_until_expiry ?? null,
    status: certR.risk_level === 'critical' ? 'critical'
          : certR.risk_level === 'high'     ? 'warning'
          : (certR.signals   ?? 0) > 0      ? 'warning'
          : certR.risk_level === null        ? 'unknown' : 'ok',
  };

  const brsRow = brsCurrentR.status === 'fulfilled' ? brsCurrentR.value : null;
  const brsHistoryRows = brsHistoryR.status === 'fulfilled' ? (brsHistoryR.value?.results || []) : [];
  const supplyRow = supplyCurrentR.status === 'fulfilled' ? supplyCurrentR.value : null;
  const supplyHistoryRows = supplyHistoryR.status === 'fulfilled' ? (supplyHistoryR.value?.results || []) : [];
  const topVendorRows = topVendorR.status === 'fulfilled' ? (topVendorR.value?.results || []) : [];
  const ceReadiness = cyberEssentialsR.status === 'fulfilled' ? cyberEssentialsR.value : null;

  // Canonical eight-domain Cyber MOT coverage states over the workspace's
  // AUTHORITATIVE (latest-complete) scan report, so the Executive PDF shows all
  // eight domains with one honest state each. Missing evidence never renders healthy.
  let cyberMotDomains;
  try {
    const posture   = await getCurrentPosturePresentation(env, { workspaceId: wsId });
    const authScanId = posture?.authoritative_scan_id ?? null;
    let authReport = null;
    if (authScanId) {
      const rObj = await env.cybermeters_reports.get(`reports/${authScanId}.json`);
      authReport = rObj ? await rObj.json() : null;
    }
    // Same canonical CE snapshot (answer-presence gated) every surface uses, so the
    // PDF's CE state matches the Dashboard / Scan Detail / Executive Report UI.
    const ceSnap = await getCyberEssentialsSnapshot(wsId, env).catch(() => null);
    cyberMotDomains = resolveCyberMotDomainStates(authReport, { scanId: authScanId, cyberEssentials: ceSnap });
  } catch {
    cyberMotDomains = resolveCyberMotDomainStates(null);
  }

  let supplyPayload = {};
  if (supplyRow?.payload_json) {
    try { supplyPayload = JSON.parse(supplyRow.payload_json); } catch { supplyPayload = {}; }
  }

  const topVendorDependencies = topVendorRows.map((v) => ({
    name: v.vendor_name,
    category: v.category,
    risk_level: v.risk_level,
    confidence: v.confidence,
    score: v.score,
  }));

  // Prefer the workspace-level BRS; if it has not been populated, fall back to
  // the latest scan's Business Risk so the report matches the scan view instead
  // of showing "unknown".
  let brsScore = brsRow?.score ?? null;
  let brsBand  = brsRow?.risk_band ?? null;
  if (brsScore == null) {
    const fb = await latestScanBusinessRisk(env, wsId);
    if (fb) { brsScore = fb.score; brsBand = fb.band || brsBand; }
  }

  const business_risk = {
    business_risk_score: brsScore,
    risk_band: brsBand ?? 'unknown',
    drivers: {
      vendor_dependency: vendor_risk.high > 0 ? 'high' : vendor_risk.medium > 0 ? 'medium' : 'low',
      findings: findings_summary.critical > 0 || findings_summary.high > 0 ? 'elevated' : 'controlled',
      asset_exposure: (asset_inventory.assets.current ?? 0) > 100 ? 'expanded' : 'normal',
    },
    recommendations: executive_summary.priority_actions,
    summary: brsScore != null
      ? `Business Risk Score is ${brsScore}/100 (${brsBand || 'unknown'}).`
      : 'Business Risk Score is not available yet. Run a scan and open the Business Risk dashboard to populate it.',
  };

  const supply_chain = {
    supply_chain_score: supplyRow?.supply_chain_score ?? supplyPayload.supply_chain_score ?? null,
    resilience_score: supplyRow?.resilience_score ?? supplyPayload.operational_resilience_score ?? null,
    operational_resilience_score: supplyPayload.operational_resilience_score ?? supplyRow?.resilience_score ?? null,
    concentration_level: supplyRow?.concentration_level ?? supplyPayload.concentration_level ?? 'unknown',
    critical_vendor_count: supplyRow?.critical_vendor_count ?? supplyPayload.critical_vendor_count ?? 0,
    spof_count: supplyRow?.spof_count ?? supplyPayload.spof_count ?? 0,
    cascading_risks: Array.isArray(supplyPayload.cascading_risks) ? supplyPayload.cascading_risks : [],
    top_vendor_dependencies: topVendorDependencies,
    narrative: supplyRow
      ? `Supply chain concentration is ${supplyRow.concentration_level || 'unknown'} with ${supplyRow.spof_count ?? 0} single point${(supplyRow.spof_count ?? 0) === 1 ? '' : 's'} of failure.`
      : 'Supply chain intelligence is not available yet. Run a scan to populate vendor dependency analysis.',
  };

  const cyber_essentials = ceReadiness ? {
    score:           ceReadiness.score,
    grade:           ceReadiness.grade,
    status:          ceReadiness.status,
    summary:         String(ceReadiness.summary || '')
      .replace(/Cyber Essentials readiness/gi, 'Cyber Essentials alignment')
      .replace(/readiness/gi, 'alignment'),
    categories:      ceReadiness.categories || [],
    top_gaps:        ceReadiness.top_gaps || [],
    recommendations: ceReadiness.recommendations || [],
    canonical_remediations: ceReadiness.canonical_remediations || [],
  } : {
    score:           null,
    grade:           null,
    status:          'unknown',
    summary:         'Cyber Essentials Alignment Summary is unavailable. CyberMeters provides indicative guidance only.',
    categories:      [],
    top_gaps:        [],
    recommendations: [],
    canonical_remediations: [],
  };

  const historical_analysis = {
    cyber_score: trendLabel(risk_trend, 'average_score'),
    business_risk_score: trendLabel(brsHistoryRows, 'score'),
    supply_chain_score: trendLabel(supplyHistoryRows, 'supply_chain_score'),
    cyber_score_snapshots: risk_trend.length,
    business_risk_score_snapshots: brsHistoryRows.length,
    supply_chain_score_snapshots: supplyHistoryRows.length,
  };

  const attack_surface = {
    exposed_assets: asset_inventory.assets.current ?? 0,
    ssl_tls_posture: sp2?.ssl_certificates?.status ?? certificate_intelligence.status ?? 'unknown',
    dns_posture: sp2?.attack_surface?.status ?? 'unknown',
    email_security_posture: sp2?.email_security?.status ?? 'unknown',
    security_headers: sp2?.attack_surface?.score != null
      ? `${sp2.attack_surface.score}/100 attack surface control score`
      : 'unknown',
  };

  function estimateRemediationEffort(item) {
    const text = `${item?.title ?? ''} ${item?.action ?? item?.description ?? ''}`.toLowerCase();
    if (text.includes('dmarc') || text.includes('spf') || text.includes('header') || text.includes('hsts')) return 'Low';
    if (text.includes('vendor') || text.includes('dependency') || text.includes('supply chain') || text.includes('admin')) return 'Medium';
    if (text.includes('critical') || text.includes('tls') || text.includes('certificate') || text.includes('exposure')) return 'Medium';
    return 'Medium';
  }

  // The priority action plan is assembled ONLY from canonical remediations —
  // the enriched top_recommendations (registry-sourced titles/actions, joined to
  // their remediation identity + business impact) and the Cyber Essentials
  // canonical remediations. No "Improve {category}" titles and no invented impact
  // strings when a canonical business impact exists; a generic impact is used
  // only as an honest fallback where the canonical field is absent.
  const GENERIC_IMPACT = 'Reduces business exposure and improves executive risk posture.';
  const ceCanonicalRemediations = Array.isArray(ceReadiness?.canonical_remediations)
    ? ceReadiness.canonical_remediations : [];
  const priority_action_plan = [
    ...top_recommendations.map((r) => ({
      remediation_id: r.remediation_id ?? null,
      title: r.title || '',
      action: r.description || r.title || '',
      recommended_action: r.description || r.title || '',
      impact: r.business_impact || GENERIC_IMPACT,
      business_impact: r.business_impact || GENERIC_IMPACT,
    })),
    ...ceCanonicalRemediations.map((rem) => ({
      remediation_id: rem.remediation_id,
      title: rem.customer_title,
      action: rem.recommended_action,
      recommended_action: rem.recommended_action,
      impact: rem.business_impact || GENERIC_IMPACT,
      business_impact: rem.business_impact || GENERIC_IMPACT,
    })),
  ].filter((item) => item.title || item.action)
    .filter((item, index, arr) => {
      // Dedupe by canonical remediation identity where present, else title+action.
      const key = item.remediation_id || `${item.title}|${item.action}`;
      return arr.findIndex((x) => (x.remediation_id || `${x.title}|${x.action}`) === key) === index;
    })
    .map((item) => ({
      ...item,
      effort_estimate: item.effort_estimate || estimateRemediationEffort(item),
    }))
    .slice(0, 5);

  const executiveStatus =
    findings_summary.critical > 0 || business_risk.risk_band === 'critical' ? 'critical' :
    findings_summary.high > 0 || business_risk.risk_band === 'high' ? 'high' :
    findings_summary.medium > 0 || business_risk.risk_band === 'medium' ? 'moderate' : 'controlled';

  const businessImpactNarrative =
    executiveStatus === 'critical'
      ? 'Immediate business attention is required because critical exposure may affect customer trust, operational continuity, or procurement readiness.'
      : executiveStatus === 'high'
        ? 'Business risk is elevated. Leadership should sponsor remediation of the highest-impact findings and vendor dependencies.'
        : executiveStatus === 'moderate'
          ? 'Business risk is manageable, but continued remediation will reduce exposure and improve resilience.'
          : 'Current external risk appears controlled based on available CyberMeters signals.';

  const topObservations = [
    ...executive_summary.weaknesses,
    supply_chain.narrative,
    cyber_essentials.summary,
  ].filter(Boolean).slice(0, 3);

  return {
    workspace:               { id: ws.id, name: ws.name, created_at: ws.created_at },
    generated_at:            generatedAt,
    overall_score:           sc.security_score    ?? null,
    risk_rating:             sc.risk_rating       ?? 'unknown',
    security_posture:        sc.security_posture  ?? null,
    executive_summary,
    findings_summary,
    top_risks,
    top_recommendations:     top_recommendations.slice(0, 10),
    risk_trend,
    asset_inventory,
    vendor_risk,
    brand_monitoring,
    certificate_intelligence,
    business_risk,
    supply_chain,
    cyber_essentials,
    cyber_mot_domains:         cyberMotDomains,
    historical_analysis,
    attack_surface,
    priority_action_plan,
    report_version:            'Executive PDF v2.3',
    report_classification:     'Confidential',
    white_label:               { footer_text: 'CyberMeters Platform' },
    executive_status:         executiveStatus,
    business_impact_narrative: businessImpactNarrative,
    top_observations:          topObservations,
    last_scan_at:            sc.last_scan_at        ?? null,
    last_scanned_domain:     sc.last_scanned_domain ?? null,
  };
}
