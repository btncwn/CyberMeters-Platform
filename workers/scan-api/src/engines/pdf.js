// ── PDF generation engine (snapshot-native, M5.d) ──
// Raw-PDF (no library) generation. Since M5.d every PDF renders the canonical
// immutable reporting snapshot (engines/report-snapshot.js) — this module owns
// NO calculation brain: no score, band, BRI, CE, domain-state, taxonomy,
// remediation or trend derivation happens here. It formats frozen facts.
//
// The legacy builders and their recalculation imports (posture scoring,
// scorecard, live resolvers, scan-path risk re-derivation, registry-by-title
// joins, five-category posture, legacy service palette) are DELETED, not merely
// unreferenced — the M5.c defect class was renderers re-deriving truth, and
// dead brains drift back to life.
//
// Determinism: rendering a given snapshot twice yields identical bytes. The
// only permitted live inputs are presentation metadata under the documented
// frozen-vs-live policy — white-label branding (logo/company name/accent) and
// the workspace display name. No clock is read here; every date printed comes
// from the snapshot (as_of / built_at) or an explicit caller argument.
import { buildDmarcPolicyPresentation } from "./dmarcbis-presentation.js";
import { certificateAssuranceFromSnapshot } from "./certificate-customer-presentation.js";
import { attackSurfaceAssuranceFromSnapshot } from "./attack-surface-customer-presentation.js";
// Canonical Related-Changes scope wording — consumed, never redefined, so the
// PDF and every other surface state the workspace scope with one voice.
import { RELATED_CHANGES_WORKSPACE_SCOPE_NOTE } from "./related-changes.js";

// Typographic → ASCII transliteration (trust-closure episode, July 2026).
// The stream encoder is ASCII-only, and the old behaviour replaced EVERY
// non-ASCII byte with a space — so a source sentence like "…this scan — not
// enough to assess." rendered as "…this scan   not enough to assess.": the
// punctuation silently vanished and left a malformed double-space (the defect
// PR #202 fixed for one limitation line at the source). Transliterating the
// common typographic characters fixes the CLASS at the renderer, for every
// current and future sentence, without touching any source copy. Anything not
// mapped still falls back to a space, exactly as before.
const PDF_ASCII_MAP = Object.freeze({
  "—": "-",  // em dash
  "–": "-",  // en dash
  "‘": "'", "’": "'",     // curly single quotes
  "“": '"', "”": '"',     // curly double quotes
  "…": "...",
  " ": " ",  // no-break space
  "≠": "!=",
  "→": "->",
  "×": "x",
  "·": "-",  // middle dot separator
});
export function pdfEsc(v) {
  return String(v == null ? "" : v)
    .replace(/[—–‘’“”… ≠→×·]/g, (c) => PDF_ASCII_MAP[c] || " ")
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
  const wrapLines = (str, width) => {
    const words = String(str ?? "").split(/\s+/);
    const lines = [];
    let line = "";
    for (const wd of words) {
      if ((line + " " + wd).trim().length > width) { if (line.trim()) lines.push(line.trim()); line = wd; }
      else line = `${line} ${wd}`;
    }
    if (line.trim()) lines.push(line.trim());
    return lines;
  };
  const prose = (str, opts = {}) => { for (const l of wrapLines(str, opts.width ?? 92)) text(l, opts); };

  // ── Controlled page breaking ────────────────────────────────────────────
  // Space left above the footer; whether the cursor is at the top of a fresh page.
  const roomLeft  = () => y - FOOT;
  const atPageTop = () => y >= PAGE_H - MARGIN - 0.5;
  // Break to a new page if `h` points won't fit here — unless already at the top
  // (a block taller than one page must still render top-aligned and paginate).
  const keepTogether = (h) => { if (!atPageTop() && roomLeft() < h) newPage(); };
  // A prose block that never splits mid-paragraph across a page boundary: measure
  // the wrapped height, break if it won't fit, then render as one unit. This is
  // what stops a limitation sentence breaking after a single word ("No" | "internal...").
  const proseKeep = (str, opts = {}) => {
    const lines = wrapLines(str, opts.width ?? 92);
    const size = opts.size ?? 10, g = opts.gap ?? 4;
    keepTogether(lines.length * (size + g));
    for (const l of lines) text(l, opts);
  };

  const heading = (str) => {
    // Never orphan a heading at the foot of a page: keep it with its accent rule
    // and room for at least one following line.
    keepTogether(22 + 6 + 16);
    y -= 22;
    buf += `${ar} ${ag} ${ab} rg ${MARGIN} ${y - 4} ${PAGE_W - 2 * MARGIN} 1.5 re f\n`;
    buf += `BT /F2 13 Tf 0.08 0.10 0.14 rg ${MARGIN} ${y} Td (${pdfEsc(str)}) Tj ET\n`;
    y -= 6;
  };
  const gap = (h = 8) => { ensure(h); y -= h; };
  // Raw content-stream ops (logo XObject drawing) — presentation only.
  const raw = (op) => { buf += op; };
  // A thin horizontal rule at the cursor (cover dividers / section separators).
  const rule = (color = "0.80 0.83 0.87") => { ensure(6); y -= 4; buf += `${color} rg ${MARGIN} ${y} ${PAGE_W - 2 * MARGIN} 0.7 re f\n`; y -= 2; };
  // Bounded explanatory callout used once on page 1. Presentation-only: the
  // copy explains how to interpret snapshot facts and never derives a verdict.
  const callout = (title, body) => {
    const lines = wrapLines(body, 84);
    const height = 18 + 13 + (lines.length * 11) + 8;
    ensure(height);
    const bottom = y - height;
    buf += `q 0.96 0.98 1 rg ${MARGIN} ${bottom} ${PAGE_W - 2 * MARGIN} ${height} re f `;
    buf += `0.69 0.80 0.94 RG 0.8 w ${MARGIN} ${bottom} ${PAGE_W - 2 * MARGIN} ${height} re S Q\n`;
    y -= 9;
    text(title, { size: 9, bold: true, color: "0.08 0.22 0.40", indent: 10, gap: 4 });
    for (const line of lines) {
      text(line, { size: 8, color: "0.25 0.35 0.48", indent: 10, gap: 3 });
    }
    y = bottom;
    gap(6);
  };
  // Large display text for the cover (wordmark / report title).
  const display = (str, { size = 22, bold = true, color = "0.08 0.10 0.14", gap: g = 8 } = {}) => {
    ensure(size + g); y -= size + g;
    buf += `BT /${bold ? "F2" : "F1"} ${size} Tf ${color} rg ${MARGIN} ${y} Td (${pdfEsc(str)}) Tj ET\n`;
  };
  // Draw the embedded /Im0 image XObject at the left margin, `lw`x`lh` points,
  // occupying the block below the current cursor. Stays within the content width
  // (the caller sizes it) and never overlaps text — the cursor advances past it.
  const image = (lw, lh, g = 10) => {
    ensure(lh + g); y -= lh;
    buf += `q ${lw} 0 0 ${lh} ${MARGIN} ${y} cm /Im0 Do Q\n`;
    y -= g;
  };
  const finish = () => { if (buf) { pages.push(buf + footer()); buf = ""; } return pages; };
  return { text, prose, proseKeep, keepTogether, heading, gap, newPage, finish, raw, rule, callout, display, image, roomLeft, atPageTop };
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

const HUMAN_EVIDENCE_STRENGTH = Object.freeze({
  L0: "Limited",
  L1: "Limited",
  L2: "Medium",
  L3: "High",
  L4: "High",
  L5: "High",
});

const HOW_TO_READ_REPORT =
  "Evidence strength shows how strongly the available evidence supports a conclusion - it is NOT your security score. " +
  "Limited evidence is normal for external assessment and does not mean weak security. " +
  "A domain we could not fully assess is shown as evidence-insufficient, not as low-risk.";

// RFC identifiers remain intact in the technical appendix. The SMB-facing body
// uses protocol names so the conclusion stays readable without losing meaning.
// This is presentation-only: the canonical snapshot strings are not changed.
function customerBodyText(value) {
  return String(value || "")
    .replace(/\s*\(RFC\s+\d+\)/gi, "")
    .replace(/\bRFC 7208 SPF\b/gi, "SPF")
    .replace(/\bRFC 9989 DMARC\b/gi, "DMARC")
    .replace(/\bRFC 6376 DKIM\b/gi, "DKIM")
    .replace(/\bRFC 8461 MTA-STS\b/gi, "MTA-STS")
    .replace(/\bRFC 8460 TLS reporting\b/gi, "TLS reporting")
    .replace(/\bHSTS RFC 6797\b/gi, "HSTS")
    .replace(/\bRFC\s+7208\b/gi, "the SPF protocol")
    .replace(/\bRFC\s+6376\b/gi, "the DKIM protocol")
    .replace(/\bRFC\s+9989\b/gi, "the DMARC protocol")
    .replace(/\bRFC\s+8461\b/gi, "the MTA-STS protocol")
    .replace(/\bRFC\s+8460\b/gi, "the TLS reporting protocol")
    .replace(/\bRFC\s+9162\b/gi, "the Certificate Transparency protocol")
    .replace(/\bRFC\s+1035\b/gi, "the DNS protocol")
    .replace(/\bRFC\s+9110\b/gi, "the HTTP protocol")
    .replace(/\bRFC\s+6797\b/gi, "the HSTS standard")
    .replace(/\bRFC\s+\d+\b/gi, "the applicable protocol")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+([,.;:])/g, "$1")
    .trim();
}

function evidenceStrength(assertion) {
  return HUMAN_EVIDENCE_STRENGTH[assertion?.grade] || "Limited";
}

function assertionLimits(assertions) {
  return [...new Set(
    assertions
      .flatMap((assertion) => Array.isArray(assertion?.limits) ? assertion.limits : [])
      .map(customerBodyText)
      .filter(Boolean)
  )];
}

// One compact, readable per-domain block. The full unabridged formal assertion
// remains in the technical appendix below.
function domainEvidenceStrengthBlock(w, assertion, { indent = 0, fallbackLimits = [] } = {}) {
  const hasGrade = Boolean(assertion?.grade);
  const limits = hasGrade
    ? assertionLimits([assertion])
    : [...new Set((fallbackLimits || []).map(customerBodyText).filter(Boolean))];
  w.text(`Evidence strength: ${hasGrade ? evidenceStrength(assertion) : "Not recorded"}`, {
    size: 8,
    bold: true,
    indent,
    color: "0.25 0.32 0.42",
  });
  w.proseKeep(`Basis: ${hasGrade
    ? (customerBodyText(assertion.basis) || "No basis recorded.")
    : "Evidence-Grade metadata was not recorded in this historical snapshot."}`, {
    size: 7,
    indent,
    color: "0.35 0.38 0.44",
    width: indent ? 96 : 104,
  });
  w.proseKeep(
    `Limits: ${limits.length ? limits.join(" ") : "No additional limit was recorded."}`,
    {
      size: 7,
      indent,
      color: "0.35 0.38 0.44",
      width: indent ? 96 : 104,
    }
  );
}

function evidenceBasisLine(w, label, assertion) {
  if (!assertion?.grade) return;
  w.proseKeep(
    `${label}: ${customerBodyText(assertion.basis) || "No basis recorded."}`,
    { size: 8, color: "0.35 0.38 0.44", width: 104 }
  );
}

function overallEvidenceStrength(w, assertions) {
  const primary = assertions.find((assertion) => assertion?.grade);
  if (!primary) return;
  const limits = assertionLimits(assertions);
  w.text(`Evidence strength: ${evidenceStrength(primary)}`, {
    size: 9,
    bold: true,
    color: "0.25 0.32 0.42",
  });
  w.proseKeep(
    `Limits: ${limits.length
      ? limits.join(" ")
      : "No additional limit was recorded."}`,
    { size: 8, color: "0.35 0.38 0.44", width: 104 }
  );
}

function sectionOverall(w, snap) {
  const o = snap.overall || {};
  const bri = o.business_risk_indicator || {};
  const ec0 = o.evidence_completeness || {};
  w.callout("How to read this report", HOW_TO_READ_REPORT);
  overallEvidenceStrength(w, [
    o.evidence_grade,
    o.assessment_evidence_grade,
    bri.evidence_grade,
  ]);
  // Explanation first, number second.
  evidenceBasisLine(w, "Score basis", o.assessment_evidence_grade);
  const scoreText = o.cyber_metrics_score == null
    ? "Not available for this assessment"
    : `${o.cyber_metrics_score} / 100`;
  w.text(`${o.assessment?.provisional ? "Provisional Score" : "Cyber Metrics Score"}: ${scoreText}`, { size: 14, bold: true });
  if (o.score_band) w.text(`CyberMeters assessment band: ${o.score_band}`, { size: 11 });
  if (o.assessment?.message) w.prose(customerBodyText(o.assessment.message), { size: 9, color: "0.45 0.35 0.10" });
  w.gap(4);
  // Coverage is incomplete when the snapshot's OWN frozen facts say so: a non-complete
  // scan quality, any skipped module, or any domain still needing further evidence /
  // customer input / monitoring. This reads only frozen snapshot facts — it never
  // recomputes the score or band.
  const coverageIncomplete =
    (ec0.scan_quality && ec0.scan_quality !== "complete") ||
    (ec0.assessment_quality && ec0.assessment_quality !== "complete") ||
    (ec0.monitoring_state && ec0.monitoring_state !== "monitoring_healthy") ||
    (Array.isArray(ec0.modules_skipped) && ec0.modules_skipped.length > 0) ||
    (Array.isArray(o.not_fully_assessed) && o.not_fully_assessed.length > 0);
  evidenceBasisLine(w, "Business Risk Indicator basis", bri.evidence_grade);
  if (bri.band) {
    // An indicator: band + explanation. Never a second numeric score.
    w.text(`Business Risk Indicator: ${String(bri.band).toUpperCase()}`, { size: 11, bold: true });
    // Evidence-honest narrative. The band is a frozen indicator; the EXPLANATION must
    // not imply a complete absence of gaps when the frozen evidence is incomplete. When
    // coverage is incomplete we present an evidence-bounded statement instead of the
    // frozen (unqualified) "no major gaps" summary — no scoring change, frozen facts only.
    if (coverageIncomplete) {
      w.proseKeep("No major gaps were identified in the evidence available. Coverage is incomplete - some checks did not run or still need customer input - so this provisional indicator is not confirmation that no other material gaps exist.", { size: 9 });
    } else if (bri.explanation) {
      w.proseKeep(customerBodyText(bri.explanation), { size: 9 });
    }
  } else if (bri.provisional) {
    w.text("Business Risk Indicator: NOT AUTHORITATIVE", { size: 11, bold: true });
    if (bri.explanation) w.proseKeep(customerBodyText(bri.explanation), { size: 9 });
  }
  if (o.summary) {
    w.gap(2);
    evidenceBasisLine(w, "Eight-domain summary basis", o.evidence_grade);
    w.prose(customerBodyText(o.summary), { size: 10 });
  }
  const ec = o.evidence_completeness || {};
  const coverageFacts = [
    ec.scan_quality ? `scan quality: ${ec.scan_quality}` : null,
    ec.assessment_quality ? `assessment quality: ${ec.assessment_quality}` : null,
    ec.monitoring_state ? `monitoring state: ${ec.monitoring_state}` : null,
  ].filter(Boolean);
  if (coverageFacts.length) {
    w.prose(`Assessment coverage - ${coverageFacts.join("; ")}.`, {
      size: 9,
      color: "0.35 0.38 0.44",
    });
  }
  if (Array.isArray(ec.modules_skipped) && ec.modules_skipped.length > 0) {
    w.prose(`Modules skipped: ${ec.modules_skipped.join(", ")}.`, {
      size: 9,
      color: "0.45 0.35 0.10",
    });
  }
  if (
    Array.isArray(ec.skipped_score_bearing_modules) &&
    ec.skipped_score_bearing_modules.length > 0
  ) {
    w.prose(
      `Score-bearing modules skipped: ${ec.skipped_score_bearing_modules.join(", ")}.`,
      { size: 9, color: "0.45 0.35 0.10" },
    );
  }
  const monitoringLimitations = Object.values(snap.monitoring_states?.signals ?? {})
    .filter((entry) => entry?.state !== "monitoring_healthy")
    .map((entry) => customerBodyText(entry?.message))
    .filter(Boolean);
  if (monitoringLimitations.length > 0) {
    w.prose(
      `Monitoring coverage: ${[...new Set(monitoringLimitations)].join(" ")}`,
      { size: 9, color: "0.45 0.35 0.10" }
    );
  }
}

// Findings/observations that belong to a domain, grouped from the snapshot's
// canonical arrays (each item carries domain_keys). No new source of truth —
// the same immutable items, organised per domain for materially richer reporting.
function domainItems(snap, domainKey, kind) {
  const arr = kind === "observation" ? (snap.observations || []) : (snap.observed_findings || []);
  return arr.filter((f) => Array.isArray(f.domain_keys) && f.domain_keys.includes(domainKey));
}

function observationHeading(item, fallbackTitle = "Observation") {
  const severity = typeof item?.severity === "string" ? item.severity.trim() : "";
  return `${severity ? `[${severity.toUpperCase()}] ` : ""}${item?.title || fallbackTitle}`;
}

function findingHeading(item, fallbackTitle = "Finding") {
  const severity = typeof item?.severity === "string" ? item.severity.trim() : "";
  return `${severity ? `[${severity.toUpperCase()}] ` : ""}${item?.title || fallbackTitle}`;
}

// Eight-domain section. `detail` = "full" (Assessment PDF: every domain's findings,
// observations, evidence completeness, managed-case state, verification support) or
// "concise" (Executive PDF: state + issue count + highest severity + top action —
// still meaningful for every domain, never a bare card).
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function highestSev(items) {
  let best = null, rank = -1;
  for (const f of items) { const r = SEV_RANK[String(f.severity || "").toLowerCase()] ?? -1; if (r > rank) { rank = r; best = f.severity; } }
  return best;
}
function sectionDomains(w, snap, { detail = "full" } = {}) {
  w.heading("Eight-Domain Cyber MOT");
  for (const d of snap.domains || []) {
    const findings = domainItems(snap, d.domain_key, "finding");
    const observations = domainItems(snap, d.domain_key, "observation");
    const wf = d.managed_workflow || {};
    const hs = highestSev(findings);

    // Keep the domain heading with its conclusion + first line of context.
    w.keepTogether(30);
    w.text(d.display_name, { size: 11, bold: true });
    domainEvidenceStrengthBlock(w, d.evidence_grade, {
      indent: 10,
      fallbackLimits: d.limitations,
    });
    w.text(`Conclusion: ${d.conclusion_label || stateLabel(d.state)}`, { size: 9, bold: true, indent: 10 });
    if (d.state_reason) w.prose(customerBodyText(d.state_reason), { size: 9, indent: 10, color: "0.25 0.28 0.33" });

    // One-line evidence posture per domain (both detail levels).
    const posture = [];
    if (findings.length) posture.push(`${findings.length} finding${findings.length === 1 ? "" : "s"}${hs ? ` (highest: ${String(hs).toUpperCase()})` : ""}`);
    if (observations.length) posture.push(`${observations.length} observation${observations.length === 1 ? "" : "s"}`);
    if (wf.open_cases) posture.push(`${wf.open_cases} open managed case${wf.open_cases === 1 ? "" : "s"}`);
    if (posture.length) w.text(posture.join(" · "), { size: 8, indent: 10, color: "0.35 0.38 0.44" });

    if (detail === "full") {
      // Per-domain findings with severity, explanation, verification support and
      // managed-case linkage — honest evidence, never invented detail.
      for (const f of findings) {
        w.text(findingHeading(f), { size: 9, bold: true, indent: 10 });
        if (f.explanation) w.prose(customerBodyText(f.explanation), { size: 8, indent: 18, color: "0.25 0.28 0.33" });
        const meta = [];
        if (f.verification_support) meta.push(`Verification: ${f.verification_support}`);
        if (f.managed_case_id) meta.push(`Managed case: ${f.managed_case_status || "linked"}`);
        if (f.evidence_ref?.count) meta.push(`${f.evidence_ref.count} evidence item(s)`);
        if (meta.length) w.text(meta.join(" · "), { size: 7, indent: 18, color: "0.45 0.48 0.54" });
      }
      for (const o of observations) {
        w.text(observationHeading(o), { size: 8, indent: 10, color: "0.25 0.28 0.33" });
        if (o.explanation) w.prose(customerBodyText(o.explanation), { size: 7, indent: 18, color: "0.35 0.38 0.44" });
      }
    } else {
      // Concise (Executive): the single most relevant action, if any.
      const top = findings.find((f) => f.remediation_id) || findings[0];
      if (top?.title) w.text(`Top item: ${top.title}`, { size: 8, indent: 10, color: "0.25 0.28 0.33" });
    }

    // The canonical limitations are already included once in the domain's
    // Evidence-strength block. Do not repeat them as separate "Limitation:" rows.
    const ceStmt = d.cyber_essentials?.external_coverage_statement;
    if (ceStmt) w.proseKeep(customerBodyText(ceStmt), { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    // Clear separation between domains (visual hierarchy).
    w.gap(6);
  }
}

function sectionCertificateAssurance(w, snap, { detail = "full" } = {}) {
  const assurance = certificateAssuranceFromSnapshot(snap);
  const summary = assurance.summary || {};
  w.heading("Certificate Evidence & Trust");
  if (assurance.historical_notice) {
    w.proseKeep(customerBodyText(assurance.historical_notice), {
      size: 9,
      color: "0.45 0.35 0.10",
    });
    // Historical snapshots contain no per-signal contract to render. Keep the
    // disclosure compact and do not manufacture fifteen technical rows from
    // fields that were never frozen.
    return;
  }
  w.proseKeep(customerBodyText(assurance.scope_note), {
    size: 8,
    color: "0.35 0.38 0.44",
  });
  for (const [label, value] of [
    ["CT issuance", summary.ct_issuance],
    ["Live TLS certificate", summary.live_tls_certificate],
    ["Declared trust-store validation", summary.trust_store_validation],
    ["OCSP / revocation assurance", summary.revocation_assurance],
  ]) {
    w.text(`${label}: ${String(value?.state || "not_observed").replaceAll("_", " ")}`, {
      size: 9,
      bold: true,
    });
    if (value?.message) {
      w.proseKeep(customerBodyText(value.message), {
        size: 8,
        indent: 10,
        color: "0.25 0.28 0.33",
      });
    }
  }
  if (summary.trust_ceiling) {
    w.callout("Trust evidence ceiling", customerBodyText(summary.trust_ceiling));
  }
  if (assurance.relationship?.customer_message) {
    w.text("Certificate relationship", { size: 9, bold: true });
    w.proseKeep(customerBodyText(assurance.relationship.customer_message), {
      size: 8,
      indent: 10,
      color: "0.25 0.28 0.33",
    });
  }
  if (assurance.lifecycle?.customer_message) {
    w.proseKeep(
      `Lifecycle evidence: ${customerBodyText(assurance.lifecycle.customer_message)}`,
      { size: 8, color: "0.35 0.38 0.44" },
    );
  }
  if (detail === "full") {
    for (const key of assurance.signal_order || []) {
      const signal = assurance.signals?.[key];
      if (!signal) continue;
      w.keepTogether(28);
      w.text(`${signal.label}: ${signal.state_label || signal.state || "Not observed"}`, {
        size: 8,
        bold: true,
      });
      w.proseKeep(customerBodyText(signal.customer_message), {
        size: 7,
        indent: 10,
        color: "0.35 0.38 0.44",
      });
    }
  }
}

function sectionAttackSurfaceAssurance(w, snap, { detail = "full" } = {}) {
  const assurance = attackSurfaceAssuranceFromSnapshot(snap);
  w.heading("Attack Surface Evidence & Lifecycle");
  if (assurance.historical_notice) {
    w.proseKeep(customerBodyText(assurance.historical_notice), {
      size: 9,
      color: "0.45 0.35 0.10",
    });
    return;
  }
  w.proseKeep(customerBodyText(assurance.scope_note), {
    size: 8,
    color: "0.35 0.38 0.44",
  });
  const signalKeys = assurance.signal_order || [];
  for (const key of detail === "full" ? signalKeys : signalKeys.slice(0, 9)) {
    const signal = assurance.signals?.[key];
    if (!signal) continue;
    w.keepTogether(28);
    w.text(`${signal.label}: ${signal.state_label || signal.state || "Not assessed"}`, {
      size: 8,
      bold: true,
    });
    w.proseKeep(customerBodyText(signal.customer_message), {
      size: 7,
      indent: 10,
      color: "0.35 0.38 0.44",
    });
  }

  w.text("Asset lifecycle", { size: 9, bold: true });
  w.proseKeep(customerBodyText(assurance.lifecycle?.customer_message), {
    size: 8,
    indent: 10,
    color: assurance.lifecycle?.status === "recorded"
      ? "0.35 0.38 0.44"
      : "0.45 0.35 0.10",
  });
  const lifecycleRecords = assurance.lifecycle?.records || [];
  for (const record of lifecycleRecords.slice(0, detail === "full" ? 25 : 5)) {
    w.text(
      `${record.hostname || record.asset_id || "Asset"}: ${record.lifecycle_state_label}`,
      { size: 8, bold: true },
    );
    w.proseKeep(
      `${customerBodyText(record.lifecycle_message)} Latest evidence: ${record.last_observation_state_label}. ${customerBodyText(record.last_observation_message)}`,
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
  }
  if (lifecycleRecords.length > (detail === "full" ? 25 : 5)) {
    w.text(
      `+${lifecycleRecords.length - (detail === "full" ? 25 : 5)} more lifecycle records retained in the canonical snapshot.`,
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
  }

  w.text("ASM alert eligibility", { size: 9, bold: true });
  w.proseKeep(customerBodyText(assurance.alert_eligibility?.customer_message), {
    size: 8,
    indent: 10,
    color: assurance.alert_eligibility?.status === "recorded"
      ? "0.35 0.38 0.44"
      : "0.45 0.35 0.10",
  });
  for (const decision of assurance.alert_eligibility?.decisions || []) {
    w.text(
      `${decision.event_type || "ASM claim"}: ${decision.eligible ? "Alert eligible" : "Alert withheld"} (${decision.reason_code})`,
      { size: 7, bold: true, indent: 10 },
    );
    w.proseKeep(customerBodyText(decision.reason_message), {
      size: 7,
      indent: 18,
      color: "0.35 0.38 0.44",
    });
  }
  const versions = assurance.model_versions || {};
  w.proseKeep(
    `Model versions - signals: ${versions.signal_completeness || "not recorded"}; lifecycle: ${versions.lifecycle_policy || "not recorded"}; alert eligibility: ${versions.alert_eligibility || "not recorded"}.`,
    { size: 7, color: "0.35 0.38 0.44" },
  );
}

function sectionFindings(w, snap) {
  const findings = snap.observed_findings || [];
  const observations = snap.observations || [];
  const assessmentComplete = snap.overall?.assessment?.authoritative === true;
  const incompleteMessage =
    snap.overall?.assessment?.message ??
    "Scan coverage was not confirmed for this run; results may be incomplete.";
  w.heading(`Observed Findings (${findings.length})`);
  if (!findings.length) {
    w.text(
      assessmentComplete
        ? "No material findings were observed in this assessment."
        : incompleteMessage,
      { size: 10 },
    );
  }
  for (const f of findings) {
    w.text(findingHeading(f), { size: 10, bold: true });
    if (f.explanation) w.prose(customerBodyText(f.explanation), { size: 9, indent: 10, color: "0.25 0.28 0.33" });
    const evidenceMeta = [];
    if (f.confidence != null) evidenceMeta.push(`Confidence: ${f.confidence}`);
    if (f.evidence_grade?.grade) evidenceMeta.push(`Evidence grade: ${f.evidence_grade.grade}`);
    if (evidenceMeta.length) {
      w.text(evidenceMeta.join(" - "), { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
    const scoreImpact = Number(f.score_impact);
    if (Number.isFinite(scoreImpact) && scoreImpact !== 0) {
      w.text(`Cyber Metrics Score impact: ${scoreImpact} points.`, {
        size: 8, indent: 10, color: "0.25 0.28 0.33",
      });
    }
  }
  w.heading(`Observations (${observations.length})`);
  if (!observations.length) {
    w.text(
      assessmentComplete ? "No additional observations." : incompleteMessage,
      { size: 10 },
    );
  }
  for (const f of observations) {
    w.text(observationHeading(f), { size: 10 });
    if (f.explanation) w.prose(customerBodyText(f.explanation), { size: 9, indent: 10, color: "0.25 0.28 0.33" });
    const evidenceMeta = [];
    if (f.confidence != null) evidenceMeta.push(`Confidence: ${f.confidence}`);
    if (f.evidence_grade?.grade) evidenceMeta.push(`Evidence grade: ${f.evidence_grade.grade}`);
    if (evidenceMeta.length) {
      w.text(evidenceMeta.join(" - "), { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
  }
}

function sectionRemediation(w, snap, {
  title = "Recommended Actions",
  limit = null,
  includeUnmapped = true,
  showWhenEmpty = true,
} = {}) {
  const allActions = snap.remediation_actions || [];
  const actions = Number.isInteger(limit) ? allActions.slice(0, limit) : allActions;
  if (!showWhenEmpty && actions.length === 0) return;
  w.heading(`${title} (${actions.length})`);
  if (!actions.length) {
    w.text(
      snap.overall?.assessment?.authoritative === true
        ? "No canonical remediation actions for this assessment."
        : (snap.overall?.assessment?.message ?? "Scan coverage was not confirmed for this run; results may be incomplete."),
      { size: 10 },
    );
  }
  for (const a of actions) {
    // Keep each recommended action's heading with its first line — actions are the
    // report's call to action and must read as a prominent, unbroken block.
    w.keepTogether(28);
    w.text(`${a.priority ? `[${String(a.priority).toUpperCase()}] ` : ""}${a.title}`, { size: 11, bold: true });
    if (a.action) w.prose(customerBodyText(a.action), { size: 9, indent: 10 });
    if (a.finding_ids?.length > 1) {
      w.text(`Resolves ${a.finding_ids.length} related findings.`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
    if (a.verification_ceiling) {
      w.text(`Verification: ${a.verification_ceiling}`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
    w.gap(3);
  }
  const unmapped = includeUnmapped ? (snap.unmapped_finding_types || []) : [];
  if (unmapped.length) {
    w.gap(4);
    w.prose(`${unmapped.length} finding type(s) have no canonical remediation registered and are listed without invented advice: ${unmapped.join(", ")}.`, { size: 8, color: "0.35 0.38 0.44" });
  }
}

// Presentation-only labels for the deterministic Related Changes rules. NOT a source
// of meaning (the backend owns that) — just human titles for the frozen summary.
// Cert halves say "a certificate signal", never "a new or changed certificate":
// the rule's cert family also matches standing conditions (sensitive hostname in
// CT, expiring soon), so a more specific claim could say more than the evidence.
// Wording is kept identical to frontend RULE_LABELS (relatedChangesDisplay.js).
const RELATED_CHANGE_LABELS = {
  new_host_with_cert: "New host with a certificate signal",
  new_host_with_identity: "New host with a possible identity-facing hostname",
  identity_with_cert: "Possible identity-facing hostname with a certificate signal",
  email_config_with_host_or_cert: "Email-authentication change with a new host or a certificate signal",
  new_sender_with_email_config: "New sending source with an email-authentication change",
  shadow_it_with_host_or_cert: "Unapproved technology with a new host or a certificate signal",
};

// M6 B1 Related Changes summary. Frozen into the snapshot (related_changes_json) and
// rendered here. Renders NOTHING when there is nothing to show, so existing reports are
// byte-unchanged. Wording is locked (design §9): "related changes … may be connected …
// confirm whether planned"; never attack chain / compromise / incident.
//
// The section is WORKSPACE-level (the summary is built per workspace, not per report
// subject), so a row may affect a different domain in the same workspace than the
// report subject. The heading, the scope note and every row state this explicitly —
// the frozen production defect was a cybermeters.com cluster rendered inside a
// sheshire.co.uk report with nothing saying which domain it affected. The scope note
// is consumed from the canonical summary field; the engine constant is the fallback
// for summaries frozen before the field existed (the fact was always workspace-level).
function sectionRelatedChanges(w, summary, { reportSubjectDomain = null } = {}) {
  const items = (summary && Array.isArray(summary.items)) ? summary.items : [];
  if (!items.length) return;
  const subject = String(reportSubjectDomain || "").trim().toLowerCase() || null;
  w.heading(`Workspace-level Related Changes observed in this period (${items.length})`);
  w.prose("Related changes are correlated observations that may be connected. Change is not compromise - confirm whether each was planned.", { size: 9, color: "0.35 0.38 0.44" });
  w.prose(summary.scope_note || RELATED_CHANGES_WORKSPACE_SCOPE_NOTE, { size: 8, color: "0.35 0.38 0.44" });
  for (const it of items) {
    const label = RELATED_CHANGE_LABELS[it.rule_id] || it.rule_id;
    const affected = String(it.affected_domain || it.registrable_domain || "").trim().toLowerCase();
    w.text(`${label} - affects ${affected}`, { size: 10, bold: true });
    w.text(`${it.signal_family_count} independent signal families - ${it.direction} - status: ${it.customer_state}`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    if (subject && affected && affected !== subject) {
      w.text(`This change affects ${affected}, a different domain in this workspace. It is not necessarily a change to ${subject}.`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    } else if (subject && affected === subject) {
      w.text(`This change affects ${affected} - this report's domain.`, { size: 8, indent: 10, color: "0.35 0.38 0.44" });
    }
  }
}

// Item 7 P6: snapshot-derived DMARC policy presentation. All text and labels
// are produced by the backend presentation contract; this PDF performs no
// protocol interpretation.
function sectionDmarcPolicy(w, presentation) {
  if (!presentation) return;
  w.heading("DMARC Policy Evidence");
  w.text(presentation.headline || "DMARC policy evidence", {
    size: 10,
    bold: true,
  });
  if (presentation.customer_message) {
    w.proseKeep(presentation.customer_message, {
      size: 9,
      color: "0.25 0.32 0.42",
    });
  }
  if (presentation.status !== "current") return;

  const policy = presentation.policy || {};
  w.text(
    `Effective requested policy: ${policy.effective_requested_label || "Not determined"}`,
    { size: 9, bold: true },
  );
  if (policy.message) {
    w.proseKeep(policy.message, {
      size: 8,
      color: "0.35 0.38 0.44",
    });
  }
  if (policy.inheritance_message) {
    w.proseKeep(policy.inheritance_message, {
      size: 8,
      color: "0.35 0.38 0.44",
    });
  }
  if (policy.testing_message) {
    w.proseKeep(policy.testing_message, {
      size: 8,
      color: "0.45 0.35 0.10",
    });
  }
  if (presentation.legacy_pct?.message) {
    w.proseKeep(presentation.legacy_pct.message, {
      size: 8,
      color: "0.45 0.35 0.10",
    });
  }
  if (presentation.monitoring?.message) {
    w.proseKeep(presentation.monitoring.message, {
      size: 8,
      color: presentation.monitoring.state === "monitoring_degraded"
        ? "0.45 0.35 0.10"
        : "0.35 0.38 0.44",
    });
  }
  for (const destination of presentation.external_rua?.destinations || []) {
    w.text(
      `${destination.status_label}: ${destination.uri || "destination not recorded"}`,
      { size: 8, bold: true },
    );
    w.proseKeep(destination.message, {
      size: 7,
      indent: 10,
      color: "0.35 0.38 0.44",
    });
  }
  appendixEvidenceAssertion(
    w,
    "DMARC policy conclusion",
    presentation.evidence_grade,
  );
}

// Canonical printable projection for one observed DMARC record. `value` is the
// customer-readable record string the parser concatenated; `raw` is the original
// DNS answer and is printable only when it is itself a string (legacy scalar
// shape). An object-only record has no customer-printable scalar and produces
// no row — internal parser structure is never serialised into a customer report.
function printableDmarcRecord(record) {
  if (typeof record?.value === "string" && record.value.trim()) return record.value;
  if (typeof record?.raw === "string" && record.raw.trim()) return record.raw;
  return null;
}

function sectionDmarcTechnicalAppendix(w, presentation) {
  if (presentation?.status !== "current" ||
      !presentation.technical_appendix) return;
  const appendix = presentation.technical_appendix;
  w.heading("Technical Appendix - DMARC Policy");
  for (const fact of appendix.facts || []) {
    w.proseKeep(`${fact.label}: ${fact.value}`, {
      size: 7,
      color: "0.35 0.38 0.44",
    });
  }
  if (appendix.lookup_path?.length) {
    w.text("Ordered DNS lookup evidence", { size: 8, bold: true });
    for (const [index, step] of appendix.lookup_path.entries()) {
      const q = step?.question || {};
      const used = step?.logically_used === false ? "not used" : "used";
      w.proseKeep(
        `${index + 1}. ${q.type || "DNS"} ${q.name || "name not recorded"} - ${step?.outcome || "outcome not recorded"} - ${used}`,
        { size: 7, indent: 10, color: "0.35 0.38 0.44" },
      );
    }
  }
  const printableRecords = (appendix.raw_records || [])
    .map(printableDmarcRecord)
    .filter((value) => value !== null);
  if (printableRecords.length) {
    w.text("Observed DMARC record data", { size: 8, bold: true });
    for (const value of printableRecords) {
      w.proseKeep(value, {
        size: 7,
        indent: 10,
        color: "0.35 0.38 0.44",
      });
    }
  }
  if (appendix.parsed_tags?.length) {
    w.text("Parsed tags", { size: 8, bold: true });
    for (const tag of appendix.parsed_tags) {
      w.proseKeep(
        `${tag?.name || "unknown"}=${tag?.raw_value ?? "not recorded"}${tag?.normalized != null ? ` (normalised: ${tag.normalized})` : ""}`,
        { size: 7, indent: 10, color: "0.35 0.38 0.44" },
      );
    }
  }
}

function sectionMethodology(w, snap) {
  const s = snap.snapshot || {};
  w.heading("Methodology & Limitations");
  w.text(`Assessed on ${pdfUtcDate(s.as_of, true)}`, { size: 10, bold: true });
  if (s.provenance === "reconstructed_on_demand") {
    w.proseKeep(`This report was reconstructed on ${pdfUtcDate(s.built_at, true)} from the immutable evidence recorded at assessment time.`, { size: 9, color: "0.45 0.35 0.10" });
  }
  // Formal version identifiers belong in the technical appendix below, not in
  // the main human narrative.
  w.gap(2);
  for (const l of snap.limitations || []) w.proseKeep(`- ${customerBodyText(l)}`, { size: 8, color: "0.35 0.38 0.44" });
}

const EVIDENCE_SOURCE_LABELS = Object.freeze({
  normative_protocol: "Normative protocol",
  configuration_baseline: "Configuration baseline",
  assurance_scheme: "Assurance scheme",
  management_framework: "Management framework",
  customer_attestation: "Customer attestation",
  product_policy: "CyberMeters product policy",
});

const SNAPSHOT_PROVENANCE_LABELS = Object.freeze({
  scan_finalize: "Created when the scan completed",
  reconstructed_on_demand: "Reconstructed from retained scan-time evidence",
});

const METHODOLOGY_LABELS = Object.freeze({
  snapshot_builder_version: "Snapshot builder",
  cyber_mot_resolver_version: "Cyber MOT resolver",
  cyber_metrics_score_methodology_version: "Cyber Metrics Score methodology",
  business_risk_methodology_version: "Business Risk Indicator methodology",
  ce_readiness_methodology_version: "Cyber Essentials readiness methodology",
  ce_readiness_methodology_revision: "Cyber Essentials readiness methodology revision",
  ce_question_set_version: "Cyber Essentials current question set",
  remediation_registry_fingerprint: "Canonical remediation registry fingerprint",
  ce_question_set_versions: "Cyber Essentials answered question set versions",
});

function methodologyLabel(key) {
  if (METHODOLOGY_LABELS[key]) return METHODOLOGY_LABELS[key];
  return String(key || "")
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function appendixEvidenceAssertion(w, label, assertion) {
  if (!assertion?.grade) return;
  const limits = Array.isArray(assertion.limits) ? assertion.limits : [];
  const limitsText = limits.join(" ");
  const sourceLabel = EVIDENCE_SOURCE_LABELS[assertion.source_type] || "Not recorded";
  // Keep each appendix assertion together when it can fit on one page. The
  // estimate deliberately errs high: an assertion heading must never be
  // orphaned at the footer with its basis beginning on the next page.
  const estimatedHeight =
    23 +
    (Math.max(1, Math.ceil(String(assertion.basis || "").length / 80)) * 11) +
    (limitsText ? Math.max(1, Math.ceil(limitsText.length / 80)) * 11 : 0);
  w.keepTogether(estimatedHeight);
  w.text(`${label}: ${assertion.grade}`, { size: 8, bold: true });
  w.text(
    `Evidence source: ${sourceLabel} · Repeated observation: ${assertion.repeat_confirmed === true ? "Yes" : "No"}`,
    { size: 7, indent: 10, color: "0.35 0.38 0.44" }
  );
  w.proseKeep(`Basis: ${assertion.basis || "No basis recorded."}`, {
    size: 7,
    indent: 10,
    color: "0.35 0.38 0.44",
  });
  if (limits.length) {
    w.proseKeep(`Limits: ${limitsText}`, {
      size: 7,
      indent: 10,
      color: "0.35 0.38 0.44",
    });
  }
}

function sectionEvidenceGradeAppendix(w, snap) {
  const s = snap.snapshot || {};
  const methodology = snap.methodology || {};
  const overall = snap.overall || {};
  w.heading("Technical Appendix - Evidence Grade & Provenance");
  w.text("Grade legend", { size: 8, bold: true });
  w.text("Evidence grades describe the strength of evidence, not the security level.", { size: 7, indent: 10, color: "0.35 0.38 0.44" });
  w.text("L0-L1: limited or externally-unverified evidence", { size: 7, indent: 10, color: "0.35 0.38 0.44" });
  w.text("L2: retained and reproducible", { size: 7, indent: 10, color: "0.35 0.38 0.44" });
  w.text("L3+: complete effective-state with stronger provenance", { size: 7, indent: 10, color: "0.35 0.38 0.44" });
  w.text(
    `Snapshot provenance: ${SNAPSHOT_PROVENANCE_LABELS[s.provenance] || "Not recorded"}`,
    { size: 8, bold: true }
  );
  w.text(`Snapshot ID: ${s.snapshot_id || "not recorded"}`, { size: 8 });
  w.text("Methodology versions", { size: 9, bold: true });
  for (const [key, value] of Object.entries(methodology)) {
    const printable = Array.isArray(value)
      ? value.join(", ")
      : (value && typeof value === "object" ? JSON.stringify(value) : value);
    const missingLabel = key === "ce_question_set_versions"
      ? "No questionnaire answers recorded"
      : "Not recorded";
    w.proseKeep(`${methodologyLabel(key)}: ${printable == null || printable === "" ? missingLabel : printable}`, {
      size: 7,
      indent: 10,
      color: "0.35 0.38 0.44",
    });
  }

  appendixEvidenceAssertion(w, "Cyber Metrics Score / CyberMeters assessment band", overall.assessment_evidence_grade);
  appendixEvidenceAssertion(w, "Business Risk Indicator", overall.business_risk_indicator?.evidence_grade);
  appendixEvidenceAssertion(w, "Eight-domain summary", overall.evidence_grade);

  for (const domain of snap.domains || []) {
    appendixEvidenceAssertion(w, `Domain - ${domain.display_name}`, domain.evidence_grade);
    appendixEvidenceAssertion(w, `${domain.display_name} - external indicator`, domain.cyber_essentials?.evidence_grade);
    appendixEvidenceAssertion(w, `${domain.display_name} - questionnaire`, domain.questionnaire?.evidence_grade);
  }
  for (const finding of snap.observed_findings || []) {
    appendixEvidenceAssertion(w, `Finding - ${finding.title || finding.finding_id || "unnamed"}`, finding.evidence_grade);
  }
  for (const observation of snap.observations || []) {
    appendixEvidenceAssertion(w, `Observation - ${observation.title || observation.finding_id || "unnamed"}`, observation.evidence_grade);
  }
  for (const action of snap.remediation_actions || []) {
    appendixEvidenceAssertion(w, `Remediation - ${action.title || action.remediation_id || "unnamed"}`, action.evidence_grade);
  }

  const certificateAssurance = certificateAssuranceFromSnapshot(snap);
  w.text("Certificate signal evidence contracts", { size: 9, bold: true });
  if (certificateAssurance.status !== "current") {
    w.proseKeep(
      customerBodyText(
        certificateAssurance.historical_notice ||
          "Certificate signal evidence contracts were not recorded in this historical snapshot.",
      ),
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
    return;
  }
  for (const key of certificateAssurance.signal_order || []) {
    const signal = certificateAssurance.signals?.[key];
    if (!signal) continue;
    const grade = signal.evidence_grade || {};
    const authorities = (signal.cited_authorities || [])
      .map((authority) => [
        authority.standard_id || authority.id || authority.authority,
        authority.standard_version || authority.version,
        authority.section,
        authority.requirement_type,
      ].filter(Boolean).join(" / "))
      .filter(Boolean);
    const provenance = signal.provenance && typeof signal.provenance === "object"
      ? Object.entries(signal.provenance)
          .filter(([, value]) => value != null && value !== "")
          .map(([name, value]) => `${name}: ${typeof value === "object" ? JSON.stringify(value) : value}`)
          .join("; ")
      : (signal.provenance || "Not recorded");
    w.keepTogether(72);
    w.text(`${signal.label}: ${signal.state_label || signal.state || "Not observed"}`, {
      size: 8,
      bold: true,
    });
    w.text(
      `Evidence grade: ${grade.achieved || "L0"} (ceiling ${grade.observable_ceiling || "not recorded"}; beta target ${grade.beta_target || "not recorded"}; minimum publishable ${grade.minimum_publishable || "not recorded"})`,
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
    w.proseKeep(
      `Source type: ${signal.source_type || "Not recorded"}. Provenance: ${provenance}.`,
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
    w.proseKeep(
      `Required corroboration: ${(signal.required_corroboration || []).join(", ") || "None recorded"}. Degrade behaviour: ${grade.degrade_behavior || "Not recorded"}.`,
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
    w.proseKeep(
      `Cited authorities: ${authorities.join("; ") || "Not recorded"}.`,
      { size: 7, indent: 10, color: "0.35 0.38 0.44" },
    );
  }
}

// Branding footer. Accepts either the v2 descriptor ({ mode, display_name }) or
// the legacy v1 shape ({ company_name }). Co-brand and the CyberMeters fallback
// keep FULL attribution ("Generated by CyberMeters"); only an entitled MSP
// white-label report reduces to "Powered by CyberMeters" — attribution is never
// removed, so no report is ever unbranded.
function footerFor(branding) {
  if (branding?.mode) {
    if (branding.mode === "white_label") {
      return `${branding.display_name || "Prepared report"} | Powered by CyberMeters | app.cybermeters.com`;
    }
    return DEFAULT_FOOTER; // co_brand / cybermeters / legacy co-brand
  }
  // Legacy v1 shape.
  return branding?.company_name
    ? `Prepared by ${branding.company_name} | Powered by CyberMeters`
    : DEFAULT_FOOTER;
}

// Primary identity name shown when there is no embeddable logo (text-mark
// fallback). Never blank — always a real name or the CyberMeters wordmark.
function primaryName(branding) {
  if (branding?.mode) {
    if (branding.mode === "cybermeters") return "CyberMeters";
    return branding.display_name || "CyberMeters";
  }
  return branding?.company_name || "CyberMeters";
}

// Strong branded cover for the Executive Security Report (page 1). Embeds the
// canonical CyberMeters logo (/Im0) prominently and proportionally when it is
// available; if the logo bytes could not be decoded/prepared it falls back to the
// CyberMeters text wordmark (never a fabricated badge). The logo is drawn, never
// cropped, stretched or recoloured — it is scaled uniformly within a cover cap.
function coverExec(w, { branding, workspaceName, domain, generatedAt, assessedAt, logoImage = null }) {
  const accent = hexToRgbF(branding?.accent || BRAND_HEX).join(" ");
  w.gap(4);
  w.rule(accent);
  w.gap(14);
  if (logoImage?.width && logoImage?.height) {
    // Prominent, aspect-preserved: uniform scale within a 300x70pt cover cap
    // (well inside the 504pt content width — no clipping, no distortion).
    const maxW = 300, maxH = 70;
    const scale = Math.min(maxW / logoImage.width, maxH / logoImage.height, 1);
    w.image(Math.max(1, Math.round(logoImage.width * scale)), Math.max(1, Math.round(logoImage.height * scale)));
  } else {
    w.display(primaryName(branding), { size: 26, color: accent });
  }
  w.display("Executive Security Report", { size: 20, color: "0.08 0.10 0.14" });
  w.gap(10);
  if (workspaceName) w.text(`Workspace:  ${workspaceName}`, { size: 11, bold: true });
  if (domain)        w.text(`Primary domain:  ${domain}`, { size: 11 });
  if (assessedAt)    w.text(`Assessment date:  ${pdfUtcDate(assessedAt, true)}`, { size: 10, color: "0.35 0.38 0.44" });
  if (generatedAt)   w.text(`Report generated:  ${pdfUtcDate(generatedAt, true)}`, { size: 10, color: "0.35 0.38 0.44" });
  w.gap(6);
  w.rule();
  w.gap(10);
}

function brandingHeader(w, branding, title, subtitle, logoImage = null) {
  if (logoImage?.width && logoImage?.height) {
    // The customer/MSP logo occupies the top-right identity slot, aspect-preserved,
    // capped at 96x40pt. For a co-brand report the CyberMeters attribution is
    // retained in the footer of every page.
    const maxW = 96, maxH = 40;
    const scale = Math.min(maxW / logoImage.width, maxH / logoImage.height, 1);
    const lw = Math.max(1, Math.round(logoImage.width * scale));
    const lh = Math.max(1, Math.round(logoImage.height * scale));
    w.raw(`q ${lw} 0 0 ${lh} ${PAGE_W - MARGIN - lw} ${PAGE_H - MARGIN - lh} cm /Im0 Do Q\n`);
  } else {
    // No embeddable logo → the approved text mark (never a blank identity slot).
    w.text(primaryName(branding), { size: 16, bold: true, color: "0.05 0.30 0.62" });
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
export function buildScanReportPdf(scan, read, branding = null, logoImage = null, relatedChanges = null) {
  const snap = read.customerSnapshot ?? read.snapshot;
  const s = snap.snapshot || {};
  const dmarcPresentation = buildDmarcPolicyPresentation(read.dmarcPolicy);
  const w = makeWriter({
    accentHex: branding?.accent || BRAND_HEX,
    footerText: footerFor(branding),
  });
  brandingHeader(w, branding, "External Security Assessment", `${s.domain || scan?.domain || ""} - assessed ${pdfUtcDate(s.as_of, true)}`, logoImage);
  sectionOverall(w, snap);
  sectionRemediation(w, snap, {
    title: "Priority Actions",
    limit: 3,
    includeUnmapped: false,
    showWhenEmpty: false,
  });
  sectionDomains(w, snap);
  sectionAttackSurfaceAssurance(w, snap);
  sectionCertificateAssurance(w, snap);
  sectionDmarcPolicy(w, dmarcPresentation);
  sectionFindings(w, snap);
  sectionRemediation(w, snap);
  sectionRelatedChanges(w, relatedChanges, { reportSubjectDomain: s.domain || scan?.domain || null });
  sectionMethodology(w, snap);
  sectionEvidenceGradeAppendix(w, snap);
  sectionDmarcTechnicalAppendix(w, dmarcPresentation);
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
export function buildWorkspaceExecutivePdf({ workspaceName, reads = [], branding = null, generatedAt = null, logoImage = null, relatedChanges = null }) {
  reads = reads.map((read) =>
    read?.status === "ok" && read.customerSnapshot
      ? { ...read, snapshot: read.customerSnapshot }
      : read
  );
  const ok = reads.filter((r) => r.status === "ok");
  const unavailable = reads.filter((r) => r.status !== "ok");
  // Presentation rule (documented): the cover headlines the most recently
  // assessed domain's snapshot; every domain is listed beneath it.
  const lead = ok.slice().sort((a, b) => String(b.snapshot.snapshot.as_of).localeCompare(String(a.snapshot.snapshot.as_of)))[0] || null;

  const w = makeWriter({
    accentHex: branding?.accent || BRAND_HEX,
    footerText: footerFor(branding),
  });

  // ── Page 1: branded cover ────────────────────────────────────────────────
  // A CUSTOMER white-label/co-brand logo keeps the top-right logo header. The
  // default CyberMeters report (and any report without a customer logo) uses the
  // strong cover: the canonical CyberMeters logo embedded prominently, or the
  // text wordmark if the logo bytes could not be prepared.
  const customerLogo = (branding?.mode === "white_label" || branding?.mode === "co_brand") && logoImage?.width && logoImage?.height;
  if (customerLogo) {
    brandingHeader(w, branding, "Executive Security Report", workspaceName ? `Workspace: ${workspaceName}` : null, logoImage);
    if (generatedAt) w.text(`Generated ${pdfUtcDate(generatedAt, true)}`, { size: 9, color: "0.35 0.38 0.44" });
    w.gap(4);
  } else {
    coverExec(w, {
      branding, workspaceName,
      domain: lead?.snapshot?.snapshot?.domain || null,
      generatedAt,
      assessedAt: lead?.snapshot?.snapshot?.as_of || null,
      logoImage,   // CyberMeters house logo → prominent on the cover
    });
  }

  if (!ok.length) {
    w.proseKeep("No canonical assessment snapshot is available for this workspace yet. Reports are produced from completed Cyber MOT assessments; run a scan to establish the first one.", { size: 10 });
  } else {
    // Executive summary (headline assessment) — flows on the cover page.
    w.heading("Executive Summary");
    w.text(`Latest assessment: ${lead.snapshot.snapshot.domain} - ${pdfUtcDate(lead.snapshot.snapshot.as_of, true)}`, { size: 10, bold: true });
    w.gap(2);
    sectionOverall(w, lead.snapshot);
    sectionRelatedChanges(w, relatedChanges);

    // Domain detail — deliberately grouped. Multiple domains each get a clean page
    // break; a single-domain workspace flows continuously (no forced blank pages).
    ok.forEach((r, i) => {
      if (i > 0) w.newPage();
      else w.keepTogether(140);
      w.heading(`Domain: ${r.snapshot.snapshot.domain}`);
      w.text(`Assessed ${pdfUtcDate(r.snapshot.snapshot.as_of, true)}`, { size: 9, color: "0.35 0.38 0.44" });
      w.gap(2);
      sectionDomains(w, r.snapshot, { detail: "concise" });
      sectionAttackSurfaceAssurance(w, r.snapshot, { detail: "concise" });
      sectionCertificateAssurance(w, r.snapshot, { detail: "concise" });
      const dmarcPresentation =
        buildDmarcPolicyPresentation(r.dmarcPolicy);
      sectionDmarcPolicy(w, dmarcPresentation);
      sectionRemediation(w, r.snapshot);
      sectionMethodology(w, r.snapshot);
      sectionEvidenceGradeAppendix(w, r.snapshot);
      sectionDmarcTechnicalAppendix(w, dmarcPresentation);
    });
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
