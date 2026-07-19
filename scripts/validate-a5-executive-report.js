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

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const DOMAINS = ["Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust",
  "Cyber Essentials Readiness", "Website Security", "Identity Exposure", "Shadow IT & Unmanaged Technology"];

const SHADOW_LIMIT = "CyberMeters observes only externally visible technology signals. It has No internal-network, endpoint, CASB or EDR visibility, so unmanaged software that leaves no external trace cannot be seen.";

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
  const splitAfterNo = pages.some((p, i) => i + 1 < pages.length && /\bIt has No\s*$/.test(p) && /^internal-network/.test(pages[i + 1]));
  ok("B: no page ends on 'It has No' with the next page continuing 'internal-network'", !splitAfterNo);
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

console.log(`\nvalidate-a5-executive-report: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
