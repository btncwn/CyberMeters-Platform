// ── Cyber Essentials readiness (v1 estimate) ──
// Lightweight UK Cyber Essentials readiness estimate from existing scan data (grades +
// per-category gaps/recommendations across the five CE controls). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Only buildCyberEssentialsReadiness is public.
import { clamp } from "./posture-scoring.js";
import { buildScorecardData } from "./scorecard.js";
import { resolveRemediation } from "./remediation-registry.js";
import { CE_QUESTIONS } from "../lib/cyber-essentials.js";

// ── Cyber Essentials Readiness v1 ────────────────────────────────────────────
//
// Lightweight UK Cyber Essentials readiness estimate using only existing
// CyberMeters scan and workspace intelligence signals. This is not certification
// logic and does not add new probes, evidence uploads, or compliance tables.

function cyberEssentialsGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 55) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

function cyberEssentialsStatus(grade) {
  if (grade === 'A' || grade === 'B') return 'likely_ready';
  if (grade === 'C') return 'partially_ready';
  return 'not_ready';
}

// ── External coverage is the repo's own honesty metadata, and it is AUTHORITATIVE ──
// Read from the same CE_QUESTIONS the managed lifecycle reads (ce-lifecycle.js), so there is
// exactly one answer to "can CyberMeters see this control?" and it cannot drift between the
// scoring path and the case path.
//
// Only `partial` is externally assessable. `access_control` and `malware_protection` declare
// `none`: they were SCORED from SPF/DKIM/DMARC, which measure anti-spoofing — not user
// access control, and not endpoint malware protection. Email authentication is not evidence
// of either. A workspace with perfect MFA and least privilege was scored 60/100 on "Access
// Control" for a missing SPF record; one with no MFA at all was scored 100/100 and flagged
// `externally_assessed: true`. Both claims were false, and the second is the dangerous one.
const CE_EXTERNAL_COVERAGE = Object.freeze(Object.fromEntries(
  CE_QUESTIONS.map((c) => [c.control_key, c.external_coverage || "none"]),
));
// The customer-facing control names come from the shared set too. They were hardcoded here
// and had drifted from it ("Phishing & Malware Exposure" vs the set's "Malware Protection"),
// so the coverage sentence named a control the questionnaire calls something else.
const CE_CONTROL_LABELS = Object.freeze(Object.fromEntries(CE_QUESTIONS.map((c) => [c.control_key, c.label])));
const LABEL_FOR = (k) => CE_CONTROL_LABELS[k] || k;
export function ceControlIsExternallyAssessable(controlKey) {
  return CE_EXTERNAL_COVERAGE[controlKey] === "partial";
}
// The one customer-facing sentence for a control the product cannot see from outside.
export const CE_NOT_ASSESSABLE_LABEL = "Not externally assessable — self-attestation only";

// ── Readiness METHODOLOGY version — a DIFFERENT contract from the questionnaire ─────
// This versions HOW the external readiness indicator is computed: which controls are
// assessable, what evidence each one may use, and therefore what the number means. The
// questionnaire's CE_QUESTION_SET_VERSION versions the WORDS a customer is asked. They move
// independently and must never be conflated — a reworded question does not change the
// methodology, and a changed denominator does not change the questions.
//
// Same format convention as the question set (founder-set): ISO 8601 `YYYY-MM-DD`, and it is
// a CyberMeters PRODUCT version, never an IASME or NCSC identifier. `revision` is a positive
// integer that increments on every material methodology change, so two outputs are
// comparable ONLY when BOTH version and revision match.
//
//   revision 1 (2026-07-16, v2026.07.16-14) — access_control and malware_protection stopped
//     being scored from SPF/DKIM/DMARC proxies. Indicator became 3 of 5.
//   revision 2 (2026-07-16, this increment)  — patch_management_readiness stopped being
//     scored from certificate expiry / certificate risk / ASM backlog / asset events.
//     Indicator became 2 of 5.
//
// THE TREND RULE: the indicator's DENOMINATOR changed at each revision, so a number from
// revision 1 and a number from revision 2 are not the same measurement. Comparing them would
// report a methodology change as a posture change — telling a customer they got worse when
// nothing about their security moved. Any consumer that compares two readiness values MUST
// check methodologyComparable() first.
export const CE_READINESS_METHODOLOGY_VERSION = "2026-07-16";
export const CE_READINESS_METHODOLOGY_REVISION = 2;

// ── Stage-1 workspace/domain-grain containment ─────────────────────────────
// CE's durable verdict is workspace-grained, while the evidence path below selects one
// latest workspace-owned scan (and therefore one linked domain). Until an explicit
// multi-domain aggregation contract exists, exactly one linked domain is the only scope in
// which that scan can support the existing workspace verdict. Do not add verification or
// deletion predicates here: workspace_domains has neither status nor deleted_at, and unlink
// is a hard DELETE. This is the ONE canonical count query used by readiness and lifecycle
// read projections.
export const CE_WORKSPACE_MULTI_DOMAIN_REASON = "workspace_multi_domain_not_aggregatable";
export const CE_WORKSPACE_NO_DOMAIN_REASON = "workspace_has_no_linked_domain";
export const CE_WORKSPACE_DOMAIN_COUNT_UNAVAILABLE_REASON = "workspace_domain_count_unavailable";

export async function resolveCeWorkspaceDomainCount(env, workspaceId) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT COUNT(*) AS n
                FROM workspace_domains
                WHERE workspace_id = ?`)
      .bind(workspaceId)
      .first();
    const raw = row?.n;
    const count = typeof raw === "number"
      ? raw
      : (typeof raw === "string" && /^(0|[1-9]\d*)$/.test(raw) ? Number(raw) : null);
    if (!Number.isSafeInteger(count) || count < 0) return { known: false, count: null };
    return { known: true, count };
  } catch {
    return { known: false, count: null };
  }
}

export function ceWorkspaceContainmentReason(domainCount) {
  if (domainCount?.known !== true) return CE_WORKSPACE_DOMAIN_COUNT_UNAVAILABLE_REASON;
  if (domainCount.count === 1) return null;
  if (domainCount.count === 0) return CE_WORKSPACE_NO_DOMAIN_REASON;
  return CE_WORKSPACE_MULTI_DOMAIN_REASON;
}

function ceContainmentCopy(reason) {
  if (reason === CE_WORKSPACE_MULTI_DOMAIN_REASON) {
    return {
      summary: "Cyber Essentials readiness cannot currently be assessed for this workspace because it has more than one linked domain.",
      limitation: "No workspace-wide readiness estimate is made until linked-domain evidence can be aggregated explicitly.",
    };
  }
  if (reason === CE_WORKSPACE_NO_DOMAIN_REASON) {
    return {
      summary: "Cyber Essentials readiness cannot currently be assessed because this workspace has no linked domain.",
      limitation: "Link one domain and complete a Cyber MOT before using the external readiness estimate.",
    };
  }
  return {
    summary: "Cyber Essentials readiness is temporarily unavailable because the workspace domain scope could not be confirmed.",
    limitation: "No readiness estimate is made while the linked-domain scope is unavailable.",
  };
}

function cyberEssentialsContainedResponse(wsId, reason) {
  const copy = ceContainmentCopy(reason);
  return {
    workspace_id: wsId,
    workspace_name: null,
    assessable: false,
    score: null,
    grade: null,
    status: "not_assessed",
    categories: [],
    top_gaps: [],
    recommendations: [],
    canonical_remediations: [],
    summary: copy.summary,
    generated_at: new Date().toISOString(),
    latest_scan: null,
    containment_reason: reason,
    limitations: [
      "CyberMeters does not certify Cyber Essentials.",
      copy.limitation,
    ],
  };
}

/**
 * May these two readiness outputs be compared as a genuine trend?
 * Only when BOTH the methodology version AND revision match. Missing metadata means the
 * value predates methodology versioning entirely, so it is NOT comparable — absent evidence
 * of comparability is not evidence of comparability.
 */
export function methodologyComparable(a, b) {
  const v = (x) => (x && typeof x === "object"
    ? { ver: x.readiness_methodology_version ?? null, rev: x.readiness_methodology_revision ?? null }
    : { ver: null, rev: null });
  const A = v(a), B = v(b);
  if (A.ver == null || B.ver == null || A.rev == null || B.rev == null) return false;
  return A.ver === B.ver && A.rev === B.rev;
}

// A control area CyberMeters cannot observe from outside. It stays VISIBLE — hiding it would
// be its own dishonesty — but it publishes no number, no band, no health, and no reason
// derived from a proxy. Its weight is 0, so it cannot enter the readiness arithmetic.
function cyberEssentialsNonAssessableCategory(key, label) {
  return {
    key,
    label,
    score: null,            // NOT 0 and NOT 100: there is no number to publish.
    weight: 0,              // Cannot influence the external-readiness indicator.
    band: null,
    reasons: [CE_NOT_ASSESSABLE_LABEL],
    gaps: [],
    unknown: [],
    externally_assessed: false,
    external_coverage: "none",
    assessable: false,
    attestation_only: true,
    recommendations: [],
    remediations: [],
  };
}

function cyberEssentialsCategory(key, label, score, reasons, gaps, recommendations, remediations, unknown) {
  if (!ceControlIsExternallyAssessable(key)) return cyberEssentialsNonAssessableCategory(key, label);
  const unknownSignals = unknown ?? [];
  return {
    key,
    label,
    score: clamp(Math.round(score)),
    // Recomputed below across the assessable controls only. A fixed 20 across five controls
    // is what let two unobservable areas carry 40% of the indicator.
    weight: 20,
    external_coverage: CE_EXTERNAL_COVERAGE[key] || "none",
    assessable: true,
    attestation_only: false,
    // "No major readiness gaps detected" is a CLAIM. It may only be made when
    // something was actually observed — otherwise the honest line is that the
    // control could not be assessed, which is what `unknown` records.
    reasons: reasons.length
      ? reasons
      : (unknownSignals.length
          ? ['This control area could not be assessed from the available external evidence.']
          : ['No major readiness gaps detected from available signals.']),
    gaps,
    // The signals CyberMeters did NOT observe for this control area. Empty means
    // every signal this control reads was actually assessed.
    unknown: unknownSignals,
    // True only when at least one signal was observed AND none is unknown.
    externally_assessed: unknownSignals.length === 0,
    recommendations,
    // Canonical remediation identities for each gap in this control area, so the
    // CE surface, Executive Report and PDF resolve the SAME remediation as the
    // scan surfaces. Readiness framing is separate from external certification.
    remediations: remediations ?? [],
  };
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  const exact = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  if (exact !== undefined) return exact;
  const found = Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase());
  return found ? found[1] : null;
}

// ── Did the module that carries this evidence actually assess it? ────────────
// CE reads other modules' output. If a module errored, was skipped by the
// subrequest budget, or self-reported `incomplete` (a probe that never executed —
// see headers-scan.js / ssl-scan.js), then CE observed NOTHING about the controls
// that module feeds.
//
// This mattered because every signal below was a loose falsy test. With no scan at
// all — or one failed R2 read, since getLatestWorkspaceScanReport returns null for
// "no scan", "object missing" and "any error" alike — `modules` is `{}`, so `!hsts`,
// `!csp`, `!email.spf` and `!email.dmarc` were all true and CE reported
// score 72 / grade C / `partially_ready`, listing gaps like "DMARC is missing or
// not confirmed". Absent evidence was graded identically to confirmed failure.
//
// The asymmetry proved it was an oversight rather than a decision: `https_available`
// was already tested with a strict `=== false` (someone deliberately separated
// "absent" from "false" for that one signal) while the other four were not.
//
// Tri-state from here on: true / false / null, where NULL MEANS UNKNOWN AND NEVER
// SCORES. addGap refuses null (below), so an unassessed control can neither deduct
// nor produce a gap. `unknown` is the honest state; a fabricated gap is not.
function moduleAssessedForCe(modules, name) {
  const m = modules?.[name];
  if (m == null) return false;
  if (m.error) return false;
  if (m.skipped === true || m.incomplete === true) return false;
  return true;
}

function hstsPresent(modules) {
  const hsts = modules?.domain_security_enrichment?.hsts;
  if (hsts && hsts.present !== undefined) return !!hsts.present;
  if (!moduleAssessedForCe(modules, 'headers')) return null;   // we did not look
  return !!headerValue(modules?.headers?.headers_observed ?? modules?.headers?.values, 'strict-transport-security');
}

function cspPresent(modules) {
  if (!moduleAssessedForCe(modules, 'headers')) return null;   // we did not look
  const value = headerValue(modules?.headers?.headers_observed ?? modules?.headers?.values, 'content-security-policy');
  return !!value;
}

function emailSignals(modules) {
  if (!moduleAssessedForCe(modules, 'email_security')) {
    return { spf: null, dmarc: null, dmarcPolicy: null, dkim: null };
  }
  const email = modules?.email_security ?? {};
  return {
    spf:   !!email.spf?.present,
    dmarc: !!email.dmarc?.present,
    dmarcPolicy: email.dmarc?.policy ?? null,
    dkim:  !!email.dkim?.present,
  };
}

// ── CE evidence is THIS workspace's own scan. Never another tenant's. ────────
// The predicate was `(s.workspace_id = ? OR wd.workspace_id = ?)` with a LEFT JOIN
// onto workspace_domains — and workspace_domains is PRIMARY KEY (workspace_id,
// domain_id), so ONE DOMAIN MAY BELONG TO SEVERAL WORKSPACES by design.
//
// The `OR` arm matched whenever the target workspace merely LINKED the domain,
// regardless of who ran the scan. Concretely: an MSP workspace and its client
// workspace both link acme.com; the MSP scans hourly, the client weekly;
// `ORDER BY s.created_at DESC LIMIT 1` therefore resolved the MSP's scan, and the
// client's Cyber Essentials readiness was graded from a scan the client never ran
// and cannot see. Today that is a stale computed view. The moment CE evidence is
// persisted as lifecycle history and mailed as an alert, it becomes a durable,
// audited, emailed cross-tenant evidence attribution — so it is fixed before that
// lifecycle is built, not after.
//
// `s.workspace_id = ?` only. Legacy scans with a NULL workspace_id are evidence for
// NOBODY: they cannot be attributed to a tenant, so the honest result is no
// evidence, which buildCyberEssentialsReadiness renders as `not_assessed` rather
// than as a grade. No fallback: a fallback is how the OR arm got here.
//
// This also removes the foreign scan id from the readiness path entirely — the
// report object key is derived from a scan this workspace owns, so a foreign
// reports/<scan_id>.json can no longer be read on a tenant's behalf.
async function getLatestWorkspaceScanReport(wsId, env) {
  try {
    const scan = await env.cybermeters_db
      .prepare(
        `SELECT s.id
         FROM scans s
         WHERE s.status = 'completed'
           AND s.workspace_id = ?
         ORDER BY s.created_at DESC LIMIT 1`
      )
      .bind(wsId)
      .first();
    if (!scan?.id) return null;

    const obj = await env.cybermeters_reports.get(`reports/${scan.id}.json`);
    if (!obj) return null;
    return await obj.json();
  } catch {
    return null;
  }
}

export async function buildCyberEssentialsReadiness(wsId, env) {
  // Stage 1: establish the workspace evidence grain before any scorecard, scan or R2
  // work. Exact count === 1 preserves the existing path byte-for-byte. Every other
  // result, including a failed/unparseable count, is not assessed and cannot select an
  // arbitrary domain's scan as a workspace verdict.
  const domainCount = await resolveCeWorkspaceDomainCount(env, wsId);
  const containmentReason = ceWorkspaceContainmentReason(domainCount);
  if (containmentReason) return cyberEssentialsContainedResponse(wsId, containmentReason);

  const [scorecard, report] = await Promise.all([
    // scanScope "workspace": CE's counts (critical_findings, admin_surfaces,
    // certificate_risks, saas_exposures) are EVIDENCE for a readiness verdict, and
    // this verdict is about to become persisted lifecycle state and an alert. The
    // default scope would let a co-owning workspace's newer scan supply them, so
    // fixing getLatestWorkspaceScanReport alone would have left CE grading a client
    // from its MSP's scan through the scorecard's back door.
    buildScorecardData(wsId, env, { scanScope: "workspace" }),
    getLatestWorkspaceScanReport(wsId, env),
  ]);
  if (!scorecard) return null;

  // ── No external evidence at all => NOT ASSESSED. Never a grade. ─────────────
  // getLatestWorkspaceScanReport returns null for three different situations that
  // must not be conflated: no completed scan, the R2 object missing, and any thrown
  // error. In all three CyberMeters has observed nothing externally, so it has
  // nothing to say about external readiness.
  //
  // This guard is mandatory BECAUSE of the tri-state fix above, not despite it.
  // Previously `modules = {}` made every loose `!signal` true, and CE reported
  // score 72 / grade C / `partially_ready` — fabricating gaps ("DMARC is missing")
  // from evidence it never collected. Making those signals honest (null) removes
  // the deductions, which alone would have flipped a no-evidence workspace to
  // score 100 / grade A / `likely_ready` — trading a fabricated failure for a
  // fabricated pass, which is far worse. Absent evidence is neither. It is unknown.
  //
  // The questionnaire is NOT consulted here and must never be: this function is the
  // answer-free external verdict. `getCyberEssentialsSnapshot` gates on the
  // questionnaire for DISPLAY; that is a separate concern, downstream of this.
  if (!report) {
    return {
      workspace_id: wsId,
      workspace_name: scorecard.workspace_name,
      assessable: false,
      score: null,
      grade: null,
      status: 'not_assessed',
      categories: [],
      top_gaps: [],
      recommendations: [],
      canonical_remediations: [],
      summary: 'Cyber Essentials readiness has not been assessed — no completed external scan evidence is available for this workspace yet.',
      generated_at: new Date().toISOString(),
      latest_scan: null,
      limitations: [
        'CyberMeters does not certify Cyber Essentials.',
        'No completed external scan evidence was available, so no readiness estimate has been made.',
      ],
    };
  }

  const modules = report?.modules ?? {};
  const ssl = modules.ssl ?? {};
  const email = emailSignals(modules);
  const certRisk = scorecard.certificate_risks ?? {};
  const certRiskLevel = certRisk.risk_level ?? null;
  const adminTotal = scorecard.admin_surfaces ?? 0;
  const saasTotal = scorecard.saas_exposures ?? 0;
  const criticalFindings = scorecard.critical_findings ?? 0;
  const highFindings = scorecard.high_findings ?? 0;
  const takeoverRisks = modules.subdomain_takeover?.risks ?? modules.subdomain_takeover?.findings ?? [];
  const takeoverCount = Array.isArray(takeoverRisks) ? takeoverRisks.length : 0;
  const hsts = hstsPresent(modules);
  const csp = cspPresent(modules);

  const categories = [];
  const allGaps = [];
  const allRecommendations = [];
  const allRemediations = [];

  // addGap now takes a canonical remediation reference (a registry finding_type)
  // instead of a hard-coded recommendation string. The recommended ACTION and its
  // identity resolve from the canonical registry, so CE readiness advice can never
  // drift from the same advice shown on the scan surfaces. The `reason` remains the
  // CE-specific RISK interpretation (readiness owns that). Falls back to the reason
  // text only if the ref does not resolve (should not happen — CI asserts coverage).
  function addGap(state, amount, reason, remediationRef) {
    state.score -= amount;
    state.reasons.push(reason);
    state.gaps.push(reason);
    const r = remediationRef ? resolveRemediation({ finding_type: remediationRef }) : null;
    const resolved = r && r.status === "resolved";
    const recommendation = resolved ? r.recommended_action : reason;
    state.recommendations.push(recommendation);
    if (resolved) {
      const rem = {
        remediation_id: r.remediation_id,
        customer_title: r.customer_title,
        recommended_action: r.recommended_action,
        business_impact: r.business_impact,
        verification_method: r.verification_method,
        domain_key: r.domain_key,
      };
      state.remediations.push(rem);
      allRemediations.push(rem);
    }
    allGaps.push({ reason, impact: amount });
    allRecommendations.push(recommendation);
  }

  function addReason(state, reason) {
    state.reasons.push(reason);
  }

  // A signal we did not observe is recorded, not scored. The customer is told the
  // control could not be assessed rather than being shown a gap the platform never
  // saw — and `unknown` is carried on the category so a consumer (and the CE
  // lifecycle) can tell "externally evidenced ready" apart from "we did not look".
  function addUnknown(state, signal, reason) {
    state.unknown.push({ signal, reason });
    state.reasons.push(reason);
  }

  // Boundary Protection: HTTPS, headers, exposed critical assets, takeover risk.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    if (ssl.https_available === false) {
      addGap(state, 30, 'HTTPS is not confirmed for the latest scanned domain.', 'ssl_not_available');
    } else if (ssl.https_available === true) {
      addReason(state, 'HTTPS is available on the latest scanned domain.');
    } else {
      addUnknown(state, 'https_available', 'HTTPS could not be assessed — the probe did not complete.');
    }
    // Strict `=== false` on BOTH: null means the headers module never assessed, and
    // "core browser boundary headers are missing" is then a claim about the
    // customer's site made from a probe that never ran.
    if (hsts === false && csp === false) {
      addGap(state, 15, 'Core browser boundary headers are missing or not confirmed.', 'header_missing_strict_transport_security');
    } else if (hsts === null && csp === null) {
      addUnknown(state, 'browser_headers', 'Browser security headers could not be assessed — the probe did not complete.');
    }
    if (criticalFindings > 0) {
      addGap(state, 20, `${criticalFindings} critical finding${criticalFindings !== 1 ? 's' : ''} remain in the latest scan.`, 'ce_open_findings_backlog');
    }
    if (adminTotal > 0) {
      addGap(state, 20, `${adminTotal} exposed admin or management surface${adminTotal !== 1 ? 's' : ''} detected.`, 'asset_exposure_admin_interface');
    }
    if (takeoverCount > 0) {
      addGap(state, 25, `${takeoverCount} potential subdomain takeover risk${takeoverCount !== 1 ? 's' : ''} detected.`, 'subdomain_takeover');
    }
    categories.push(cyberEssentialsCategory('boundary_protection', 'Boundary Protection', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  // Secure Configuration: HSTS, CSP, TLS posture, certificate health.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    if (hsts === false) {
      addGap(state, 25, 'HSTS is not present or could not be confirmed.', 'header_missing_strict_transport_security');
    } else if (hsts === true) {
      addReason(state, 'HSTS is present.');
    } else {
      addUnknown(state, 'hsts', 'HSTS could not be assessed — the header probe did not complete.');
    }
    if (csp === false) {
      addGap(state, 20, 'Content Security Policy is not present or could not be confirmed.', 'header_missing_content_security_policy');
    } else if (csp === true) {
      addReason(state, 'Content Security Policy is present.');
    } else {
      addUnknown(state, 'csp', 'Content Security Policy could not be assessed — the header probe did not complete.');
    }
    if (ssl.http_redirects_to_https === false) {
      addGap(state, 15, 'HTTP to HTTPS redirect is not confirmed.', 'ssl_no_http_redirect');
    }
    if (ssl.https_available === false) {
      addGap(state, 25, 'TLS is not available on the latest scanned domain.', 'ssl_not_available');
    }
    if (certRiskLevel === 'critical' || certRiskLevel === 'high') {
      addGap(state, certRiskLevel === 'critical' ? 25 : 15, `Certificate intelligence risk is ${certRiskLevel}.`, 'ce_cert_review');
    }
    categories.push(cyberEssentialsCategory('secure_configuration', 'Secure Configuration', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  // ── Access Control — NOT externally assessable ────────────────────────────
  // Previously scored from SPF/DMARC/DKIM (plus admin/SaaS exposure) and published as a
  // number with a colour band and `externally_assessed: true`. Email authentication tells
  // you whether someone can spoof your domain. It says NOTHING about whether your staff use
  // MFA, whether admin rights are separated, or whether leavers are deprovisioned — which is
  // what this control actually asks. The proxy is not weak evidence here; it is evidence of
  // a different thing.
  //
  // Nothing observable is lost by removing it: exposed admin surfaces already drive
  // `boundary_protection` above (the assessable control they belong to) and the Attack
  // Surface domain. The SaaS-portal signal (`ce_saas_access_review`) was attributed ONLY
  // here; SaaS exposure remains visible in Shadow IT & Unmanaged Technology, where the
  // evidence legitimately lives. It is deliberately not re-attributed to a control the
  // product cannot see.
  categories.push(cyberEssentialsCategory('access_control', LABEL_FOR('access_control'), 0, [], [], [], [], []));

  // ── Phishing & Malware Exposure — NOT externally assessable ───────────────
  // Previously an "estimate" from the same email-auth proxies. Anti-spoofing enforcement is
  // not endpoint malware protection: it cannot tell you whether AV is installed, updated or
  // enabled on a single device. The old copy admitted it was "estimated from available
  // signals only" and then published 100/100 in green anyway — the admission did not undo
  // the claim.
  categories.push(cyberEssentialsCategory('malware_protection', LABEL_FOR('malware_protection'), 0, [], [], [], [], []));

  // ── Security Update Management — NOT externally assessable ────────────────
  // Previously `partial`, and scored from certificate expiry, certificate risk, open
  // critical/high ASM findings and asset-change events. None of those measures ANY of the
  // four questions this control asks: automatic updates, unsupported software removal, an
  // update-review process, or 14-day critical patching. A certificate expiring is not a
  // software patch. An open attack-surface finding is not patch status. And
  // "No critical or high findings in the latest scan." was published as a POSITIVE reason
  // for patch readiness — the same shape as "SPF is present." → Access Control 100/100.
  //
  // Nothing observable is lost. Certificate expiry/risk still drive Certificates & Trust
  // (cert.expiry.*, cert.intelligence.review); the critical/high backlog still drives Attack
  // Surface and the scan findings; software-version disclosure still drives Website Security
  // and Attack Surface. They are simply no longer re-attributed to a control they do not
  // measure. No replacement proxy: a real external patch signal would be its own
  // evidence-governed detection increment.
  categories.push(cyberEssentialsCategory('patch_management_readiness', LABEL_FOR('patch_management_readiness'), 0, [], [], [], [], []));

  // ── The external-readiness indicator: assessable control areas ONLY ───────
  // The old arithmetic gave all five a fixed weight of 20, so two control areas the product
  // cannot observe carried 40% of the number. Weight is now shared across the assessable
  // areas only, and the non-assessable ones hold weight 0 — they cannot move it at all.
  const assessableCategories = categories.filter((c) => c.assessable);
  const nonAssessable = categories.filter((c) => !c.assessable);
  // Weight is presentation only — the indicator below is the plain mean of the assessable
  // areas — but it must still sum to exactly 100, so the remainder from an uneven split
  // (3 areas → 33.33 × 3 = 99.99) goes to the first rather than quietly going missing.
  if (assessableCategories.length) {
    const per = Math.round((100 / assessableCategories.length) * 100) / 100;
    for (const c of assessableCategories) c.weight = per;
    const drift = Math.round((100 - per * assessableCategories.length) * 100) / 100;
    assessableCategories[0].weight = Math.round((per + drift) * 100) / 100;
  }
  const score = assessableCategories.length
    ? Math.round(assessableCategories.reduce((sum, c) => sum + c.score, 0) / assessableCategories.length)
    : null;
  const grade = score == null ? null : cyberEssentialsGrade(score);
  // Say the coverage out loud, on the object every surface reads. A number whose denominator
  // is invisible invites the reader to assume it covers everything.
  const nonAssessableLabels = nonAssessable.map((c) => c.label);
  // "A and B and C" is not a sentence. With three non-assessable controls the list needs a
  // real conjunction, and the verb has to agree with the count.
  const listOf = (xs) => (xs.length <= 1 ? (xs[0] || '')
    : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);
  const coverageStatement =
    `External readiness indicator based on ${assessableCategories.length} of ${categories.length} `
    + `Cyber Essentials control areas.`
    + (nonAssessableLabels.length
        ? ` ${listOf(nonAssessableLabels)} require${nonAssessableLabels.length === 1 ? 's' : ''} customer attestation.`
        : '');
  const topGaps = [...new Map(
    allGaps
      .sort((a, b) => b.impact - a.impact)
      .map(g => [g.reason, g.reason])
  ).values()].slice(0, 5);
  const recommendations = [...new Set(allRecommendations)].slice(0, 6);
  // Deduplicated canonical remediation identities across all control areas, so a
  // consumer (Executive Report, PDF, tests) can join CE readiness to the SAME
  // remediation shown on scan surfaces. Certification remains external (below).
  const canonicalRemediations = [...new Map(
    allRemediations.map((r) => [r.remediation_id, r])
  ).values()];

  return {
    workspace_id: wsId,
    workspace_name: scorecard.workspace_name,
    // External scan evidence existed and was graded. The `not_assessed` early
    // return above is the only path that reports otherwise.
    assessable: true,
    score,
    grade,
    status: cyberEssentialsStatus(grade),
    categories,
    // The denominator, stated. Additive: every existing field keeps its meaning.
    external_coverage_statement: coverageStatement,
    // HOW this number was computed. A consumer comparing two readiness values must check
    // these first — see methodologyComparable(). Without them a denominator change reads as
    // a posture change.
    readiness_methodology_version: CE_READINESS_METHODOLOGY_VERSION,
    readiness_methodology_revision: CE_READINESS_METHODOLOGY_REVISION,
    readiness_as_of: new Date().toISOString(),
    assessable_control_count: assessableCategories.length,
    total_control_count: categories.length,
    non_assessable_controls: nonAssessable.map((c) => ({ key: c.key, label: c.label, reason: CE_NOT_ASSESSABLE_LABEL })),
    top_gaps: topGaps,
    recommendations,
    canonical_remediations: canonicalRemediations,
    summary: topGaps.length
      ? `Cyber Essentials readiness is ${cyberEssentialsStatus(grade).replace(/_/g, ' ')}. Two areas to address first: ${topGaps.slice(0, 2).map(g => String(g).trim().replace(/\.+$/, '')).join('; ')}.`
      : 'Cyber Essentials readiness looks strong from currently available CyberMeters signals.',
    generated_at: new Date().toISOString(),
    latest_scan: {
      domain: scorecard.last_scanned_domain,
      scanned_at: scorecard.last_scan_at,
      security_score: scorecard.security_score,
      risk_rating: scorecard.risk_rating,
    },
    limitations: [
      'CyberMeters does not certify Cyber Essentials.',
      'This readiness estimate uses externally observable CyberMeters signals only.',
      coverageStatement,
      // Derived, not hardcoded: this line named two controls by hand and used a label
      // ("Phishing & Malware Exposure") the questionnaire does not use. It is now built from
      // the same non-assessable set as the coverage sentence, so it cannot go stale again.
      `${listOf(nonAssessableLabels)} cannot be observed from outside at all. `
        + `They are not scored, and their state comes from your own attestation.`,
      'Endpoint protection, internal device configuration, and user access policies cannot be fully assessed from external ASM data.',
    ],
  };
}

// isCyberEssentialsQuestionnaireComplete — the canonical completeness contract:
// every question of every control has a non-"unknown" answer (mirrors mergeReadiness'
// `answered` predicate in lib/cyber-essentials.js). A single or partial answer set is
// NOT complete, so it can never permit an authoritative readiness verdict.
export function isCyberEssentialsQuestionnaireComplete(answersMap = {}) {
  return CE_QUESTIONS.every((ctrl) => {
    const ans = answersMap[ctrl.control_key] || {};
    const answered = ctrl.questions.filter((q) => ans[q.key] && ans[q.key] !== "unknown");
    return answered.length === ctrl.questions.length;
  });
}

// getCyberEssentialsSnapshot — the ONE canonical Cyber Essentials snapshot used by
// every surface's eight-domain resolver, so a workspace shows the SAME CE state on
// the Dashboard, Scan Detail, Executive Report UI and Executive PDF.
//
// Cyber Essentials readiness is only meaningful once the customer has COMPLETED the
// self-attestation questionnaire — external signals alone (and a partial answer set)
// are indicative, not a readiness verdict. So the snapshot carries both flags:
//   • no answers            → { has_answers:false, complete:false } → customer_input_required;
//   • partial answers       → { has_answers:true,  complete:false } → customer_input_required;
//   • complete questionnaire → { has_answers:true,  complete:true, status } → readiness verdict.
// The readiness (heavier) computation only runs once the questionnaire is complete.
export async function getCyberEssentialsSnapshot(wsId, env) {
  let rows = [];
  try {
    const r = await env.cybermeters_db
      .prepare('SELECT control_key, question_key, answer FROM cyber_essentials_answers WHERE workspace_id = ?')
      .bind(wsId).all();
    rows = r?.results || [];
  } catch { rows = []; }

  const has_answers = rows.length > 0;
  if (!has_answers) return { has_answers: false, complete: false, status: null, top_gaps: [] };

  const answersMap = {};
  for (const r of rows) {
    if (!answersMap[r.control_key]) answersMap[r.control_key] = {};
    answersMap[r.control_key][r.question_key] = r.answer;
  }
  const complete = isCyberEssentialsQuestionnaireComplete(answersMap);

  let readiness = null;
  if (complete) {
    try { readiness = await buildCyberEssentialsReadiness(wsId, env); } catch { readiness = null; }
  }
  const snapshot = {
    has_answers: true,
    complete,
    status: readiness?.status ?? null,
    top_gaps: Array.isArray(readiness?.top_gaps) ? readiness.top_gaps : [],
  };
  // Add containment provenance only when containment is active. This keeps the
  // single-domain snapshot byte-shape unchanged while giving durable snapshot/state
  // writers enough canonical context to avoid relabelling "cannot aggregate" as
  // "no scan ran".
  if (readiness?.containment_reason) {
    snapshot.assessable = false;
    snapshot.containment_reason = readiness.containment_reason;
    snapshot.summary = readiness.summary;
    snapshot.limitations = readiness.limitations;
  }
  return snapshot;
}
