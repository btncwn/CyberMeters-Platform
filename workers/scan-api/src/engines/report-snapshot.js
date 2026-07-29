// ── Canonical Cyber MOT reporting snapshot (M5.c) ──
//
// One completed Cyber MOT → one immutable canonical eight-domain snapshot,
// persisted before any report is considered available (founder package,
// 2026-07-16). This engine is the ONLY writer of scan_report_snapshots
// (migration 093) and of the reports/snapshots/ R2 prefix.
//
// It owns NO calculation brain. Every assessment fact is the verbatim output of
// the canonical producer that already owns it:
//   • eight-domain states       → resolveCyberMotDomainStates (cyber-mot-domains.js)
//   • Cyber Metrics Score       → the scan's own computeScore output + the
//                                 canonical assessment presentation
//   • Business Risk Indicator   → deriveScanBusinessRisk (business-risk.js)
//   • CE readiness + methodology→ buildCyberEssentialsReadiness (ce-readiness.js)
//   • remediation meaning       → the Canonical Remediation Registry
//   • verification support      → verificationSupportForMethod (managed-case-model.js)
// A renderer that later re-derives any of these from live tables is the defect
// class M5.c exists to close.
//
// Concurrency/idempotency: the 081 atomic-claim pattern. INSERT OR IGNORE against
// the partial UNIQUE (scan_id WHERE status != 'failed') picks exactly one winner;
// losers do zero side effects. Write ordering is R2-first — the D1 row claims
// 'completed' only after the JSON is durable, so readers (which serve ONLY
// completed rows) can never observe a half-written snapshot.
//
// Failure visibility: a build that cannot complete flips its own row to 'failed'
// with the reason in metadata_json — visible and retryable, never silent, never
// exposed as completed.

import { resolveCyberMotDomainStates, CYBER_MOT_RESOLVER_VERSION } from "./cyber-mot-domains.js";
import { resolveAssessmentPresentation } from "./assessment-presentation.js";
import { deriveScanBusinessRisk, BUSINESS_RISK_METHODOLOGY_VERSION } from "./business-risk.js";
import { CYBER_METRICS_SCORE_METHODOLOGY_VERSION } from "./scoring.js";
import { buildCyberEssentialsReadiness, getCyberEssentialsSnapshot } from "./ce-readiness.js";
import { CE_QUESTION_SET_VERSION } from "../lib/cyber-essentials.js";
import { applyEvidenceQuality, isActionableFinding, normalizeFindingSchema } from "./findings.js";
import { findingRemediation, getRemediationById, remediationRegistryFingerprint } from "./remediation-registry.js";
import { verificationSupportForMethod } from "./managed-case-model.js";
import { CYBER_MOT_DOMAINS } from "./cyber-mot-domains.js";
import { createId } from "../lib/util.js";
import { normalizeSignalMonitoringStates } from "./signal-monitoring-state.js";
import {
  readDmarcPolicyEvidenceFromSnapshot,
  sealDmarcPolicyEvidence,
} from "./dmarcbis-contract.js";
import {
  buildCertificateCustomerPresentation,
  buildCertificateLifecycleAssurance,
} from "./certificate-customer-presentation.js";
import {
  buildAttackSurfaceCustomerPresentation,
} from "./attack-surface-customer-presentation.js";
import {
  projectPhase5EvidenceForCustomer,
  projectPhase5SnapshotForCustomer,
} from "./phase5-evidence.js";

export const SNAPSHOT_SCHEMA_VERSION = "1";
export const SNAPSHOT_BUILDER_VERSION = "2026-07-27.1";
export const CANONICAL_REPORT_SNAPSHOT_AVAILABLE_FROM = "2026-07-17";
export const CANONICAL_REPORT_SNAPSHOT_AVAILABLE_FROM_DISPLAY = "17 July 2026";

// Compatibility-only availability state. It is intentionally NOT a substitute
// snapshot and contains no security conclusion. Completed legacy scans that
// cannot be reconstructed should render this calm historical boundary rather
// than a red operational error or an implication of data loss.
export function historicalReportSnapshotAvailability(scan) {
  if (scan?.status !== "completed" || !scan?.created_at) return null;
  const raw = String(scan.created_at);
  const createdAt = new Date(
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(raw) ? raw.replace(" ", "T") + "Z" : raw
  );
  const boundary = new Date(`${CANONICAL_REPORT_SNAPSHOT_AVAILABLE_FROM}T00:00:00.000Z`);
  if (Number.isNaN(createdAt.getTime()) || createdAt >= boundary) return null;
  return {
    status: "historical_scan_no_canonical_snapshot",
    available_from: CANONICAL_REPORT_SNAPSHOT_AVAILABLE_FROM,
    message:
      `This scan predates the canonical report snapshot; a full evidence-graded report is available ` +
      `for scans from ${CANONICAL_REPORT_SNAPSHOT_AVAILABLE_FROM_DISPLAY} onward.`,
  };
}

// Evidence-Grade Law v2 — minimal-viable Item 6 pilot.
//
// These five fields are the complete pilot contract. Corroboration status and
// full standard-provenance fields remain deliberately out of scope until a
// signal-level contract requires them. The detector's existing
// finding.confidence is a separate axis and is never read or overwritten here.
export const EVIDENCE_GRADES = Object.freeze(["L0", "L1", "L2", "L3", "L4", "L5"]);
export const EVIDENCE_SOURCE_TYPES = Object.freeze([
  "normative_protocol",
  "configuration_baseline",
  "assurance_scheme",
  "management_framework",
  "customer_attestation",
  "product_policy",
]);
const EVIDENCE_GRADE_RANK = Object.freeze(
  Object.fromEntries(EVIDENCE_GRADES.map((grade, rank) => [grade, rank]))
);
const EVIDENCE_SOURCE_TYPE_SET = new Set(EVIDENCE_SOURCE_TYPES);

export function evidenceGrade({
  grade = "L0",
  source_type = "product_policy",
  basis = "The assertion has no recorded external evidence basis.",
  limits = [],
  repeat_confirmed = false,
} = {}) {
  const safeGrade = Object.prototype.hasOwnProperty.call(EVIDENCE_GRADE_RANK, grade)
    ? grade
    : "L0";
  const safeSourceType = EVIDENCE_SOURCE_TYPE_SET.has(source_type)
    ? source_type
    : "product_policy";
  const normalizedLimits = [...new Set(
    (Array.isArray(limits) ? limits : [limits])
      .map((limit) => String(limit || "").trim())
      .filter(Boolean)
  )];
  return {
    grade: safeGrade,
    source_type: safeSourceType,
    basis: String(basis || "The assertion has no recorded external evidence basis."),
    limits: normalizedLimits.length
      ? normalizedLimits
      : ["Limited to the evidence and scope recorded in this snapshot; no unobserved state is implied."],
    // Re-observation is a separate attribute. The pilot never infers it from a
    // completed scan, historical persistence, or detector confidence.
    repeat_confirmed: repeat_confirmed === true,
  };
}

function lowerGrade(left, right) {
  const l = Object.prototype.hasOwnProperty.call(EVIDENCE_GRADE_RANK, left) ? left : "L0";
  const r = Object.prototype.hasOwnProperty.call(EVIDENCE_GRADE_RANK, right) ? right : "L0";
  return EVIDENCE_GRADE_RANK[l] <= EVIDENCE_GRADE_RANK[r] ? l : r;
}

function lowestEvidenceGrade(assertions = []) {
  if (!assertions.length) return "L0";
  return assertions.reduce(
    (lowest, assertion) => lowerGrade(lowest, assertion?.grade),
    "L5"
  );
}

const DOMAIN_EVIDENCE_BASIS = Object.freeze({
  brand_protection:
    "One external candidate observation under CyberMeters product policy. A lookalike candidate is not proof of abuse.",
  attack_surface:
    "Single external observations from Certificate Transparency (RFC 9162), DNS (RFC 1035) and HTTP (RFC 9110), evaluated under CyberMeters product policy.",
  certificates_trust:
    "Certificate Transparency (RFC 9162) records that a certificate or precertificate was logged; it does not establish which certificate a server currently presents.",
  cyber_essentials_readiness:
    "CyberMeters external indicator over 2 of 5 Cyber Essentials control areas, combined with customer attestation for internally observable controls. This is product policy, not NCSC/IASME scheme conformance.",
  website_security:
    "Single external HTTP observations evaluated against RFC 9110, HSTS RFC 6797 and Content Security Policy Level 3 under CyberMeters product policy.",
  identity_exposure:
    "Single external observations of public login and identity-facing surfaces under CyberMeters product policy.",
  shadow_it_unmanaged_technology:
    "Single external technology observations; approval, ownership and authorisation remain customer classifications rather than CyberMeters observations.",
});

function findingEvidenceGrade(finding, report) {
  const id = String(finding?.id || "").toLowerCase();
  const moduleName = String(finding?.module || "").toLowerCase();
  const retainedEvidence = Array.isArray(finding?.evidence) && finding.evidence.length > 0;
  let grade = retainedEvidence ? "L1" : "L0";
  let sourceType = "product_policy";
  let basis = "CyberMeters product-policy interpretation of an externally observed scan signal.";
  const limits = [];

  if (/spf/.test(id)) {
    sourceType = "normative_protocol";
    const spf = report?.modules?.email_security?.spf;
    const effectiveResolved =
      spf?.present === true &&
      spf?.resolution_status === "complete" &&
      Array.isArray(spf?.resolved_pass_authorisations);
    grade = retainedEvidence ? (effectiveResolved ? "L3" : "L1") : "L0";
    basis = effectiveResolved
      ? "RFC 7208 SPF observation with the include/redirect/a/mx PASS-authorisation chain resolved and retained."
      : "RFC 7208 SPF DNS observation; an unresolved or absent effective chain cannot exceed a single observation.";
    if (!effectiveResolved) limits.push("The complete effective SPF authorisation chain was not resolved for this assertion.");
  } else if (/dmarc/.test(id)) {
    sourceType = "normative_protocol";
    basis = "RFC 9989 DMARC DNS-policy observation.";
    limits.push("This snapshot does not prove a complete RFC 9989 organisational-domain policy tree-walk or receiver enforcement.");
  } else if (/dkim/.test(id)) {
    sourceType = "normative_protocol";
    basis = "RFC 6376 DKIM selector observation.";
    limits.push("Only the selectors recorded by the scan were checked; a non-match is not proof that DKIM is absent.");
  } else if (/mta[_-]?sts/.test(id)) {
    sourceType = "normative_protocol";
    basis = "RFC 8461 MTA-STS DNS and policy observation.";
  } else if (/tlsrpt|tls[_-]?rpt/.test(id)) {
    sourceType = "normative_protocol";
    basis = "RFC 8460 TLS reporting DNS observation.";
  } else if (/^(cert_|certificate_)/.test(id) || moduleName === "certificate_intelligence") {
    sourceType = /expir|soon|risk|anomal|weak/.test(id) ? "product_policy" : "normative_protocol";
    basis = sourceType === "product_policy"
      ? "CyberMeters product-policy threshold applied to a Certificate Transparency observation under RFC 9162."
      : "Certificate Transparency observation under RFC 9162.";
    limits.push(
      "Certificate Transparency proves logging, not which certificate is live; chain validity, root trust, OCSP and revocation were not verified."
    );
  } else if (/^(header_|https_|redirect_|canonical_|ssl_|tech_)/.test(id)) {
    sourceType = /weak|risk|score|grade|expir/.test(id) ? "product_policy" : "normative_protocol";
    basis = sourceType === "product_policy"
      ? "CyberMeters product-policy interpretation of an HTTP/TLS observation."
      : "External HTTP observation under RFC 9110, HSTS RFC 6797 or Content Security Policy Level 3, as applicable.";
  } else if (/^brand_/.test(id) || moduleName === "brand_monitoring") {
    basis = DOMAIN_EVIDENCE_BASIS.brand_protection;
    limits.push("A candidate or similarity signal is not proof of impersonation, malicious intent or abuse.");
  } else if (/^identity_/.test(id) || moduleName === "identity_discovery") {
    basis = DOMAIN_EVIDENCE_BASIS.identity_exposure;
    limits.push("No leaked-credential, breached-password, stealer-log, dark-web or compromise evidence is claimed.");
  } else if (/^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_)/.test(id)) {
    basis = DOMAIN_EVIDENCE_BASIS.attack_surface;
    limits.push("External observation does not establish internal ownership, intent or complete asset coverage.");
  }

  if (!retainedEvidence) {
    limits.unshift("No raw evidence item was retained on this finding assertion, so it remains L0.");
  }
  return evidenceGrade({
    grade,
    source_type: sourceType,
    basis,
    limits,
  });
}

function domainEvidenceGrade(entry, report) {
  const limits = [...(entry?.limitations || [])];
  let grade = "L1";
  let basis = DOMAIN_EVIDENCE_BASIS[entry?.domain_key] ||
    "Single external observations evaluated under CyberMeters product policy.";

  if (entry?.domain_key === "email_protection") {
    const spf = report?.modules?.email_security?.spf;
    const spfEffective =
      spf?.present === true &&
      spf?.resolution_status === "complete" &&
      Array.isArray(spf?.resolved_pass_authorisations);
    basis =
      `Email conclusion uses the lowest decisive input: DNS observations under RFC 7208, RFC 6376, RFC 9989, RFC 8461 and RFC 8460 are L1; ` +
      `the retained SPF effective-state path is ${spfEffective ? "L3" : "not established above L1"}. RUA remains observational.`;
    limits.push(
      "A complete organisational-domain tree-walk under RFC 9989 is not recorded for every DMARC assertion; DKIM selector coverage is bounded."
    );
  }

  if (entry?.domain_key === "cyber_essentials_readiness") {
    // Full-domain CE conclusion is always L0 in this pilot: three internally
    // observable control areas remain attestation-only. The named 2-of-5
    // external indicator below carries its own L1 assertion.
    grade = "L0";
    limits.push(
      "Cyber Essentials Requirements for IT Infrastructure v3.3 (effective 27 April 2026) covers five controls; CyberMeters externally indicates only 2 of 5 and does not certify scheme conformance."
    );
  } else if (entry?.domain_key === "shadow_it_unmanaged_technology") {
    // Observation is L1; the domain's classification/authorisation conclusion is
    // bounded by customer classification at L0, so the composite is L0.
    grade = "L0";
    limits.push("Approval, ownership and removal classifications are customer-attested and not externally verified.");
  }

  const intrinsicallyInsufficientState = [
    "degraded",
    "unavailable",
    "not_configured",
    "customer_input_required",
    "not_yet_assessed",
    "evidence_insufficient",
  ].includes(entry?.state);
  const monitoringIncomplete = Object.values(entry?.monitoring_signals || {})
    .some((signal) => signal?.state !== "monitoring_healthy");
  const definition = CYBER_MOT_DOMAINS.find(
    (candidate) => candidate.domain_key === entry?.domain_key
  );
  const skipped = new Set(report?.scan_quality?.modules_skipped || []);
  const requiredModules = Array.isArray(definition?.required) && definition.required.length
    ? definition.required
    : (definition?.modules || []);
  const ownRequiredEvidenceIncomplete = requiredModules.some((name) => {
    const moduleResult = report?.modules?.[name];
    return moduleResult == null ||
      moduleResult.error ||
      moduleResult.skipped === true ||
      moduleResult.incomplete === true ||
      skipped.has(name);
  });

  // `entry.coverage` and the `provisional` state can reflect a DIFFERENT
  // module's failure. Evidence Grade is domain-local: Email, for example, keeps
  // its own grade when SPF/DMARC/DKIM evidence is intact but subdomain discovery
  // was skipped. A domain is capped only by its own required modules, its own
  // declared monitoring dependencies, or an intrinsically insufficient state.
  if (intrinsicallyInsufficientState || ownRequiredEvidenceIncomplete || monitoringIncomplete) {
    grade = "L0";
    limits.push("Decisive evidence was missing, degraded, provider-unavailable or not fully assessed in this snapshot.");
  }

  return evidenceGrade({
    grade,
    source_type: "product_policy",
    basis,
    limits,
  });
}

function assessmentEvidenceGrade({ assessment, domainEntries, methodologyVersion, label }) {
  const degradedDomains = domainEntries.filter((entry) => entry?.evidence_grade?.grade === "L0");
  const limits = [
    `${label} is a CyberMeters product-policy indicator, not an external standard, certification or assurance opinion.`,
  ];
  // Score/band and BRI are composite conclusions. Their ceiling is therefore
  // the lowest decisive constituent-domain grade, never the average or the
  // highest-confidence input.
  let grade = lowestEvidenceGrade(domainEntries.map((entry) => entry.evidence_grade));
  if (assessment?.authoritative !== true) {
    grade = lowerGrade(grade, "L0");
    limits.push("Scan coverage or monitoring/provider evidence was incomplete, so the conclusion is provisional.");
  }
  if (degradedDomains.length) {
    limits.push(
      `Lower-grade domain conclusions remain visible: ${degradedDomains.map((entry) => entry.display_name).join(", ")}.`
    );
  }
  return evidenceGrade({
    grade,
    source_type: "product_policy",
    basis: `${label} applies CyberMeters methodology ${methodologyVersion || "unversioned"} to frozen scan-time evidence.`,
    limits,
  });
}

// The versions this code can faithfully interpret. Readers FAIL CLOSED on any
// other value (mig 093 designed the column for exactly this gate): a future v2
// snapshot must never be misrendered under v1 assumptions.
export const SUPPORTED_SNAPSHOT_SCHEMA_VERSIONS = Object.freeze(new Set([SNAPSHOT_SCHEMA_VERSION]));

// Snapshot provenance (founder policy, 2026-07-17):
//   scan_finalize          — built in the scan-finalize post-terminal block with
//                            the live world in view (cases, CE answers).
//   reconstructed_on_demand — built later, from the immutable scan-time report
//                            ONLY. Current managed-case/workflow/ownership state
//                            and current CE answers are NEVER injected; anything
//                            not reconstructable from scan-time evidence is
//                            marked unavailable with an explicit limitation.
export const SNAPSHOT_PROVENANCE_FINALIZE = "scan_finalize";
export const SNAPSHOT_PROVENANCE_RECONSTRUCTED = "reconstructed_on_demand";

// A read-path build for a scan older than this uses strict reconstruction mode;
// within the window it is a near-contemporaneous crash repair and may build with
// the live world (what finalize itself would have produced moments earlier).
export const RECONSTRUCTION_AGE_MINUTES = 30;

// A 'building' claim older than this is presumed crashed and may be reclaimed
// (the STALE_REPORT_CLAIM_MINUTES precedent, plan-usage.js). Exported so the
// read route's repair-on-read gate uses the SAME threshold that governs the
// builder's own reclaim.
export const STALE_BUILDING_MINUTES = 30;

// Defensive bound on the workspace case read — one query, never per-row.
const CASE_READ_LIMIT = 2000;
const CERTIFICATE_LIFECYCLE_READ_LIMIT = 100;
const ATTACK_SURFACE_LIFECYCLE_READ_LIMIT = 500;

async function loadCertificateLifecycleRecordsForSnapshot(
  env,
  workspaceId,
  domainId,
) {
  const result = await env.cybermeters_db
    .prepare(
      `SELECT cl.*,
              current_observation.evidence_json AS current_observation_evidence_json,
              previous_observation.evidence_json AS previous_observation_evidence_json
       FROM certificate_lifecycle cl
       LEFT JOIN certificate_observations current_observation
         ON current_observation.id = cl.current_certificate_observation_id
        AND current_observation.workspace_id = cl.workspace_id
       LEFT JOIN certificate_observations previous_observation
         ON previous_observation.id = cl.previous_certificate_observation_id
        AND previous_observation.workspace_id = cl.workspace_id
       WHERE cl.workspace_id = ? AND cl.domain_id = ?
       ORDER BY (cl.days_remaining IS NULL), cl.days_remaining ASC,
                cl.last_seen_at DESC
       LIMIT ?`
    )
    .bind(workspaceId, domainId, CERTIFICATE_LIFECYCLE_READ_LIMIT)
    .all();
  return (result?.results || []).map((row) => ({
    certificate_lifecycle_id: row.id,
    domain_id: row.domain_id,
    primary_hostname: row.primary_hostname || null,
    certificate_identity: row.certificate_identity || null,
    current_certificate_observation_id:
      row.current_certificate_observation_id || null,
    previous_certificate_observation_id:
      row.previous_certificate_observation_id || null,
    issuer: row.issuer || null,
    not_before: row.not_before || null,
    not_after: row.not_after || null,
    days_remaining: row.days_remaining ?? null,
    renewal_readiness: row.renewal_readiness || null,
    renewal_status: row.renewal_status || null,
    replacement_detected_at: row.replacement_detected_at || null,
    replacement_recorded_at: row.replacement_recorded_at || null,
    coverage_status: row.coverage_status || null,
    verification_status: row.verification_status || null,
    lifecycle_state: row.lifecycle_state || null,
    first_seen_at: row.first_seen_at || null,
    last_seen_at: row.last_seen_at || null,
    certificate_assurance: buildCertificateLifecycleAssurance(row),
  }));
}

async function loadAttackSurfaceLifecycleRecordsForSnapshot(
  env,
  workspaceId,
  domainId,
  scanId,
) {
  const result = await env.cybermeters_db
    .prepare(
      `SELECT id AS asset_id, hostname, lifecycle_state,
              last_observation_state, lifecycle_policy_version,
              confirmed_removed_at, last_observation_scan_id
       FROM workspace_assets
       WHERE workspace_id = ? AND domain_id = ?
         AND last_observation_scan_id = ?
       ORDER BY hostname, id
       LIMIT ?`
    )
    .bind(
      workspaceId,
      domainId,
      scanId,
      ATTACK_SURFACE_LIFECYCLE_READ_LIMIT,
    )
    .all();
  return result?.results || [];
}

export function snapshotR2Key(workspaceId, scanId, snapshotId) {
  return `reports/snapshots/${workspaceId}/${scanId}/${snapshotId}.json`;
}

// Local WebCrypto digest (the auth-crypto.js / brand-cases.js inline precedent —
// importing lib/dmarc-ingest.js's sha256Hex would drag the DMARC ingest chain
// into the scan-finalize import graph). Exported so the read route can verify
// the served bytes against the D1 checksum with the SAME function that wrote it.
export async function snapshotSha256Hex(input) {
  return sha256Hex(input);
}
async function sha256Hex(input) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(input)));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Verification ceiling wording ─────────────────────────────────────────────
// The canonical customer-safe ceiling per support value. "Verified"/"Confirmed"
// are reserved for automated (system-observed) support ONLY —
// docs/verification-vocabulary.md. Fail-closed: an unrecognised support value
// gets the unsupported wording, never the stronger claim.
export function verificationCeiling(support) {
  switch (support) {
    case "automated":
      return "Can be verified by CyberMeters re-observation.";
    case "manual":
      return "Attested by customer — not externally verifiable.";
    case "external":
      return "Requires independent third-party evidence.";
    default:
      return "No verification path exists on this platform today.";
  }
}

const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function highestSeverity(findings) {
  let best = null;
  for (const f of findings) {
    const s = String(f.severity || "").toLowerCase();
    if ((SEV_ORDER[s] ?? 0) > (SEV_ORDER[best] ?? 0)) best = s;
  }
  return best;
}

// ── composeSnapshot — PURE ────────────────────────────────────────────────────
// Builds the canonical snapshot object from already-gathered inputs. Pure and
// deterministic so the contract is directly testable: same inputs → same
// snapshot, byte for byte (built_at/created stamps are passed IN, never read
// from the clock here).
export function composeSnapshot({
  snapshotId,
  workspaceId,
  domainId,
  scanId,
  domain,
  report,
  dmarcPolicyEvidence = null,
  cyberEssentials,   // resolver snapshot: { has_answers, complete, status, top_gaps }
  ceReadiness,       // full buildCyberEssentialsReadiness output, or null
  caseRows,          // workspace managed_cases rows (one bounded query)
  questionSetVersions, // distinct answer question_set_version values (mig 092)
  certificateLifecycleRecords = null, // null = unavailable; [] = observed empty
  attackSurfaceLifecycleRecords = null, // null = unavailable; [] = recorded empty
  supersedesSnapshotId,
  builtAt,
  reconstruction = false, // strict historical reconstruction (founder policy)
}) {
  const assessedAt = report?.completed_at || null;
  const scanQuality = report?.scan_quality ?? null;
  const qualityStatus = scanQuality?.status ?? null;
  // Freeze the canonical monitoring contract beside the assessment. Missing
  // legacy/provider provenance is normalised to evidence_incomplete, never to a
  // healthy default, so every snapshot-native consumer sees the same limitation.
  const monitoringStates = normalizeSignalMonitoringStates(report?.monitoring_states);
  for (const [signal, entry] of Object.entries(monitoringStates.signals)) {
    entry.evidence_grade = evidenceGrade({
      grade: entry.state === "monitoring_healthy" ? "L1" : "L0",
      source_type: "product_policy",
      basis: `CyberMeters monitoring-coverage policy applied to the frozen ${signal} module/provider execution provenance.`,
      limits: entry.state === "monitoring_healthy"
        ? ["Monitoring health describes evidence collection in this run; it is not a security-health verdict."]
        : [entry.message, "Incomplete monitoring coverage cannot support a healthy negative conclusion."],
    });
  }

  // Normalise exactly as the canonical read paths do (routes/scans.js /report,
  // deriveScanBusinessRisk) so the frozen findings equal what those paths served.
  const findings = applyEvidenceQuality(
    (Array.isArray(report?.findings) ? report.findings : []).map(normalizeFindingSchema)
  );

  // Canonical producers — verbatim, never second-guessed.
  const domains = resolveCyberMotDomainStates(report, { scanId, cyberEssentials });
  const businessRisk = deriveScanBusinessRisk(report);
  const assessment = resolveAssessmentPresentation({
    score: report?.cyber_metrics_score ?? null,
    scanQuality: qualityStatus,
    status: "completed",
    monitoringStates,
    requireMonitoring: true,
  });

  // ── Finding → domain attribution ──────────────────────────────────────────
  // A finding may legitimately belong to more than one domain (one certificate
  // problem is a Certificates & Trust fact AND a Website Security consequence).
  // The snapshot preserves every legitimate consequence; the shared
  // remediation_id below is what lets a renderer show ONE fix instead of three
  // unrelated actions.
  const domainKeysForFinding = (f) =>
    CYBER_MOT_DOMAINS.filter((d) => {
      try { return typeof d.match === "function" && d.match(f); } catch { return false; }
    }).map((d) => d.domain_key);

  // ── Managed-case linkage (data gathered by the caller in ONE query) ───────
  // Reconstruction: caseRows MUST be empty (the builder never queries them), and
  // the workflow summary is marked UNAVAILABLE rather than claiming zero cases —
  // "no cases" is a fact about the workspace; "not reconstructable" is the truth.
  const rows = reconstruction ? [] : (Array.isArray(caseRows) ? caseRows : []);
  const WORKFLOW_UNAVAILABLE = Object.freeze({
    unavailable: true,
    reason: "Managed-workflow state at scan time cannot be reconstructed from scan-time evidence.",
  });
  const caseByFindingId = new Map();
  for (const c of rows) {
    if (c.finding_id && !caseByFindingId.has(c.finding_id)) caseByFindingId.set(c.finding_id, c);
  }
  const TERMINAL_CASE_STATUSES = new Set(["closed", "false_positive", "risk_accepted"]);
  const workflowByDomain = new Map();
  for (const c of rows) {
    if (!c.domain_key) continue;
    const w = workflowByDomain.get(c.domain_key) || { total_cases: 0, open_cases: 0, statuses: {} };
    w.total_cases += 1;
    if (!TERMINAL_CASE_STATUSES.has(c.status)) w.open_cases += 1;
    w.statuses[c.status] = (w.statuses[c.status] || 0) + 1;
    workflowByDomain.set(c.domain_key, w);
  }

  // ── Findings / observations (taxonomy: "Observed Findings" by default) ────
  const unmappedTypes = new Set();
  const itemFor = (f) => {
    const rem = findingRemediation(f);
    if (!rem && f.finding_type !== "observation" && f.id) unmappedTypes.add(f.id);
    const method = rem?.verification_method ?? null;
    const support = rem ? verificationSupportForMethod(method) : null;
    const linkedCase = f.id ? caseByFindingId.get(f.id) || null : null;
    return {
      finding_id: f.id ?? null,
      domain_keys: domainKeysForFinding(f),
      finding_type: f.finding_type ?? "finding",
      title: f.title ?? null,
      explanation: f.description ?? f.recommendation ?? null,
      severity: f.severity ?? null,
      module: f.module ?? null,
      confidence: f.confidence ?? null,
      evidence_quality: f.evidence_quality ?? null,
      evidence_grade: findingEvidenceGrade(f, report),
      // Evidence stays in the immutable source artefact; the snapshot references it.
      evidence_ref: {
        source: "scan_report",
        count: Array.isArray(f.evidence) ? f.evidence.length : 0,
      },
      observed_at: assessedAt,
      remediation_id: rem?.remediation_id ?? null,
      verification_method: method,
      verification_support: support,
      managed_case_id: linkedCase?.id ?? null,
      managed_case_status: linkedCase?.status ?? null,
    };
  };
  const observedFindings = findings.filter((f) => isActionableFinding(f)).map(itemFor);
  const observations = findings.filter((f) => !isActionableFinding(f)).map(itemFor);

  // ── Remediation actions — one root action may reference many findings ─────
  // Every action resolves through the canonical registry. An unmapped finding
  // type is recorded explicitly (fail closed) — no invented remediation, ever.
  const byRemediation = new Map();
  for (const item of observedFindings) {
    if (!item.remediation_id) continue;
    const g = byRemediation.get(item.remediation_id) || [];
    g.push(item);
    byRemediation.set(item.remediation_id, g);
  }
  const remediationActions = [];
  for (const [remId, items] of byRemediation) {
    const entry = getRemediationById(remId);
    if (!entry) {
      // Fail closed: a remediation id the registry no longer resolves is an
      // explicit unmapped action, never invented copy. Namespaced so a consumer
      // can tell a registry-miss from an unmapped finding type.
      unmappedTypes.add(`unresolved_remediation:${remId}`);
      continue;
    }
    const method = entry.verification_method ?? null;
    const support = verificationSupportForMethod(method);
    const linkedCase = rows.find((c) => c.remediation_id === remId && !TERMINAL_CASE_STATUSES.has(c.status)) || null;
    remediationActions.push({
      remediation_id: remId,
      title: entry.customer_title ?? null,
      action: entry.recommended_action ?? null,
      // Honest priority: the highest severity among the findings this action
      // resolves — never an invented rank.
      priority: highestSeverity(items),
      domain_keys: [...new Set(items.flatMap((i) => i.domain_keys))].sort(),
      finding_ids: items.map((i) => i.finding_id).filter(Boolean).sort(),
      verification_method: method,
      verification_support: support,
      verification_ceiling: verificationCeiling(support),
      case_id: linkedCase?.id ?? null,
      case_status: linkedCase?.status ?? null,
      owner_type: linkedCase?.owner_type ?? null,
      owner_ref: linkedCase?.owner_ref ?? null,
      evidence_grade: evidenceGrade({
        grade: lowestEvidenceGrade(items.map((item) => item.evidence_grade)),
        source_type: "product_policy",
        basis:
          `Canonical remediation ${remId} is CyberMeters product policy applied to the linked observed finding evidence.`,
        limits: [
          ...items.flatMap((item) => item.evidence_grade?.limits || []),
          verificationCeiling(support),
        ],
      }),
    });
  }
  remediationActions.sort((a, b) => (SEV_ORDER[b.priority] ?? 0) - (SEV_ORDER[a.priority] ?? 0) || String(a.remediation_id).localeCompare(String(b.remediation_id)));

  // ── Eight equal domains — resolver verbatim + snapshot-only metadata ──────
  const findingsByDomain = new Map();
  for (const item of observedFindings) {
    for (const dk of item.domain_keys) {
      const g = findingsByDomain.get(dk) || [];
      g.push(item);
      findingsByDomain.set(dk, g);
    }
  }
  const domainEntries = domains.map((d) => {
    const items = findingsByDomain.get(d.domain_key) || [];
    const supports = [...new Set(items.map((i) => i.verification_support).filter(Boolean))].sort();
    const entry = {
      // Resolver's verbatim output — the same eight rows migration 091 persists.
      ...d,
      state_reason: d.summary,
      as_of: assessedAt,
      // Trend comparability metadata (the 091 gate): only rows sharing a
      // resolver_version on a complete scan may establish a trend.
      trend: {
        resolver_version: CYBER_MOT_RESOLVER_VERSION,
        scan_quality: qualityStatus,
        comparable_basis: qualityStatus === "complete",
      },
      remediation_ids: [...new Set(items.map((i) => i.remediation_id).filter(Boolean))].sort(),
      verification_support_distribution: supports,
      managed_workflow: reconstruction
        ? WORKFLOW_UNAVAILABLE
        : (workflowByDomain.get(d.domain_key) || { total_cases: 0, open_cases: 0, statuses: {} }),
      methodology_version: CYBER_MOT_RESOLVER_VERSION,
    };
    if (d.domain_key === "cyber_essentials_readiness") {
      // The released CE contract travels with the snapshot VERBATIM — 2-of-5
      // denominator, methodology version/revision, non-assessable controls.
      // A snapshot without these silently undoes v2026.07.16-14/-17.
      //
      // Scope caveat: ceReadiness grades the workspace's LATEST completed scan
      // at build time. At scan finalize that is this scan — except when a
      // sibling domain's scan completes in the same window, in which case the
      // CE block reflects the newer evidence. readiness_as_of states which.
      entry.cyber_essentials = ceReadiness
        ? {
            assessable: ceReadiness.assessable ?? null,
            status: ceReadiness.status ?? null,
            score: ceReadiness.score ?? null,
            grade: ceReadiness.grade ?? null,
            external_coverage_statement: ceReadiness.external_coverage_statement ?? null,
            readiness_methodology_version: ceReadiness.readiness_methodology_version ?? null,
            readiness_methodology_revision: ceReadiness.readiness_methodology_revision ?? null,
            readiness_as_of: ceReadiness.readiness_as_of ?? null,
            assessable_control_count: ceReadiness.assessable_control_count ?? null,
            total_control_count: ceReadiness.total_control_count ?? null,
            non_assessable_controls: ceReadiness.non_assessable_controls ?? [],
            limitations: ceReadiness.limitations ?? [],
            evidence_grade: evidenceGrade({
              grade: ceReadiness.assessable === true ? "L1" : "L0",
              source_type: "product_policy",
              basis:
                "CyberMeters external indicator over 2 of 5 Cyber Essentials control areas; scheme reference is NCSC Cyber Essentials Requirements for IT Infrastructure v3.3, effective 27 April 2026.",
              limits: [
                "This is a CyberMeters product-policy indicator, not NCSC/IASME scheme conformance or certification.",
                "Access Control, Malware Protection and Security Update Management require customer attestation and are not scored by this external indicator.",
              ],
            }),
          }
        : null;
      entry.questionnaire = {
        has_answers: cyberEssentials?.has_answers ?? false,
        complete: cyberEssentials?.complete ?? false,
        question_set_versions: questionSetVersions ?? [],
        evidence_grade: evidenceGrade({
          grade: "L0",
          source_type: "customer_attestation",
          basis: "Customer-supplied Cyber Essentials questionnaire answers.",
          limits: ["Customer attestation is not externally verified by CyberMeters."],
        }),
      };
      if (reconstruction) {
        // The CE questionnaire has no history table, so readiness AT SCAN TIME
        // is genuinely unknowable. Current answers are NEVER injected (founder
        // policy); the state resolves evidence_insufficient via the resolver's
        // own not_assessed path and the wording says exactly why.
        const ceUnavailable =
          "Cyber Essentials readiness at scan time cannot be reconstructed from scan-time evidence.";
        entry.summary = ceUnavailable;
        entry.state_reason = ceUnavailable;
        entry.cyber_essentials = null;
        entry.questionnaire = {
          unavailable: true,
          reason: ceUnavailable,
          evidence_grade: evidenceGrade({
            grade: "L0",
            source_type: "customer_attestation",
            basis: "No historical customer-attestation state can be reconstructed for this scan.",
            limits: [ceUnavailable],
          }),
        };
      }
    }
    if (d.domain_key === "certificates_trust") {
      // RFC 9162 establishes that a certificate/precertificate was logged. The
      // scan did not capture the certificate actively presented by the live
      // service, so this hard false prevents a CT observation being rendered as
      // a live-certificate verification claim.
      entry.live_certificate_verified = false;
      if (entry.state === "assessed_healthy") {
        entry.summary = "No material issue in the observed Certificate Transparency evidence.";
        entry.state_reason = entry.summary;
        entry.conclusion_label = "No material issue in observed CT evidence";
      }
    }
    entry.evidence_grade = domainEvidenceGrade(entry, report);
    return entry;
  });

  // ── Overall assessment ─────────────────────────────────────────────────────
  const stateCounts = {};
  for (const d of domainEntries) stateCounts[d.state] = (stateCounts[d.state] || 0) + 1;
  const healthy = stateCounts.assessed_healthy || 0;
  const issues = stateCounts.issue_detected || 0;
  const attention = domainEntries.length - healthy - issues;
  const overallSummary =
    `Across the eight Cyber MOT domains: ${healthy} assessed healthy, ${issues} with issues detected, ` +
    `and ${attention} needing further evidence, customer input or monitoring.`;
  const skippedModules = Array.isArray(scanQuality?.modules_skipped) ? scanQuality.modules_skipped : [];
  const notFullyAssessed = domainEntries
    .filter((d) => !["assessed_healthy", "issue_detected"].includes(d.state))
    .map((d) => ({
      domain_key: d.domain_key,
      state: d.state,
      reason: d.state_reason,
      evidence_grade: d.evidence_grade,
    }));
  const overallEvidenceGrade = evidenceGrade({
    grade: lowestEvidenceGrade(domainEntries.map((entry) => entry.evidence_grade)),
    source_type: "product_policy",
    basis:
      "The eight-domain conclusion uses the lowest decisive constituent-domain Evidence Grade; a lower-grade or insufficient domain cannot be hidden by higher-grade domains.",
    limits: domainEntries
      .filter((entry) => entry.evidence_grade?.grade === "L0")
      .map((entry) => `${entry.display_name}: ${entry.state_reason}`),
  });
  const scoreEvidenceGrade = assessmentEvidenceGrade({
    assessment,
    domainEntries,
    methodologyVersion: CYBER_METRICS_SCORE_METHODOLOGY_VERSION,
    label: "Cyber Metrics Score and CyberMeters assessment band",
  });
  const businessRiskEvidenceGrade = assessmentEvidenceGrade({
    assessment,
    domainEntries,
    methodologyVersion: BUSINESS_RISK_METHODOLOGY_VERSION,
    label: "Business Risk Indicator",
  });
  const certificateAssurance = buildCertificateCustomerPresentation({
    signalCompleteness:
      report?.modules?.certificate_intelligence?.signal_completeness ?? null,
    absenceReason:
      "Per-signal certificate assurance was not recorded by this scan. Missing fields are not interpreted as favourable results.",
  });
  const lifecycleRelationship = Array.isArray(certificateLifecycleRecords)
    ? certificateLifecycleRecords.find(
        (record) => record?.certificate_assurance?.relationship,
      )?.certificate_assurance?.relationship
    : null;
  if (lifecycleRelationship) {
    // Reuse the lifecycle engine's canonical current/previous observation
    // projection. Do not reconstruct replacement semantics in the renderer.
    certificateAssurance.relationship = lifecycleRelationship;
  }
  certificateAssurance.lifecycle = reconstruction
    ? {
        status: "unavailable",
        records: [],
        customer_message:
          "Certificate lifecycle state at scan time cannot be reconstructed from scan-time report evidence and is not inferred from current records.",
      }
    : Array.isArray(certificateLifecycleRecords)
      ? {
          status: "recorded",
          records: certificateLifecycleRecords,
          customer_message: certificateLifecycleRecords.length
            ? "Certificate lifecycle records were frozen with this report snapshot."
            : "No certificate lifecycle record was observed for this protected domain when the snapshot was built.",
        }
      : {
          status: "unavailable",
          records: [],
          customer_message:
            "Certificate lifecycle records were unavailable when this snapshot was built. This is not interpreted as no lifecycle activity.",
        };
  const attackSurfaceAssurance = buildAttackSurfaceCustomerPresentation({
    signalCompleteness:
      report?.modules?.attack_surface_signal_completeness ?? null,
    lifecycleRecords: reconstruction
      ? null
      : attackSurfaceLifecycleRecords,
    absenceReason:
      "Per-signal Attack Surface evidence was not recorded by this scan. Missing fields are not interpreted as favourable results.",
    lifecycleAbsenceReason: reconstruction
      ? "Attack Surface lifecycle state at scan time cannot be reconstructed from scan-time report evidence and is not inferred from current records."
      : "Attack Surface lifecycle evidence was unavailable when this snapshot was built. Legacy active/inactive status is not interpreted as confirmed removal.",
    alertAbsenceReason:
      "ASM alert eligibility is evaluated after snapshot creation and was not frozen into this snapshot. No alert outcome is inferred.",
    asOf: assessedAt,
  });

  return {
    snapshot: {
      snapshot_id: snapshotId,
      snapshot_schema_version: SNAPSHOT_SCHEMA_VERSION,
      status: "completed",
      workspace_id: workspaceId,
      domain_id: domainId,
      scan_id: scanId,
      domain,
      as_of: assessedAt,
      scan_started_at: report?.started_at ?? null,
      scan_completed_at: assessedAt,
      built_at: builtAt,
      provenance: reconstruction ? SNAPSHOT_PROVENANCE_RECONSTRUCTED : SNAPSHOT_PROVENANCE_FINALIZE,
      supersedes_snapshot_id: supersedesSnapshotId ?? null,
    },
    methodology: {
      snapshot_builder_version: SNAPSHOT_BUILDER_VERSION,
      cyber_mot_resolver_version: CYBER_MOT_RESOLVER_VERSION,
      cyber_metrics_score_methodology_version: CYBER_METRICS_SCORE_METHODOLOGY_VERSION,
      business_risk_methodology_version: BUSINESS_RISK_METHODOLOGY_VERSION,
      ce_readiness_methodology_version: ceReadiness?.readiness_methodology_version ?? null,
      ce_readiness_methodology_revision: ceReadiness?.readiness_methodology_revision ?? null,
      ce_question_set_version: CE_QUESTION_SET_VERSION,
      remediation_registry_fingerprint: remediationRegistryFingerprint(),
      ce_question_set_versions: questionSetVersions ?? [],
    },
    overall: {
      // The ONLY customer-facing numeric called "score" (one-score rule).
      cyber_metrics_score: assessment.display_score,
      score_band: assessment.display_rating,
      assessment,
      assessment_evidence_grade: scoreEvidenceGrade,
      summary: overallSummary,
      // Composite grade is the LOWEST decisive domain grade.
      evidence_grade: overallEvidenceGrade,
      // An indicator — a band plus explanation — never a second competing score.
      // The numeric and category breakdown are internal metrics for methodology
      // and trend purposes only.
      business_risk_indicator: {
        band: assessment.authoritative ? (businessRisk?.band ?? null) : null,
        explanation: assessment.authoritative
          ? (businessRisk?.summary ?? null)
          : "Business Risk Indicator is not authoritative because monitoring evidence or scan coverage was incomplete.",
        provisional: !assessment.authoritative,
        methodology_disclosure:
          "The Business Risk Indicator is derived from externally observed scan evidence " +
          "across weighted categories (email, service health, customer trust, brand exposure, " +
          "supply-chain signals). It is an indicator band with an explanation, not a score.",
        evidence_grade: businessRiskEvidenceGrade,
        internal_metrics: {
          score: businessRisk?.score ?? null,
          categories: businessRisk?.categories ?? null,
          top_business_risks: businessRisk?.top_business_risks ?? null,
        },
      },
      evidence_completeness: {
        scan_quality: qualityStatus,
        assessment_quality: assessment.quality,
        monitoring_state: assessment.coverage?.monitoring_state ?? null,
        monitoring_degraded_signals: Object.entries(monitoringStates.signals)
          .filter(([, entry]) => entry.state !== "monitoring_healthy")
          .map(([signal, entry]) => ({
            signal,
            state: entry.state,
            message: entry.message,
          })),
        modules_skipped: skippedModules,
        warnings: Array.isArray(scanQuality?.warnings) ? scanQuality.warnings : [],
        evidence_grade: evidenceGrade({
          grade: assessment.authoritative ? "L1" : "L0",
          source_type: "product_policy",
          basis: "Frozen scan-quality and signal-monitoring provenance for this assessment.",
          limits: assessment.authoritative
            ? ["Evidence completeness describes recorded coverage, not the absence of undiscovered issues."]
            : ["One or more decisive checks, providers or monitoring signals were incomplete or degraded."],
        }),
      },
      not_fully_assessed: notFullyAssessed,
    },
    protocol_evidence: {
      ...(dmarcPolicyEvidence
        ? { dmarc: dmarcPolicyEvidence }
        : {}),
    },
    monitoring_states: monitoringStates,
    certificate_assurance: certificateAssurance,
    attack_surface_assurance: attackSurfaceAssurance,
    domains: domainEntries,
    observed_findings: observedFindings,
    observations,
    remediation_actions: remediationActions,
    // Fail-closed record of finding types / remediation ids the registry could
    // not resolve. Explicit and visible — never replaced with invented advice.
    unmapped_finding_types: [...unmappedTypes].sort(),
    source_artifacts: {
      scan_report_r2_key: `reports/${scanId}.json`,
    },
    limitations: [
      "This snapshot records what CyberMeters externally observed at the assessment time shown; it is not a certification.",
      "Customer attestation and CyberMeters verification are different states and are labelled as such.",
      "Evidence that was missing or incomplete at assessment time is recorded as such and is never presented as healthy.",
      ...(reconstruction
        ? [
            "This snapshot was reconstructed on demand from the immutable scan-time report, after the scan completed.",
            "Managed-workflow state and Cyber Essentials questionnaire state at scan time cannot be reconstructed and are marked unavailable rather than guessed.",
          ]
        : []),
    ],
  };
}

// ── buildScanReportSnapshot — the ONE builder ────────────────────────────────
// Invoked from the scan-finalize post-terminal block (non-fatal by construction:
// a scan that completed must never be reported as failed because recording it
// did not). Idempotent per scan; concurrency-safe via the 081 claim.
//
// Returns { status: 'completed'|'exists'|'in_progress'|'skipped'|'failed', ... }.
export async function buildScanReportSnapshot(env, opts = {}) {
  const { workspaceId, domainId, scanId, domain, report, cyberEssentials = null, assessedAt,
          reconstruction = false } = opts;
  if (!workspaceId || !domainId || !scanId || !report) {
    return { status: "skipped", reason: "missing_identity" };
  }

  // Soft-deleted workspaces are nonexistent to writers (lifecycle-engine guard).
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(workspaceId).first().catch(() => null);
  if (!ws) return { status: "skipped", reason: "workspace_inactive" };

  // Reclaim a stale crashed claim so the partial UNIQUE can accept a retry.
  await env.cybermeters_db
    .prepare(
      `UPDATE scan_report_snapshots
       SET status = 'failed',
           metadata_json = json_object('failure_reason', 'stale_building_reclaimed')
       WHERE scan_id = ? AND status = 'building'
         AND created_at < datetime('now', ?)`
    )
    .bind(scanId, `-${STALE_BUILDING_MINUTES} minutes`)
    .run()
    .catch(() => {});

  const snapshotId = createId("snap");
  const r2Key = snapshotR2Key(workspaceId, scanId, snapshotId);
  // assessed_at is the SCAN's completion time — the occurrence identity. It is
  // never fabricated from the clock (migration 093 contract); a report with no
  // completion time has nothing honest to record.
  const occurredAt = assessedAt || report?.completed_at || null;
  if (!occurredAt) return { status: "skipped", reason: "missing_assessed_at" };

  // Supersession is recorded APPEND-ONLY on the new row at creation; the
  // superseded row is never touched. The predecessor is the latest completed
  // snapshot whose assessed_at PRECEDES this scan's — so a late-finishing scan
  // of an OLDER assessment can never claim to supersede a newer one, and
  // concurrent same-domain builds at most share a predecessor (the read paths
  // resolve the chain deterministically by assessed_at).
  const previous = await env.cybermeters_db
    .prepare(
      `SELECT id FROM scan_report_snapshots
       WHERE workspace_id = ? AND domain_id = ? AND status = 'completed' AND assessed_at < ?
       ORDER BY assessed_at DESC LIMIT 1`
    )
    .bind(workspaceId, domainId, occurredAt).first().catch(() => null);
  const supersedesSnapshotId = previous?.id ?? null;

  // Atomic claim: exactly one concurrent builder gets changes=1.
  const claim = await env.cybermeters_db
    .prepare(
      `INSERT OR IGNORE INTO scan_report_snapshots
         (id, workspace_id, domain_id, scan_id, status, r2_key,
          snapshot_schema_version, resolver_version, scan_quality, assessed_at,
          supersedes_snapshot_id)
       VALUES (?, ?, ?, ?, 'building', ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      snapshotId, workspaceId, domainId, scanId, r2Key,
      SNAPSHOT_SCHEMA_VERSION, CYBER_MOT_RESOLVER_VERSION,
      report?.scan_quality?.status ?? null, occurredAt,
      supersedesSnapshotId
    )
    .run();

  if ((claim.meta?.changes ?? 0) === 0) {
    // An ACTIVE snapshot already exists for this scan: completed → idempotent
    // no-op returning the canonical one; building → another builder owns it.
    const existing = await env.cybermeters_db
      .prepare(`SELECT id, status FROM scan_report_snapshots WHERE scan_id = ? AND status != 'failed'`)
      .bind(scanId).first().catch(() => null);
    if (existing?.status === "completed") return { status: "exists", snapshot_id: existing.id };
    return { status: "in_progress", snapshot_id: existing?.id ?? null };
  }

  try {
    // Gather the remaining inputs (each bounded; no per-row queries).
    // Strict reconstruction (founder policy 2026-07-17): security facts come
    // ONLY from the immutable scan-time report. The live-world queries below
    // are all SKIPPED — current CE answers, current readiness and current
    // managed-case state must never be injected into a historical snapshot.
    let ceReadiness = null;
    if (!reconstruction) {
      try { ceReadiness = await buildCyberEssentialsReadiness(workspaceId, env); } catch { ceReadiness = null; }
    }

    let caseRows = [];
    if (!reconstruction) try {
      const r = await env.cybermeters_db
        .prepare(
          `SELECT id, case_type, domain_key, domain, finding_id, remediation_id,
                  status, owner_type, owner_ref, created_at, resolved_at, reopened_count
           FROM managed_cases WHERE workspace_id = ?
           ORDER BY created_at DESC LIMIT ?`
        )
        .bind(workspaceId, CASE_READ_LIMIT).all();
      caseRows = r?.results || [];
    } catch { caseRows = []; }

    let questionSetVersions = [];
    if (!reconstruction) try {
      const r = await env.cybermeters_db
        .prepare(
          `SELECT DISTINCT question_set_version FROM cyber_essentials_answers
           WHERE workspace_id = ? AND question_set_version IS NOT NULL
           ORDER BY question_set_version`
        )
        .bind(workspaceId).all();
      questionSetVersions = (r?.results || []).map((x) => x.question_set_version);
    } catch { questionSetVersions = []; }

    let certificateLifecycleRecords = null;
    if (!reconstruction) {
      try {
        certificateLifecycleRecords =
          await loadCertificateLifecycleRecordsForSnapshot(
            env,
            workspaceId,
            domainId,
          );
      } catch {
        certificateLifecycleRecords = null;
      }
    }

    let attackSurfaceLifecycleRecords = null;
    if (!reconstruction) {
      try {
        attackSurfaceLifecycleRecords =
          await loadAttackSurfaceLifecycleRecordsForSnapshot(
            env,
            workspaceId,
            domainId,
            scanId,
          );
      } catch {
        // Migration 102 is founder-gated and may be absent. Preserve that fact
        // as not_recorded rather than failing the immutable snapshot build.
        attackSurfaceLifecycleRecords = null;
      }
    }

    const dmarcPolicyEvidence = await sealDmarcPolicyEvidence(
      report?.modules?.dmarc_core ?? null,
    );
    const snapshot = composeSnapshot({
      snapshotId, workspaceId, domainId, scanId, domain,
      report,
      dmarcPolicyEvidence,
      // Reconstruction: CE readiness at scan time is unknowable — the resolver's
      // own not_assessed path yields evidence_insufficient, never a guess.
      cyberEssentials: reconstruction ? { status: "not_assessed" } : cyberEssentials,
      ceReadiness, caseRows, questionSetVersions, certificateLifecycleRecords,
      attackSurfaceLifecycleRecords,
      supersedesSnapshotId,
      builtAt: new Date().toISOString(),
      reconstruction,
    });

    const body = JSON.stringify(snapshot, null, 2);
    const checksum = await sha256Hex(body);

    // R2 first — 'completed' is only ever claimed over a durable object.
    await env.cybermeters_reports.put(r2Key, body, {
      httpMetadata: { contentType: "application/json" },
      customMetadata: {
        workspace_id: workspaceId,
        scan_id: scanId,
        snapshot_id: snapshotId,
        snapshot_schema_version: SNAPSHOT_SCHEMA_VERSION,
        checksum_sha256: checksum,
      },
    });

    // Guarded finalise: only OUR building row may become completed. A completed
    // row is immutable — nothing in this codebase updates one.
    const fin = await env.cybermeters_db
      .prepare(
        `UPDATE scan_report_snapshots
         SET status = 'completed', checksum_sha256 = ?, size_bytes = ?, completed_at = ?
         WHERE id = ? AND status = 'building'`
      )
      .bind(checksum, new TextEncoder().encode(body).length, new Date().toISOString(), snapshotId)
      .run();
    if ((fin.meta?.changes ?? 0) === 0) {
      // Our claim was reclaimed as stale while we built. The row is 'failed';
      // the orphan object under OUR per-attempt key is unreachable (readers only
      // follow completed rows) and a retry writes a fresh key.
      return { status: "failed", snapshot_id: snapshotId, reason: "claim_lost" };
    }

    return { status: "completed", snapshot_id: snapshotId, checksum_sha256: checksum };
  } catch (err) {
    // Visible, retryable failure — never a silent catch, never exposed as
    // completed. The guarded WHERE keeps a concurrent reclaim consistent.
    await env.cybermeters_db
      .prepare(
        `UPDATE scan_report_snapshots
         SET status = 'failed', metadata_json = json_object('failure_reason', ?)
         WHERE id = ? AND status = 'building'`
      )
      .bind(String(err?.message ?? "snapshot_build_error").slice(0, 300), snapshotId)
      .run()
      .catch(() => {});
    return { status: "failed", snapshot_id: snapshotId, reason: String(err?.message ?? "snapshot_build_error") };
  }
}

// ── readScanReportSnapshot — the ONE canonical read path (M5.d) ──────────────
// Every consumer of a snapshot — the snapshot API route AND every renderer —
// goes through this helper, so retrieval, the schema-version gate, checksum
// integrity, repair-on-read and reconstruction live in exactly one place.
// The helper performs NO authorization: callers own tenancy and must gate
// before calling (requireScanReadAccess / requireWorkspaceRole / trusted cron
// workspace scoping).
//
// Availability contract (deterministic for every state a scan can be in):
//   ok                         — completed row, supported schema, verified bytes
//   building                   — a fresh claim is in flight; retryable (409)
//   not_found                  — no snapshot and nothing to honestly build
//   integrity_error            — completed row with missing object or checksum
//                                mismatch; NEVER served silently
//   unsupported_schema_version — future schema; fail closed, never misrender
//
// Repair/reconstruction (founder policy 2026-07-17):
//   • stale 'building' or failed-only attempts on a completed scan are rebuilt
//     from the durable scan report;
//   • with allowReconstruction, a scan with NO attempt is built the same way —
//     the first authorised request triggers the ONE canonical builder, and
//     every later request serves the immutable completed snapshot;
//   • any read-path build for a scan older than RECONSTRUCTION_AGE_MINUTES uses
//     strict reconstruction mode (no live-world injection); younger builds are
//     near-contemporaneous crash repairs and build as finalize would have;
//   • no bulk backfill: builds happen one authorised read at a time.
export async function readScanReportSnapshot(env, scanId, opts = {}) {
  const { repair = true, allowReconstruction = false, includeSuccessor = true } = opts;

  const selectActive = () => env.cybermeters_db
    .prepare(
      `SELECT id, workspace_id, domain_id, scan_id, status, r2_key, checksum_sha256,
              snapshot_schema_version, assessed_at, created_at, branding_json, related_changes_json
       FROM scan_report_snapshots WHERE scan_id = ? AND status != 'failed'`
    )
    .bind(scanId)
    .first();
  let row = await selectActive();

  if (repair) {
    const staleBuilding = row?.status === "building" &&
      (Date.now() - new Date(String(row.created_at).includes("T") ? row.created_at : row.created_at.replace(" ", "T") + "Z").getTime())
        > STALE_BUILDING_MINUTES * 60 * 1000;
    const anyRow = row ? true : !!(await env.cybermeters_db
      .prepare(`SELECT id FROM scan_report_snapshots WHERE scan_id = ? LIMIT 1`)
      .bind(scanId).first().catch(() => null));
    const failedOnly = !row && anyRow;
    const noAttempt = !row && !anyRow;

    if (staleBuilding || failedOnly || (noAttempt && allowReconstruction)) {
      try {
        const scanRow = await env.cybermeters_db
          .prepare(`SELECT workspace_id, domain_id, domain, status, created_at FROM scans WHERE id = ?`)
          .bind(scanId).first();
        if (scanRow?.status === "completed" && scanRow.workspace_id) {
          const repObj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
          const rep = repObj ? await repObj.json() : null;
          if (rep?.status === "completed" && rep?.completed_at) {
            const ageMs = Date.now() - new Date(rep.completed_at).getTime();
            const reconstruction = ageMs > RECONSTRUCTION_AGE_MINUTES * 60 * 1000;
            // A NO-ATTEMPT scan younger than the window is finalize-in-flight:
            // Phase 8o has not finished writing this scan's cases/CE yet, and a
            // read-path build here would win the claim and freeze an INCOMPLETE
            // snapshot forever. Report "building" — honest and retryable —
            // rather than racing the finalize pipeline.
            if (noAttempt && !reconstruction) {
              return { status: "building", reason: "finalize_in_progress" };
            }
            let ceSnap = null;
            if (!reconstruction) {
              try { ceSnap = await getCyberEssentialsSnapshot(scanRow.workspace_id, env); } catch { ceSnap = null; }
            }
            await buildScanReportSnapshot(env, {
              workspaceId: scanRow.workspace_id, domainId: scanRow.domain_id,
              scanId, domain: scanRow.domain, report: rep,
              cyberEssentials: ceSnap, assessedAt: rep.completed_at,
              reconstruction,
            });
          }
        }
      } catch { /* best-effort — the honest gates below still apply */ }
      row = await selectActive();
    }
  }

  if (!row) return { status: "not_found", reason: "no_snapshot" };
  if (row.status !== "completed") return { status: "building", row, reason: "build_in_progress" };

  // Fail closed on any schema this code cannot faithfully interpret.
  if (!SUPPORTED_SNAPSHOT_SCHEMA_VERSIONS.has(String(row.snapshot_schema_version))) {
    return { status: "unsupported_schema_version", row, reason: `schema_${row.snapshot_schema_version}` };
  }

  const obj = await env.cybermeters_reports.get(row.r2_key);
  if (!obj) {
    // A completed row is only ever claimed over a durable object — anomaly.
    return { status: "integrity_error", row, reason: "object_missing" };
  }
  const raw = await obj.text();
  const checksum = await sha256Hex(raw);
  if (row.checksum_sha256 && checksum !== row.checksum_sha256) {
    return { status: "integrity_error", row, reason: "checksum_mismatch" };
  }

  let snapshot;
  try { snapshot = JSON.parse(raw); } catch {
    return { status: "integrity_error", row, reason: "unparseable" };
  }
  // Defence in depth: the body must agree with the row it was indexed under.
  if (String(snapshot?.snapshot?.snapshot_schema_version) !== String(row.snapshot_schema_version)) {
    return { status: "integrity_error", row, reason: "schema_version_row_body_mismatch" };
  }
  const dmarcPolicy = await readDmarcPolicyEvidenceFromSnapshot(snapshot);
  if (["unsupported_schema", "invalid_contract", "integrity_error"].includes(
    dmarcPolicy.status,
  )) {
    return {
      status: "integrity_error",
      row,
      reason: `dmarc_${dmarcPolicy.reason}`,
    };
  }

  let supersededBy = null;
  if (includeSuccessor) {
    const successor = await env.cybermeters_db
      .prepare(
        `SELECT id, scan_id, assessed_at FROM scan_report_snapshots
         WHERE workspace_id = ? AND supersedes_snapshot_id = ? AND status = 'completed'
         ORDER BY assessed_at ASC LIMIT 1`
      )
      .bind(row.workspace_id, row.id)
      .first().catch(() => null);
    supersededBy = successor
      ? { snapshot_id: successor.id, scan_id: successor.scan_id, assessed_at: successor.assessed_at }
      : null;
  }

  // The checksum-gated snapshot above remains the immutable/verbatim object.
  // Customer renderers receive a separate read-time projection whose score,
  // band and clean narrative are withheld unless the referenced scan report
  // explicitly proves all required Phase-5 evidence publishable.
  let sourceModules = {};
  try {
    // This key comes only from the checksum-verified, scan/workspace-scoped
    // immutable snapshot above; no request-controlled key reaches R2.
    const sourceReportKey = snapshot?.source_artifacts?.scan_report_r2_key;
    const sourceObject = sourceReportKey
      ? await env.cybermeters_reports.get(sourceReportKey)
      : null;
    const sourceReport = sourceObject ? await sourceObject.json() : null;
    sourceModules =
      sourceReport?.modules && typeof sourceReport.modules === "object"
        ? sourceReport.modules
        : {};
  } catch {
    sourceModules = {};
  }
  const customerModules = projectPhase5EvidenceForCustomer(sourceModules);
  const customerSnapshot = projectPhase5SnapshotForCustomer(snapshot, sourceModules);

  return {
    status: "ok",
    snapshot,
    customerSnapshot,
    customerModules,
    raw,
    row,
    dmarcPolicy,
    supersededBy,
    integrity: { checksum_sha256: row.checksum_sha256, verified: !!row.checksum_sha256 },
  };
}

// ── readLatestWorkspaceSnapshots — workspace-scoped composition (M5.d) ───────
// Latest completed snapshot per domain for one tenant, each integrity-verified
// through readScanReportSnapshot (no duplicate checksum/schema logic). Used by
// workspace-level renderers (executive PDF, workspace report). Repair and
// reconstruction are OFF by default here: a workspace render must not fan out
// into N on-demand builds (subrequest budget); per-scan interactive reads are
// where reconstruction happens.
export async function readLatestWorkspaceSnapshots(env, workspaceId, opts = {}) {
  const { repair = false } = opts;
  const rows = await env.cybermeters_db
    .prepare(
      `SELECT s.scan_id, s.domain_id FROM scan_report_snapshots s
       WHERE s.workspace_id = ? AND s.status = 'completed'
         AND s.id = (
           SELECT n.id FROM scan_report_snapshots n
           WHERE n.workspace_id = s.workspace_id AND n.domain_id = s.domain_id
             AND n.status = 'completed'
           ORDER BY n.assessed_at DESC, n.id DESC LIMIT 1
         )
       ORDER BY s.assessed_at DESC`
    )
    .bind(workspaceId)
    .all().catch(() => null);
  const out = [];
  for (const r of rows?.results || []) {
    const read = await readScanReportSnapshot(env, r.scan_id, { repair, allowReconstruction: false, includeSuccessor: false });
    // Tenant belt-and-braces: the row must belong to the requested workspace.
    if (read.status === "ok" && read.row.workspace_id === workspaceId) out.push(read);
    else out.push({ status: read.status === "ok" ? "integrity_error" : read.status, domain_id: r.domain_id, scan_id: r.scan_id, reason: read.reason ?? "workspace_mismatch" });
  }
  return out;
}

// Latest completed snapshot for one tenant-owned domain. This is the bounded
// read used by Email Protection and Hosted-DMARC technical projections: one D1
// lookup and one integrity-gated R2 read, never a workspace-wide fan-out.
// Repair/reconstruction is deliberately disabled because these routes are
// read-only and must not create historical artifacts as a side effect.
export async function readLatestDomainDmarcPolicyEvidence(
  env,
  workspaceId,
  domainId,
) {
  if (!workspaceId || !domainId) {
    return { status: "not_available", evidence: null, reason: "missing_identity" };
  }
  const row = await env.cybermeters_db
    .prepare(
      `SELECT s.scan_id
       FROM scan_report_snapshots s
       JOIN workspaces w ON w.id = s.workspace_id AND w.deleted_at IS NULL
       WHERE s.workspace_id = ? AND s.domain_id = ? AND s.status = 'completed'
       ORDER BY s.assessed_at DESC, s.id DESC
       LIMIT 1`
    )
    .bind(workspaceId, domainId)
    .first()
    .catch(() => null);
  if (!row?.scan_id) {
    return { status: "not_available", evidence: null, reason: "no_snapshot" };
  }
  const read = await readScanReportSnapshot(env, row.scan_id, {
    repair: false,
    allowReconstruction: false,
    includeSuccessor: false,
  });
  if (read.status !== "ok") {
    return {
      status: "not_available",
      evidence: null,
      reason: read.reason || read.status,
    };
  }
  if (
    read.row.workspace_id !== workspaceId ||
    read.row.domain_id !== domainId
  ) {
    return {
      status: "not_available",
      evidence: null,
      reason: "workspace_domain_mismatch",
    };
  }
  return read.dmarcPolicy;
}
