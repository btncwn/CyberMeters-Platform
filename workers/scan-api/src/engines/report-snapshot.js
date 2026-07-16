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
import { buildCyberEssentialsReadiness } from "./ce-readiness.js";
import { applyEvidenceQuality, isActionableFinding, normalizeFindingSchema } from "./findings.js";
import { findingRemediation, getRemediationById, remediationRegistryFingerprint } from "./remediation-registry.js";
import { verificationSupportForMethod } from "./managed-case-model.js";
import { CYBER_MOT_DOMAINS } from "./cyber-mot-domains.js";
import { createId } from "../lib/util.js";

export const SNAPSHOT_SCHEMA_VERSION = "1";
export const SNAPSHOT_BUILDER_VERSION = "2026-07-16.1";

// A 'building' claim older than this is presumed crashed and may be reclaimed
// (the STALE_REPORT_CLAIM_MINUTES precedent, plan-usage.js). Exported so the
// read route's repair-on-read gate uses the SAME threshold that governs the
// builder's own reclaim.
export const STALE_BUILDING_MINUTES = 30;

// Defensive bound on the workspace case read — one query, never per-row.
const CASE_READ_LIMIT = 2000;

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
  cyberEssentials,   // resolver snapshot: { has_answers, complete, status, top_gaps }
  ceReadiness,       // full buildCyberEssentialsReadiness output, or null
  caseRows,          // workspace managed_cases rows (one bounded query)
  questionSetVersions, // distinct answer question_set_version values (mig 092)
  supersedesSnapshotId,
  builtAt,
}) {
  const assessedAt = report?.completed_at || null;
  const scanQuality = report?.scan_quality ?? null;
  const qualityStatus = scanQuality?.status ?? null;

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
  const rows = Array.isArray(caseRows) ? caseRows : [];
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
      managed_workflow: workflowByDomain.get(d.domain_key) || { total_cases: 0, open_cases: 0, statuses: {} },
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
          }
        : null;
      entry.questionnaire = {
        has_answers: cyberEssentials?.has_answers ?? false,
        complete: cyberEssentials?.complete ?? false,
        question_set_versions: questionSetVersions ?? [],
      };
    }
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
    .map((d) => ({ domain_key: d.domain_key, state: d.state, reason: d.state_reason }));

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
      supersedes_snapshot_id: supersedesSnapshotId ?? null,
    },
    methodology: {
      snapshot_builder_version: SNAPSHOT_BUILDER_VERSION,
      cyber_mot_resolver_version: CYBER_MOT_RESOLVER_VERSION,
      cyber_metrics_score_methodology_version: CYBER_METRICS_SCORE_METHODOLOGY_VERSION,
      business_risk_methodology_version: BUSINESS_RISK_METHODOLOGY_VERSION,
      ce_readiness_methodology_version: ceReadiness?.readiness_methodology_version ?? null,
      ce_readiness_methodology_revision: ceReadiness?.readiness_methodology_revision ?? null,
      remediation_registry_fingerprint: remediationRegistryFingerprint(),
      ce_question_set_versions: questionSetVersions ?? [],
    },
    overall: {
      // The ONLY customer-facing numeric called "score" (one-score rule).
      cyber_metrics_score: assessment.display_score,
      score_band: assessment.display_rating,
      assessment,
      summary: overallSummary,
      // An indicator — a band plus explanation — never a second competing score.
      // The numeric and category breakdown are internal metrics for methodology
      // and trend purposes only.
      business_risk_indicator: {
        band: businessRisk?.band ?? null,
        explanation: businessRisk?.summary ?? null,
        methodology_disclosure:
          "The Business Risk Indicator is derived from externally observed scan evidence " +
          "across weighted categories (email, service health, customer trust, brand exposure, " +
          "supply-chain signals). It is an indicator band with an explanation, not a score.",
        internal_metrics: {
          score: businessRisk?.score ?? null,
          categories: businessRisk?.categories ?? null,
          top_business_risks: businessRisk?.top_business_risks ?? null,
        },
      },
      evidence_completeness: {
        scan_quality: qualityStatus,
        modules_skipped: skippedModules,
        warnings: Array.isArray(scanQuality?.warnings) ? scanQuality.warnings : [],
      },
      not_fully_assessed: notFullyAssessed,
    },
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
  const { workspaceId, domainId, scanId, domain, report, cyberEssentials = null, assessedAt } = opts;
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
    let ceReadiness = null;
    try { ceReadiness = await buildCyberEssentialsReadiness(workspaceId, env); } catch { ceReadiness = null; }

    let caseRows = [];
    try {
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
    try {
      const r = await env.cybermeters_db
        .prepare(
          `SELECT DISTINCT question_set_version FROM cyber_essentials_answers
           WHERE workspace_id = ? AND question_set_version IS NOT NULL
           ORDER BY question_set_version`
        )
        .bind(workspaceId).all();
      questionSetVersions = (r?.results || []).map((x) => x.question_set_version);
    } catch { questionSetVersions = []; }

    const snapshot = composeSnapshot({
      snapshotId, workspaceId, domainId, scanId, domain,
      report, cyberEssentials, ceReadiness, caseRows, questionSetVersions,
      supersedesSnapshotId,
      builtAt: new Date().toISOString(),
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
