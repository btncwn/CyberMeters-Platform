// ── Historical comparison module ──
// Compares the current scan's score/findings against the previous scan (D1 column → R2
// fallback) to produce trend/delta signals. Never throws — safe fallback shape. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c).
import { customerSafeFailure } from "../lib/errors.js";
import { mtaStsAdmission } from "./email-analysis.js";
import { resolvePhase5HistoricalCustomerProjection } from "./phase5-evidence.js";
import { TLS_RUNTIME_STATES } from "./tls-evidence.js";

const OBSERVED_DMARC_EVIDENCE_STATES = new Set(["observed_policy", "absent", "malformed"]);
const isDmarcFindingId = (id) => /^email_(?:dmarc_|missing_dmarc$)/.test(String(id || ""));

function currentProducerWasReobserved(finding, currentModules) {
  if (isDmarcFindingId(finding?.id)) {
    return OBSERVED_DMARC_EVIDENCE_STATES.has(
      currentModules?.email_security?.dmarc_state?.canonical_evidence_state,
    );
  }
  if (finding?.id === "email_intel_mta_sts_missing") {
    if (currentModules?.email_security?.applicability?.applicable === false) return false;
    const module = currentModules?.email_security_intelligence;
    if (!module || typeof module !== "object" || module.executed === false ||
        module.incomplete === true || module.skipped === true || module.error != null ||
        module.outcome === "deadline_exceeded") return false;
    const state = mtaStsAdmission(module.mta_sts).state;
    return state === "present" || state === "definitive_absent";
  }
  if (finding?.id === "certificate_expiring_critical" ||
      finding?.id === "certificate_expiring_soon") {
    const module = currentModules?.certificate_intelligence;
    if (currentModules?.ssl?.tls_state !== TLS_RUNTIME_STATES.OBSERVED_PRESENT ||
        !module || typeof module !== "object" || module.executed === false ||
        module.incomplete === true || module.skipped === true || module.error != null ||
        module.outcome === "deadline_exceeded" ||
        module.tls_state !== TLS_RUNTIME_STATES.OBSERVED_PRESENT ||
        module.evidence_source !== "certificate_transparency" ||
        module.live_certificate_verified !== false || module.expiry_evidence !== "usable") {
      return false;
    }
    const expiresAtMs = typeof module.expires_at === "string" && module.expires_at.trim()
      ? Date.parse(module.expires_at)
      : Number.NaN;
    const observedAtMs = Date.parse(
      module.signal_completeness?.signals?.expiry?.provenance?.observed_at || "",
    );
    const days = module.days_until_expiry;
    return Number.isFinite(observedAtMs) && Number.isFinite(expiresAtMs) &&
      expiresAtMs > observedAtMs && Number.isFinite(days) && Number.isInteger(days) && days >= 0 &&
      Math.abs(Math.floor((expiresAtMs - observedAtMs) / 86_400_000) - days) <= 1 &&
      (Number(module.ct_sources?.crt_sh) > 0 || Number(module.ct_sources?.certspotter) > 0);
  }
  const module = currentModules?.[finding?.module];
  if (!module || typeof module !== "object") return false;
  return module.executed !== false
    && module.incomplete !== true
    && module.skipped !== true
    && module.error == null
    && module.outcome !== "deadline_exceeded";
}

function compactFindingRows(findings) {
  const seen = new Set();
  const rows = [];
  for (const finding of Array.isArray(findings) ? findings : []) {
    const id = finding?.id;
    if (id == null || seen.has(id)) continue;
    seen.add(id);
    rows.push({
      id,
      module: finding?.module,
      severity: finding?.severity,
      title: finding?.title,
    });
  }
  return rows;
}

function withPreviousFindings(result, previousFindings) {
  Object.defineProperty(result, "_previous_findings", {
    value: previousFindings,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return result;
}

export function reconcileLateFindings(historicalChanges, currentFindings, currentModules) {
  if (!historicalChanges || typeof historicalChanges !== "object" || Array.isArray(historicalChanges)) {
    return historicalChanges;
  }
  const previousFindings = historicalChanges._previous_findings;
  if (historicalChanges.has_previous !== true || !Array.isArray(previousFindings)) {
    return historicalChanges;
  }

  const currentRows = compactFindingRows(currentFindings);
  const previousRows = compactFindingRows(previousFindings);
  const currentIds = new Set(currentRows.map((finding) => finding.id));
  const previousIds = new Set(previousRows.map((finding) => finding.id));

  const newFindings = currentRows.filter((finding) => !previousIds.has(finding.id));
  const missingPreviousFindings = previousRows.filter((finding) => !currentIds.has(finding.id));
  const resolvedFindings = missingPreviousFindings.filter((finding) =>
    currentProducerWasReobserved(finding, currentModules));
  const notReobservedFindings = missingPreviousFindings.filter((finding) =>
    !currentProducerWasReobserved(finding, currentModules));

  return withPreviousFindings({
    ...historicalChanges,
    new_findings: newFindings,
    resolved_findings: resolvedFindings,
    not_reobserved_findings: notReobservedFindings,
  }, previousRows);
}

export function applyScanComparability(historicalChanges, comparable, scanQualityStatus) {
  if (!historicalChanges || typeof historicalChanges !== "object" || Array.isArray(historicalChanges)) {
    return historicalChanges;
  }

  const {
    comparison_suppressed_reason: _comparisonSuppressedReason,
    comparison_scan_quality: _comparisonScanQuality,
    ...stored
  } = historicalChanges;
  const preserved = Object.fromEntries(
    Object.entries(stored).map(([key, value]) => [key, Array.isArray(value) ? [...value] : value]),
  );

  if (comparable === true) {
    return {
      ...preserved,
      comparable: true,
    };
  }

  const quality = typeof scanQualityStatus === "string" && scanQualityStatus.trim().length > 0
    ? scanQualityStatus.trim()
    : "unknown";
  return {
    ...preserved,
    comparable: false,
    score_change: null,
    new_findings: [],
    resolved_findings: [],
    not_reobserved_findings: Array.isArray(preserved.not_reobserved_findings)
      ? preserved.not_reobserved_findings
      : [],
    comparison_suppressed_reason: "scan_not_comparable",
    comparison_scan_quality: quality,
  };
}

/**
 * Compare the current scan's results against the most recent previous completed
 * scan for the same domain. Requires D1 + R2 access via `env`.
 *
 * Must be called AFTER computeScore so current score and findings are available.
 * Never throws — all errors produce a safe fallback shape.
 */
export async function runHistoricalModule(scanId, domain, currentScore, currentFindings, currentModules, env, workspaceId = null) {
  const source = "previous_scan_comparison";

  // Canonical empty result for any case where comparison is impossible
  const empty = (hasPrev, prevId, prevScore, error) => withPreviousFindings({
    has_previous:       hasPrev,
    previous_scan_id:   prevId,
    previous_score:     prevScore,
    current_score:      currentScore,
    score_change:       prevScore != null ? currentScore - prevScore : null,
    new_subdomains:     [],
    removed_subdomains: [],
    new_findings:       [],
    resolved_findings:  [],
    not_reobserved_findings: [],
    new_takeover_risks: [],
    new_exposed_assets: [],
    source,
    error: error ?? null,
  }, null);

  // Step 1: find the most recent previous completed scan for this domain in D1
  let prevScan;
  try {
    // Trend baseline must be a COMPLETE assessment — a partial/degraded/unknown
    // previous scan is never a comparable baseline (partial-scan honesty).
    //
    // TENANT SCOPE (M5.d fix): the same hostname can be scanned by two
    // independent tenants. An unscoped `WHERE domain = ?` diffed one tenant's
    // scan against another's — cross-tenant score deltas and subdomain diffs
    // that then froze into canonical snapshots. The baseline is now the SAME
    // workspace's previous scan, never a stranger's; legacy scans with no
    // workspace lose baseline continuity, which is honest.
    prevScan = await env.cybermeters_db
      .prepare(
        `SELECT id, score FROM scans
         WHERE domain = ? AND workspace_id = ? AND status = 'completed'
           AND scan_quality = 'complete' AND id != ?
         ORDER BY created_at DESC, id DESC LIMIT 1`
      )
      .bind(domain, workspaceId ?? null, scanId)
      .first();
  } catch (err) {
    return empty(false, null, null, customerSafeFailure("scan/history/d1", err, "Historical comparison unavailable"));
  }

  if (!prevScan) {
    // First completed scan for this domain — nothing to compare against
    return empty(false, null, null, null);
  }

  // Step 2: read previous report from R2
  let prevReport;
  try {
    const obj = await env.cybermeters_reports.get(`reports/${prevScan.id}.json`);
    if (!obj) {
      return empty(true, prevScan.id, prevScan.score ?? null, "Previous report not found in R2");
    }
    prevReport = await obj.json();
  } catch (err) {
    return empty(true, prevScan.id, prevScan.score ?? null, customerSafeFailure("scan/history/r2", err, "Historical comparison unavailable"));
  }

  // Resolve the historical baseline through the same customer evidence contract.
  // A complete-quality legacy row is not comparable when its report does not
  // explicitly prove every required Phase-5 module publishable.
  const previousCustomerAssessment = resolvePhase5HistoricalCustomerProjection({
    score: prevScan.score ?? prevReport.cyber_metrics_score ?? null,
    riskLevel: prevReport.risk_level ?? null,
    scanQuality: prevReport.scan_quality?.status ?? "complete",
    modules: prevReport.modules ?? {},
  });
  const prevScore = previousCustomerAssessment.score;

  // Step 3: Diff subdomains
  const currSubSet = new Set(currentModules.subdomains?.items || []);
  const prevSubSet = new Set(prevReport.modules?.subdomains?.items || []);
  const newSubdomains     = [...currSubSet].filter((h) => !prevSubSet.has(h));
  const removedSubdomains = [...prevSubSet].filter((h) => !currSubSet.has(h));

  // Step 4: Diff findings by ID
  const currFindingIds = new Set((currentFindings || []).map((f) => f.id));
  const prevFindingIds = new Set((prevReport.findings || []).map((f) => f.id));

  const currFindingMap = Object.fromEntries((currentFindings || []).map((f) => [f.id, f]));
  const prevFindingMap = Object.fromEntries((prevReport.findings || []).map((f) => [f.id, f]));

  const newFindings = [...currFindingIds]
    .filter((id) => !prevFindingIds.has(id))
    .map((id) => {
      const f = currFindingMap[id];
      return { id: f.id, module: f.module, severity: f.severity, title: f.title };
    });

  const missingPreviousFindings = [...prevFindingIds]
    .filter((id) => !currFindingIds.has(id));
  const resolvedFindings = missingPreviousFindings
    .filter((id) => currentProducerWasReobserved(prevFindingMap[id], currentModules))
    .map((id) => {
      const f = prevFindingMap[id];
      return { id: f.id, module: f.module, severity: f.severity, title: f.title };
    });
  const notReobservedFindings = missingPreviousFindings
    .filter((id) => !currentProducerWasReobserved(prevFindingMap[id], currentModules))
    .map((id) => {
      const f = prevFindingMap[id];
      return { id: f.id, module: f.module, severity: f.severity, title: f.title };
    });

  // Step 5: Diff takeover risks by host
  const prevTakeoverHosts = new Set(
    (prevReport.modules?.subdomain_takeover?.risks || []).map((r) => r.host)
  );
  const newTakeoverRisks = (currentModules.subdomain_takeover?.risks || [])
    .filter((r) => !prevTakeoverHosts.has(r.host))
    .map(({ host, service, cname, severity }) => ({ host, service, cname, severity }));

  // Step 6: Diff reachable exposed assets by host
  const prevExposedHosts = new Set(
    (prevReport.modules?.asset_exposure?.assets || [])
      .filter((a) => a.reachable)
      .map((a) => a.host)
  );
  const newExposedAssets = (currentModules.asset_exposure?.assets || [])
    .filter((a) => a.reachable && !prevExposedHosts.has(a.host))
    .map(({ host, url, status, title, server, tech }) => ({ host, url, status, title, server, tech }));

  return withPreviousFindings({
    has_previous:       true,
    previous_scan_id:   prevScan.id,
    previous_score:     prevScore,
    current_score:      currentScore,
    score_change:       prevScore != null ? currentScore - prevScore : null,
    new_subdomains:     newSubdomains,
    removed_subdomains: removedSubdomains,
    new_findings:       newFindings,
    resolved_findings:  resolvedFindings,
    not_reobserved_findings: notReobservedFindings,
    new_takeover_risks: newTakeoverRisks,
    new_exposed_assets: newExposedAssets,
    source,
    error: null,
  }, compactFindingRows(prevReport.findings));
}
