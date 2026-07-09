// ── Historical comparison module ──
// Compares the current scan's score/findings against the previous scan (D1 column → R2
// fallback) to produce trend/delta signals. Never throws — safe fallback shape. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c).
import { customerSafeFailure } from "../lib/errors.js";

/**
 * Compare the current scan's results against the most recent previous completed
 * scan for the same domain. Requires D1 + R2 access via `env`.
 *
 * Must be called AFTER computeScore so current score and findings are available.
 * Never throws — all errors produce a safe fallback shape.
 */
export async function runHistoricalModule(scanId, domain, currentScore, currentFindings, currentModules, env) {
  const source = "previous_scan_comparison";

  // Canonical empty result for any case where comparison is impossible
  const empty = (hasPrev, prevId, prevScore, error) => ({
    has_previous:       hasPrev,
    previous_scan_id:   prevId,
    previous_score:     prevScore,
    current_score:      currentScore,
    score_change:       prevScore != null ? currentScore - prevScore : null,
    new_subdomains:     [],
    removed_subdomains: [],
    new_findings:       [],
    resolved_findings:  [],
    new_takeover_risks: [],
    new_exposed_assets: [],
    source,
    error: error ?? null,
  });

  // Step 1: find the most recent previous completed scan for this domain in D1
  let prevScan;
  try {
    prevScan = await env.cybermeters_db
      .prepare(
        `SELECT id, score FROM scans
         WHERE domain = ? AND status = 'completed' AND id != ?
         ORDER BY created_at DESC LIMIT 1`
      )
      .bind(domain, scanId)
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

  // Resolve previous score — prefer D1 column (written on completion) then R2 field
  const prevScore = prevScan.score != null
    ? prevScan.score
    : (prevReport.cyber_metrics_score ?? null);

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

  const resolvedFindings = [...prevFindingIds]
    .filter((id) => !currFindingIds.has(id))
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

  return {
    has_previous:       true,
    previous_scan_id:   prevScan.id,
    previous_score:     prevScore,
    current_score:      currentScore,
    score_change:       prevScore != null ? currentScore - prevScore : null,
    new_subdomains:     newSubdomains,
    removed_subdomains: removedSubdomains,
    new_findings:       newFindings,
    resolved_findings:  resolvedFindings,
    new_takeover_risks: newTakeoverRisks,
    new_exposed_assets: newExposedAssets,
    source,
    error: null,
  };
}
