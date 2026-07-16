// ── MSP portfolio risk engine (v1) ──
// Aggregates per-workspace risk across an MSP portfolio: risk bands, portfolio executive
// summary, the portfolio risk computation, and D1 snapshot persistence. Extracted verbatim
// from index.js (monolith decomposition, Phase 1c). Only computePortfolioRisk is public.

// ── MSP Portfolio Risk Engine v1 ──────────────────────────────────────────────
//
// Aggregates existing intelligence (BRS, Supply Chain, Vendor Risk) across all
// workspaces accessible to a user to produce a portfolio-level risk view.
//
// Intelligence-layer only. No new scanning, no external APIs.
// Does NOT modify BRS Engine, Vendor Risk Engine, or Supply Chain Engine.
//
// Data sources:
//   workspace_brs_scores          — current BRS per workspace
//   workspace_brs_score_history   — 30-day BRS history (trending)
//   workspace_supply_chain_scores — supply chain concentration + SPOF data
//   workspace_vendors             — shared vendor dependency analysis
//   workspaces                    — workspace names

/**
 * riskBand(score) — maps BRS score (0-100, higher=safer) to a risk label.
 */
function portfolioRiskBand(score) {
  if (score == null) return 'unknown';
  if (score < 25)   return 'critical';
  if (score < 50)   return 'high';
  if (score < 75)   return 'medium';
  return 'low';
}

/**
 * generatePortfolioExecutiveSummary(stats)
 *
 * Produces a plain-English executive summary for MSP owners / Directors.
 * Non-technical language. No jargon.
 */
function generatePortfolioExecutiveSummary(stats) {
  const {
    workspace_count, portfolio_score, critical_workspaces,
    high_risk_workspaces, improving, deteriorating, shared_dependencies,
  } = stats;

  if (workspace_count === 0) {
    return 'No customer environments are currently monitored. Add workspaces to begin portfolio risk tracking.';
  }

  const parts = [];

  // Lead with overall health
  const healthWord =
    portfolio_score >= 75 ? 'healthy' :
    portfolio_score >= 55 ? 'moderate' :
    portfolio_score >= 35 ? 'elevated' : 'serious';
  parts.push(`Your portfolio of ${workspace_count} customer environment${workspace_count !== 1 ? 's' : ''} is showing ${healthWord} overall risk (portfolio score: ${portfolio_score}/100).`);

  // Critical / high risk callout
  if (critical_workspaces > 0) {
    parts.push(`${critical_workspaces} customer environment${critical_workspaces !== 1 ? 's require' : ' requires'} immediate attention due to critically elevated risk levels.`);
  } else if (high_risk_workspaces > 0) {
    parts.push(`${high_risk_workspaces} customer environment${high_risk_workspaces !== 1 ? 's have' : ' has'} high risk levels and should be reviewed this week.`);
  } else {
    parts.push('No customer environments are currently in critical or high risk states.');
  }

  // Trend
  if (deteriorating.length > 0 && improving.length > 0) {
    parts.push(`Risk is increasing for ${deteriorating.length} customer${deteriorating.length !== 1 ? 's' : ''} and improving for ${improving.length} over the past 30 days.`);
  } else if (deteriorating.length > 0) {
    parts.push(`Risk is increasing for ${deteriorating.length} customer environment${deteriorating.length !== 1 ? 's' : ''} over the past 30 days — early intervention is recommended.`);
  } else if (improving.length > 0) {
    parts.push(`${improving.length} customer environment${improving.length !== 1 ? 's are' : ' is'} showing measurable security improvement over the past 30 days.`);
  }

  // Shared vendor concentration
  const topShared = shared_dependencies.slice(0, 2);
  if (topShared.length > 0) {
    const shareDesc = topShared.map(d => `${d.vendor_name} (${d.workspace_count} customers)`).join(' and ');
    parts.push(`Portfolio-wide vendor concentration exists: ${shareDesc} — a disruption to these providers would affect multiple customers simultaneously.`);
  }

  return parts.join(' ');
}

/**
 * computePortfolioRisk(workspaceIds, env)
 *
 * Core portfolio intelligence function. Reads from D1 only — zero network I/O, and
 * now zero writes: the docstring claimed "reads from D1 only" while the body appended
 * a snapshot row on every call.
 *
 * `userId` was the third parameter and is gone. It fed exactly one thing — the
 * per-request `portfolio_risk_snapshots` write keyed by `users.id` — so keeping it
 * would leave a user identity threaded into a function that no longer has any business
 * knowing who is asking. The portfolio's scope is `workspaceIds`, which the caller has
 * already resolved through `getAccessibleWorkspaceIds()`; that is the tenant boundary,
 * and it is the only one this engine needs.
 */
export async function computePortfolioRisk(workspaceIds, env) {
  const db = env.cybermeters_db;
  const now = new Date().toISOString();

  if (workspaceIds.length === 0) {
    return {
      portfolio_score:      null,
      workspace_count:      0,
      high_risk_workspaces: 0,
      critical_workspaces:  0,
      risk_rankings:        [],
      trending:             { improving: [], deteriorating: [] },
      portfolio_alerts:     [],
      shared_dependencies:  [],
      executive_summary:    'No customer environments are currently monitored. Add workspaces to begin portfolio risk tracking.',
      calculated_at:        now,
    };
  }

  const wsIn = workspaceIds.map(() => '?').join(',');

  // ── Batch D1 reads ──────────────────────────────────────────────────────────
  const [
    wsNamesRes, brsRes, brsHistRes, scRes, vendorRes,
  ] = await Promise.allSettled([
    // Workspace names
    db.prepare(`SELECT id, name FROM workspaces WHERE id IN (${wsIn})`)
      .bind(...workspaceIds).all(),

    // Current BRS per workspace
    db.prepare(`SELECT workspace_id, score, risk_band FROM workspace_brs_scores WHERE workspace_id IN (${wsIn})`)
      .bind(...workspaceIds).all(),

    // Earliest BRS snapshot in the last 30 days per workspace (for trending)
    db.prepare(`
      SELECT workspace_id, score, risk_band, calculated_at
      FROM workspace_brs_score_history
      WHERE workspace_id IN (${wsIn})
        AND calculated_at >= datetime('now', '-30 days')
      ORDER BY calculated_at ASC
    `).bind(...workspaceIds).all(),

    // Supply chain scores per workspace
    db.prepare(`
      SELECT workspace_id, supply_chain_score, concentration_level, spof_count, critical_vendor_count
      FROM workspace_supply_chain_scores
      WHERE workspace_id IN (${wsIn})
    `).bind(...workspaceIds).all(),

    // Active vendors across workspaces — grouped to find shared dependencies
    db.prepare(`
      SELECT vendor_name,
             COUNT(DISTINCT workspace_id) AS workspace_count,
             GROUP_CONCAT(DISTINCT workspace_id) AS workspace_ids
      FROM workspace_vendors
      WHERE workspace_id IN (${wsIn})
        AND status = 'active'
        AND source_module = 'vendor_risk'
      GROUP BY vendor_name
      HAVING workspace_count > 1
      ORDER BY workspace_count DESC
      LIMIT 20
    `).bind(...workspaceIds).all(),
  ]);

  // ── Build lookup maps ───────────────────────────────────────────────────────
  const wsNames = {};
  for (const r of (wsNamesRes.status === 'fulfilled' ? (wsNamesRes.value?.results ?? []) : [])) {
    wsNames[r.id] = r.name || r.id;
  }

  const brsMap = {};
  for (const r of (brsRes.status === 'fulfilled' ? (brsRes.value?.results ?? []) : [])) {
    brsMap[r.workspace_id] = { score: r.score, risk_band: r.risk_band };
  }

  // For trending: take the *first* (oldest) record per workspace in last 30 days
  const brsHistMap = {};
  for (const r of (brsHistRes.status === 'fulfilled' ? (brsHistRes.value?.results ?? []) : [])) {
    if (!brsHistMap[r.workspace_id]) {
      brsHistMap[r.workspace_id] = { score: r.score, calculated_at: r.calculated_at };
    }
  }

  const scMap = {};
  for (const r of (scRes.status === 'fulfilled' ? (scRes.value?.results ?? []) : [])) {
    scMap[r.workspace_id] = r;
  }

  const sharedVendors = (vendorRes.status === 'fulfilled' ? (vendorRes.value?.results ?? []) : []).map(r => ({
    vendor_name:     r.vendor_name,
    workspace_count: r.workspace_count,
    pct_of_portfolio: workspaceIds.length > 0
      ? Math.round((r.workspace_count / workspaceIds.length) * 100)
      : 0,
  }));

  // ── Build risk rankings ─────────────────────────────────────────────────────
  const TREND_THRESHOLD = 5; // score change to qualify as improving/deteriorating

  const rankings = workspaceIds.map(wsId => {
    const brs   = brsMap[wsId];
    const sc    = scMap[wsId];
    const hist  = brsHistMap[wsId];
    const score = brs?.score ?? null;
    const prevScore = hist?.score ?? null;
    const delta = (score != null && prevScore != null) ? (score - prevScore) : null;

    return {
      workspace_id:        wsId,
      workspace_name:      wsNames[wsId] ?? wsId,
      brs_score:           score,
      risk_band:           score != null ? portfolioRiskBand(score) : 'unknown',
      supply_chain_score:  sc?.supply_chain_score ?? null,
      concentration_level: sc?.concentration_level ?? null,
      spof_count:          sc?.spof_count ?? 0,
      critical_vendor_count: sc?.critical_vendor_count ?? 0,
      score_delta_30d:     delta,
      trend:               delta == null ? 'no_data' : delta > TREND_THRESHOLD ? 'improving' : delta < -TREND_THRESHOLD ? 'deteriorating' : 'stable',
    };
  });

  // Sort: lowest BRS first (highest risk), nulls last
  rankings.sort((a, b) => {
    if (a.brs_score == null && b.brs_score == null) return 0;
    if (a.brs_score == null) return 1;
    if (b.brs_score == null) return -1;
    return a.brs_score - b.brs_score;
  });

  // ── Portfolio-level aggregates ──────────────────────────────────────────────
  const scored = rankings.filter(r => r.brs_score != null);
  const portfolioScore = scored.length > 0
    ? Math.round(scored.reduce((s, r) => s + r.brs_score, 0) / scored.length)
    : null;

  const criticalWorkspaces  = rankings.filter(r => r.risk_band === 'critical').length;
  const highRiskWorkspaces  = rankings.filter(r => r.risk_band === 'high').length;
  const improving    = rankings.filter(r => r.trend === 'improving').map(r => ({ workspace_id: r.workspace_id, workspace_name: r.workspace_name, brs_score: r.brs_score, delta: r.score_delta_30d }));
  const deteriorating = rankings.filter(r => r.trend === 'deteriorating').map(r => ({ workspace_id: r.workspace_id, workspace_name: r.workspace_name, brs_score: r.brs_score, delta: r.score_delta_30d }));

  // ── Portfolio alerts ────────────────────────────────────────────────────────
  const portfolioAlerts = [];

  for (const r of rankings) {
    // Critical risk alert
    if (r.risk_band === 'critical') {
      portfolioAlerts.push({
        type:            'critical_risk',
        severity:        'critical',
        workspace_id:    r.workspace_id,
        workspace_name:  r.workspace_name,
        message:         `${r.workspace_name} has critical business risk (BRS: ${r.brs_score ?? '—'}/100) — immediate review required`,
      });
    }

    // Large score drop
    if (r.score_delta_30d != null && r.score_delta_30d <= -15) {
      portfolioAlerts.push({
        type:            'score_drop',
        severity:        'high',
        workspace_id:    r.workspace_id,
        workspace_name:  r.workspace_name,
        message:         `${r.workspace_name} risk score dropped ${Math.abs(r.score_delta_30d)} points in 30 days (now ${r.brs_score}/100)`,
      });
    }

    // Concentration risk alert
    if (r.concentration_level === 'critical' || r.concentration_level === 'high') {
      portfolioAlerts.push({
        type:            'concentration_risk',
        severity:        r.concentration_level,
        workspace_id:    r.workspace_id,
        workspace_name:  r.workspace_name,
        message:         `${r.workspace_name} has ${r.concentration_level} vendor concentration risk with ${r.spof_count} single point${r.spof_count !== 1 ? 's' : ''} of failure`,
      });
    }

    // High critical vendor count
    if (r.critical_vendor_count >= 5) {
      portfolioAlerts.push({
        type:            'vendor_risk',
        severity:        'high',
        workspace_id:    r.workspace_id,
        workspace_name:  r.workspace_name,
        message:         `${r.workspace_name} has ${r.critical_vendor_count} critical vendors — elevated third-party risk`,
      });
    }
  }

  // Shared dependency alert (>50% portfolio exposure)
  for (const dep of sharedVendors.filter(d => d.pct_of_portfolio >= 50)) {
    portfolioAlerts.push({
      type:            'shared_dependency',
      severity:        'medium',
      workspace_id:    null,
      workspace_name:  null,
      message:         `${dep.vendor_name} is used by ${dep.pct_of_portfolio}% of customer environments — a disruption would have portfolio-wide impact`,
    });
  }

  // Sort alerts: critical first
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  portfolioAlerts.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  // This function is a pure read, and must stay one. It used to append a
  // `portfolio_risk_snapshots` row here on every call — and its only caller is
  // `GET /api/portfolio/risk`, so opening a page wrote to the database. Removed rather
  // than moved to a cron because nothing reads that table: there is no SELECT against
  // it anywhere, and the 30-day trend returned below comes from
  // `workspace_brs_score_history`. Table and rows are kept; the write is gone.
  // Guarded by `scripts/validate-portfolio-read-purity.js`, which explains the rest.

  // ── Executive summary ───────────────────────────────────────────────────────
  const executiveSummary = generatePortfolioExecutiveSummary({
    workspace_count:      workspaceIds.length,
    portfolio_score:      portfolioScore,
    critical_workspaces:  criticalWorkspaces,
    high_risk_workspaces: highRiskWorkspaces,
    improving,
    deteriorating,
    shared_dependencies:  sharedVendors,
  });

  return {
    portfolio_score:      portfolioScore,
    workspace_count:      workspaceIds.length,
    high_risk_workspaces: highRiskWorkspaces,
    critical_workspaces:  criticalWorkspaces,
    risk_rankings:        rankings,
    trending:             { improving, deteriorating },
    portfolio_alerts:     portfolioAlerts,
    shared_dependencies:  sharedVendors,
    executive_summary:    executiveSummary,
    calculated_at:        now,
  };
}

// `upsertPortfolioRiskSnapshot()` lived here. It is deleted rather than left unused:
// a private writer nobody calls is an invitation to reconnect it, and its docstring
// claimed "for historical trend tracking" for a table no reader has ever queried.
