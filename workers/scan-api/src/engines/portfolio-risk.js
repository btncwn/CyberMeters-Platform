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
  if (!Number.isFinite(score)) return 'unknown';
  if (score < 25)   return 'critical';
  if (score < 50)   return 'high';
  if (score < 75)   return 'medium';
  return 'low';
}

/**
 * Portfolio score states — the ONE contract for "is this score sayable?".
 *
 * `portfolio_score` is the mean BRS of the customer environments that HAVE a BRS.
 * That single number cannot answer the only question that matters when evidence is
 * thin: how much of the portfolio is it actually speaking for? Consumers were left to
 * infer that from `null`, and the executive summary inferred it wrong — a null score
 * failed `>= 75`, `>= 55` and `>= 35` alike and fell through to "serious", so a
 * portfolio with no assessments at all was reported as *"showing serious overall risk
 * (portfolio score: null/100)"*. Absent evidence became a verdict, and a fabricated
 * failure is exactly as dishonest as a fabricated pass.
 *
 * The states are additive fields, not a replacement: `portfolio_score` keeps its
 * existing meaning and value for every consumer that already reads it.
 *
 *   no_workspaces         — nothing is monitored. Not healthy, not at risk.
 *   evidence_insufficient — environments are monitored, none has a completed
 *                           assessment yet. There is no score to say.
 *   partial               — some environments are assessed, some are not. The score is
 *                           real but speaks only for the assessed ones. Disclosed,
 *                           because a 90 drawn from 1 of 5 customers is not a 90.
 *   available             — every monitored environment is assessed.
 */
export const PORTFOLIO_SCORE_STATES = Object.freeze({
  NO_WORKSPACES:         'no_workspaces',
  UNAVAILABLE:           'unavailable',
  EVIDENCE_INSUFFICIENT: 'evidence_insufficient',
  PARTIAL:               'partial',
  AVAILABLE:             'available',
});

/**
 * resolvePortfolioScoreState({ workspaceCount, scoredCount, score })
 *
 * The single source of truth for portfolio score sayability. The API returns its
 * output verbatim so the frontend renders a decision it did not make — no second
 * ladder, no `null` interpreted twice, no way for the two to disagree.
 *
 * Returns { state, reason, basis: { scored_workspaces, total_workspaces } }.
 * `reason` is customer-safe prose: every non-available state must say WHY, or an
 * unknown is just a shrug.
 */
export function resolvePortfolioScoreState({ workspaceCount, scoredCount, score }) {
  const total  = Number.isFinite(workspaceCount) ? workspaceCount : 0;
  const scored = Number.isFinite(scoredCount) ? scoredCount : 0;
  const basis  = { scored_workspaces: scored, total_workspaces: total };
  const plural = (n) => (n === 1 ? 'environment' : 'environments');

  if (total === 0) {
    return {
      state:  PORTFOLIO_SCORE_STATES.NO_WORKSPACES,
      reason: 'No customer environments are being monitored yet.',
      basis,
    };
  }
  // Guards the score itself, not just the count: a non-finite score with a positive
  // scored count would otherwise be published as a number. Belt and braces, because
  // the cost of being wrong here is a fabricated verdict.
  if (scored === 0 || !Number.isFinite(score)) {
    return {
      state:  PORTFOLIO_SCORE_STATES.EVIDENCE_INSUFFICIENT,
      reason: `No completed business risk assessment exists for any of the ${total} monitored customer ${plural(total)} yet, so a portfolio score cannot be calculated.`,
      basis,
    };
  }
  if (scored < total) {
    const missing = total - scored;
    return {
      state:  PORTFOLIO_SCORE_STATES.PARTIAL,
      reason: `Based on ${scored} of ${total} monitored customer ${plural(total)}; ${missing} ${plural(missing)} ${missing === 1 ? 'has' : 'have'} no completed assessment and ${missing === 1 ? 'is' : 'are'} not represented in this score.`,
      basis,
    };
  }
  return {
    state:  PORTFOLIO_SCORE_STATES.AVAILABLE,
    reason: `Based on all ${total} monitored customer ${plural(total)}.`,
    basis,
  };
}

/**
 * portfolioScoreBand(score) — the narrative word for a portfolio score.
 *
 * Extracted from the executive summary, where it was an inline ternary chain that
 * `null` silently fell through: `null >= 75`, `null >= 55` and `null >= 35` are all
 * false, so no-evidence produced 'serious'. Returning **null** for anything
 * non-finite is the whole point — there is no word for a score that does not exist,
 * and inventing one is how absent evidence became a verdict.
 *
 * The API now publishes this so the frontend renders the band rather than deriving
 * it from the number a second time. `PortfolioRiskPage` carried a byte-identical
 * 75/55/35 ladder, which is duplicated backend logic that had already drifted from
 * `portfolioRiskBand`'s 25/50/75 partition.
 *
 * Boundaries are unchanged from the code this replaces: 75 / 55 / 35. They are
 * deliberately NOT reconciled with `portfolioRiskBand` here — that would silently
 * restate real customers' scores, which is a product decision, not an honesty fix.
 */
function portfolioScoreBand(score) {
  if (!Number.isFinite(score)) return null;
  if (score >= 75) return 'healthy';
  if (score >= 55) return 'moderate';
  if (score >= 35) return 'elevated';
  return 'serious';
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
    score_state, score_reason,
  } = stats;

  if (workspace_count === 0) {
    return 'No customer environments are currently monitored. Add workspaces to begin portfolio risk tracking.';
  }

  const parts = [];

  // Lead with overall health — but only when there IS a score to lead with.
  const healthWord = portfolioScoreBand(portfolio_score);
  if (healthWord === null) {
    // No score. Say so, say why, and stop — do not reach for the risk vocabulary at
    // all. This sentence replaces "showing serious overall risk (portfolio score:
    // null/100)", which told an MSP with no assessments yet that its customers were
    // in serious danger. The rest of the summary still runs: findings-based callouts
    // below are real evidence and do not depend on a score existing.
    parts.push(`A portfolio risk score is not available for your ${workspace_count} customer environment${workspace_count !== 1 ? 's' : ''} yet. ${score_reason}`);
  } else {
    parts.push(`Your portfolio of ${workspace_count} customer environment${workspace_count !== 1 ? 's' : ''} is showing ${healthWord} overall risk (portfolio score: ${portfolio_score}/100).`);
    // A score drawn from 1 of 5 customers is not a portfolio score, and presenting it
    // as one lets missing evidence flatter the verdict. Disclose the basis inline —
    // the sentence above is the one that gets read.
    if (score_state === PORTFOLIO_SCORE_STATES.PARTIAL) {
      parts.push(score_reason);
    }
  }

  // Critical / high risk callout.
  //
  // The `else` here is the quiet one. `critical_workspaces` and `high_risk_workspaces`
  // count rows whose band is 'critical' or 'high' — and an UNASSESSED environment's band
  // is 'unknown', so it counts toward neither. With no assessments at all both counters
  // are zero, and the old unconditional else then said "No customer environments are
  // currently in critical or high risk states." to an MSP we knew literally nothing
  // about. Every word of it was technically true and the impression was false: silence
  // read as an all-clear. Absence of a finding is not a finding of absence.
  //
  // So the reassurance is scoped to what was actually assessed, and withheld entirely
  // when nothing was.
  if (critical_workspaces > 0) {
    parts.push(`${critical_workspaces} customer environment${critical_workspaces !== 1 ? 's require' : ' requires'} immediate attention due to critically elevated risk levels.`);
  } else if (high_risk_workspaces > 0) {
    parts.push(`${high_risk_workspaces} customer environment${high_risk_workspaces !== 1 ? 's have' : ' has'} high risk levels and should be reviewed this week.`);
  } else if (score_state === PORTFOLIO_SCORE_STATES.AVAILABLE) {
    parts.push('No customer environments are currently in critical or high risk states.');
  } else if (score_state === PORTFOLIO_SCORE_STATES.PARTIAL) {
    // A clean bill of health for the assessed subset only — never for the portfolio.
    parts.push('None of the assessed customer environments are currently in critical or high risk states; the unassessed environments above are not covered by this statement.');
  }
  // no_workspaces / evidence_insufficient: say nothing. There is nothing to say.

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
    const empty = resolvePortfolioScoreState({ workspaceCount: 0, scoredCount: 0, score: null });
    return {
      portfolio_score:        null,
      portfolio_score_band:   null,
      portfolio_score_state:  empty.state,
      portfolio_score_reason: empty.reason,
      portfolio_score_basis:  empty.basis,
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

  if (brsRes.status === 'rejected') {
    return {
      portfolio_score:        null,
      portfolio_score_band:   null,
      portfolio_score_state:  PORTFOLIO_SCORE_STATES.UNAVAILABLE,
      portfolio_score_reason: 'Portfolio score is temporarily unavailable because the current Business Risk records could not be read.',
      portfolio_score_basis:  { scored_workspaces: 0, total_workspaces: workspaceIds.length },
      workspace_count:      workspaceIds.length,
      high_risk_workspaces: 0,
      critical_workspaces:  0,
      risk_rankings:        [],
      trending:             { improving: [], deteriorating: [] },
      portfolio_alerts:     [],
      shared_dependencies:  [],
      executive_summary:    'Portfolio risk is temporarily unavailable because the current Business Risk records could not be read. Try again later.',
      calculated_at:        now,
    };
  }

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
      // M5.e: a workspace with NO supply-chain assessment row is unassessed,
      // not clean — null, never a zero that ranks as healthy.
      spof_count:          sc ? (sc.spof_count ?? 0) : null,
      critical_vendor_count: sc ? (sc.critical_vendor_count ?? 0) : null,
      supply_chain_state:  sc ? 'assessed' : 'not_assessed',
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

  // ── Score sayability ────────────────────────────────────────────────────────
  // Resolved once, published, and reused by the summary — so the prose, the API
  // fields and the frontend badge cannot disagree about whether a score exists.
  const scoreState = resolvePortfolioScoreState({
    workspaceCount: workspaceIds.length,
    scoredCount:    scored.length,
    score:          portfolioScore,
  });

  // ── Executive summary ───────────────────────────────────────────────────────
  const executiveSummary = generatePortfolioExecutiveSummary({
    workspace_count:      workspaceIds.length,
    portfolio_score:      portfolioScore,
    critical_workspaces:  criticalWorkspaces,
    high_risk_workspaces: highRiskWorkspaces,
    improving,
    deteriorating,
    shared_dependencies:  sharedVendors,
    score_state:          scoreState.state,
    score_reason:         scoreState.reason,
  });

  return {
    portfolio_score:        portfolioScore,
    portfolio_score_band:   portfolioScoreBand(portfolioScore),
    portfolio_score_state:  scoreState.state,
    portfolio_score_reason: scoreState.reason,
    portfolio_score_basis:  scoreState.basis,
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
