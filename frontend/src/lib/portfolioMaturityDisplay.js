// Presentation for /api/portfolio/maturity and /api/portfolio/executive-summary.
// The backend decides every stage (worst-case fold) and writes the summary
// sentence; this maps codes to words and lists facts. Nothing is derived.
import { STAGE_META } from './maturityDisplay'

export const PORTFOLIO_MATURITY_STATE_TEXT = Object.freeze({
  no_workspaces: 'No customers in your portfolio yet.',
  no_evidence: 'No customer has a completed assessment yet, so no domain is established.',
  unavailable: 'Portfolio maturity is temporarily unavailable.',
})

export function portfolioMaturityRows(domains) {
  return (Array.isArray(domains) ? domains : []).map((d) => {
    const meta = STAGE_META[d.portfolio_stage] || STAGE_META.not_established
    const total = Number(d.workspaces_total) || 0
    const est = Number(d.workspaces_established) || 0
    const notes = []
    if (d.unmanaged_count > 0) notes.push(`${d.unmanaged_count} with an issue that has no owner`)
    if (d.regressed_count > 0) notes.push(`${d.regressed_count} where an issue came back`)
    if (d.attested_count > 0) notes.push(`${d.attested_count} attested by the customer — not externally verified`)
    return {
      key: d.domain_key,
      name: d.display_name || d.domain_key,
      label: meta.label,
      tone: meta.tone,
      coverage: total ? `${est} of ${total} customer${total === 1 ? '' : 's'} assessed` : 'No customers',
      notes,
    }
  })
}

/** Why a customer is on the attention list — facts from the backend row. */
export function attentionReasons(row) {
  const out = []
  if (row?.critical_findings > 0) out.push(`${row.critical_findings} critical finding${row.critical_findings === 1 ? '' : 's'}`)
  const high = row?.customer_changes_7d_high
  if (high > 0) out.push(`${high} new high-severity change${high === 1 ? '' : 's'} this week`)
  if (Number.isFinite(row?.latest_score) && row.latest_score < 60) out.push(`score ${row.latest_score}/100`)
  return out
}
