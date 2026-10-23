import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { MODULES, moduleForDomainKey } from '../../lib/moduleRegistry'
import ScanNowButton from '../ScanNowButton'

// "Your next actions" — one list across all eight areas, in security-priority
// order, each row with ONE action that does the job or opens exactly where it is
// done (founder, 21 Oct 2026: "no hunting"). Every row comes from backend
// values: the area resolver rows (state, highest severity, registry-mapped
// findings), the Shadow IT classification counts and the DMARC reporting
// signal. Nothing is invented: an unmapped finding says "Review findings", and an
// area the scan could not establish asks for a scan rather than reading healthy.

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const EVIDENCE_RANK = { issue_detected: 0, provisional: 1 }
const NEEDS_SCAN = new Set(['not_yet_assessed', 'not_assessed', 'evidence_insufficient', 'unavailable', 'unknown'])
const SEVERITY_WORD = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

const isMtaSts = (id) => /mta_sts/i.test(String(id || ''))
const isDmarcPolicy = (id) => /dmarc_(policy|reporting_only|partial)|weak_dmarc/i.test(String(id || ''))

/** The ordered rows. Pure: tested on its own. */
export function buildNextActions({ domains = [], request = 'ok', unclassified = null, dmarcConnected = null, mcp = null } = {}) {
  if (request !== 'ok' || !Array.isArray(domains)) return []
  const order = new Map(MODULES.map((m, i) => [m.domainKey, i]))
  const rows = []
  const needsScan = []
  for (const entry of domains) {
    const module = moduleForDomainKey(entry?.domain_key)
    if (!module) continue
    const severity = SEVERITY_RANK[entry.highest_severity] != null ? entry.highest_severity : null
    const base = { area: module.title, domainKey: module.domainKey, severity, evidence: entry.state }
    const details = Array.isArray(entry.finding_details) ? entry.finding_details : []
    const mapped = details.filter((d) => d?.status === 'resolved' && d.customer_title)
    if (module.domainKey === 'email_protection') {
      const mta = mapped.find((d) => isMtaSts(d.finding_id))
      if (mta) rows.push({ ...base, key: 'email-mta-sts', title: 'Set up MTA-STS', body: mta.recommended_action, action: { label: 'Set up MTA-STS', to: '/ws/email-protection?tab=settings#mta-sts-setup' } })
      const policy = mapped.find((d) => isDmarcPolicy(d.finding_id))
      if (policy) rows.push({ ...base, key: 'email-dmarc-policy', title: policy.customer_title, body: policy.recommended_action, action: { label: 'Review DMARC policy steps', to: '/ws/email-protection?tab=settings#dmarc-enforcement' } })
      const rest = mapped.filter((d) => d !== mta && d !== policy)
      if (rest.length) rows.push({ ...base, key: 'email-findings', title: rest[0].customer_title, body: rest[0].recommended_action, more: rest.length - 1, action: { label: 'View fix', to: `${module.to}?tab=findings` } })
    } else if (mapped.length) {
      rows.push({ ...base, key: `${module.domainKey}-findings`, title: mapped[0].customer_title, body: mapped[0].recommended_action, more: mapped.length - 1, action: { label: 'View fix', to: `${module.to}?tab=findings` } })
    }
    if (!mapped.length && (entry.finding_count ?? 0) > 0) {
      rows.push({ ...base, key: `${module.domainKey}-unmapped`, title: `Review the findings in ${module.title}`, body: 'No registered remediation is mapped for these findings yet, so none is invented here.', action: { label: 'Review findings', to: `${module.to}?tab=findings` } })
    }
    if (NEEDS_SCAN.has(String(entry.state || '').toLowerCase()) || entry.evidence_freshness === 'stale') needsScan.push(module.title)
  }
  if (Number.isFinite(unclassified) && unclassified > 0) {
    rows.push({ area: 'Shadow IT & Unmanaged Technology', domainKey: 'shadow_it_unmanaged_technology', severity: 'low', evidence: 'provisional', key: 'shadow-it-classify', title: `${unclassified} technolog${unclassified === 1 ? 'y' : 'ies'} not yet classified`, body: 'Approve, reject or record an exception for each, so CyberMeters knows what you expect to see.', action: { label: 'Classify', to: '/ws/shadow-it' } })
  }
  if (dmarcConnected === false) {
    rows.push({ area: 'Email Protection', domainKey: 'email_protection', severity: 'medium', evidence: 'provisional', key: 'email-dmarc-reporting', title: 'Connect DMARC reporting', body: 'Reports show who sends email as your domain, which the next policy step depends on.', action: { label: 'Set up', to: '/ws/email-protection?tab=settings#dmarc-setup' } })
  }
  // The API decides eligibility; an unread answer suggests nothing.
  if (mcp?.eligible === true && mcp.active === 0) {
    rows.push({ area: 'Account', domainKey: null, severity: null, evidence: null, key: 'mcp-connect', title: 'Connect your AI assistant', body: 'Let an AI assistant read your CyberMeters data, read-only. You approve each connection and can remove it at any time.', action: { label: 'Connect', to: '/account/mcp' } })
  }
  rows.sort((a, b) =>
    (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5)
    || (EVIDENCE_RANK[a.evidence] ?? 2) - (EVIDENCE_RANK[b.evidence] ?? 2)
    || (order.get(a.domainKey) ?? 9) - (order.get(b.domainKey) ?? 9))
  if (needsScan.length) {
    rows.push({ key: 'scan', area: needsScan.join(' · '), severity: null, title: 'Run a fresh scan', body: `The latest assessment could not establish ${needsScan.join(', ')}, or its evidence is out of date. Missing evidence is never shown as healthy.`, action: { scan: true } })
  }
  return rows
}

export default function NextActionsList({ workspaceId, domains, request, dmarcConnected, scanDomain = null, showScanRow = true }) {
  const [unclassified, setUnclassified] = useState(null)
  const [mcp, setMcp] = useState(null)
  useEffect(() => {
    setMcp(null)
    let alive = true
    Promise.resolve().then(() => api.getMcpConnections?.())
      .then((res) => {
        if (!alive || typeof res?.eligible !== 'boolean' || !Array.isArray(res.connections)) return
        setMcp({ eligible: res.eligible, active: res.connections.filter((c) => c?.status === 'active').length })
      })
      .catch(() => { if (alive) setMcp(null) })
    return () => { alive = false }
  }, [workspaceId])
  useEffect(() => {
    setUnclassified(null)
    if (!workspaceId) return undefined
    let alive = true
    Promise.resolve().then(() => api.getShadowItInventory(workspaceId, { limit: 1 }))
      .then((res) => { if (alive) setUnclassified(Number.isFinite(res?.counts?.unreviewed) ? res.counts.unreviewed : null) })
      .catch(() => { if (alive) setUnclassified(null) })
    return () => { alive = false }
  }, [workspaceId])

  // On the Overview the scan has its own box at the top; the row would be a
  // second scan control (design standard §1), so the page shows that fact there.
  const rows = buildNextActions({ domains, request, unclassified, dmarcConnected, mcp }).filter((r) => showScanRow || r.key !== 'scan')
  return (
    <section className="card p-5" aria-labelledby="next-actions-heading" data-testid="next-actions">
      <h2 id="next-actions-heading" className="section-title">Your next actions</h2>
      <p className="text-xs text-gray-500 mt-1">Across your whole external posture, most important first. Each button does the job or opens exactly where it is done.</p>
      {request === 'loading' && <p className="text-sm text-gray-500 mt-3">Reading the latest assessment…</p>}
      {request === 'error' && <p className="text-sm text-gray-600 mt-3">The latest assessment could not be read, so no action is suggested. Nothing is assumed in the meantime.</p>}
      {request === 'ok' && rows.length === 0 && (
        <p className="text-sm text-gray-600 mt-3">Nothing to act on from the latest assessment. CyberMeters keeps monitoring and will raise anything new.</p>
      )}
      {rows.length > 0 && (
        <ol className="mt-3 divide-y divide-gray-100">
          {rows.map((row) => (
            <li key={row.key} className="py-3 flex flex-col sm:flex-row sm:items-center gap-3" data-testid="next-action-row">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-gray-500">
                  {row.area}{row.severity ? ` · ${SEVERITY_WORD[row.severity]}` : ''}
                </p>
                <p className="text-sm font-semibold text-gray-900 mt-0.5">
                  {row.title}{row.more > 0 ? ` and ${row.more} more` : ''}
                </p>
                {row.body && <p className="text-xs text-gray-600 mt-0.5 leading-relaxed">{row.body}</p>}
              </div>
              <div className="shrink-0">
                {row.action.scan
                  ? <ScanNowButton workspaceId={workspaceId} domain={scanDomain} label="Run a fresh scan" />
                  // Secondary: the Overview's one primary is its scan control (one primary per screen).
                  : <Link to={row.action.to} className="btn-secondary text-sm" aria-label={row.action.label === row.title ? row.title : `${row.action.label}: ${row.title}`}>{row.action.label}</Link>}
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}
