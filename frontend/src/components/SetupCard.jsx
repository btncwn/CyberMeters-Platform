// SetupCard — the "Get set up" steps that lived on /services, now at the top
// of Overview while setup is incomplete (founder, 17 Oct 2026). It reads the
// same flags the launcher read — a domain exists, an external security check has run, DMARC
// reporting is connected (#673's definition: an inbound report has been received
// AND the DMARC DNS record verifies) — and renders nothing once every step is Done.
// Statuses are never invented: an unknown flag reads as a step still to take.
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'

const STATUS = {
  done:    { label: 'Done',    cls: 'text-brand-900 bg-brand-200 border-brand-200' },
  next:    { label: 'Next',    cls: 'text-brand-700 bg-transparent border-[1.5px] border-brand-700' },
  waiting: { label: 'Waiting', cls: 'text-gray-600 bg-gray-50 border-gray-200' },
}

/** Pure: the three steps from the flags. `null` flags read as not done. */
export function setupSteps({ hasDomain, hasScan, dmarcConnected } = {}) {
  const domain = hasDomain === true
  const scan = hasScan === true
  const dmarc = dmarcConnected === true
  return [
    { key: 'domain', title: 'Add or confirm your primary domain', explanation: 'Tell CyberMeters which domain to protect.', status: domain ? 'done' : 'next', actionLabel: 'Add domain', to: '/ws/domains' },
    { key: 'scan',   title: 'Run your first security check', explanation: 'Check your website, email posture, certificates and visible external posture.', status: scan ? 'done' : domain ? 'next' : 'waiting', actionLabel: 'Go to the scan box', to: '#overview-scan' },
    { key: 'dmarc',  title: 'Connect DMARC reporting', explanation: 'Start receiving reports on who is sending email using your domain.', status: dmarc ? 'done' : scan ? 'next' : 'waiting', actionLabel: dmarc ? 'Review' : 'Set up', to: '/ws/email-protection' },
  ]
}

export function setupComplete(flags) {
  return setupSteps(flags).every((s) => s.status === 'done')
}

/**
 * Read the flags for a workspace: domains from the workspace's domain list, a
 * scan from the summary (a latest score or any report only exists after one),
 * DMARC reporting for the primary domain (else the first): connected only when
 * the ingest endpoint has received a report AND the DMARC DNS record verifies.
 * Either read failing leaves the flag unknown, which reads as not done.
 */
export async function readSetupFlags(wsId) {
  const [s, d] = await Promise.allSettled([api.getWorkspaceSummary(wsId), api.getWorkspaceDomains(wsId)])
  const summary = s.status === 'fulfilled' ? s.value : null
  const domainList = d.status === 'fulfilled' ? (d.value?.domains || []) : null
  const domainCount = domainList ? domainList.length : (typeof summary?.domains === 'number' ? summary.domains : null)
  const hasDomain = domainCount == null ? null : domainCount > 0
  const hasScan = summary == null ? null : (summary.latest_score != null || (summary.reports_count || 0) > 0)
  let dmarcConnected = null
  const name = domainList?.find((item) => item.is_primary)?.domain || domainList?.[0]?.domain
  if (name) {
    const [endpoint, dns] = await Promise.allSettled([
      Promise.resolve().then(() => api.getDmarcIngestEndpoint(wsId, name)),
      Promise.resolve().then(() => api.verifyDmarcDns(wsId, name)),
    ])
    if (endpoint.status === 'fulfilled' && dns.status === 'fulfilled') {
      dmarcConnected = Boolean(endpoint.value?.endpoint?.last_inbound_at && dns.value?.status === 'verified')
    }
  }
  return { hasDomain, hasScan, dmarcConnected }
}

export default function SetupCard({ workspaceId, onFlags }) {
  const [state, setState] = useState({ workspaceId: null, flags: null })
  const onFlagsRef = useRef(onFlags)
  onFlagsRef.current = onFlags

  useEffect(() => {
    if (!workspaceId) return undefined
    let alive = true
    Promise.resolve().then(() => readSetupFlags(workspaceId))
      .then((flags) => { if (alive) { setState({ workspaceId, flags }); onFlagsRef.current?.(workspaceId, flags) } })
      .catch(() => { if (alive) { setState({ workspaceId, flags: {} }); onFlagsRef.current?.(workspaceId, {}) } })
    return () => { alive = false }
  }, [workspaceId])

  if (!workspaceId || state.workspaceId !== workspaceId || !state.flags) return null
  if (setupComplete(state.flags)) return null
  const steps = setupSteps(state.flags)
  const done = steps.filter((s) => s.status === 'done').length

  return (
    <section className="card p-6" aria-labelledby="setup-card-title" data-testid="setup-card">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="setup-card-title" className="section-title">Get set up</h2>
        <p className="text-sm text-gray-600">{done} of {steps.length} done</p>
      </div>
      <p className="text-sm text-gray-600 mt-0.5 mb-2">A few steps to get the most from CyberMeters.</p>
      <ul className="divide-y divide-gray-100">
        {steps.map((s, i) => {
          const st = STATUS[s.status]
          return (
            <li key={s.key} className="flex flex-col sm:flex-row sm:items-center gap-3 py-3" data-testid={`setup-step-${s.key}`} data-status={s.status}>
              <span className="w-7 h-7 rounded-full bg-gray-100 text-gray-700 text-xs font-bold grid place-items-center shrink-0">{i + 1}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-gray-900">{s.title}</p>
                <p className="text-xs text-gray-600 mt-0.5">{s.explanation}</p>
              </div>
              <span className={`inline-flex whitespace-nowrap text-xs font-semibold px-2 py-0.5 rounded-full border ${st.cls}`}>{st.label}</span>
              {/* The scan step points at the Overview's one scan box rather than
                  being a second scan control (design standard §1). */}
              {s.status !== 'done' && (s.to.startsWith('#')
                ? <a href={s.to} className="btn-secondary text-sm shrink-0">{s.actionLabel}</a>
                : <Link to={s.to} className="btn-secondary text-sm shrink-0">{s.actionLabel}</Link>)}
            </li>
          )
        })}
      </ul>
    </section>
  )
}
