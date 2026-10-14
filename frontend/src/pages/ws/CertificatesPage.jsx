import { useState, useEffect, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Lock, AlertTriangle, XCircle, ShieldCheck, Clock,
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'
import StatCard from '../../components/StatCard'
import DataTable from '../../components/DataTable'
import CertificateAssuranceSummary from '../../components/CertificateAssuranceSummary'

function expiryStatus(daysLeft) {
  if (daysLeft == null) return { label: 'Unknown', cls: 'text-gray-400' }
  if (daysLeft < 0)  return { label: 'Expired',        cls: 'text-red-600 font-semibold' }
  if (daysLeft < 14) return { label: `${daysLeft}d left`, cls: 'text-red-500 font-semibold' }
  if (daysLeft < 30) return { label: `${daysLeft}d left`, cls: 'text-amber-500 font-semibold' }
  return { label: `${daysLeft}d left`, cls: 'text-brand-600' }
}

function trustPathState(row) {
  const assurance = row.certificate_assurance || {}
  const signals = assurance.signals || {}
  if (signals.expiry?.state === 'observed' && row.days_until_expiry < 0) {
    return { label: 'Expired certificate observed', tone: 'bad' }
  }
  // historical: records stored before certificate logs were retired can carry
  // only a log record and no live certificate.
  if (assurance.summary?.ct_only === true) {
    return { label: 'Historical log record only', tone: 'info' }
  }
  // A captured certificate that failed a check says which, from the backend's
  // check outcome; "observed" alone never stands in for a pass.
  if (signals.hostname_match?.check?.outcome === 'failed') return { label: 'Name does not match', tone: 'bad' }
  if (signals.trust_store_validation?.check?.outcome === 'failed') return { label: 'Not trusted', tone: 'bad' }
  if (signals.leaf?.state === 'observed') {
    return { label: 'Live TLS certificate observed', tone: 'info' }
  }
  if (signals.active_service?.state === 'observed') {
    return { label: 'HTTPS response observed', tone: 'info' }
  }
  if (['unknown', 'unavailable', 'incomplete', 'not_observed'].includes(signals.leaf?.state)) {
    return {
      label: signals.leaf.state === 'not_observed'
        ? 'Live TLS not observed'
        : `Live TLS ${signals.leaf.state}`,
      tone: signals.leaf.state === 'incomplete' ? 'warn' : 'na',
    }
  }
  const path = row.trust_path || {}
  if (path.https_reachable === false) return { label: 'HTTPS not reachable', tone: 'bad' }
  if (path.expiry_ok === false) return { label: 'Expiry problem', tone: 'bad' }
  return { label: 'Live TLS not recorded', tone: 'na' }
}

function HttpsChip({ row }) {
  const s = trustPathState(row)
  const cls = s.tone === 'ok' ? 'bg-brand-50 text-brand-700 border-brand-100'
    : s.tone === 'bad' ? 'bg-red-50 text-red-600 border-red-100'
    : s.tone === 'info' ? 'bg-blue-50 text-blue-700 border-blue-100'
    : s.tone === 'warn' ? 'bg-amber-50 text-amber-700 border-amber-100'
    : 'bg-gray-50 text-gray-500 border-gray-200'
  return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[13px] font-semibold border ${cls}`}>{s.label}</span>
}

const COLUMNS = [
  { key: 'domain', label: 'Domain / Hostname', render: v => <span className="font-medium text-sm text-gray-900 mono">{v || '—'}</span> },
  { key: 'issuer', label: 'Issuer', render: v => <span className="text-xs text-gray-500">{v || '—'}</span> },
  { key: 'expires_at', label: 'Expires', render: v => <span className="text-xs text-gray-500">{v ? new Date(v).toLocaleDateString() : '—'}</span> },
  {
    key: 'days_until_expiry', label: 'Days remaining',
    render: v => { const { label, cls } = expiryStatus(v); return <span className={`text-xs ${cls}`}>{label}</span> },
  },
  { key: 'https', label: 'TLS evidence', render: (v, row) => <HttpsChip row={row} /> },
  { key: 'certificate_risk_level', label: 'Risk', render: v => <RiskBadge level={v} /> },
  {
    key: 'last_scan', label: 'Last scan',
    render: (v, row) => {
      const t = row.last_scan_at || row.last_seen || row.scanned_at || null
      return <span className="text-xs text-gray-400">{t ? new Date(t).toLocaleDateString() : '—'}</span>
    },
  },
]

// ── Expiry risk buckets ───────────────────────────────────────────────────────
const BUCKETS = [
  { key: 'expired', label: 'Expired',  tone: 'bad' },
  { key: 'd0_7',    label: '0–7 days', tone: 'bad' },
  { key: 'd8_30',   label: '8–30 days', tone: 'warn' },
  { key: 'd31_90',  label: '31–90 days', tone: 'warn' },
  { key: 'healthy', label: '>90 days', tone: 'info' },
  { key: 'unknown', label: 'Unknown',  tone: 'na' },
]
function bucketCounts(certs) {
  const b = { expired: 0, d0_7: 0, d8_30: 0, d31_90: 0, healthy: 0, unknown: 0 }
  for (const c of certs) {
    const d = c.days_until_expiry
    if (d == null) b.unknown++
    else if (d < 0) b.expired++
    else if (d <= 7) b.d0_7++
    else if (d <= 30) b.d8_30++
    else if (d <= 90) b.d31_90++
    else b.healthy++
  }
  return b
}

function ActionCard({ severity, title, body }) {
  const cfg = {
    critical: { bar: 'bg-red-500',   chip: 'bg-red-50 text-red-700 border-red-100' },
    high:     { bar: 'bg-amber-500', chip: 'bg-amber-50 text-amber-700 border-amber-100' },
    medium:   { bar: 'bg-amber-400', chip: 'bg-amber-50 text-amber-700 border-amber-100' },
  }[severity] || { bar: 'bg-gray-300', chip: 'bg-gray-50 text-gray-600 border-gray-200' }
  return (
    <div className="card p-4 flex gap-3">
      <div className={`w-1 rounded-full ${cfg.bar} flex-shrink-0`} />
      <div className="flex-1">
        <div className="flex items-center justify-between gap-2 mb-1">
          <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
          <span className={`text-[13px] uppercase font-bold px-2 py-0.5 rounded-full border ${cfg.chip}`}>{severity}</span>
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">{body}</p>
      </div>
    </div>
  )
}

function TrustTile({ label, status, tone, hint, to }) {
  const cls = tone === 'ok' ? 'text-brand-600' : tone === 'bad' ? 'text-red-500' : tone === 'warn' ? 'text-amber-500' : tone === 'info' ? 'text-blue-600' : 'text-gray-400'
  const inner = (
    <div className="card p-4 h-full hover:shadow-card-md transition-shadow">
      <div className="mb-1.5">
        <span className="text-sm font-semibold text-gray-800">{label}</span>
      </div>
      <p className={`text-sm font-medium ${cls}`}>{status}</p>
      {hint && <p className="text-[13px] text-gray-400 mt-1 leading-relaxed">{hint}</p>}
    </div>
  )
  return to ? <Link to={to} className="block">{inner}</Link> : inner
}

function FindingPill({ finding }) {
  const cls = finding.severity === 'critical' ? 'bg-red-100 text-red-800 border-red-200'
    : finding.severity === 'high' ? 'bg-red-50 text-red-700 border-red-100'
    : finding.severity === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-100'
    : finding.severity === 'low' ? 'bg-blue-50 text-blue-700 border-blue-100'
    : 'bg-gray-50 text-gray-600 border-gray-200'
  return (
    <div className="rounded-lg border border-gray-100 bg-white p-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-gray-900">{finding.title || finding.type}</p>
          <p className="text-xs text-gray-500 mt-1">{finding.reasons?.[0] || 'Certificate evidence needs review.'}</p>
        </div>
        <span className={`text-[13px] uppercase font-bold px-2 py-0.5 rounded-full border ${cls}`}>{finding.severity || 'info'}</span>
      </div>
    </div>
  )
}

const SERVICE_LABELS = { https: 'HTTPS', smtp: 'SMTP with STARTTLS', smtps: 'SMTP over TLS', imap: 'IMAP with STARTTLS', imaps: 'IMAP over TLS', pop3: 'POP3 with STARTTLS', pop3s: 'POP3 over TLS' }
const EMPTY_SERVICE = { domain_id: '', hostname: '', network_target_id: '', protocol: 'https:443' }

// One workspace permission for the bounded special controls; service scope is
// separately declared. Neither action starts a scan or authorizes a shared IP.
export function TlsAuthorizationSettings({ workspaceId }) {
  const [data, setData] = useState(null)
  const [desired, setDesired] = useState(false)
  const [service, setService] = useState(EMPTY_SERVICE)
  const [attested, setAttested] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const scope = useRef(workspaceId)
  scope.current = workspaceId
  const latest = useRef(0)
  const load = useCallback(async () => {
    const ticket = ++latest.current
    try {
      const result = await api.getTlsAuthorization(workspaceId)
      if (ticket !== latest.current || scope.current !== workspaceId) return
      setData({ ...result, workspaceId }); setDesired(result.authorization?.enabled === true); setError(null)
    } catch {
      if (ticket === latest.current && scope.current === workspaceId) setError('TLS permissions could not be loaded. Try again.')
    }
  }, [workspaceId])
  useEffect(() => {
    setData(null); setService(EMPTY_SERVICE); setAttested(false); setNotice(null); setError(null); setBusy(false)
    load()
    return () => { latest.current++ }
  }, [load])
  const current = data?.workspaceId === workspaceId ? data : null
  const canManage = current?.capabilities?.can_manage === true
  async function mutate(operation, message) {
    const requestedWorkspace = workspaceId
    setBusy(true); setError(null); setNotice(null)
    try {
      await operation()
      if (scope.current !== requestedWorkspace) return
      setNotice(message); setService(EMPTY_SERVICE); setAttested(false)
      await load()
    } catch (failure) {
      if (scope.current === requestedWorkspace) setError(failure?.message || 'The permission could not be saved. Try again.')
    } finally { if (scope.current === requestedWorkspace) setBusy(false) }
  }
  function savePermission(event) {
    event.preventDefault()
    if (!canManage || !current || busy) return
    mutate(() => api.saveTlsAuthorization(workspaceId, { enabled: desired, ...(desired ? { authorization_confirmed: true, consent_version: current.consent_version } : {}) }), desired ? 'Permission saved for this workspace. No scan was started.' : 'Special TLS permission revoked. Running special checks must stop; recorded evidence remains available.')
  }
  function addService(event) {
    event.preventDefault()
    if (!canManage || !attested || busy) return
    const [application_protocol, rawPort] = service.protocol.split(':')
    const hostname = service.hostname.trim().toLowerCase()
    mutate(() => api.authorizeTlsService(workspaceId, { domain_id: service.domain_id, hostname, sni: hostname, port: Number(rawPort), application_protocol, network_target_id: service.network_target_id, authorization_confirmed: true }), 'Service scope saved. No scan was started.')
  }
  const services = current?.services || []
  if (current && current.capabilities?.assessment_available !== true) return null
  return <section id="tls-permissions" className="card p-5 mb-6 space-y-4" aria-label="TLS scan permissions">
    <div><h2 className="text-lg font-semibold text-gray-900">TLS scan permissions</h2><p className="text-sm text-gray-600 mt-1">Normal scans assess protocols, ciphers and certificates on authorized endpoints. Additional services need their own scope below.</p></div>
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
    {notice && <p role="status" className="text-sm text-gray-700">{notice}</p>}
    {!current ? <button type="button" className="btn-secondary text-sm" onClick={load}>Reload TLS permissions</button> : <>
      {current.capabilities?.special_controls_available === true && <form onSubmit={savePermission} className="space-y-2">
        <label className="flex items-start gap-2 text-sm text-gray-800"><input type="checkbox" className="mt-1" checked={desired} onChange={event => setDesired(event.target.checked)} disabled={!canManage || busy} /><span>Allow bounded checks for known TLS vulnerabilities on this workspace’s authorized targets.</span></label>
        <p className="text-xs text-gray-500">This permission is reserved for separately validated, bounded Heartbleed, ROBOT and CCS checks. No memory harvesting, data decryption or load testing. It adds no domains, IP addresses or ports to your scope.</p>
        <p className="text-xs text-gray-500">{current.authorization?.enabled ? 'Special checks are permitted.' : 'Special checks are not permitted.'} Saving this setting does not start a scan.</p>
        {canManage ? <button className="btn-secondary text-sm" disabled={busy || desired === (current.authorization?.enabled === true)}>{busy ? 'Saving…' : 'Save TLS permission'}</button> : <p className="text-xs text-gray-500">A workspace admin can change these permissions.</p>}
      </form>}
      <details className="border-t border-gray-100 pt-3">
        <summary className="cursor-pointer text-sm font-semibold">Additional TLS services ({services.length})</summary>
        <p className="text-sm text-gray-600 mt-3">A verified domain does not authorize other ports or other customers on a shared IP. Add each service explicitly using a verified domain and an IP target you are authorized to test. Before a check, its current DNS address must match that target.</p>
        {services.length > 0 && <ul className="divide-y divide-gray-100 mt-3" aria-label="Authorized TLS services">{services.map(row => <li key={row.id} className="py-2 flex flex-wrap justify-between gap-2 text-sm"><span>{row.hostname}:{row.port} · {SERVICE_LABELS[row.application_protocol] || row.application_protocol}<span className="block text-xs text-gray-500">SNI: {row.sni}</span></span>{canManage && <button className="btn-secondary text-xs" type="button" disabled={busy} onClick={() => mutate(() => api.revokeTlsService(workspaceId, row.id), 'Service permission revoked. Recorded evidence remains available.')} aria-label={`Revoke ${row.hostname}:${row.port}`}>Revoke</button>}</li>)}</ul>}
        {canManage && <form onSubmit={addService} className="mt-4 grid gap-3 sm:grid-cols-2" aria-label="Authorize a TLS service">
          <label className="text-sm">Verified domain<select className="input mt-1" aria-label="Verified domain" required value={service.domain_id} onChange={event => setService(previous => ({ ...previous, domain_id: event.target.value, hostname: current.verified_domains?.find(row => row.domain_id === event.target.value)?.domain || '' }))} disabled={busy}><option value="">Choose domain</option>{(current.verified_domains || []).map(row => <option key={row.domain_id} value={row.domain_id}>{row.domain}</option>)}</select></label>
          <label className="text-sm">Service hostname<input className="input mt-1" required maxLength={253} value={service.hostname} onChange={event => setService(previous => ({ ...previous, hostname: event.target.value }))} disabled={busy} /><span className="text-xs text-gray-500">This same name is sent as SNI.</span></label>
          <label className="text-sm">Service and port<select className="input mt-1" value={service.protocol} onChange={event => setService(previous => ({ ...previous, protocol: event.target.value }))} disabled={busy}>{Object.entries(current.allowed_services || {}).flatMap(([application, ports]) => ports.map(port => <option key={`${application}:${port}`} value={`${application}:${port}`}>{SERVICE_LABELS[application] || application} · {port}</option>))}</select></label>
          <label className="text-sm">Authorized IP target<select className="input mt-1" aria-label="Authorized IP target" required value={service.network_target_id} onChange={event => setService(previous => ({ ...previous, network_target_id: event.target.value }))} disabled={busy}><option value="">Choose target</option>{(current.network_targets || []).map(row => <option key={row.id} value={row.id}>{row.target}</option>)}</select></label>
          <p className="text-xs text-gray-500 sm:col-span-2">Manage public IP targets under <Link to="/assets" className="underline">Network assets</Link>. Certificate names and shared hosting do not establish permission.</p>
          <label className="flex items-start gap-2 text-sm sm:col-span-2"><input type="checkbox" className="mt-1" checked={attested} onChange={event => setAttested(event.target.checked)} disabled={busy} /><span>I am authorized to test this hostname and selected service on this IP target.</span></label>
          <button className="btn-secondary text-sm justify-center" disabled={busy || !attested || !service.domain_id || !service.hostname.trim() || !service.network_target_id}>Authorize service</button>
        </form>}
      </details>
    </>}
  </section>
}

export default function CertificatesPage() {
  const { wsId, wsName } = useWorkspace()
  const [certs, setCerts]     = useState([])
  const [timeline, setTimeline] = useState([])
  const [certTimeline, setCertTimeline] = useState([])
  const [issuerHistory, setIssuerHistory] = useState([])
  const [churn, setChurn] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const issuesRef = useRef(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const [c, t] = await Promise.allSettled([
        api.getWorkspaceCertificates(wsId),
        api.getWorkspaceCertificatesTimeline(wsId),
      ])
      setCerts(c.status === 'fulfilled' ? (c.value.certificates || []) : [])
      if (t.status === 'fulfilled') {
        setTimeline(t.value.timeline || [])
        setCertTimeline(t.value.certificate_timeline || [])
        setIssuerHistory(t.value.issuer_history || [])
        setChurn(t.value.churn || null)
      } else {
        setTimeline([]); setCertTimeline([]); setIssuerHistory([]); setChurn(null)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const hasData      = certs.length > 0
  const expiringSoon = certs.filter(c => c.days_until_expiry != null && c.days_until_expiry < 30 && c.days_until_expiry >= 0).length
  const expired      = certs.filter(c => c.days_until_expiry != null && c.days_until_expiry < 0).length
  // Certificates whose name match or trust-store check failed (backend-owned outcomes).
  const checkFailed = certs.filter(c =>
    ['hostname_match', 'trust_store_validation'].some(key => c.certificate_assurance?.signals?.[key]?.check?.outcome === 'failed')
  ).length
  const httpsIssues  = certs.filter(c => c.trust_path?.https_reachable === false || c.trust_path?.expiry_ok === false).length
  const needsReview  = certs.filter(c => ['high', 'critical'].includes(c.certificate_risk_level)).length
  const l2Findings   = certs.flatMap(c => (c.findings || []).filter(f => f.type !== 'unknown').map(f => ({ ...f, domain: c.domain })))
  const anomalies    = certs.flatMap(c => (c.anomalies || []).map(a => ({ ...a, domain: c.domain })))
  const buckets      = bucketCounts(certs)
  const chartData    = timeline.slice().reverse().map(day => ({ day: day.day, events: day.events?.length || 0 }))

  // Certificate-derived actions only — never invented.
  const actions = []
  if (expired > 0)      actions.push({ severity: 'critical', title: 'Certificate expired', body: `${expired} certificate${expired === 1 ? '' : 's'} have expired. Renew now to restore certificate validity for affected hosts.` })
  if (expiringSoon > 0) actions.push({ severity: 'high', title: 'Certificate expiring soon', body: `${expiringSoon} certificate${expiringSoon === 1 ? '' : 's'} expire within 30 days. Schedule renewal to avoid an outage.` })
  if (httpsIssues > 0)  actions.push({ severity: 'high', title: 'HTTPS or expiry issue', body: `${httpsIssues} certificate record${httpsIssues === 1 ? '' : 's'} show HTTPS reachability or expiry evidence that needs review.` })
  if (anomalies.length > 0) actions.push({ severity: 'medium', title: 'Certificate change needs review', body: `${anomalies.length} certificate change${anomalies.length === 1 ? ' was' : 's were'} seen between scans in issuer, SAN or parallel-certificate evidence.` })
  if (needsReview > 0)  actions.push({ severity: 'medium', title: 'Certificate evidence needs review', body: `${needsReview} certificate${needsReview === 1 ? '' : 's'} are flagged high or critical risk and should be reviewed.` })

  const scrollToIssues = () => issuesRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })

  // Trust-posture tile states (cert tiles use real data; transport tiles point
  // to Email Protection, which owns MTA-STS / TLS-RPT / redirect checks).
  // Expiry is presented only as a validity-window observation; it is never a
  // whole-certificate trust conclusion.
  const hasKnownExpiry = certs.some(c => c.days_until_expiry != null)
  const expiryTile = expired > 0 ? { status: 'Expired certs present', tone: 'bad' }
    : expiringSoon > 0 ? { status: 'Renewals due soon', tone: 'warn' }
    : hasKnownExpiry ? { status: 'In date (>30d)', tone: 'info' }
    : hasData ? { status: 'Not yet retrieved', tone: 'na' }
    : { status: 'No data yet', tone: 'na' }

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* 1 · Hero / module header */}
      <div className="card p-6 mb-6 flex flex-col lg:flex-row lg:items-center gap-5">
        <div className="flex-1 min-w-0">
          <span className="eyebrow" style={{ color: '#0F689F' }}>Certificates &amp; Trust</span>
          <h1 className="text-2xl font-bold text-gray-900 leading-tight">Certificates &amp; Trust</h1>
          <p className="text-sm text-gray-500 mt-1 leading-relaxed">
            The certificate each website presented when CyberMeters connected: whether it matches the name, when it expires and whether it is trusted.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 flex-shrink-0">
          <button onClick={scrollToIssues} className="btn-primary text-sm" disabled={!hasData}>
            Review certificate risks
          </button>
          <Link to="/scans/new" className="btn-secondary text-sm">Run scan</Link>
        </div>
      </div>

      <TlsAuthorizationSettings key={wsId} workspaceId={wsId} />

      {!hasData && !loading ? (
        /* 8 · Empty state */
        <div className="card p-10 text-center mb-6">
          <p className="text-base font-bold text-gray-900 mb-1">Run a scan to start certificate and trust monitoring</p>
          <p className="text-sm text-gray-500 max-w-md mx-auto mb-5">
            CyberMeters reads the certificate your website presents when it connects, checks its name, expiry and trust, and says which checks it could not run. Past certificates and certificates on names it did not connect to are not listed.
          </p>
          <Link to="/scans/new" className="btn-primary mx-auto inline-flex">Run scan</Link>
        </div>
      ) : (
        <>
          {/* 2 · Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <StatCard icon={Lock}        label="Certificates"      value={certs.length} />
            <StatCard icon={Clock}       label="Expiring (<30d)"   value={expiringSoon} warning={expiringSoon > 0} />
            <StatCard icon={XCircle}     label="Expired"           value={expired}      danger={expired > 0} />
            <StatCard icon={AlertTriangle} label="Name or trust failed" value={checkFailed} danger={checkFailed > 0} />
            <StatCard icon={ShieldCheck} label="Needs review"      value={needsReview}  warning={needsReview > 0} />
          </div>

          {/* 3 · Certificate expiry risk buckets */}
          <div id="cert-expiry" className="card p-6 mb-6 scroll-mt-20">
            <h2 className="font-semibold text-gray-900 mb-4">Certificate expiry risk</h2>
            {hasData ? (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {BUCKETS.map(b => {
                  const n = buckets[b.key]
                  const tone = b.tone === 'bad' ? 'text-red-600' : b.tone === 'warn' ? 'text-amber-600' : b.tone === 'ok' ? 'text-brand-600' : 'text-gray-400'
                  return (
                    <div key={b.key} className="rounded-xl border border-gray-200 bg-white p-3 text-center">
                      <p className="text-xs font-semibold text-gray-700">{b.label}</p>
                      <p className={`text-lg font-bold mt-1 tabular-nums ${n > 0 ? tone : 'text-gray-300'}`}>{n}</p>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-sm text-gray-400 py-4 text-center">Run a scan to populate certificate expiry monitoring.</p>
            )}
          </div>

          {/* 5 · Issues / recommended actions */}
          <div id="cert-actions" ref={issuesRef} className="mb-6 scroll-mt-20">
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-semibold text-gray-900">Recommended actions{actions.length > 0 && <span className="text-gray-400 font-semibold"> · {actions.length} open</span>}</h2>
            </div>
            {actions.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {actions.map((a, i) => <ActionCard key={i} {...a} />)}
              </div>
            ) : (
              <div className="card p-6 text-center text-sm text-gray-400">
                {hasKnownExpiry
                  ? 'No expiry issue was detected in the latest recorded certificate evidence. Separately unavailable chain, trust-store or revocation evidence remains unknown and is shown below.'
                  : 'Certificate details have not been retrieved yet for the monitored hosts. Run a scan to populate issuer, expiry and HTTPS status.'}
              </div>
            )}
          </div>

          {/* 6 · Trust posture */}
          <div id="cert-trust" className="card p-6 mb-6 scroll-mt-20">
            <h2 className="font-semibold text-gray-900 mb-1">Trust posture</h2>
            <p className="text-sm text-gray-500 leading-relaxed mb-4 max-w-3xl">
              Active HTTPS, the live-presented certificate, hostname match, chain evidence, declared trust-store validation and revocation assurance are separate observations.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
              <TrustTile label="Certificate expiry"      status={expiryTile.status} tone={expiryTile.tone} hint="Expiry across monitored hosts" />
              <TrustTile label="MTA-STS"                 status="Checked in Email Protection" tone="na" hint="Mail transport policy" to="/ws/email-protection" />
              <TrustTile label="TLS-RPT"                 status="Checked in Email Protection" tone="na" hint="TLS reporting readiness" to="/ws/email-protection" />
            </div>
            <div className="space-y-3">
              {certs.map((cert, index) => (
                <CertificateAssuranceSummary
                  key={`${cert.domain || 'certificate'}-${index}`}
                  presentation={cert.certificate_assurance}
                  liveTls={cert.live_tls}
                  title={`Certificate evidence · ${cert.domain || 'hostname not recorded'}`}
                  showEvidence
                />
              ))}
            </div>
          </div>

          {(l2Findings.length > 0 || anomalies.length > 0) && (
            <div className="card p-6 mb-6">
              <div className="flex items-center justify-between gap-3 mb-4">
                <div>
                  <h2 className="font-semibold text-gray-900">Certificate L2 findings</h2>
                  <p className="text-sm text-gray-500 mt-1">Certificate changes between scans and renewal signals, from the certificates CyberMeters recorded.</p>
                </div>
                <span className="text-sm text-gray-400">{l2Findings.length + anomalies.length} item{l2Findings.length + anomalies.length === 1 ? '' : 's'}</span>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {[...l2Findings, ...anomalies].slice(0, 8).map((finding, idx) => (
                  <FindingPill key={`${finding.domain || 'domain'}-${finding.type}-${idx}`} finding={finding} />
                ))}
              </div>
            </div>
          )}

          {/* 4 · Certificate inventory */}
          <div id="cert-inventory" className="card overflow-hidden mb-6 scroll-mt-20">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-gray-900">Certificates checked</h2>
                <p className="text-xs text-gray-500 mt-0.5">One row per monitored domain: the certificate its website presented on port 443 at the latest scan.</p>
              </div>
              <span className="text-sm text-gray-400">{certs.length} total</span>
            </div>
            <DataTable
              columns={COLUMNS}
              rows={certs}
              empty={<div className="py-12 text-center text-sm text-gray-400">No certificate evidence found. Run a scan to record the certificate your site presents.</div>}
            />
          </div>

          {/* Existing detail: timeline chart (preserved) */}
          {chartData.length > 0 && (
            <div className="card p-6 mb-6">
              <h2 className="font-semibold text-gray-900 mb-4">Certificate timeline</h2>
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={chartData} margin={{ top: 4, right: 0, left: -28, bottom: 0 }}>
                  <defs>
                    <linearGradient id="certGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00876A" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#00876A" stopOpacity={0}   />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="day" tick={{ fontSize: 13, fill: '#94a3b8' }} />
                  <YAxis tick={{ fontSize: 13, fill: '#94a3b8' }} allowDecimals={false} />
                  <Tooltip contentStyle={{ fontSize: 13, borderRadius: 8 }} />
                  <Area type="monotone" dataKey="events" stroke="#00876A" strokeWidth={2} fill="url(#certGrad)" name="Events" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Existing detail: churn / issuer history / recent alerts (preserved) */}
          {(churn || issuerHistory.length > 0 || certTimeline.length > 0) && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="card p-5">
                <h2 className="font-semibold text-gray-900 mb-3">New certificates seen</h2>
                <div className="space-y-2 text-sm text-gray-600">
                  <div className="flex justify-between"><span>Last 30 days</span><span className="font-medium">{churn?.certificates_last_30_days ?? 0}</span></div>
                  <div className="flex justify-between"><span>Last 90 days</span><span className="font-medium">{churn?.certificates_last_90_days ?? 0}</span></div>
                  <div className="flex justify-between"><span>Classification</span><span className="font-medium capitalize">{churn?.classification || 'low'}</span></div>
                </div>
              </div>

              <div className="card p-5">
                <h2 className="font-semibold text-gray-900 mb-3">Issuers seen</h2>
                <div className="space-y-2">
                  {issuerHistory.slice(0, 5).map((issuer, idx) => (
                    <div key={`${issuer.issuer || 'unknown'}-${idx}`} className="text-sm">
                      <div className="font-medium text-gray-800">{issuer.issuer || 'Unknown issuer'}</div>
                      <div className="text-xs text-gray-400">{issuer.certificates} certificate{issuer.certificates === 1 ? '' : 's'} recorded</div>
                    </div>
                  ))}
                  {issuerHistory.length === 0 && <div className="text-sm text-gray-400">No issuers recorded yet.</div>}
                </div>
              </div>

              <div className="card p-5">
                <h2 className="font-semibold text-gray-900 mb-3">Recent alerts</h2>
                <div className="space-y-2">
                  {timeline.flatMap(day => day.events || []).slice(0, 5).map((event, idx) => (
                    <div key={`${event.event_type}-${idx}`} className="text-sm">
                      <div className="font-medium text-gray-800">{event.hostname || event.event_type}</div>
                      <div className="text-xs text-gray-400">{event.description}</div>
                    </div>
                  ))}
                  {timeline.length === 0 && <div className="text-sm text-gray-400">No certificate alerts yet.</div>}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </WsPage>
  )
}
