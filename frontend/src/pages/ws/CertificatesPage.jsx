import { useState, useEffect, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Lock, AlertTriangle, XCircle, ShieldCheck, Clock, ScanLine, Globe, Mail,
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

function expiryStatus(daysLeft) {
  if (daysLeft == null) return { label: 'Unknown', cls: 'text-gray-400' }
  if (daysLeft < 0)  return { label: 'Expired',        cls: 'text-red-600 font-semibold' }
  if (daysLeft < 14) return { label: `${daysLeft}d left`, cls: 'text-red-500 font-semibold' }
  if (daysLeft < 30) return { label: `${daysLeft}d left`, cls: 'text-amber-500 font-semibold' }
  return { label: `${daysLeft}d left`, cls: 'text-brand-600' }
}

// HTTPS / certificate trust state derived from existing validity fields only.
function httpsState(row) {
  const valid = row.valid ?? row.chain_valid
  if (valid === true)  return { label: 'Secure', tone: 'ok' }
  if (valid === false) return { label: 'Broken / untrusted', tone: 'bad' }
  return { label: 'Unknown', tone: 'na' }
}

function HttpsChip({ row }) {
  const s = httpsState(row)
  const cls = s.tone === 'ok' ? 'bg-brand-50 text-brand-700 border-brand-100'
    : s.tone === 'bad' ? 'bg-red-50 text-red-600 border-red-100'
    : 'bg-gray-50 text-gray-500 border-gray-200'
  return <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${cls}`}>{s.label}</span>
}

const COLUMNS = [
  { key: 'domain', label: 'Domain / Hostname', render: v => <span className="font-medium text-sm text-gray-900 mono">{v || '—'}</span> },
  { key: 'issuer', label: 'Issuer', render: v => <span className="text-xs text-gray-500">{v || '—'}</span> },
  { key: 'expires_at', label: 'Expires', render: v => <span className="text-xs text-gray-500">{v ? new Date(v).toLocaleDateString() : '—'}</span> },
  {
    key: 'days_until_expiry', label: 'Days remaining',
    render: v => { const { label, cls } = expiryStatus(v); return <span className={`text-xs ${cls}`}>{label}</span> },
  },
  { key: 'https', label: 'HTTPS status', render: (v, row) => <HttpsChip row={row} /> },
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
  { key: 'healthy', label: 'Healthy',  tone: 'ok' },
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
    critical: { bar: 'bg-red-500',   chip: 'bg-red-50 text-red-700 border-red-100',     icon: XCircle },
    high:     { bar: 'bg-amber-500', chip: 'bg-amber-50 text-amber-700 border-amber-100', icon: AlertTriangle },
    medium:   { bar: 'bg-amber-400', chip: 'bg-amber-50 text-amber-700 border-amber-100', icon: AlertTriangle },
  }[severity] || { bar: 'bg-gray-300', chip: 'bg-gray-50 text-gray-600 border-gray-200', icon: AlertTriangle }
  const Icon = cfg.icon
  return (
    <div className="card p-4 flex gap-3">
      <div className={`w-1 rounded-full ${cfg.bar} flex-shrink-0`} />
      <div className="flex-1">
        <div className="flex items-center justify-between gap-2 mb-1">
          <h3 className="text-sm font-semibold text-gray-900 flex items-center gap-1.5"><Icon className="w-4 h-4 text-gray-400" /> {title}</h3>
          <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border ${cfg.chip}`}>{severity}</span>
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">{body}</p>
      </div>
    </div>
  )
}

function TrustTile({ icon: Icon, label, status, tone, hint, to }) {
  const cls = tone === 'ok' ? 'text-brand-600' : tone === 'bad' ? 'text-red-500' : tone === 'warn' ? 'text-amber-500' : 'text-gray-400'
  const inner = (
    <div className="card p-4 h-full hover:shadow-card-md transition-shadow">
      <div className="flex items-center gap-2 mb-1.5">
        <Icon className={`w-4 h-4 ${cls}`} />
        <span className="text-sm font-semibold text-gray-800">{label}</span>
      </div>
      <p className={`text-sm font-medium ${cls}`}>{status}</p>
      {hint && <p className="text-[11px] text-gray-400 mt-1 leading-relaxed">{hint}</p>}
    </div>
  )
  return to ? <Link to={to} className="block">{inner}</Link> : inner
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
  const broken       = certs.filter(c => (c.valid ?? c.chain_valid) === false).length
  const needsReview  = certs.filter(c => ['high', 'critical'].includes(c.certificate_risk_level)).length
  const buckets      = bucketCounts(certs)
  const chartData    = timeline.slice().reverse().map(day => ({ day: day.day, events: day.events?.length || 0 }))

  // Certificate-derived actions only — never invented.
  const actions = []
  if (expired > 0)      actions.push({ severity: 'critical', title: 'Certificate expired', body: `${expired} certificate${expired === 1 ? '' : 's'} have expired. Renew now to restore HTTPS trust for affected hosts.` })
  if (expiringSoon > 0) actions.push({ severity: 'high', title: 'Certificate expiring soon', body: `${expiringSoon} certificate${expiringSoon === 1 ? '' : 's'} expire within 30 days. Schedule renewal to avoid an outage.` })
  if (broken > 0)       actions.push({ severity: 'high', title: 'HTTPS not available or untrusted', body: `${broken} host${broken === 1 ? '' : 's'} returned an invalid or untrusted certificate chain.` })
  if (needsReview > 0)  actions.push({ severity: 'medium', title: 'Certificate trust needs review', body: `${needsReview} certificate${needsReview === 1 ? '' : 's'} are flagged high or critical risk and should be reviewed.` })

  const scrollToIssues = () => issuesRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })

  // Trust-posture tile states (cert tiles use real data; transport tiles point
  // to Email Protection, which owns MTA-STS / TLS-RPT / redirect checks).
  // "Healthy"/"Monitored" require REAL data — an observed cert whose details we
  // could not retrieve (expiry/validity unknown) must never read as healthy.
  const hasKnownExpiry = certs.some(c => c.days_until_expiry != null)
  const hasKnownHttps  = certs.some(c => (c.valid ?? c.chain_valid) != null)
  const expiryTile = expired > 0 ? { status: 'Expired certs present', tone: 'bad' }
    : expiringSoon > 0 ? { status: 'Renewals due soon', tone: 'warn' }
    : hasKnownExpiry ? { status: 'Healthy', tone: 'ok' }
    : hasData ? { status: 'Not yet retrieved', tone: 'na' }
    : { status: 'No data yet', tone: 'na' }
  const httpsTile = broken > 0 ? { status: 'Issues found', tone: 'bad' }
    : hasKnownHttps ? { status: 'Monitored', tone: 'ok' }
    : hasData ? { status: 'Not yet retrieved', tone: 'na' }
    : { status: 'No data yet', tone: 'na' }

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* 1 · Hero / module header */}
      <div className="card p-6 mb-6 flex flex-col lg:flex-row lg:items-center gap-5">
        <div className="w-12 h-12 rounded-2xl bg-brand-50 flex items-center justify-center flex-shrink-0">
          <ShieldCheck className="w-6 h-6 text-brand-600" />
        </div>
        <div className="flex-1 min-w-0">
          <span className="eyebrow">Certificates &amp; Trust</span>
          <h1 className="text-2xl font-bold text-gray-900 leading-tight">Certificates &amp; Trust</h1>
          <p className="text-sm text-gray-500 mt-1 leading-relaxed">
            Monitor certificate expiry, HTTPS trust posture and domain transport security across your workspace.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 flex-shrink-0">
          <button onClick={scrollToIssues} className="btn-primary text-sm" disabled={!hasData}>
            <ShieldCheck className="w-4 h-4" /> Review certificate risks
          </button>
          <Link to="/scans/new" className="btn-secondary text-sm"><ScanLine className="w-4 h-4" /> Run scan</Link>
        </div>
      </div>

      {!hasData && !loading ? (
        /* 8 · Empty state */
        <div className="card p-10 text-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center mx-auto mb-4">
            <Lock className="w-7 h-7 text-brand-600" />
          </div>
          <p className="text-base font-bold text-gray-900 mb-1">Run a scan to start certificate and trust monitoring</p>
          <p className="text-sm text-gray-500 max-w-md mx-auto mb-5">
            CyberMeters discovers your TLS certificates, tracks expiry risk and assesses HTTPS and transport-security posture from each scan.
          </p>
          <Link to="/scans/new" className="btn-primary mx-auto inline-flex"><ScanLine className="w-4 h-4" /> Run scan</Link>
        </div>
      ) : (
        <>
          {/* 2 · Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <StatCard icon={Lock}        label="Certificates"      value={certs.length} />
            <StatCard icon={Clock}       label="Expiring (<30d)"   value={expiringSoon} warning={expiringSoon > 0} />
            <StatCard icon={XCircle}     label="Expired"           value={expired}      danger={expired > 0} />
            <StatCard icon={AlertTriangle} label="Broken HTTPS"    value={broken}       danger={broken > 0} />
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
                  ? 'No certificate issues detected in the latest scan. Expiry, HTTPS and trust signals look healthy.'
                  : 'Certificate details have not been retrieved yet for the monitored hosts. Run a scan to populate issuer, expiry and HTTPS status.'}
              </div>
            )}
          </div>

          {/* 6 · Trust posture */}
          <div id="cert-trust" className="card p-6 mb-6 scroll-mt-20">
            <h2 className="font-semibold text-gray-900 mb-1">Trust posture</h2>
            <p className="text-sm text-gray-500 leading-relaxed mb-4 max-w-3xl">
              Certificate and transport-security signals help determine whether customers, mail receivers and partners can trust this domain’s infrastructure.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
              <TrustTile icon={Lock}        label="HTTPS / TLS certificate" status={httpsTile.status}  tone={httpsTile.tone} hint="From discovered certificates" />
              <TrustTile icon={Clock}       label="Certificate expiry"      status={expiryTile.status} tone={expiryTile.tone} hint="Expiry across monitored hosts" />
              <TrustTile icon={Mail}        label="MTA-STS"                 status="Checked in Email Protection" tone="na" hint="Mail transport policy" to="/ws/email-protection" />
              <TrustTile icon={Mail}        label="TLS-RPT"                 status="Checked in Email Protection" tone="na" hint="TLS reporting readiness" to="/ws/email-protection" />
              <TrustTile icon={Globe}       label="Secure redirect"        status="Checked during scan" tone="na" hint="HTTP→HTTPS posture" />
            </div>
          </div>

          {/* 4 · Certificate inventory */}
          <div id="cert-inventory" className="card overflow-hidden mb-6 scroll-mt-20">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <h2 className="font-semibold text-gray-900">Certificate inventory</h2>
              <span className="text-sm text-gray-400">{certs.length} total</span>
            </div>
            <DataTable
              columns={COLUMNS}
              rows={certs}
              empty={<div className="py-12 text-center text-sm text-gray-400">No certificates found. Run a scan to discover TLS certificates.</div>}
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
                  <XAxis dataKey="day" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                  <Area type="monotone" dataKey="events" stroke="#00876A" strokeWidth={2} fill="url(#certGrad)" name="Events" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Existing detail: churn / issuer history / recent alerts (preserved) */}
          {(churn || issuerHistory.length > 0 || certTimeline.length > 0) && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="card p-5">
                <h2 className="font-semibold text-gray-900 mb-3">Certificate churn</h2>
                <div className="space-y-2 text-sm text-gray-600">
                  <div className="flex justify-between"><span>Last 30 days</span><span className="font-medium">{churn?.certificates_last_30_days ?? 0}</span></div>
                  <div className="flex justify-between"><span>Last 90 days</span><span className="font-medium">{churn?.certificates_last_90_days ?? 0}</span></div>
                  <div className="flex justify-between"><span>Classification</span><span className="font-medium capitalize">{churn?.classification || 'low'}</span></div>
                </div>
              </div>

              <div className="card p-5">
                <h2 className="font-semibold text-gray-900 mb-3">Issuer history</h2>
                <div className="space-y-2">
                  {issuerHistory.slice(0, 5).map((issuer, idx) => (
                    <div key={`${issuer.issuer || 'unknown'}-${idx}`} className="text-sm">
                      <div className="font-medium text-gray-800">{issuer.issuer || 'Unknown issuer'}</div>
                      <div className="text-xs text-gray-400">{issuer.certificates} certificate{issuer.certificates === 1 ? '' : 's'} observed</div>
                    </div>
                  ))}
                  {issuerHistory.length === 0 && <div className="text-sm text-gray-400">No issuer history yet.</div>}
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
