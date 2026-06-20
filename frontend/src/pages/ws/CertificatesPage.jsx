import { useState, useEffect, useCallback } from 'react'
import { Lock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
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

function ValidIcon({ valid }) {
  if (valid === true)  return <CheckCircle className="w-4 h-4 text-brand-500" />
  if (valid === false) return <XCircle     className="w-4 h-4 text-red-500"   />
  return <AlertTriangle className="w-4 h-4 text-amber-400" />
}

const COLUMNS = [
  {
    key: 'domain',
    label: 'Domain',
    render: v => <span className="font-medium text-sm text-gray-900 mono">{v}</span>,
  },
  { key: 'issuer',  label: 'Issuer',  render: v => <span className="text-xs text-gray-500">{v || '—'}</span> },
  { key: 'san_count', label: 'SANs', render: v => <span className="text-xs text-gray-500">{v ?? 0}</span> },
  { key: 'certificate_risk_level', label: 'Risk', render: v => <RiskBadge level={v} /> },
  {
    key: 'days_until_expiry',
    label: 'Expiry',
    render: v => {
      const { label, cls } = expiryStatus(v)
      return <span className={`text-xs ${cls}`}>{label}</span>
    },
  },
  {
    key: 'valid',
    label: 'Valid',
    render: (v, row) => <ValidIcon valid={row.valid ?? row.chain_valid} />,
  },
  {
    key: 'expires_at',
    label: 'Expires',
    render: v => v ? new Date(v).toLocaleDateString() : '—',
  },
]

export default function CertificatesPage() {
  const { wsId, wsName } = useWorkspace()
  const [certs, setCerts]     = useState([])
  const [timeline, setTimeline] = useState([])
  const [certTimeline, setCertTimeline] = useState([])
  const [issuerHistory, setIssuerHistory] = useState([])
  const [churn, setChurn] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

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
        setTimeline([])
        setCertTimeline([])
        setIssuerHistory([])
        setChurn(null)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const expiringSoon = certs.filter(c => c.days_until_expiry != null && c.days_until_expiry < 30 && c.days_until_expiry >= 0).length
  const expired      = certs.filter(c => c.days_until_expiry != null && c.days_until_expiry < 0).length
  const highRisk     = certs.filter(c => ['high', 'critical'].includes(c.certificate_risk_level)).length
  const chartData    = timeline.slice().reverse().map(day => ({
    day: day.day,
    events: day.events?.length || 0,
  }))

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Certificate Intelligence</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard icon={Lock} label="Total Certificates" value={certs.length} />
        <StatCard icon={Lock} label="Expiring (&lt;30d)"   value={expiringSoon} warning={expiringSoon > 0} />
        <StatCard icon={Lock} label="Expired"             value={expired}      danger={expired > 0} />
        <StatCard icon={Lock} label="High Risk"           value={highRisk}     danger={highRisk > 0} />
        <StatCard icon={Lock} label="Churn"               value={churn?.classification || 'low'} warning={['high', 'unusual'].includes(churn?.classification)} />
      </div>

      {chartData.length > 0 && (
        <div className="card p-6 mb-6">
          <h2 className="font-semibold text-gray-900 mb-4">Certificate Timeline</h2>
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
              <Area
                type="monotone"
                dataKey="events"
                stroke="#00876A"
                strokeWidth={2}
                fill="url(#certGrad)"
                name="Events"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {(churn || issuerHistory.length > 0 || certTimeline.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
          <div className="card p-5">
            <h2 className="font-semibold text-gray-900 mb-3">Certificate Churn</h2>
            <div className="space-y-2 text-sm text-gray-600">
              <div className="flex justify-between"><span>Last 30 days</span><span className="font-medium">{churn?.certificates_last_30_days ?? 0}</span></div>
              <div className="flex justify-between"><span>Last 90 days</span><span className="font-medium">{churn?.certificates_last_90_days ?? 0}</span></div>
              <div className="flex justify-between"><span>Classification</span><span className="font-medium capitalize">{churn?.classification || 'low'}</span></div>
            </div>
          </div>

          <div className="card p-5">
            <h2 className="font-semibold text-gray-900 mb-3">Issuer History</h2>
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
            <h2 className="font-semibold text-gray-900 mb-3">Recent Alerts</h2>
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

      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900">Certificates</h2>
          <span className="text-sm text-gray-400">{certs.length} total</span>
        </div>
        <DataTable
          columns={COLUMNS}
          rows={certs}
          empty={
            <div className="py-12 text-center text-sm text-gray-400">
              No certificates found. Run a scan to discover TLS certificates.
            </div>
          }
        />
      </div>
    </WsPage>
  )
}
