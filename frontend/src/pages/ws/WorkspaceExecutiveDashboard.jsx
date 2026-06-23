import { useState, useEffect, useCallback } from 'react'
import {
  TrendingUp, TrendingDown, Minus,
  ShieldCheck, AlertTriangle, AlertOctagon, Globe,
  CheckCircle2, Layers, FileBarChart2, Clock,
  Zap, Eye, ChevronRight,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from 'recharts'
import { useWorkspace }           from '../../hooks/useWorkspace'
import { api }                    from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'

// ── Colour helpers ────────────────────────────────────────────────────────────

const SEV_COLORS = {
  critical: '#EF4444',
  high:     '#F97316',
  medium:   '#EAB308',
  low:      '#22C55E',
  info:     '#6B7280',
}

const SCORE_COLOR = (s) =>
  s >= 80 ? '#00876A'
  : s >= 60 ? '#3B82F6'
  : s >= 40 ? '#F59E0B'
  : '#EF4444'

// Maps score-derived posture rating values to display labels (Security Rating system).
// Kept separate from finding severity (critical/high/medium/low) which uses RiskBadge.
const RATING_LABEL = {
  excellent: 'Excellent',
  good:      'Good',
  moderate:  'Moderate',
  high:      'Poor',
  critical:  'Critical',
  // legacy letter grades
  a: 'Excellent', b: 'Good', c: 'Moderate', d: 'Poor', f: 'Critical',
  // legacy string grades
  fair: 'Moderate', warning: 'Poor',
}
function riskLabel(rating) {
  return RATING_LABEL[rating?.toLowerCase()] ?? rating ?? '—'
}

// ── Summary cards ─────────────────────────────────────────────────────────────

function SummaryCard({ label, value, sub, Icon, color = 'text-gray-800', iconBg = 'bg-gray-100' }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-start gap-4">
      <div className={`w-10 h-10 rounded-lg ${iconBg} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div className="min-w-0">
        <p className="text-xs text-gray-500 font-medium uppercase tracking-wide">{label}</p>
        <p className={`text-2xl font-bold ${color} leading-tight`}>{value}</p>
        {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

// ── Score trend chart ─────────────────────────────────────────────────────────

function ScoreTrendChart({ trend }) {
  if (!trend?.length) {
    return (
      <div className="flex items-center justify-center h-48 text-sm text-gray-400">
        No trend data — complete more scans to build history.
      </div>
    )
  }

  const data = trend.map((p, i) => ({
    name:  p.domain ? `${p.domain.slice(0, 16)}…` : `Scan ${i + 1}`,
    score: p.score,
    date:  p.scanned_at ? new Date(p.scanned_at).toLocaleDateString('en-GB', { month: 'short', day: 'numeric' }) : '',
  }))

  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data} margin={{ top: 4, right: 8, bottom: 4, left: -24 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6" />
        <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#9CA3AF' }} />
        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#9CA3AF' }} />
        <Tooltip
          formatter={(v) => [`${v}`, 'Score']}
          contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #E5E7EB' }}
        />
        <Line
          type="monotone"
          dataKey="score"
          stroke="#00876A"
          strokeWidth={2}
          dot={{ r: 3, fill: '#00876A' }}
          activeDot={{ r: 5 }}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

// ── Risk distribution pie ─────────────────────────────────────────────────────

function RiskDistPie({ dist }) {
  const entries = Object.entries(dist ?? {})
    .filter(([k, v]) => k !== 'total' && v > 0)
    .map(([k, v]) => ({ name: k, value: v, color: SEV_COLORS[k] ?? '#6B7280' }))

  if (!entries.length) {
    return (
      <div className="flex items-center justify-center h-48 text-sm text-gray-400">
        No findings in last 30 days.
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={entries}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={2}
          dataKey="value"
        >
          {entries.map((e, i) => (
            <Cell key={i} fill={e.color} />
          ))}
        </Pie>
        <Legend
          formatter={(v) => <span className="text-xs capitalize text-gray-600">{v}</span>}
          iconSize={8}
        />
        <Tooltip
          formatter={(v, n) => [`${v}`, n]}
          contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #E5E7EB' }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

// ── Top risks table ───────────────────────────────────────────────────────────

function SevBadge({ severity }) {
  const s = severity?.toLowerCase()
  const cls = {
    critical: 'bg-red-100 text-red-700',
    high:     'bg-orange-100 text-orange-700',
    medium:   'bg-yellow-100 text-yellow-700',
    low:      'bg-green-100 text-green-700',
    info:     'bg-gray-100 text-gray-600',
  }[s] ?? 'bg-gray-100 text-gray-500'
  return (
    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${cls}`}>
      {severity ?? '—'}
    </span>
  )
}

function TopRisksTable({ risks }) {
  if (!risks?.length) {
    return <p className="text-sm text-gray-400 py-4 text-center">No risks in last 30 days.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-100">
            <th className="text-left text-xs text-gray-400 font-medium py-2 pr-4">Finding</th>
            <th className="text-left text-xs text-gray-400 font-medium py-2 pr-4">Severity</th>
            <th className="text-left text-xs text-gray-400 font-medium py-2 pr-4">Domain</th>
            <th className="text-left text-xs text-gray-400 font-medium py-2">Detected</th>
          </tr>
        </thead>
        <tbody>
          {risks.map((r, i) => (
            <tr key={i} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
              <td className="py-2.5 pr-4 text-gray-800 font-medium max-w-[220px] truncate">{r.title}</td>
              <td className="py-2.5 pr-4"><SevBadge severity={r.severity} /></td>
              <td className="py-2.5 pr-4 text-gray-500 font-mono text-xs truncate max-w-[120px]">{r.domain}</td>
              <td className="py-2.5 text-gray-400 text-xs whitespace-nowrap">
                {r.detected_at ? new Date(r.detected_at).toLocaleDateString('en-GB', { month: 'short', day: 'numeric' }) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Changes widget ────────────────────────────────────────────────────────────

function ChangesWidget({ changes }) {
  const { score_current, score_previous, score_delta, score_direction, new_assets_7d } = changes ?? {}
  const DeltaIcon = score_direction === 'up' ? TrendingUp
    : score_direction === 'down' ? TrendingDown : Minus
  const deltaColor = score_direction === 'up' ? 'text-green-600'
    : score_direction === 'down' ? 'text-red-500' : 'text-gray-400'

  return (
    <div className="grid grid-cols-2 gap-4">
      <div className="bg-gray-50 rounded-lg p-4">
        <p className="text-xs text-gray-500 mb-1">Score Change</p>
        <div className="flex items-center gap-2">
          <DeltaIcon className={`w-5 h-5 ${deltaColor}`} />
          <span className={`text-xl font-bold ${deltaColor}`}>
            {score_delta != null ? `${score_delta > 0 ? '+' : ''}${score_delta}` : '—'}
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          {score_previous != null && score_current != null
            ? `${score_previous} → ${score_current}`
            : 'Insufficient scan history'}
        </p>
      </div>
      <div className="bg-gray-50 rounded-lg p-4">
        <p className="text-xs text-gray-500 mb-1">New Assets (7d)</p>
        <p className="text-xl font-bold text-gray-800">{new_assets_7d ?? 0}</p>
        <p className="text-xs text-gray-400 mt-1">assets discovered</p>
      </div>
    </div>
  )
}

// ── Remediation priorities ────────────────────────────────────────────────────

function RemBucket({ label, items, accent }) {
  const accentCls = {
    red:    { dot: 'bg-red-500',    text: 'text-red-700',    label: 'bg-red-50 text-red-700 border-red-100' },
    amber:  { dot: 'bg-amber-400',  text: 'text-amber-700',  label: 'bg-amber-50 text-amber-700 border-amber-100' },
    blue:   { dot: 'bg-blue-400',   text: 'text-blue-700',   label: 'bg-blue-50 text-blue-700 border-blue-100' },
  }[accent]

  return (
    <div>
      <div className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border mb-3 ${accentCls.label}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${accentCls.dot}`} />
        {label}
      </div>
      {items?.length ? (
        <ul className="space-y-2">
          {items.map((item, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <ChevronRight className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${accentCls.text}`} />
              <div>
                <p className="text-gray-800 font-medium leading-tight">{item.title}</p>
                {item.domain && <p className="text-gray-400 text-xs font-mono">{item.domain}</p>}
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-gray-400">Nothing here.</p>
      )}
    </div>
  )
}

// ── KPI bar ───────────────────────────────────────────────────────────────────

function KpiBar({ kpis }) {
  const items = [
    { label: 'Verification Rate', value: kpis?.verification_rate != null ? `${kpis.verification_rate}%` : '—', Icon: CheckCircle2 },
    { label: 'Avg Score',         value: kpis?.average_score ?? '—',        Icon: ShieldCheck    },
    { label: 'Critical Risks',    value: kpis?.critical_risks ?? 0,          Icon: AlertOctagon   },
    { label: 'Reports Generated', value: kpis?.reports_generated ?? 0,       Icon: FileBarChart2  },
    { label: 'Assets Tracked',    value: kpis?.assets_discovered ?? 0,       Icon: Layers         },
  ]
  return (
    <div className="bg-white rounded-xl border border-gray-200">
      <div className="grid grid-cols-5 divide-x divide-gray-100">
        {items.map(({ label, value, Icon }) => (
          <div key={label} className="flex flex-col items-center py-4 px-3 text-center">
            <Icon className="w-4 h-4 text-brand-500 mb-1.5" />
            <span className="text-xl font-bold text-gray-900">{value}</span>
            <span className="text-[10px] text-gray-400 uppercase tracking-wide mt-0.5">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WorkspaceExecutiveDashboard() {
  const { wsId, wsName } = useWorkspace()
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  const load = useCallback(async () => {
    if (!wsId) return
    setLoading(true)
    setError(null)
    try {
      const res = await api.getExecutiveDashboard(wsId)
      setData(res)
    } catch (e) {
      setError(e.message ?? 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const s   = data?.summary          ?? {}
  const gen = data?.generated_at

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Executive Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Security posture overview for <span className="font-medium">{wsName}</span>
          </p>
        </div>
        {gen && (
          <div className="flex items-center gap-1.5 text-xs text-gray-400">
            <Clock className="w-3.5 h-3.5" />
            Updated {new Date(gen).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}
          </div>
        )}
      </div>

      {/* KPI bar */}
      {data && <KpiBar kpis={data.kpis} />}

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5">
        <SummaryCard
          label="Security Score"
          value={s.security_score ?? '—'}
          sub={s.risk_level ? `Rating: ${riskLabel(s.risk_level)}` : undefined}
          Icon={ShieldCheck}
          color={s.security_score != null ? (s.security_score >= 80 ? 'text-brand-700' : s.security_score >= 60 ? 'text-blue-700' : s.security_score >= 40 ? 'text-amber-700' : 'text-red-700') : 'text-gray-400'}
          iconBg={s.security_score != null ? (s.security_score >= 80 ? 'bg-brand-50' : s.security_score >= 60 ? 'bg-blue-50' : s.security_score >= 40 ? 'bg-amber-50' : 'bg-red-50') : 'bg-gray-50'}
        />
        <SummaryCard
          label="Domains"
          value={s.domains ?? 0}
          sub={`${s.verified_domains ?? 0} verified (${s.verification_rate ?? 0}%)`}
          Icon={Globe}
          color="text-blue-700"
          iconBg="bg-blue-50"
        />
        <SummaryCard
          label="Critical Findings"
          value={s.critical_findings ?? 0}
          sub="Last 30 days"
          Icon={AlertOctagon}
          color={s.critical_findings > 0 ? 'text-red-700' : 'text-gray-500'}
          iconBg={s.critical_findings > 0 ? 'bg-red-50' : 'bg-gray-50'}
        />
        <SummaryCard
          label="High Findings"
          value={s.high_findings ?? 0}
          sub="Last 30 days"
          Icon={AlertTriangle}
          color={s.high_findings > 0 ? 'text-orange-700' : 'text-gray-500'}
          iconBg={s.high_findings > 0 ? 'bg-orange-50' : 'bg-gray-50'}
        />
      </div>

      {/* Score trend + Risk distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-5">
        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="text-sm font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-brand-500" />
            Security Score Trend
          </h2>
          <ScoreTrendChart trend={data?.score_trend} />
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="text-sm font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <Eye className="w-4 h-4 text-brand-500" />
            Risk Distribution (30d)
          </h2>
          <RiskDistPie dist={data?.risk_distribution} />
        </div>
      </div>

      {/* Top risks + Changes */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-5">
        <div className="md:col-span-2 bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="text-sm font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-red-500" />
            Top 10 Risks
          </h2>
          <TopRisksTable risks={data?.top_risks} />
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="text-sm font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-500" />
            Changes Since Last Scan
          </h2>
          <ChangesWidget changes={data?.changes} />
          {s.last_scan_at && (
            <p className="text-xs text-gray-400 mt-4 flex items-center gap-1">
              <Clock className="w-3 h-3" />
              Last scan: {new Date(s.last_scan_at).toLocaleDateString('en-GB', { month: 'short', day: 'numeric', year: 'numeric' })}
              {s.last_scan_domain && ` · ${s.last_scan_domain}`}
            </p>
          )}
        </div>
      </div>

      {/* Remediation priorities */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 mt-5">
        <h2 className="text-sm font-semibold text-gray-800 mb-5 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-brand-500" />
          Remediation Priorities
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <RemBucket label="Fix Now"  items={data?.remediation?.fix_now}  accent="red"   />
          <RemBucket label="Fix Next" items={data?.remediation?.fix_next} accent="amber" />
          <RemBucket label="Monitor"  items={data?.remediation?.monitor}  accent="blue"  />
        </div>
      </div>
    </WsPage>
  )
}
