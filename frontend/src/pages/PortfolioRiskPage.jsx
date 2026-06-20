import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle, ArrowRight, CheckCircle2, GitBranch,
  RefreshCw, Shield, TrendingDown, TrendingUp, Users,
} from 'lucide-react'
import { api } from '../api'
import StatCard from '../components/StatCard'
import RiskBadge from '../components/RiskBadge'

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score == null) return '#9CA3AF'
  if (score >= 75) return '#00876A'
  if (score >= 55) return '#22C55E'
  if (score >= 35) return '#F59E0B'
  return '#EF4444'
}

function riskBandLabel(band) {
  return { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: '—' }[band] ?? band ?? '—'
}

function ScoreBar({ score, max = 100 }) {
  const pct = score == null ? 0 : Math.max(0, Math.min(100, (score / max) * 100))
  return (
    <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden w-full">
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: scoreColor(score) }} />
    </div>
  )
}

function TrendIcon({ trend }) {
  if (trend === 'improving')     return <TrendingUp   className="w-3.5 h-3.5 text-brand-500" />
  if (trend === 'deteriorating') return <TrendingDown  className="w-3.5 h-3.5 text-red-500" />
  return <span className="w-3.5 h-3.5 inline-block rounded-full bg-gray-200" />
}

function DeltaChip({ delta }) {
  if (delta == null) return null
  const pos = delta >= 0
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
      pos ? 'bg-brand-50 text-brand-700' : 'bg-red-50 text-red-700'
    }`}>
      {pos ? '+' : ''}{delta}
    </span>
  )
}

function AlertSeverityBar({ level }) {
  const cls =
    level === 'critical' ? 'bg-red-500' :
    level === 'high'     ? 'bg-orange-400' :
    level === 'medium'   ? 'bg-amber-400' : 'bg-gray-300'
  return <span className={`inline-block w-1 self-stretch rounded-full flex-shrink-0 ${cls}`} />
}

// ── Sub-sections ──────────────────────────────────────────────────────────────

function PortfolioScoreRing({ score }) {
  const size = 100
  const r = (size - 12) / 2
  const circ = 2 * Math.PI * r
  const dash = score == null ? 0 : circ * (score / 100)
  const color = scoreColor(score)
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#F3F4F6" strokeWidth={8} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color} strokeWidth={8}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x={size / 2} y={size / 2 + 5} textAnchor="middle" fontSize={18} fontWeight="700" fill="#111827">
        {score ?? '—'}
      </text>
    </svg>
  )
}

function RiskRankingsTable({ rankings, onWorkspaceClick }) {
  if (!rankings?.length) {
    return <p className="text-sm text-gray-400 py-6 text-center">No workspace risk data available. Run scans to populate rankings.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-100 text-left text-xs text-gray-400 uppercase tracking-wide">
            <th className="pb-2 font-medium w-6">#</th>
            <th className="pb-2 font-medium">Customer</th>
            <th className="pb-2 font-medium">BRS</th>
            <th className="pb-2 font-medium">Risk</th>
            <th className="pb-2 font-medium">30d</th>
            <th className="pb-2 font-medium">SC Score</th>
            <th className="pb-2 font-medium">SPOFs</th>
            <th className="pb-2 font-medium w-6" />
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {rankings.map((r, i) => (
            <tr key={r.workspace_id} className="hover:bg-gray-50 transition-colors">
              <td className="py-2.5 pr-2 text-gray-300 text-xs font-medium">{i + 1}</td>
              <td className="py-2.5 pr-4">
                <div className="flex items-center gap-2">
                  <TrendIcon trend={r.trend} />
                  <span className="font-medium text-gray-800">{r.workspace_name}</span>
                </div>
                <ScoreBar score={r.brs_score} />
              </td>
              <td className="py-2.5 pr-4">
                <span className="font-bold text-gray-900">{r.brs_score ?? '—'}</span>
                <span className="text-gray-400 text-xs">/100</span>
              </td>
              <td className="py-2.5 pr-4">
                <RiskBadge level={r.risk_band} />
              </td>
              <td className="py-2.5 pr-4">
                <DeltaChip delta={r.score_delta_30d} />
              </td>
              <td className="py-2.5 pr-4 text-gray-500 text-xs">
                {r.supply_chain_score ?? '—'}
              </td>
              <td className="py-2.5 pr-4">
                {r.spof_count > 0 && (
                  <span className="text-xs font-semibold text-red-600">{r.spof_count}</span>
                )}
              </td>
              <td className="py-2.5">
                <button
                  onClick={() => onWorkspaceClick(r.workspace_id)}
                  className="text-gray-300 hover:text-brand-600 transition-colors"
                >
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertsList({ alerts }) {
  if (!alerts?.length) {
    return (
      <div className="flex items-center gap-2 text-sm text-brand-600 py-3">
        <CheckCircle2 className="w-4 h-4" />
        No active portfolio alerts.
      </div>
    )
  }
  return (
    <ul className="space-y-2">
      {alerts.map((a, i) => (
        <li key={i} className="flex gap-3 items-start">
          <AlertSeverityBar level={a.severity} />
          <div className="min-w-0">
            <p className="text-sm text-gray-800 leading-snug">{a.message}</p>
            {a.workspace_name && (
              <p className="text-[10px] text-gray-400 mt-0.5 capitalize">{a.type.replace(/_/g, ' ')} · {a.workspace_name}</p>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}

function TrendSection({ trending }) {
  const { improving = [], deteriorating = [] } = trending ?? {}
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div>
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
          <TrendingUp className="w-3.5 h-3.5 text-brand-500" /> Improving
        </h3>
        {improving.length === 0
          ? <p className="text-xs text-gray-400">No workspaces improving this month.</p>
          : (
            <ul className="space-y-1.5">
              {improving.map(r => (
                <li key={r.workspace_id} className="flex items-center justify-between text-sm">
                  <span className="text-gray-700 font-medium">{r.workspace_name}</span>
                  <DeltaChip delta={r.delta} />
                </li>
              ))}
            </ul>
          )
        }
      </div>
      <div>
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
          <TrendingDown className="w-3.5 h-3.5 text-red-500" /> Deteriorating
        </h3>
        {deteriorating.length === 0
          ? <p className="text-xs text-gray-400">No workspaces deteriorating this month.</p>
          : (
            <ul className="space-y-1.5">
              {deteriorating.map(r => (
                <li key={r.workspace_id} className="flex items-center justify-between text-sm">
                  <span className="text-gray-700 font-medium">{r.workspace_name}</span>
                  <DeltaChip delta={r.delta} />
                </li>
              ))}
            </ul>
          )
        }
      </div>
    </div>
  )
}

function SharedDepsTable({ deps }) {
  if (!deps?.length) {
    return <p className="text-sm text-gray-400 py-3">No shared vendor dependencies detected across multiple customers.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-100 text-left text-xs text-gray-400 uppercase tracking-wide">
            <th className="pb-2 font-medium">Vendor</th>
            <th className="pb-2 font-medium">Customers</th>
            <th className="pb-2 font-medium">Portfolio %</th>
            <th className="pb-2 font-medium">Exposure</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {deps.map((d, i) => (
            <tr key={i}>
              <td className="py-2 font-medium text-gray-800">{d.vendor_name}</td>
              <td className="py-2 text-gray-600">{d.workspace_count}</td>
              <td className="py-2 text-gray-600">{d.pct_of_portfolio}%</td>
              <td className="py-2">
                <div className="w-24 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${d.pct_of_portfolio}%`,
                      backgroundColor: d.pct_of_portfolio >= 75 ? '#EF4444' : d.pct_of_portfolio >= 50 ? '#F59E0B' : '#00876A',
                    }}
                  />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PortfolioRiskPage() {
  const navigate   = useNavigate()
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await api.getPortfolioRisk())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleWorkspaceClick = (wsId) => {
    localStorage.setItem('cybermeters_workspace_id', wsId)
    navigate('/ws/business-risk')
  }

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <div className="animate-spin w-6 h-6 border-2 border-brand-600 border-t-transparent rounded-full" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-8">
        <div className="card p-6 border border-red-100 bg-red-50 flex items-center gap-3 text-red-700">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <div>
            <p className="font-semibold">Failed to load portfolio risk</p>
            <p className="text-sm mt-0.5">{error}</p>
          </div>
          <button onClick={load} className="ml-auto btn-ghost text-red-600">Retry</button>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-screen-xl mx-auto">

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Portfolio Risk</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Multi-customer risk intelligence for MSPs and security teams.
          </p>
        </div>
        <button onClick={load} className="btn-ghost flex items-center gap-1.5">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {data && (
        <>
          {/* Executive summary */}
          {data.executive_summary && (
            <div className="card p-5 mb-6 border-l-4 border-brand-500 bg-brand-50">
              <p className="text-sm font-semibold text-brand-900 mb-1">Executive Summary</p>
              <p className="text-sm text-brand-800 leading-relaxed">{data.executive_summary}</p>
            </div>
          )}

          {/* KPI row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatCard icon={Users}         label="Customers Monitored" value={data.workspace_count ?? 0} />
            <StatCard icon={Shield}        label="Portfolio Score"      value={data.portfolio_score ?? '—'} />
            <StatCard
              icon={AlertTriangle}
              label="High Risk"
              value={data.high_risk_workspaces ?? 0}
              warning={(data.high_risk_workspaces ?? 0) > 0}
            />
            <StatCard
              icon={AlertTriangle}
              label="Critical"
              value={data.critical_workspaces ?? 0}
              danger={(data.critical_workspaces ?? 0) > 0}
            />
          </div>

          {/* Portfolio score + Alerts side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">

            {/* Score ring card */}
            <div className="card p-6 flex flex-col items-center justify-center gap-3">
              <PortfolioScoreRing score={data.portfolio_score} />
              <div className="text-center">
                <p className="font-semibold text-gray-900">Portfolio Score</p>
                <p className="text-xs text-gray-400 mt-0.5">Average BRS across all customers</p>
              </div>
              {data.portfolio_score != null && (
                <span className={`text-xs font-semibold px-3 py-1 rounded-full capitalize ${
                  data.portfolio_score >= 75 ? 'bg-brand-50 text-brand-700' :
                  data.portfolio_score >= 55 ? 'bg-amber-50 text-amber-700' :
                  data.portfolio_score >= 35 ? 'bg-orange-50 text-orange-700' :
                  'bg-red-50 text-red-700'
                }`}>
                  {data.portfolio_score >= 75 ? 'Healthy' : data.portfolio_score >= 55 ? 'Moderate' : data.portfolio_score >= 35 ? 'Elevated' : 'Serious'}
                </span>
              )}
            </div>

            {/* Alerts */}
            <div className="card p-6 lg:col-span-2">
              <h2 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                Portfolio Alerts
                {data.portfolio_alerts?.length > 0 && (
                  <span className="ml-auto text-xs font-bold bg-red-50 text-red-700 px-2 py-0.5 rounded-full">
                    {data.portfolio_alerts.length}
                  </span>
                )}
              </h2>
              <AlertsList alerts={data.portfolio_alerts} />
            </div>
          </div>

          {/* Rankings table */}
          <div className="card p-6 mb-6">
            <h2 className="font-semibold text-gray-900 mb-4">Customer Risk Rankings</h2>
            <RiskRankingsTable rankings={data.risk_rankings} onWorkspaceClick={handleWorkspaceClick} />
          </div>

          {/* Trend + Shared deps */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-4">Risk Trends (30 days)</h2>
              <TrendSection trending={data.trending} />
            </div>

            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-1 flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-gray-400" />
                Shared Vendor Dependencies
              </h2>
              <p className="text-xs text-gray-400 mb-4">
                Vendors used across multiple customer environments. A disruption to these providers creates portfolio-wide exposure.
              </p>
              <SharedDepsTable deps={data.shared_dependencies} />
            </div>
          </div>

          {/* Footer note */}
          <div className="mt-6 card p-4 border border-blue-100 bg-blue-50">
            <p className="text-xs text-blue-700 leading-relaxed">
              Portfolio risk intelligence is derived entirely from existing CyberMeters scan data. BRS scores, supply chain intelligence, and vendor risk data are aggregated across all accessible customer workspaces. Last calculated: {data.calculated_at ? new Date(data.calculated_at).toLocaleString() : '—'}
            </p>
          </div>
        </>
      )}

      {!data && !loading && !error && (
        <div className="card p-12 text-center">
          <Shield className="w-10 h-10 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500 font-medium">No portfolio risk data yet</p>
          <p className="text-sm text-gray-400 mt-1">Add workspaces and run scans to generate portfolio intelligence.</p>
        </div>
      )}
    </div>
  )
}
