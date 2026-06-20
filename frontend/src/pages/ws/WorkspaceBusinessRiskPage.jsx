import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle, CheckCircle2, TrendingUp, Mail, Globe,
  ShieldCheck, Tag, Package2, RefreshCw,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage from '../../components/WsPage'

// ── Grade badge ──────────────────────────────────────────────────────────────
function GradeBadge({ grade, label, score }) {
  const styles = {
    A: 'bg-emerald-50 border-emerald-200 text-emerald-700',
    B: 'bg-blue-50   border-blue-200   text-blue-700',
    C: 'bg-amber-50  border-amber-200  text-amber-700',
    D: 'bg-orange-50 border-orange-200 text-orange-700',
    F: 'bg-red-50    border-red-200    text-red-700',
  }
  const style = styles[grade] ?? styles['F']
  return (
    <div className={`inline-flex items-center gap-4 rounded-2xl border px-6 py-5 ${style}`}>
      <span className="text-5xl font-black leading-none">{grade}</span>
      <div>
        <p className="text-xs font-semibold uppercase tracking-widest opacity-60">Business Risk Score</p>
        <p className="text-3xl font-bold leading-tight">{score}<span className="text-base font-normal opacity-50">/100</span></p>
        <p className="text-sm font-medium opacity-70">{label}</p>
      </div>
    </div>
  )
}

// ── Category row ─────────────────────────────────────────────────────────────
function CategoryRow({ icon: Icon, label, category, weight }) {
  if (!category) return null
  const { score, issues } = category
  const pct = Math.max(0, Math.min(100, score))
  const barColor = score >= 80 ? 'bg-emerald-500' : score >= 60 ? 'bg-blue-500' : score >= 40 ? 'bg-amber-500' : 'bg-red-500'
  const textColor = score >= 80 ? 'text-emerald-700' : score >= 60 ? 'text-blue-700' : score >= 40 ? 'text-amber-700' : 'text-red-700'

  return (
    <div className="py-4 border-b border-gray-100 last:border-0">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-8 h-8 rounded-lg bg-gray-50 flex items-center justify-center flex-shrink-0">
          <Icon className="w-4 h-4 text-gray-500" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm font-semibold text-gray-800">{label}</span>
            <span className="flex items-center gap-2">
              <span className="text-xs text-gray-400">weight {Math.round(weight * 100)}%</span>
              <span className={`text-sm font-bold ${textColor}`}>{score}</span>
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-gray-100 overflow-hidden">
            <div className={`h-full ${barColor} transition-all`} style={{ width: `${pct}%` }} />
          </div>
        </div>
      </div>
      {issues && issues.length > 0 && (
        <div className="ml-11 space-y-1">
          {issues.map((issue, i) => (
            <div key={i} className="flex items-start gap-1.5 text-xs text-gray-500">
              <AlertTriangle className="w-3 h-3 text-amber-400 flex-shrink-0 mt-0.5" />
              {issue}
            </div>
          ))}
        </div>
      )}
      {(!issues || issues.length === 0) && (
        <div className="ml-11 flex items-center gap-1.5 text-xs text-emerald-600">
          <CheckCircle2 className="w-3 h-3" />
          No issues detected
        </div>
      )}
    </div>
  )
}

// ── Custom tooltip for chart ──────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-white border border-gray-200 rounded-lg px-3 py-2 shadow text-xs">
      <p className="text-gray-500 mb-1">{new Date(label).toLocaleDateString()}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: p.color }} className="font-semibold">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
const CATEGORIES = [
  { key: 'email_risk',    label: 'Email Risk',      icon: Mail,       weight: 0.25 },
  { key: 'service_health', label: 'Service Health',  icon: Globe,      weight: 0.20 },
  { key: 'customer_trust', label: 'Customer Trust',  icon: ShieldCheck, weight: 0.20 },
  { key: 'brand_exposure', label: 'Brand Exposure',  icon: Tag,        weight: 0.20 },
  { key: 'supply_chain',  label: 'Supply Chain',    icon: Package2,   weight: 0.15 },
]

export default function WorkspaceBusinessRiskPage() {
  const { wsId, wsName } = useWorkspace()
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId) return
    setLoading(true)
    setError(null)
    try {
      setData(await api.getWorkspaceBusinessRisk(wsId))
    } catch (e) {
      setError(e.message || 'Failed to load business risk score')
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  const trendData = (data?.trend ?? []).map(t => ({
    date:   t.date,
    BRS:    t.brs_score,
    ASM:    t.asm_score,
  }))

  return (
    <WsPage wsId={wsId} wsName={wsName}>
      <div className="max-w-screen-lg mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Business Risk Score</h1>
            <p className="text-sm text-gray-500 mt-1">
              Executive risk composite across email, infrastructure, brand, and supply chain.
            </p>
          </div>
          <button onClick={load} disabled={loading} className="btn-secondary flex items-center gap-2">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="rounded-xl border border-red-100 bg-red-50 px-4 py-3 flex items-center gap-2 text-sm text-red-600 mb-6">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        {loading && !data ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="card p-6 animate-pulse">
                <div className="h-4 bg-gray-100 rounded w-1/3 mb-3" />
                <div className="h-8 bg-gray-100 rounded w-1/2" />
              </div>
            ))}
          </div>
        ) : data ? (
          <div className="space-y-5">

            {/* Grade + Narrative */}
            <div className="card p-6">
              <div className="flex flex-col md:flex-row md:items-start gap-6">
                <GradeBadge grade={data.grade} label={data.grade_label} score={data.brs} />
                <div className="flex-1">
                  <p className="text-sm text-gray-700 leading-relaxed mb-4">{data.narrative}</p>
                  {data.latest_scan && (
                    <div className="text-xs text-gray-400 space-y-0.5">
                      <p>ASM Score: <span className="font-semibold text-gray-600">{data.latest_scan.asm_score} ({data.latest_scan.asm_rating})</span></p>
                      <p>Last scan: <span className="font-semibold text-gray-600">{new Date(data.latest_scan.scanned_at).toLocaleString()}</span></p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Top Concerns */}
            {data.top_concerns?.length > 0 && (
              <div className="card p-6">
                <h2 className="text-sm font-semibold text-gray-900 mb-4">Top Concerns</h2>
                <div className="space-y-2">
                  {data.top_concerns.map((c, i) => (
                    <div key={i} className="flex items-start gap-3 rounded-lg bg-amber-50 border border-amber-100 px-4 py-3">
                      <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="text-xs font-semibold text-amber-700">{c.category}</p>
                        <p className="text-sm text-amber-800">{c.issue}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Category Breakdown */}
            <div className="card p-6">
              <h2 className="text-sm font-semibold text-gray-900 mb-2">Category Breakdown</h2>
              <p className="text-xs text-gray-400 mb-4">
                BRS = (Email 25%) + (Service Health 20%) + (Customer Trust 20%) + (Brand 20%) + (Supply Chain 15%)
              </p>
              <div>
                {CATEGORIES.map(({ key, label, icon, weight }) => (
                  <CategoryRow
                    key={key}
                    icon={icon}
                    label={label}
                    weight={weight}
                    category={data.categories?.[key]}
                  />
                ))}
              </div>
            </div>

            {/* Workspace Context */}
            <div className="card p-6">
              <h2 className="text-sm font-semibold text-gray-900 mb-4">Workspace Intelligence</h2>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="rounded-lg bg-gray-50 px-4 py-3">
                  <p className="text-xs text-gray-500 mb-1">Active Brand Risks</p>
                  <p className="text-xl font-bold text-gray-900">
                    {(data.workspace_context?.brand_high_risk ?? 0) + (data.workspace_context?.brand_med_risk ?? 0)}
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {data.workspace_context?.brand_high_risk ?? 0} high · {data.workspace_context?.brand_med_risk ?? 0} medium
                  </p>
                </div>
                <div className="rounded-lg bg-gray-50 px-4 py-3">
                  <p className="text-xs text-gray-500 mb-1">Active Vendors</p>
                  <p className="text-xl font-bold text-gray-900">{data.workspace_context?.vendor_total ?? 0}</p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {data.workspace_context?.vendor_high_risk ?? 0} high · {data.workspace_context?.vendor_med_risk ?? 0} medium risk
                  </p>
                </div>
                <div className="rounded-lg bg-gray-50 px-4 py-3">
                  <p className="text-xs text-gray-500 mb-1">Score Last Updated</p>
                  <p className="text-sm font-semibold text-gray-900">
                    {data.generated_at ? new Date(data.generated_at).toLocaleString() : '—'}
                  </p>
                </div>
              </div>
            </div>

            {/* Trend chart */}
            {trendData.length > 1 && (
              <div className="card p-6">
                <div className="flex items-center gap-2 mb-4">
                  <TrendingUp className="w-4 h-4 text-gray-400" />
                  <h2 className="text-sm font-semibold text-gray-900">Score Trend</h2>
                </div>
                <ResponsiveContainer width="100%" height={180}>
                  <LineChart data={trendData} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                    <XAxis
                      dataKey="date"
                      tick={{ fontSize: 11, fill: '#9ca3af' }}
                      tickFormatter={v => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                    />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#9ca3af' }} />
                    <Tooltip content={<ChartTooltip />} />
                    <Line type="monotone" dataKey="BRS" stroke="#6366f1" strokeWidth={2} dot={false} name="BRS" />
                    <Line type="monotone" dataKey="ASM" stroke="#94a3b8" strokeWidth={1.5} dot={false} name="ASM" strokeDasharray="4 2" />
                  </LineChart>
                </ResponsiveContainer>
                <p className="text-[11px] text-gray-400 mt-2 text-center">
                  BRS (indigo) vs ASM technical score (gray dashed) — last {trendData.length} scans
                </p>
              </div>
            )}

            {trendData.length === 0 && !loading && (
              <div className="card p-6 text-center text-sm text-gray-500">
                <TrendingUp className="w-6 h-6 text-gray-300 mx-auto mb-2" />
                Trend data will appear after multiple scans.
              </div>
            )}

          </div>
        ) : null}
      </div>
    </WsPage>
  )
}
