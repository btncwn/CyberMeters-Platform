import { useState, useEffect, useCallback } from 'react'
import {
  BarChart2, Shield, Server, AlertTriangle,
  Package2, Zap, Tag, Terminal, TrendingUp, TrendingDown, Minus,
} from 'lucide-react'
import {
  AreaChart, Area, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import StatCard from '../../components/StatCard'

function fmt(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function ScoreGauge({ score, rating }) {
  if (score == null) return <span className="text-3xl font-black text-gray-300">—</span>
  const color = score >= 80 ? 'text-brand-600' : score >= 60 ? 'text-amber-500' : 'text-red-500'
  return (
    <div className="flex items-end gap-2">
      <span className={`text-5xl font-black leading-none ${color}`}>{score}</span>
      <span className="text-sm text-gray-400 mb-1">/ 100</span>
    </div>
  )
}

export default function WorkspaceDashboard() {
  const { wsId, wsName } = useWorkspace()
  const [scorecard, setScorecard] = useState(null)
  const [timeline, setTimeline]   = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const [sc, tl] = await Promise.all([
        api.getWorkspaceScorecard(wsId),
        api.getWorkspacePostureTimeline(wsId).catch(() => ({ timeline: [] })),
      ])
      setScorecard(sc)
      setTimeline((tl.timeline || []).slice(-30))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const sc = scorecard

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Executive Dashboard</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {wsName} · Last scan {sc ? fmt(sc.last_scan_at) : '—'}
          </p>
        </div>
        <div className="card px-6 py-4 text-center">
          <p className="label mb-1">Security Score</p>
          <ScoreGauge score={sc?.security_score} rating={sc?.risk_rating} />
          <p className="text-xs font-semibold text-gray-400 mt-1 capitalize">{sc?.risk_rating || '—'}</p>
        </div>
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard icon={Server}       label="Active Assets"    value={sc?.active_assets ?? '—'} sub={`${sc?.new_assets_30d ?? 0} new in 30d`} />
        <StatCard icon={AlertTriangle} label="Critical Findings" value={sc?.critical_findings ?? '—'} danger={(sc?.critical_findings ?? 0) > 0} />
        <StatCard icon={Package2}     label="Vendors Detected" value={sc?.vendors_detected ?? '—'} warning={(sc?.vendor_risk?.high ?? 0) > 0} sub={sc?.vendor_risk?.high > 0 ? `${sc.vendor_risk.high} high-risk` : undefined} />
        <StatCard icon={Zap}          label="SaaS Exposures"   value={sc?.saas_exposures ?? '—'} warning={(sc?.saas_exposures ?? 0) > 0} />
        <StatCard icon={Tag}          label="Brand Risks"      value={sc?.brand_risks?.active ?? '—'} danger={(sc?.brand_risks?.high ?? 0) > 0} sub={sc?.brand_risks?.high > 0 ? `${sc.brand_risks.high} high-risk` : undefined} />
        <StatCard icon={Terminal}     label="Admin Surfaces"   value={sc?.admin_surfaces ?? '—'} danger={(sc?.admin_surfaces ?? 0) > 0} />
        <StatCard icon={Shield}       label="Cert Risk"        value={sc?.certificate_risks?.risk_level ?? '—'} warning={['high','critical'].includes(sc?.certificate_risks?.risk_level)} />
        <StatCard icon={BarChart2}    label="Events (30d)"     value={sc?.asset_events_30d ?? '—'} sub="surface changes" />
      </div>

      {/* Charts */}
      {timeline.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          {/* Score Trend */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-gray-900">Risk Score Trend</h2>
              {timeline.length > 1 && (() => {
                const first = timeline[0]?.score
                const last  = timeline[timeline.length - 1]?.score
                const diff  = last - first
                const Icon  = diff > 0 ? TrendingUp : diff < 0 ? TrendingDown : Minus
                const color = diff > 0 ? 'text-brand-600' : diff < 0 ? 'text-red-500' : 'text-gray-400'
                return (
                  <span className={`flex items-center gap-1 text-sm font-semibold ${color}`}>
                    <Icon className="w-4 h-4" />
                    {diff > 0 ? '+' : ''}{diff}
                  </span>
                )
              })()}
            </div>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickFormatter={fmt} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} width={28} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                <Line type="monotone" dataKey="score" stroke="#00876A" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Asset Growth */}
          <div className="card p-6">
            <h2 className="font-semibold text-gray-900 mb-4">Asset Growth</h2>
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickFormatter={fmt} />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} width={28} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                <Area type="monotone" dataKey="total_assets" stroke="#00876A" fill="#e6f4f1" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Executive Summary */}
      {sc?.executive_summary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Good */}
          <div className="card p-5">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-brand-500" />
              <h3 className="font-semibold text-gray-900 text-sm">Good</h3>
            </div>
            {sc.executive_summary.good.length === 0
              ? <p className="text-xs text-gray-400">No positive signals yet.</p>
              : sc.executive_summary.good.map((s, i) => (
                  <p key={i} className="text-xs text-gray-600 mb-1.5 leading-relaxed">{s}</p>
                ))}
          </div>

          {/* Attention */}
          <div className="card p-5">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-amber-400" />
              <h3 className="font-semibold text-gray-900 text-sm">Attention Required</h3>
            </div>
            {sc.executive_summary.attention_required.length === 0
              ? <p className="text-xs text-gray-400">Nothing requires attention.</p>
              : sc.executive_summary.attention_required.map((s, i) => (
                  <p key={i} className="text-xs text-gray-600 mb-1.5 leading-relaxed">{s}</p>
                ))}
          </div>

          {/* Urgent */}
          <div className="card p-5 border-red-100">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <h3 className="font-semibold text-gray-900 text-sm">Urgent</h3>
            </div>
            {sc.executive_summary.urgent.length === 0
              ? <p className="text-xs text-gray-400">No urgent issues.</p>
              : sc.executive_summary.urgent.map((s, i) => (
                  <p key={i} className="text-xs text-red-700 mb-1.5 leading-relaxed">{s}</p>
                ))}
          </div>
        </div>
      )}
    </WsPage>
  )
}
