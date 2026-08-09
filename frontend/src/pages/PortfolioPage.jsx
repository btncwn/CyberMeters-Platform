import { parseServerDate } from '../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Globe, Server, Package2, AlertTriangle, Shield, Activity,
  FileText, TrendingUp, TrendingDown, Minus, Clock, ArrowRight,
  Building2, Layers, RefreshCw, ShieldCheck, XCircle,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { api } from '../api'
import StatCard from '../components/StatCard'
import RiskBadge from '../components/RiskBadge'
import { bandMeta, metaForScore } from '../lib/score-presentation'
import { assetLifecycleClaimDisplay } from '../lib/assetLifecycleClaimDisplay'

// RatingBadge renders the CANONICAL Cyber Metrics Score band vocabulary via the
// mirror module (M5.e) — one label/tone source, unknown stays neutral.
function RatingBadge({ rating }) {
  if (!rating) return <span className="text-gray-300 text-xs">—</span>
  const meta = bandMeta(String(rating).toLowerCase())
  const cfg = { label: meta.label, cls: meta.pill }
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded-full border capitalize ${cfg.cls}`}>
      {cfg.label}
    </span>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return parseServerDate(s).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function fmtDateTime(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return parseServerDate(s).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function fmtDay(str) {
  if (!str) return str
  const [, m, d] = str.split('-')
  return `${m}/${d}`
}

function ScorePill({ score }) {
  if (score == null) return <span className="text-gray-300 text-sm font-semibold">—</span>
  return <span className={`text-sm font-bold ${metaForScore(score).text}`}>{score}</span>
}

function SeverityBadge({ level }) {
  const cls = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
    info:     'badge-low',
  }[(level || '').toLowerCase()] ?? 'badge-unknown'
  return <span className={cls}>{level || 'unknown'}</span>
}

function StatusDot({ status }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${
      status === 'active' ? 'text-brand-600' : 'text-gray-400'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${
        status === 'active' ? 'bg-brand-500' : 'bg-gray-300'
      }`} />
      {status === 'active' ? 'Active' : 'Inactive'}
    </span>
  )
}

function SectionError({ message, onRetry }) {
  return (
    <div className="rounded-xl border border-red-100 bg-red-50 px-4 py-3 flex items-center gap-3 text-sm text-red-600">
      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
      <span>{message}</span>
      {onRetry && (
        <button onClick={onRetry} className="ml-auto btn-ghost text-red-500 hover:text-red-600 py-0.5 px-2">
          Retry
        </button>
      )}
    </div>
  )
}

function EmptyMessage({ children }) {
  return (
    <div className="py-12 text-center text-gray-400 text-sm">{children}</div>
  )
}

// ── Overview Section ──────────────────────────────────────────────────────────

function OverviewSection({ data, loading, error, onRetry }) {
  if (loading) return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
      {Array.from({ length: 9 }).map((_, i) => (
        <div key={i} className="card p-5 animate-pulse">
          <div className="h-3 bg-gray-100 rounded w-1/2 mb-3" />
          <div className="h-7 bg-gray-100 rounded w-2/3" />
        </div>
      ))}
    </div>
  )
  if (error) return <div className="mb-8"><SectionError message={error} onRetry={onRetry} /></div>
  if (!data) return null

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
      <StatCard icon={Building2}     label="Workspaces"       value={data.total_workspaces}       sub={`${data.total_domains} domains`} />
      <StatCard icon={Globe}         label="Domains"          value={data.total_domains} />
      <StatCard icon={Server}        label="Active Assets"    value={data.total_assets}           sub={`+${data.new_assets_7d} this week`} />
      <StatCard icon={Package2}      label="Vendors"          value={data.total_vendors} />
      <StatCard icon={FileText}      label="Reports (30d)"    value={data.new_reports_30d}        sub={`${data.total_reports} total`} />
      <StatCard icon={AlertTriangle} label="Critical Findings" value={data.critical_findings}
        danger={(data.critical_findings ?? 0) > 0} />
      <StatCard icon={AlertTriangle} label="High Findings"    value={data.high_findings}
        warning={(data.high_findings ?? 0) > 0} />
      <StatCard icon={Shield}        label="Avg Score"        value={data.average_score ?? '—'}   sub="across all workspaces" />
      <StatCard icon={Activity}      label="New Assets (7d)"  value={data.new_assets_7d} />
      <StatCard icon={ShieldCheck}   label="Verified Domains"   value={data.verified_domains ?? '—'} />
      <StatCard icon={Clock}         label="Unverified Domains" value={data.unverified_domains ?? '—'} warning={(data.unverified_domains ?? 0) > 0} />
      <StatCard icon={XCircle}       label="Verif. Failures"    value={data.verification_failures ?? '—'} danger={(data.verification_failures ?? 0) > 0} />
    </div>
  )
}

// ── Workspace Risk Table ──────────────────────────────────────────────────────

function WorkspaceTable({ rows, loading, error, onRetry }) {
  const navigate = useNavigate()

  function openWorkspace(ws) {
    localStorage.setItem('cybermeters_workspace_id', ws.workspace_id)
    localStorage.setItem('cybermeters_workspace_name', ws.workspace_name)
    navigate('/ws/dashboard')
  }

  if (loading) return (
    <div className="card overflow-hidden mb-8">
      <div className="p-6 border-b border-gray-100">
        <div className="h-5 bg-gray-100 rounded animate-pulse w-48" />
      </div>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="px-6 py-4 border-b border-gray-50 flex gap-4">
          {Array.from({ length: 6 }).map((_, j) => (
            <div key={j} className="h-4 bg-gray-100 rounded animate-pulse flex-1" />
          ))}
        </div>
      ))}
    </div>
  )

  if (error) return <div className="mb-8"><SectionError message={error} onRetry={onRetry} /></div>

  if (!rows || rows.length === 0) return (
    <div className="card p-8 mb-8 text-center">
      <Building2 className="w-10 h-10 text-gray-200 mx-auto mb-3" />
      <p className="text-sm text-gray-500 font-medium">Create a workspace to start monitoring your portfolio.</p>
      <button onClick={() => navigate('/workspaces')} className="btn-primary mt-4 mx-auto">
        <Building2 className="w-4 h-4" /> Create Workspace
      </button>
    </div>
  )

  return (
    <div className="card overflow-hidden mb-8">
      <div className="flex items-center justify-between p-6 border-b border-gray-100">
        <h2 className="font-semibold text-gray-900">Workspace Risk Overview</h2>
        <span className="text-xs text-gray-400">{rows.length} workspace{rows.length !== 1 ? 's' : ''} · sorted by risk</span>
      </div>
      <div className="overflow-x-auto">
        <table className="data-table w-full">
          <thead>
            <tr>
              <th className="text-left">Workspace</th>
              <th className="text-center">Domains</th>
              <th className="text-center">Assets</th>
              <th className="text-center">Score</th>
              <th className="text-center">CyberMeters assessment band</th>
              <th className="text-center">Critical</th>
              <th className="text-center">High</th>
              <th className="text-left">Last Scan</th>
              <th className="text-left">Last Report</th>
              <th className="text-center">Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((ws) => (
              <tr
                key={ws.workspace_id}
                className="hover:bg-gray-50/60 cursor-pointer transition-colors"
                onClick={() => openWorkspace(ws)}
              >
                <td className="font-medium text-gray-900">{ws.workspace_name}</td>
                <td className="text-center text-gray-600">{ws.domains}</td>
                <td className="text-center text-gray-600">{ws.active_assets}</td>
                <td className="text-center"><ScorePill score={ws.latest_score} /></td>
                <td className="text-center">
                  <RatingBadge rating={ws.risk_rating} />
                </td>
                <td className="text-center">
                  {(ws.critical_findings ?? 0) > 0
                    ? <span className="badge-critical">{ws.critical_findings}</span>
                    : <span className="text-gray-300 text-xs">0</span>}
                </td>
                <td className="text-center">
                  {(ws.high_findings ?? 0) > 0
                    ? <span className="badge-high">{ws.high_findings}</span>
                    : <span className="text-gray-300 text-xs">0</span>}
                </td>
                <td className="text-gray-500 text-sm">{fmtDate(ws.last_scan_at)}</td>
                <td className="text-gray-500 text-sm">{fmtDate(ws.last_report_at)}</td>
                <td className="text-center"><StatusDot status={ws.status} /></td>
                <td>
                  <ArrowRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Alerts Feed ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function AlertsSection({ alerts, loading, error, onRetry }) {
  if (loading) return (
    <div className="card p-6 mb-8">
      <div className="h-5 bg-gray-100 rounded animate-pulse w-40 mb-4" />
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex gap-3 py-3 border-b border-gray-50 animate-pulse">
          <div className="h-5 w-16 bg-gray-100 rounded-full" />
          <div className="flex-1 space-y-2">
            <div className="h-4 bg-gray-100 rounded w-2/3" />
            <div className="h-3 bg-gray-100 rounded w-1/2" />
          </div>
        </div>
      ))}
    </div>
  )
  if (error) return <div className="mb-8"><SectionError message={error} onRetry={onRetry} /></div>
  if (!alerts || alerts.length === 0) return (
    <div className="card p-8 mb-8 text-center">
      <Shield className="w-10 h-10 text-gray-200 mx-auto mb-3" />
      <p className="text-sm text-gray-500">No portfolio alerts yet.</p>
    </div>
  )

  // Group by severity tier
  const grouped = {
    'critical/high': alerts.filter(a => ['critical','high'].includes((a.severity||'').toLowerCase())),
    'medium':        alerts.filter(a => (a.severity||'').toLowerCase() === 'medium'),
    'low/info':      alerts.filter(a => ['low','info'].includes((a.severity||'').toLowerCase())),
  }

  const tierLabels = {
    'critical/high': { label: 'Critical / High', border: 'border-red-100', bg: 'bg-red-50/30' },
    'medium':        { label: 'Medium',           border: 'border-amber-100', bg: 'bg-amber-50/20' },
    'low/info':      { label: 'Low / Info',       border: 'border-gray-100', bg: '' },
  }

  return (
    <div className="card overflow-hidden mb-8">
      <div className="flex items-center justify-between p-6 border-b border-gray-100">
        <h2 className="font-semibold text-gray-900">Portfolio Alerts</h2>
        <span className="text-xs text-gray-400">{alerts.length} alert{alerts.length !== 1 ? 's' : ''}</span>
      </div>
      <div>
        {Object.entries(grouped).map(([tier, items]) => {
          if (items.length === 0) return null
          const { label, border, bg } = tierLabels[tier]
          return (
            <div key={tier} className={`border-b ${border} last:border-0 ${bg}`}>
              <div className="px-6 py-2 text-[10px] font-semibold text-gray-400 uppercase tracking-widest">
                {label} · {items.length}
              </div>
              {items.map((alert, idx) => (
                <div
                  key={idx}
                  className="px-6 py-3 border-t border-gray-50 first:border-t-0 flex items-start gap-3"
                >
                  <div className="mt-0.5 flex-shrink-0">
                    <SeverityBadge level={alert.severity} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-gray-500">{alert.workspace_name}</span>
                      <span className="text-xs text-gray-300">·</span>
                      <span className="text-xs text-gray-400 font-mono">{(alert.type || '').replace(/_/g, ' ')}</span>
                    </div>
                    <p className="text-sm font-medium text-gray-800 mt-0.5 truncate">{assetLifecycleClaimDisplay({ ...alert, event_type: alert.type }).title}</p>
                    {assetLifecycleClaimDisplay({ ...alert, event_type: alert.type }).description && (
                      <p className="text-xs text-gray-400 mt-0.5 line-clamp-1">{assetLifecycleClaimDisplay({ ...alert, event_type: alert.type }).description}</p>
                    )}
                  </div>
                  <div className="flex-shrink-0 flex items-center gap-1 text-xs text-gray-300">
                    <Clock className="w-3 h-3" />
                    {fmtDateTime(alert.created_at)}
                  </div>
                </div>
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Trends Chart ──────────────────────────────────────────────────────────────

function TrendsSection({ trend, loading, error, onRetry }) {
  if (loading) return (
    <div className="card p-6 mb-8 animate-pulse">
      <div className="h-5 bg-gray-100 rounded w-48 mb-6" />
      <div className="h-48 bg-gray-50 rounded-xl" />
    </div>
  )
  if (error) return <div className="mb-8"><SectionError message={error} onRetry={onRetry} /></div>
  if (!trend || trend.length === 0) return (
    <div className="card p-8 mb-8 text-center">
      <TrendingUp className="w-10 h-10 text-gray-200 mx-auto mb-3" />
      <p className="text-sm text-gray-500">Trend data will appear after scans complete.</p>
    </div>
  )

  // Score trend direction indicator
  const first = trend[0]?.average_score
  const last  = trend[trend.length - 1]?.average_score
  const diff  = last != null && first != null ? Math.round(last - first) : null
  const TrendIcon  = diff == null ? null : diff > 0 ? TrendingUp : diff < 0 ? TrendingDown : Minus
  const trendColor = diff == null ? '' : diff > 0 ? 'text-brand-600' : diff < 0 ? 'text-red-500' : 'text-gray-400'

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      {/* Score trend */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-gray-900">Portfolio Score Trend (30d)</h2>
          {TrendIcon && diff != null && (
            <span className={`flex items-center gap-1 text-sm font-semibold ${trendColor}`}>
              <TrendIcon className="w-4 h-4" />
              {diff > 0 ? '+' : ''}{diff} pts
            </span>
          )}
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={trend} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
            <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} tickFormatter={fmtDay} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} width={28} />
            <Tooltip
              contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }}
              formatter={(v, n) => [v != null ? v : '—', n]}
            />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Line type="monotone" dataKey="average_score" name="Avg Score"  stroke="#00876A" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="lowest_score"  name="Lowest"     stroke="#ef4444" strokeWidth={1.5} dot={false} strokeDasharray="4 3" />
            <Line type="monotone" dataKey="highest_score" name="Highest"    stroke="#3b82f6" strokeWidth={1.5} dot={false} strokeDasharray="4 3" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Findings trend */}
      <div className="card p-6">
        <h2 className="font-semibold text-gray-900 mb-4">Daily Findings + Scans (30d)</h2>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={trend} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
            <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} tickFormatter={fmtDay} />
            <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} width={28} />
            <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Line type="monotone" dataKey="critical_findings" name="Critical" stroke="#ef4444" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="high_findings"     name="High"    stroke="#f97316" strokeWidth={1.5} dot={false} />
            <Line type="monotone" dataKey="scans"             name="Scans"   stroke="#94a3b8" strokeWidth={1} dot={false} strokeDasharray="4 3" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function PortfolioPage() {
  const [overview,   setOverview]   = useState(null)
  const [workspaces, setWorkspaces] = useState(null)
  const [alerts,     setAlerts]     = useState(null)
  const [trend,      setTrend]      = useState(null)

  const [overviewErr,   setOverviewErr]   = useState(null)
  const [workspacesErr, setWorkspacesErr] = useState(null)
  const [alertsErr,     setAlertsErr]     = useState(null)
  const [trendErr,      setTrendErr]      = useState(null)

  const [overviewLoading,   setOverviewLoading]   = useState(true)
  const [workspacesLoading, setWorkspacesLoading] = useState(true)
  const [alertsLoading,     setAlertsLoading]     = useState(true)
  const [trendLoading,      setTrendLoading]      = useState(true)

  const [refreshing, setRefreshing] = useState(false)

  const loadAll = useCallback(async (silent = false) => {
    if (!silent) {
      setOverviewLoading(true); setWorkspacesLoading(true)
      setAlertsLoading(true);   setTrendLoading(true)
    } else {
      setRefreshing(true)
    }
    setOverviewErr(null); setWorkspacesErr(null)
    setAlertsErr(null);   setTrendErr(null)

    const [ov, ws, al, tr] = await Promise.allSettled([
      api.getPortfolioOverview(),
      api.getPortfolioWorkspaces(),
      api.getPortfolioAlerts(50),
      api.getPortfolioTrends(),
    ])

    if (ov.status === 'fulfilled') setOverview(ov.value)
    else setOverviewErr(ov.reason?.message ?? 'Failed to load overview')

    if (ws.status === 'fulfilled') setWorkspaces(ws.value?.workspaces ?? [])
    else setWorkspacesErr(ws.reason?.message ?? 'Failed to load workspaces')

    if (al.status === 'fulfilled') setAlerts(al.value?.alerts ?? [])
    else setAlertsErr(al.reason?.message ?? 'Failed to load alerts')

    if (tr.status === 'fulfilled') setTrend(tr.value?.trend ?? [])
    else setTrendErr(tr.reason?.message ?? 'Failed to load trends')

    setOverviewLoading(false); setWorkspacesLoading(false)
    setAlertsLoading(false);   setTrendLoading(false)
    setRefreshing(false)
  }, [])

  useEffect(() => { loadAll() }, [loadAll])

  const generatedAt = overview?.generated_at
  const highestRisk = overview?.highest_risk_workspace

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">

      {/* Page header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Layers className="w-6 h-6 text-brand-600" />
            Portfolio Dashboard
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Multi-workspace security posture overview
            {generatedAt && ` · as of ${fmtDateTime(generatedAt)}`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {highestRisk && (
            <div className="card px-4 py-2.5 text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-500" />
              <span className="text-gray-500">Highest risk:</span>
              <span className="font-semibold text-gray-900">{highestRisk.name}</span>
              <span className="badge-critical">{highestRisk.critical_findings} critical</span>
            </div>
          )}
          <button
            onClick={() => loadAll(true)}
            disabled={refreshing}
            className="btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Overview cards */}
      <OverviewSection
        data={overview}
        loading={overviewLoading}
        error={overviewErr}
        onRetry={() => {
          setOverviewLoading(true); setOverviewErr(null)
          api.getPortfolioOverview().then(setOverview).catch(e => setOverviewErr(e.message)).finally(() => setOverviewLoading(false))
        }}
      />

      {/* Workspace risk table */}
      <WorkspaceTable
        rows={workspaces}
        loading={workspacesLoading}
        error={workspacesErr}
        onRetry={() => {
          setWorkspacesLoading(true); setWorkspacesErr(null)
          api.getPortfolioWorkspaces().then(d => setWorkspaces(d.workspaces ?? [])).catch(e => setWorkspacesErr(e.message)).finally(() => setWorkspacesLoading(false))
        }}
      />

      {/* Trend charts */}
      <TrendsSection
        trend={trend}
        loading={trendLoading}
        error={trendErr}
        onRetry={() => {
          setTrendLoading(true); setTrendErr(null)
          api.getPortfolioTrends().then(d => setTrend(d.trend ?? [])).catch(e => setTrendErr(e.message)).finally(() => setTrendLoading(false))
        }}
      />

      {/* Alerts feed */}
      <AlertsSection
        alerts={alerts}
        loading={alertsLoading}
        error={alertsErr}
        onRetry={() => {
          setAlertsLoading(true); setAlertsErr(null)
          api.getPortfolioAlerts(50).then(d => setAlerts(d.alerts ?? [])).catch(e => setAlertsErr(e.message)).finally(() => setAlertsLoading(false))
        }}
      />

    </div>
  )
}
