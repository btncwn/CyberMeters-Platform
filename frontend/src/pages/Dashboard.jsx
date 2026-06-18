import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  RefreshCw, AlertTriangle, ShieldAlert, Eye, Wifi,
  Globe, CheckCircle, XCircle, AlertCircle, ChevronRight,
  ArrowUpRight, ScanLine, Clock, TrendingUp,
} from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'

/* ─── Helpers ──────────────────────────────────────────────────────────── */

function formatDate(str) {
  if (!str) return '—'
  return new Date(str.replace(' ', 'T') + 'Z')
    .toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function relativeTime(str) {
  if (!str) return ''
  const diff = Date.now() - new Date(str.replace(' ', 'T') + 'Z').getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

/* ─── Derive insights from real scan data + optional report ─────────────── */

function deriveInsights(scans, report) {
  const completed = scans.filter(s => s.status === 'completed')
  const failed    = scans.filter(s => s.status === 'failed').length
  const active    = scans.filter(s => ['queued','running','processing'].includes(s.status)).length
  const domains   = [...new Set(scans.map(s => s.domain))]

  // Score: use the real score from D1 (set by scan engine on the latest completed scan)
  const latestCompleted = completed[0] || null
  const score = latestCompleted?.score ?? null
  const riskLevel = latestCompleted?.rating ?? null

  // Health categories: derive from report modules if available, else use scan counts
  const mods = report?.modules ?? {}
  const healthCategories = [
    {
      label:  'DNS',
      status: mods.dns
        ? (mods.dns.resolves ? 'good' : 'danger')
        : (completed.length > 0 ? 'good' : 'unknown'),
    },
    {
      label:  'SSL / HTTPS',
      status: mods.ssl
        ? (mods.ssl.https_available ? (mods.ssl.http_redirects_to_https ? 'good' : 'warning') : 'danger')
        : (completed.length > 0 ? 'good' : 'unknown'),
    },
    {
      label:  'Email Security',
      status: mods.email_security
        ? (!mods.email_security.spf?.present || !mods.email_security.dmarc?.present
            ? 'warning'
            : mods.email_security.dmarc?.policy === 'none' ? 'warning' : 'good')
        : (failed > 0 ? 'warning' : completed.length > 0 ? 'good' : 'unknown'),
    },
    {
      label:  'Security Headers',
      status: mods.headers
        ? (mods.headers.missing?.length > 3 ? 'danger' : mods.headers.missing?.length > 1 ? 'warning' : 'good')
        : (completed.length > 0 ? 'good' : 'unknown'),
    },
    {
      label:  'IPv6',
      status: mods.dns
        ? (mods.dns.has_ipv6 ? 'good' : 'warning')
        : 'unknown',
    },
    {
      label:  'DKIM Signing',
      status: mods.email_security
        ? (mods.email_security.dkim?.present ? 'good' : 'warning')
        : 'unknown',
    },
  ]

  // Findings: use real findings from report, fall back to status-based notices
  const findings = report?.findings
    ? report.findings.slice(0, 5).map((f, i) => ({
        id:     f.id || `rf${i}`,
        title:  f.title,
        detail: f.description,
        risk:   f.severity === 'critical' ? 'critical'
              : f.severity === 'high'     ? 'high'
              : f.severity === 'medium'   ? 'medium'
              : 'low',
        scanId: report.scan_id,
      }))
    : buildStatusFindings(scans, failed, active, domains)

  // Trend: use real scores from D1 (completed scans only, newest-last for chart)
  const trend = completed
    .slice(0, 7)
    .reverse()
    .map((s, i) => ({
      label: s.domain?.split('.')[0] || `#${i + 1}`,
      value: s.score ?? 0,
      date:  s.created_at,
    }))

  // Recommended actions
  const actions = []
  if (scans.length === 0) {
    actions.push({ id: 'a1', priority: 1, title: 'Run your first security scan',  desc: 'Add a domain to discover your external attack surface exposure.',   cta: 'Start Scan', href: '/scans/new' })
  } else if (failed > 0) {
    actions.push({ id: 'a2', priority: 1, title: 'Investigate failed scans',      desc: `${failed} scan(s) returned errors. Review and retry to ensure full coverage.`, cta: 'View Scans', href: '/scans' })
  }
  if (domains.length > 0) {
    actions.push({ id: 'a3', priority: 2, title: 'Schedule regular assessments',  desc: 'Enable weekly automated scans to track your security posture over time.', cta: 'Configure',  href: '/settings' })
    actions.push({ id: 'a4', priority: 3, title: 'Export security report',        desc: 'Share your cyber risk posture with stakeholders or clients as a PDF.',    cta: 'Reports',    href: '/reports'  })
  }
  // Surface top recommendations from the report
  if (report?.recommendations?.length) {
    const topRec = report.recommendations[0]
    actions.unshift({
      id:       'ar1',
      priority: 1,
      title:    topRec.title,
      desc:     topRec.description,
      cta:      'View Details',
      href:     `/scans/${report.scan_id}`,
    })
  }

  // Count critical & high findings from report
  const criticalCount = report?.findings?.filter(f => f.severity === 'critical').length ?? 0
  const highCount     = report?.findings?.filter(f => f.severity === 'high').length ?? 0

  return {
    score, riskLevel, completed, failed, active, domains,
    healthCategories, findings, trend, actions,
    criticalCount, highCount,
  }
}

function buildStatusFindings(scans, failed, active, domains) {
  const out = []
  if (scans.length === 0)
    out.push({ id: 'f0', title: 'No domains scanned',           risk: 'high',   detail: 'Add a domain to begin your security assessment' })
  if (failed > 0)
    out.push({ id: 'f1', title: 'Scan failures detected',       risk: 'high',   detail: `${failed} scan(s) did not complete successfully` })
  if (active > 0)
    out.push({ id: 'f2', title: 'Active scans in progress',     risk: 'medium', detail: `${active} scan(s) currently running` })
  if (domains.length > 3)
    out.push({ id: 'f3', title: 'Multiple domains tracked',     risk: 'medium', detail: `${domains.length} unique domains monitored` })
  return out
}

/* ─── Score Ring ───────────────────────────────────────────────────────── */

const RISK_COLOR = {
  excellent: '#00876A', good: '#00876A', moderate: '#F59E0B',
  high: '#F97316', critical: '#EF4444',
}
const RISK_TEXT_CLS = {
  excellent: 'text-brand-600', good: 'text-brand-600', moderate: 'text-amber-500',
  high: 'text-orange-500', critical: 'text-red-500',
}
const RISK_LABEL = {
  excellent: 'Excellent', good: 'Good', moderate: 'Moderate Risk',
  high: 'High Risk', critical: 'Critical Risk',
}

function ScoreRing({ score, riskLevel }) {
  const r    = 88
  const circ = 2 * Math.PI * r

  const color  = riskLevel ? (RISK_COLOR[riskLevel] || '#E5E7EB') : score === null ? '#E5E7EB' : score >= 75 ? '#00876A' : score >= 50 ? '#F59E0B' : '#EF4444'
  const fill   = score !== null ? circ * (score / 100) : 0
  const valCls = riskLevel ? (RISK_TEXT_CLS[riskLevel] || 'text-gray-300') : score === null ? 'text-gray-300' : score >= 75 ? 'text-brand-600' : score >= 50 ? 'text-amber-500' : 'text-red-500'
  const label  = riskLevel ? (RISK_LABEL[riskLevel] || 'Unknown') : score === null ? 'No data yet' : score >= 75 ? 'Low Risk' : score >= 50 ? 'Moderate Risk' : 'High Risk'

  return (
    <div className="flex flex-col items-center select-none">
      <div className="relative w-52 h-52">
        <svg viewBox="0 0 200 200" className="w-full h-full -rotate-90">
          <circle cx="100" cy="100" r={r} fill="none" stroke="#F3F4F6" strokeWidth="14" />
          {score !== null && (
            <circle
              cx="100" cy="100" r={r} fill="none"
              stroke={color} strokeWidth="14" strokeLinecap="round"
              strokeDasharray={`${fill} ${circ - fill}`}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score !== null
            ? <><span className={`text-5xl font-bold ${valCls}`}>{score}</span><span className="text-xs text-gray-300 font-semibold mt-1 uppercase tracking-widest">/100</span></>
            : <span className="text-gray-300 text-sm font-medium">No data</span>
          }
        </div>
      </div>
      <div className={`text-base font-bold mt-1 ${valCls}`}>{label}</div>
    </div>
  )
}

/* ─── Exposure Card ────────────────────────────────────────────────────── */

const EXPOSURE_STYLES = {
  red:    { bg: 'bg-red-50',    icon: 'text-red-500',    val: 'text-red-700'    },
  orange: { bg: 'bg-orange-50', icon: 'text-orange-500', val: 'text-orange-700' },
  amber:  { bg: 'bg-amber-50',  icon: 'text-amber-500',  val: 'text-amber-700'  },
  brand:  { bg: 'bg-brand-50',  icon: 'text-brand-600',  val: 'text-brand-700'  },
}

function ExposureCard({ icon: Icon, label, value, color }) {
  const s = EXPOSURE_STYLES[color]
  return (
    <div className="card p-6 flex items-center gap-4">
      <div className={`w-12 h-12 rounded-2xl ${s.bg} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-6 h-6 ${s.icon}`} />
      </div>
      <div>
        <p className={`text-3xl font-bold ${s.val}`}>{value}</p>
        <p className="text-sm font-medium text-gray-500 mt-0.5">{label}</p>
      </div>
    </div>
  )
}

/* ─── Security Health ──────────────────────────────────────────────────── */

const HEALTH_CFG = {
  good:    { dot: 'bg-brand-500',  pill: 'bg-brand-50 text-brand-700 border-brand-100',  lbl: 'Good'    },
  warning: { dot: 'bg-amber-500',  pill: 'bg-amber-50 text-amber-700 border-amber-100',  lbl: 'Warning' },
  danger:  { dot: 'bg-red-500',    pill: 'bg-red-50 text-red-700 border-red-100',         lbl: 'At Risk' },
  unknown: { dot: 'bg-gray-300',   pill: 'bg-gray-100 text-gray-500 border-gray-200',    lbl: 'Unknown' },
}

function HealthPill({ label, status }) {
  const cfg = HEALTH_CFG[status] || HEALTH_CFG.unknown
  return (
    <div className="flex flex-col items-center gap-2">
      <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border ${cfg.pill}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
        {cfg.lbl}
      </div>
      <span className="text-xs text-gray-500 font-medium text-center">{label}</span>
    </div>
  )
}

/* ─── Trend Chart ──────────────────────────────────────────────────────── */

function TrendChart({ points }) {
  if (!points || points.length < 2) {
    return (
      <div className="h-36 flex flex-col items-center justify-center gap-2 text-gray-300 text-sm">
        <TrendingUp className="w-6 h-6" />
        Run more scans to see trend data
      </div>
    )
  }
  const W = 600, H = 130, PX = 24, PY = 16
  const vals = points.map(p => p.value)
  const min  = Math.max(0, Math.min(...vals) - 8)
  const max  = Math.min(100, Math.max(...vals) + 8)
  const xStep = (W - PX * 2) / (points.length - 1)
  const coords = points.map((p, i) => ({
    x: PX + i * xStep,
    y: PY + (1 - (p.value - min) / Math.max(1, max - min)) * (H - PY * 2),
  }))
  const pathD = coords.map((c, i) => `${i === 0 ? 'M' : 'L'}${c.x},${c.y}`).join(' ')
  const areaD = `${pathD} L${coords[coords.length-1].x},${H} L${coords[0].x},${H}Z`

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 130 }}>
      <defs>
        <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#00876A" stopOpacity="0.12" />
          <stop offset="100%" stopColor="#00876A" stopOpacity="0"    />
        </linearGradient>
      </defs>
      {[0, 0.33, 0.66, 1].map(t => (
        <line key={t} x1={PX} y1={PY + t*(H-PY*2)} x2={W-PX} y2={PY + t*(H-PY*2)} stroke="#F3F4F6" strokeWidth="1" />
      ))}
      <path d={areaD} fill="url(#trendGrad)" />
      <path d={pathD} fill="none" stroke="#00876A" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      {coords.map((c, i) => (
        <circle key={i} cx={c.x} cy={c.y} r="4" fill="#00876A" stroke="white" strokeWidth="2" />
      ))}
      {points.map((p, i) => (
        <text key={i} x={coords[i].x} y={H - 1} textAnchor="middle" fontSize="9" fill="#9CA3AF" fontFamily="Inter,sans-serif">
          {p.label}
        </text>
      ))}
    </svg>
  )
}

/* ─── Risk Badge ───────────────────────────────────────────────────────── */

function RiskBadge({ risk }) {
  if (risk === 'critical') return <span className="badge-critical">Critical</span>
  if (risk === 'high')     return <span className="badge-high">High</span>
  if (risk === 'medium')   return <span className="badge-medium">Medium</span>
  return <span className="badge-low">Low</span>
}

/* ─── Main Dashboard ───────────────────────────────────────────────────── */

export default function Dashboard() {
  const [scans,      setScans]      = useState([])
  const [report,     setReport]     = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const reportFetchedForRef = useRef(null) // tracks which scan ID we fetched report for
  const navigate = useNavigate()

  const loadReport = useCallback(async (scanId) => {
    if (reportFetchedForRef.current === scanId) return
    reportFetchedForRef.current = scanId
    try {
      const r = await api.getScanReport(scanId)
      // Only use the report if the scan is completed with real data
      if (r.status === 'completed' && (r.findings?.length > 0 || r.cyber_metrics_score > 0)) {
        setReport(r)
      }
    } catch {
      // silently fail — dashboard degrades gracefully without the report
    }
  }, [])

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getScans()
      const list = data.scans || []
      setScans(list)

      // Fetch report for the latest completed scan to populate health + findings
      const latestCompleted = list.find(s => s.status === 'completed')
      if (latestCompleted && reportFetchedForRef.current !== latestCompleted.id) {
        loadReport(latestCompleted.id)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [loadReport])

  useEffect(() => { load() }, [load])

  const ins        = deriveInsights(scans, report)
  const latestScan = scans[0] || null

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Spinner size="lg" />
      </div>
    )
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-8">

      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Overview</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {latestScan
              ? `Last assessment: ${latestScan.domain} · ${relativeTime(latestScan.created_at)}`
              : 'No scans yet — run your first assessment below'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/scans/new" className="btn-primary">
            <ScanLine className="w-4 h-4" />
            New Scan
          </Link>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* ── 1. Cyber Metrics Score ── */}
      <div className="card-md overflow-hidden">
        <div className="flex flex-col lg:flex-row">
          {/* Score ring */}
          <div className="flex flex-col items-center justify-center gap-4 px-10 py-10 lg:border-r border-gray-100 lg:min-w-[280px]">
            <span className="label">Cyber Metrics Score</span>
            <ScoreRing score={ins.score} riskLevel={ins.riskLevel} />
            <p className="text-center text-gray-400 text-xs leading-relaxed max-w-[200px]">
              {ins.score === null
                ? 'Run your first scan to generate your score.'
                : ins.score >= 75
                  ? 'Your external attack surface is well protected.'
                  : ins.score >= 50
                    ? `Moderate exposure. ${ins.findings.length} issue${ins.findings.length !== 1 ? 's' : ''} require attention.`
                    : 'Critical exposures detected — immediate action required.'}
            </p>
            {report && (
              <Link
                to={`/scans/${report.scan_id}`}
                className="text-xs text-brand-600 hover:text-brand-700 font-semibold flex items-center gap-1"
              >
                View full report <ChevronRight className="w-3 h-3" />
              </Link>
            )}
          </div>

          {/* Stats grid — real counts */}
          <div className="flex-1 grid grid-cols-2 divide-x divide-y divide-gray-100">
            {[
              { label: 'Total Scans',     value: scans.length,         sub: 'all time'          },
              { label: 'Completed',       value: ins.completed.length, sub: 'successful'         },
              { label: 'Active Scans',    value: ins.active,           sub: 'currently running'  },
              { label: 'Domains Tracked', value: ins.domains.length,   sub: 'unique domains'     },
            ].map(({ label, value, sub }) => (
              <div key={label} className="flex flex-col justify-center px-8 py-7">
                <span className="text-4xl font-bold text-gray-900">{value}</span>
                <span className="text-sm font-semibold text-gray-700 mt-1">{label}</span>
                <span className="text-xs text-gray-400 mt-0.5">{sub}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── 2. Exposure Overview ── */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-gray-900">Exposure Overview</h2>
          <Link to="/scans" className="btn-ghost text-xs">View all <ChevronRight className="w-3.5 h-3.5" /></Link>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <ExposureCard icon={ShieldAlert}   label="Critical Findings"  value={ins.criticalCount}         color="red"    />
          <ExposureCard icon={AlertTriangle} label="High Risk Findings"  value={ins.highCount}             color="orange" />
          <ExposureCard icon={Eye}           label="Domains Tracked"     value={ins.domains.length}        color="amber"  />
          <ExposureCard icon={Wifi}          label="Scans In Progress"   value={ins.active}                color="brand"  />
        </div>
      </section>

      {/* ── 3. Security Health + 5. Top Findings ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

        {/* Security Health */}
        <div className="lg:col-span-2 card p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-base font-bold text-gray-900">Security Health</h2>
            {report && (
              <span className="text-[10px] text-gray-400 font-medium">{report.domain}</span>
            )}
          </div>
          <div className="grid grid-cols-3 gap-x-4 gap-y-6">
            {ins.healthCategories.map(({ label, status }) => (
              <HealthPill key={label} label={label} status={status} />
            ))}
          </div>
          {scans.length === 0 && (
            <div className="mt-6 pt-5 border-t border-gray-100 text-center">
              <p className="text-xs text-gray-400 mb-3">Health indicators appear after your first completed scan.</p>
              <Link to="/scans/new" className="btn-primary text-xs px-4 py-2">Start a scan</Link>
            </div>
          )}
        </div>

        {/* Top Findings */}
        <div className="lg:col-span-3 card overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <h2 className="text-base font-bold text-gray-900">Top Findings</h2>
            {report && (
              <Link to={`/scans/${report.scan_id}`} className="text-xs text-brand-600 hover:text-brand-700 font-semibold flex items-center gap-1">
                Full report <ChevronRight className="w-3 h-3" />
              </Link>
            )}
          </div>
          {ins.findings.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center px-6">
              <div className="w-12 h-12 rounded-2xl bg-brand-50 flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-brand-600" />
              </div>
              <p className="text-sm font-semibold text-gray-900">No findings</p>
              <p className="text-xs text-gray-400">All checks passed on the latest completed scan</p>
            </div>
          ) : (
            <ul className="divide-y divide-gray-50">
              {ins.findings.map((f, i) => (
                <li
                  key={f.id}
                  onClick={() => f.scanId ? navigate(`/scans/${f.scanId}`) : navigate('/scans')}
                  className="flex items-start gap-4 px-6 py-4 hover:bg-gray-50 cursor-pointer transition-colors"
                >
                  <div className={`w-6 h-6 rounded-lg flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0 mt-0.5 ${
                    f.risk === 'critical' ? 'bg-red-500'    :
                    f.risk === 'high'     ? 'bg-orange-500' :
                    f.risk === 'medium'   ? 'bg-amber-400'  : 'bg-blue-400'
                  }`}>{i + 1}</div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-900">{f.title}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{f.detail}</p>
                  </div>
                  <RiskBadge risk={f.risk} />
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* ── 4. Exposure Trend ── */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-base font-bold text-gray-900">Score Trend</h2>
            <p className="text-xs text-gray-400 mt-0.5">
              {ins.trend.length > 0
                ? 'Cyber Metrics Score across completed scans'
                : 'Score history will appear after completed scans'}
            </p>
          </div>
          <span className="flex items-center gap-1.5 text-xs text-brand-600 font-semibold">
            <TrendingUp className="w-3.5 h-3.5" />
            Last {ins.trend.length} scans
          </span>
        </div>
        <TrendChart points={ins.trend} />
      </div>

      {/* ── 6. Recommended Actions ── */}
      {ins.actions.length > 0 && (
        <section>
          <h2 className="text-lg font-bold text-gray-900 mb-4">Recommended Actions</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {ins.actions.slice(0, 3).map((action, i) => (
              <div key={action.id} className="card p-5 flex flex-col gap-4 hover:shadow-card-md transition-shadow">
                <div className="flex items-start gap-3">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0 mt-0.5 ${
                    i === 0 ? 'bg-red-500' : i === 1 ? 'bg-amber-500' : 'bg-brand-600'
                  }`}>{action.priority}</div>
                  <div>
                    <p className="text-sm font-bold text-gray-900">{action.title}</p>
                    <p className="text-xs text-gray-400 mt-1 leading-relaxed">{action.desc}</p>
                  </div>
                </div>
                <Link to={action.href} className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-600 hover:text-brand-700 transition-colors">
                  {action.cta} <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Recent Scans (compact) */}
      {scans.length > 0 && (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <h2 className="text-base font-bold text-gray-900">Recent Scans</h2>
            <Link to="/scans" className="btn-ghost text-xs">View all <ChevronRight className="w-3.5 h-3.5" /></Link>
          </div>
          <ul className="divide-y divide-gray-50">
            {scans.slice(0, 5).map(scan => (
              <li
                key={scan.id}
                onClick={() => navigate(`/scans/${scan.id}`)}
                className="flex items-center gap-4 px-6 py-3.5 hover:bg-gray-50 cursor-pointer transition-colors group"
              >
                <div className="w-7 h-7 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
                  <Globe className="w-3.5 h-3.5 text-gray-400" />
                </div>
                <span className="text-sm font-semibold text-gray-900 flex-1 truncate">{scan.domain}</span>
                {/* Show real score if available */}
                {scan.score != null && (
                  <span className="text-sm font-bold text-brand-600 flex-shrink-0">{scan.score}</span>
                )}
                <span className="flex items-center gap-1.5 text-xs text-gray-500">
                  {scan.status === 'completed'
                    ? <CheckCircle className="w-4 h-4 text-brand-600" />
                    : scan.status === 'failed'
                      ? <XCircle className="w-4 h-4 text-red-500" />
                      : <Clock className="w-4 h-4 text-amber-400" />}
                  <span className="capitalize">{scan.status}</span>
                </span>
                <span className="text-xs text-gray-400 hidden sm:block flex-shrink-0">{formatDate(scan.created_at)}</span>
                <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500 transition-colors flex-shrink-0" />
              </li>
            ))}
          </ul>
        </div>
      )}

    </div>
  )
}
