import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import OnboardingProgress  from '../components/OnboardingProgress'
import FirstResultsGuide   from '../components/FirstResultsGuide'
import TeamOnboardingCard  from '../components/TeamOnboardingCard'
import RecentChangesCard   from '../components/RecentChangesCard'
import { bandMeta, metaForScore, scoreBand } from '../lib/score-presentation'
import CyberMotDomains      from '../components/CyberMotDomains'
import { SERVICE_COLORS }   from '../theme/serviceColors'

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

function assessedScan(scan) {
  const assessment = scan?.assessment
  const score = assessment
    ? Number.isFinite(assessment.display_score) ? assessment.display_score : null
    : Number.isFinite(scan?.score) ? scan.score : null
  // The backend assessment is the authority for finality. A stored scan row
  // can say "complete" while required monitoring evidence is still missing.
  const authoritative = scan?.status === 'completed'
    && scan?.scan_quality === 'complete'
    && assessment?.quality === 'complete'
    && assessment?.authoritative === true
    && assessment?.provisional === false
    && assessment?.display_rating != null
    && Number.isFinite(assessment?.display_score)
  return { score, authoritative, comparable: authoritative && assessment?.comparable === true,
    rating: authoritative ? assessment.display_rating : null }
}

/* ─── Derive insights from real scan data + optional report ─────────────── */

export function deriveInsights(scans, report) {
  const completed = scans.filter(s => s.status === 'completed')
  const failed    = scans.filter(s => s.status === 'failed').length
  const active    = scans.filter(s => ['queued','running','processing'].includes(s.status)).length
  const domains   = [...new Set(scans.map(s => s.domain))]

  // The hero describes the latest finished scan. An older complete scan cannot
  // turn a newer partial result into an established current posture.
  const latest = completed[0] || null
  const latestAssessment = assessedScan(latest)
  const score = latestAssessment.score
  const postureEstablished = latestAssessment.authoritative
  const postureProvisional = !!latest && !postureEstablished
  const riskLevel = latestAssessment.rating

  // Health categories: derive from report modules if available, else use scan counts
  const mods = report?.modules ?? {}
  // M5.e: security-state tiles are BACKEND-OWNED — each tile renders one of the
  // eight canonical domain states from the resolver (state→tone is vocabulary
  // display of a backend verdict, never a frontend security decision). Raw
  // module-derived statuses are gone.
  const DOMAIN_TONE = {
    assessed_healthy: 'good', issue_detected: 'danger',
    provisional: 'warning', degraded: 'warning',
  }
  const healthCategories = (report?.cyber_mot_domains ?? []).map((d) => ({
    label: d.display_name,
    status: DOMAIN_TONE[d.state] ?? 'unknown',
  }))

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

  // Only fully assessed scores are comparable; partial scores remain visible
  // on their own scan reports, never as points on an unqualified trend.
  const trend = completed
    .filter(s => assessedScan(s).comparable)
    .slice(0, 7)
    .reverse()
    .map((s, i) => ({
      label: s.domain?.split('.')[0] || `#${i + 1}`,
      value: s.assessment.display_score,
      date:  s.created_at,
    }))

  // Recommended actions
  const actions = []
  if (scans.length === 0) {
    actions.push({ id: 'a1', priority: 1, title: 'Start your first Cyber MOT',  desc: 'Add a domain to see what is visible from outside and get a plain-English fix list.',   cta: 'Start Cyber MOT', href: '/scans/new' })
  } else if (failed > 0) {
    actions.push({ id: 'a2', priority: 1, title: 'Investigate failed scans',      desc: `${failed} scan${failed !== 1 ? 's' : ''} stopped with an error, so ${failed !== 1 ? 'their' : 'its'} checks did not finish. Review and run ${failed !== 1 ? 'them' : 'it'} again.`, cta: 'View Scans', href: '/scans' })
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
    score, riskLevel, postureProvisional, postureEstablished, completed, failed, active, domains,
    // A finished run whose checks did not all complete is counted, never hidden.
    partialCompleted: completed.filter(s => !assessedScan(s).authoritative).length,
    healthCategories, findings, trend, actions,
    scanQuality: postureEstablished ? 'complete' : latest?.assessment?.quality ?? latest?.scan_quality ?? null,
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
// Security Rating labels — posture quality (never used for finding severity)
const RISK_LABEL = {
  excellent: 'Excellent',
  good:      'Good',
  moderate:  'Moderate',
  high:      bandMeta('high').label,
  critical:  'Critical',
}

function ScoreRing({ score, riskLevel, provisional = false }) {
  const r    = 88
  const circ = 2 * Math.PI * r

  // M5.e: backend rating first; otherwise the CANONICAL mirror bands — never a
  // local 3-band ladder that disagrees with every other surface.
  const sMeta  = metaForScore(score)
  const color  = provisional ? '#B45309' : riskLevel ? (RISK_COLOR[riskLevel] || '#E5E7EB') : score === null ? '#E5E7EB' : sMeta.color
  const fill   = score !== null ? circ * (score / 100) : 0
  const valCls = provisional ? 'text-amber-700' : riskLevel ? (RISK_TEXT_CLS[riskLevel] || 'text-gray-300') : score === null ? 'text-gray-300' : sMeta.text
  const label  = provisional ? 'Unrated' : riskLevel ? (RISK_LABEL[riskLevel] || 'Unknown') : score === null ? 'No data yet' : sMeta.label

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

function ExposureCard({ label, value, color }) {
  const s = EXPOSURE_STYLES[color]
  return (
    <div className="card p-5">
      {/* Label leads on top; the number sits below and is smaller. */}
      <div className="flex items-center gap-3">
        <p className="text-[15px] font-semibold text-gray-900 leading-snug">{label}</p>
      </div>
      <p className={`text-[14px] font-bold mt-2.5 tabular-nums ${s.val}`}>{value}</p>
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
        <text key={i} x={coords[i].x} y={H - 1} textAnchor="middle" fontSize="11" fill="#9CA3AF" fontFamily="'Computer Modern Text',Georgia,serif">
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

/* ─── No-workspace / create-workspace states ───────────────────────────── */

/**
 * Shown when the user has 0 workspaces — the true "brand new user" state.
 * Replaces the old forced navigate('/onboarding') redirect so the user stays
 * oriented inside the app.
 */
function CreateFirstWorkspaceState() {
  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Security Overview</h1>
        <p className="text-sm text-gray-400 mt-0.5">Your attack surface dashboard</p>
      </div>

      {/* Hero banner */}
      <div className="card p-10 flex flex-col items-center text-center mb-6">
        <h2 className="text-xl font-bold text-gray-900 mb-2">Create your first workspace</h2>
        <p className="text-sm text-gray-400 mb-2 max-w-md leading-relaxed">
          A workspace holds the domains, scans, and reports for one organisation or client.
          Create your first workspace to begin monitoring your website, email and certificate security.
        </p>
        <p className="text-xs text-gray-300 mb-8">Takes less than a minute · No credit card required</p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          <Link to="/onboarding" className="btn-primary">
            Get Started
          </Link>
          <Link to="/workspaces" className="btn-secondary">
            Go to Workspaces
          </Link>
        </div>
      </div>

      {/* What you'll get */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          {
            title: 'Attack Surface Visibility',
            desc:  'Find subdomains, exposed services and cloud assets linked to your domains.',
          },
          {
            title: 'Continuous Risk Scoring',
            desc:  'Your Cyber Metrics Score updates with each scan — track improvement over time.',
          },
          {
            title: 'Executive Reporting',
            desc:  'One-click PDF reports for stakeholders, clients, and compliance requirements.',
          },
        ].map(({ title, desc }) => (
          <div key={title} className="card p-5">
            <p className="text-sm font-semibold text-gray-900 mb-1">{title}</p>
            <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * Shown when user has workspaces but none is selected via the top-nav selector.
 */
function SelectWorkspaceState() {
  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Overview</h1>
          <p className="text-sm text-gray-400 mt-0.5">Select a workspace to view security data</p>
        </div>
      </div>
      <div className="card p-12 flex flex-col items-center text-center">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No workspace selected</h3>
        <p className="text-sm text-gray-400 mb-6 max-w-sm">
          The dashboard is scoped to a workspace. Select one from the workspace selector in the top nav,
          or create a new workspace to get started.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          <Link to="/workspaces" className="btn-primary">
            Go to Workspaces
          </Link>
          <Link to="/onboarding" className="btn-secondary">
            Get Started Guide
          </Link>
        </div>
      </div>
    </div>
  )
}

/* ─── Domain shortcut card ──────────────────────────────────────────────── */

// Glacier identity colours — from the shared single source of truth so domain
// cards always match the landing, workspace pages and sidebar.
const SERVICE_THEME = SERVICE_COLORS

const titleCase = (s) => (s ? String(s).replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : '—')

function ServiceKpiCard({ title, to, cta, accentTone, kpis, fallback, status, theme }) {
  const accent = accentTone === 'bad' ? 'accent-danger' : accentTone === 'warn' ? 'accent-warning' : ''
  return (
    <div className={`card p-5 flex flex-col relative overflow-hidden ${accent}`}>
      {theme && <span className="absolute top-0 left-0 right-0 h-[3px]" style={{ background: theme.icon, opacity: 0.85 }} />}
      <div className="flex items-center gap-2 mb-3">
        <h3 className="text-sm font-bold text-gray-900">{title}</h3>
      </div>
      {status && (
        <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1.5">{status}</p>
      )}
      {kpis && kpis.length ? (
        <dl className="space-y-1.5 flex-1">
          {kpis.map((k, i) => (
            <div key={i} className="flex items-center justify-between gap-2">
              <dt className="text-xs text-gray-600">{k.label}</dt>
              <dd className={`text-xs font-bold tabular-nums ${k.tone === 'bad' ? 'text-red-700' : k.tone === 'warn' ? 'text-amber-700' : 'text-gray-800'}`}>{k.value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-xs text-gray-500 leading-relaxed flex-1">{fallback}</p>
      )}
      <Link to={to} className="mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-brand-700 hover:text-brand-800">
        {cta}
      </Link>
    </div>
  )
}

/* ─── Main Dashboard ───────────────────────────────────────────────────── */

export default function Dashboard() {
  const [scans,         setScans]         = useState([])
  const [report,        setReport]        = useState(null)
  const [motDomains,    setMotDomains]    = useState([])   // server-resolved eight-domain states (always 8)
  const [scorecard,     setScorecard]     = useState(null)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [refreshing,    setRefreshing]    = useState(false)
  const [domainCount,   setDomainCount]   = useState(null)
  // null = unknown (still loading), true/false once resolved
  const [hasWorkspaces, setHasWorkspaces] = useState(null)

  // Workspace isolation — read from localStorage; re-derive on storage events
  const [activeWorkspaceId,   setActiveWorkspaceId]   = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [activeWorkspaceName, setActiveWorkspaceName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))

  const reportFetchedForRef = useRef(null) // tracks which scan ID we fetched report for
  const navigate = useNavigate()

  // Keep workspace state in sync when the nav selector changes it
  useEffect(() => {
    function onStorage(e) {
      if (e.key === 'cybermeters_workspace_id') {
        setActiveWorkspaceId(e.newValue)
        setScans([])
        setReport(null)
        reportFetchedForRef.current = null
      }
      if (e.key === 'cybermeters_workspace_name') {
        setActiveWorkspaceName(e.newValue)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const loadReport = useCallback(async (scanId) => {
    if (reportFetchedForRef.current === scanId) return
    reportFetchedForRef.current = scanId
    try {
      const r = await api.getScanReport(scanId)
      if (r.status === 'completed' && (r.findings?.length > 0 || r.cyber_metrics_score > 0)) {
        setReport(r)
      }
    } catch {
      // silently fail — dashboard degrades gracefully without the report
    }
  }, [])

  const load = useCallback(async (silent = false) => {
    // Pending invite redirect — if user signed up then landed on Dashboard,
    // pick up the stored invite token and send them to the landing page to accept.
    const pendingInvite = localStorage.getItem('cybermeters_pending_invite')
    if (pendingInvite) {
      localStorage.removeItem('cybermeters_pending_invite')
      navigate(`/invitations/${pendingInvite}`)
      return
    }

    // Re-read from localStorage on each load — ensures consistency if selector
    // wrote to localStorage but the storage event hasn't fired yet (same tab).
    const wsId = localStorage.getItem('cybermeters_workspace_id')
    const wsName = localStorage.getItem('cybermeters_workspace_name')
    setActiveWorkspaceId(wsId)
    setActiveWorkspaceName(wsName)

    // Security gate — never call global /api/scans when a workspace is set.
    // If no workspace is selected, resolve hasWorkspaces to show the right empty state.
    if (!wsId) {
      try {
        const data = await api.getWorkspaces()
        setHasWorkspaces((data.workspaces || []).length > 0)
      } catch {
        // Fall through — show select-workspace state (neutral)
        setHasWorkspaces(null)
      }
      setLoading(false)
      setRefreshing(false)
      setScans([])
      setReport(null)
      setDomainCount(null)
      return
    }
    // User has a workspace selected — they definitely have workspaces
    setHasWorkspaces(true)

    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const [data, domainsData, scorecardData, motData] = await Promise.all([
        api.getWorkspaceScans(wsId),
        api.getWorkspaceDomains(wsId).catch(() => ({ domains: [] })),
        api.getWorkspaceScorecard(wsId).catch(() => null), // optional; powers service KPIs
        api.getCyberMotDomains(wsId).catch(() => null),    // canonical eight-domain states (server-resolved)
      ])
      const list = data.scans || []
      setScans(list)
      setDomainCount((domainsData.domains || []).length)
      setScorecard(scorecardData)
      // Always eight; the endpoint returns canonical no-scan states when no scan exists.
      setMotDomains(Array.isArray(motData?.cyber_mot_domains) ? motData.cyber_mot_domains : [])

      // Fetch report for the latest completed scan in this workspace
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
  }, [loadReport, navigate])

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

  // Security gate — no workspace selected → show appropriate empty state
  if (!activeWorkspaceId) {
    if (hasWorkspaces === false) return <CreateFirstWorkspaceState />
    return <SelectWorkspaceState />
  }

  const hasDomain        = domainCount !== null && domainCount > 0
  const hasCompletedScan = ins.completed.length > 0
  // Show onboarding progress until all 4 steps are done AND dismissed
  const showProgress = true // OnboardingProgress manages its own dismissed state
  const showGuide    = hasCompletedScan // FirstResultsGuide manages its own dismissed state
  // Show team onboarding card for users who joined via invitation (flag set by InvitationLandingPage)
  const showTeamOnboarding = localStorage.getItem('cybermeters_joined_via_invite') === 'true'

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-8">

      {/* Header */}
      <div className="flex items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            {activeWorkspaceName && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white border border-gray-200 shadow-card text-xs font-semibold text-gray-700">
                {activeWorkspaceName}
              </span>
            )}
          </div>
          <h1 className="page-title">Security overview</h1>
          <p className="page-subtitle max-w-2xl">Monitor the eight Cyber MOT areas for {activeWorkspaceName || 'the selected workspace'}.</p>
          <p className="text-xs text-gray-400 mt-1">
            {latestScan
              ? `Last assessment: ${latestScan.domain} · ${relativeTime(latestScan.created_at)}`
              : 'No scans in this workspace yet'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          {error}
        </div>
      )}

      {/* ── Operational KPI overview + recommended action + observations ── */}
      {(() => {
        const sc = scorecard
        const brand = sc?.brand_risks
        const cr = sc?.certificate_risks?.risk_level
        const critical = ins.criticalCount ?? 0
        const high = ins.highCount ?? 0

        const brandKpis = brand && (brand.active != null || brand.high != null) ? [
          { label: 'High-risk lookalikes', value: brand.high ?? 0, tone: (brand.high ?? 0) > 0 ? 'bad' : '' },
          { label: 'Active candidates',    value: brand.active ?? 0 },
        ] : null
        const surfaceKpis = hasCompletedScan ? [
          { label: 'Critical findings', value: critical, tone: critical > 0 ? 'bad' : '' },
          { label: 'High findings',     value: high, tone: high > 0 ? 'warn' : '' },
          ...(sc?.active_assets != null ? [{ label: 'Active assets', value: sc.active_assets }] : []),
        ] : null
        const certKpis = cr ? [
          { label: 'Certificate risk', value: titleCase(cr), tone: ['high', 'critical'].includes(cr) ? 'bad' : cr === 'medium' ? 'warn' : '' },
          ...(sc?.certificate_risks?.expiring_soon != null ? [{ label: 'Expiring soon', value: sc.certificate_risks.expiring_soon, tone: sc.certificate_risks.expiring_soon > 0 ? 'warn' : '' }] : []),
        ] : null

        // Recommended next action — derived honestly from real signals only.
        const rec = domainCount === 0
          ? { text: 'Add your first domain so CyberMeters can start monitoring it.', cta: 'Add a domain', to: '/ws/dashboard' }
          : !hasCompletedScan
            ? { text: 'Run your first external scan to discover exposed assets and email posture.', cta: 'Run a scan', to: '/scans/new' }
            : (cr && ['high', 'critical'].includes(cr))
              ? { text: 'Certificate trust needs attention — review expiry and HTTPS posture.', cta: 'Review certificates', to: '/ws/certificates' }
              : (brand && (brand.high ?? 0) > 0)
                ? { text: 'High-risk lookalike domains detected — review brand candidates.', cta: 'Review brand candidates', to: '/ws/brand-monitoring' }
                : critical > 0
                  ? { text: 'Critical findings on your attack surface — review and remediate.', cta: 'Review attack surface', to: '/assets' }
                  : { text: 'Connect Email Protection to measure impersonation exposure and receive DMARC reports.', cta: 'Open Email Protection', to: '/ws/email-protection' }

        // M5.e: this block no longer DECIDES security states locally — counts are
        // presented as observations; the eight-domain Cyber MOT grid below is
        // the one canonical state surface on this page.
        const posture = [
          { label: 'Brand candidates',  value: brand ? `${brand.active ?? 0} active${(brand.high ?? 0) > 0 ? `, ${brand.high} high-risk` : ''}` : 'Unknown', tone: brand && (brand.high ?? 0) > 0 ? 'bad' : 'na' },
          { label: 'Open findings',     value: hasCompletedScan ? `${critical} critical, ${high} high` : 'No completed scan', tone: critical > 0 ? 'bad' : high > 0 ? 'warn' : 'na' },
          { label: 'Certificate risk',  value: cr ? titleCase(cr) : 'Unknown', tone: cr && ['high', 'critical'].includes(cr) ? 'bad' : cr === 'medium' ? 'warn' : 'na' },
        ]
        const pTone = (t) => t === 'bad' ? 'text-red-700' : t === 'warn' ? 'text-amber-700' : t === 'ok' ? 'text-brand-700' : 'text-gray-400'

        return (
          <div className="space-y-6">
            {/* Eight-domain Cyber MOT coverage — ALWAYS all eight, server-resolved
                (canonical no-scan states before any scan); missing evidence is never
                shown as healthy and no domain silently disappears. */}
            <CyberMotDomains
              domains={motDomains.length ? motDomains : report?.cyber_mot_domains}
              subtitle="All eight Cyber MOT areas, each with what the latest scan could establish." />

            {/* Domain shortcut cards */}
            <div>
              <h2 className="section-title mb-3">Your Cyber MOT domains</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                <ServiceKpiCard title="Identity Exposure" to="/ws/identity-exposure" cta="Review Identity Exposure"
                  theme={SERVICE_THEME.identity} status="Externally observed"
                  fallback="Review observed identity-provider relationships and identity-facing hostnames. Endpoint reachability is shown only with HTTP evidence." />
                <ServiceKpiCard title="Attack Surface" to="/assets" cta="Review Attack Surface"
                  theme={SERVICE_THEME.surface} kpis={surfaceKpis} accentTone={critical > 0 ? 'bad' : high > 0 ? 'warn' : ''}
                  fallback="Run your first external scan to discover exposed assets." />
                <ServiceKpiCard title="Email Protection" to="/ws/email-protection" cta="Open Email Protection"
                  theme={SERVICE_THEME.email} status="Not measured"
                  fallback="Connect DMARC reporting to measure impersonation exposure." />
                <ServiceKpiCard title="Website Security" to="/ws/website-security" cta="Review Website Security"
                  theme={SERVICE_THEME.website} status="Externally observed"
                  fallback="Review HTTPS, redirects, headers and cookie flag evidence." />
                <ServiceKpiCard title="Shadow IT & Unmanaged Technology" to="/ws/shadow-it" cta="Review Shadow IT"
                  theme={SERVICE_THEME.shadow_it} status="Externally observed"
                  fallback="Review SaaS, vendor, script and unmanaged technology observations." />
                <ServiceKpiCard title="Certificates & Trust" to="/ws/certificates" cta="Review Certificates"
                  theme={SERVICE_THEME.certs} kpis={certKpis} accentTone={cr && ['high', 'critical'].includes(cr) ? 'bad' : cr === 'medium' ? 'warn' : ''}
                  fallback="Review certificate expiry and HTTPS trust posture." />
                <ServiceKpiCard title="Brand Protection" to="/ws/brand-monitoring" cta="Review Brand Protection"
                  theme={SERVICE_THEME.brand} kpis={brandKpis} accentTone={brand && (brand.high ?? 0) > 0 ? 'bad' : ''}
                  fallback="Add a protected brand profile to monitor lookalike domains." />
                <ServiceKpiCard title="Cyber Essentials Readiness" to="/ws/cyber-essentials" cta="Review Readiness"
                  theme={SERVICE_THEME.cyber_essentials} status="Evidence-led"
                  fallback="Review readiness evidence and saved questionnaire answers." />
              </div>
            </div>

            {/* Recommended next action */}
            <div className="card p-5 border-brand-100 bg-brand-50/40 flex flex-col sm:flex-row sm:items-center gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-brand-700 uppercase tracking-wide">Recommended next action</p>
                <p className="text-sm text-gray-800 mt-0.5 leading-relaxed">{rec.text}</p>
              </div>
              <Link to={rec.to} className="btn-primary text-sm flex-shrink-0">{rec.cta}</Link>
            </div>

            {/* Posture overview */}
            <div className="card p-5">
              <h3 className="section-title mb-3">Posture overview</h3>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {posture.map(p => (
                  <div key={p.label} className="rounded-xl border border-gray-200 bg-white px-4 py-3">
                    <p className="text-sm font-semibold text-gray-900 leading-snug">{p.label}</p>
                    <p className={`text-[14px] font-bold mt-1 ${pTone(p.tone)}`}>{p.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )
      })()}

      {/* ── Recent changes (Exposure Timeline habit hook — self-hides when empty) ── */}
      <RecentChangesCard workspaceId={activeWorkspaceId} />

      {/* ── Team onboarding card — shown once after joining via invitation ── */}
      {showTeamOnboarding && <TeamOnboardingCard />}

      {/* ── Onboarding progress tracker ── */}
      <OnboardingProgress
        hasWorkspace={true}
        hasDomain={hasDomain}
        hasCompletedScan={hasCompletedScan}
      />

      {/* ── Domain setup nudge (replaces generic progress bar when 0 domains) ── */}
      {domainCount === 0 && (
        <div className="card p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-brand-100 bg-brand-50/40">
          <div className="flex items-start gap-3">
            <div>
              <p className="text-sm font-bold text-gray-900">Add your first domain</p>
              <p className="text-sm text-gray-500 mt-0.5">
                Add and verify a domain to generate your cyber risk assessment. Try{' '}
                <span className="font-mono text-xs text-gray-700">example.com</span> or{' '}
                <span className="font-mono text-xs text-gray-700">company.co.uk</span>.
              </p>
            </div>
          </div>
          <Link to="/ws/dashboard" className="btn-primary flex-shrink-0">
            Add Domain
          </Link>
        </div>
      )}

      {/* ── 1. Cyber Metrics Score — focused hero ── */}
      <div className="card-md overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center gap-8 px-8 py-8">
          {/* Score ring */}
          <div className="flex flex-col items-center gap-3 lg:min-w-[240px]">
            <span className="eyebrow">{ins.postureProvisional && ins.score != null ? 'Provisional Score' : 'Cyber Metrics Score'}</span>
            <ScoreRing score={ins.score} riskLevel={ins.riskLevel} provisional={ins.postureProvisional} />
            {ins.postureProvisional && (
              <p className="text-xs text-amber-700 text-center leading-relaxed max-w-[200px] font-medium">
                {ins.score != null
                  ? 'Some checks or required evidence are incomplete. This score is provisional.'
                  : 'Some checks or required evidence are incomplete, so no score is shown for this scan.'}
              </p>
            )}
          </div>

          {/* Posture statement + actions */}
          <div className="flex-1 lg:border-l border-gray-200 lg:pl-8">
            <p className="text-[15px] text-gray-700 leading-relaxed max-w-lg">
              {ins.postureProvisional
                ? 'The current assessment is provisional because checks or required evidence are incomplete. Review the report and re-run the Cyber MOT.'
                : ins.score === null
                ? 'Run your first Cyber MOT to generate your Cyber Metrics Score and reveal your external security posture.'
                : ['excellent', 'good'].includes(scoreBand(ins.score))
                  ? 'No serious issue was found in what the latest complete scan checked. Keep monitoring to catch new exposure as it appears.'
                  : scoreBand(ins.score) === 'moderate'
                    ? `Moderate exposure detected. ${ins.findings.length} issue${ins.findings.length !== 1 ? 's' : ''} require attention to strengthen your posture.`
                    : 'Serious exposures detected. Prioritise the findings below — immediate action is recommended.'}
            </p>
            <div className="mt-6 flex flex-wrap items-center gap-3">
              {report ? (
                <Link to={`/scans/${report.scan_id}`} className="btn-primary">
                  View Executive Report
                </Link>
              ) : (
                <Link to="/scans/new" className="btn-primary">
                  Run your first Cyber MOT
                </Link>
              )}
              <Link to="/scans" className="btn-secondary">View all scans</Link>
            </div>
          </div>
        </div>
      </div>

      {/* ── KPI tiles ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Scans',     value: scans.length,         sub: 'all time' },
          { label: 'Completed',       value: ins.completed.length, sub: ins.partialCompleted > 0 ? `${ins.partialCompleted} with partial results` : 'finished runs' },
          { label: 'Active Scans',    value: ins.active,           sub: 'currently running' },
          { label: 'Domains Tracked', value: ins.domains.length,   sub: 'unique domains' },
        ].map(({ label, value, sub }) => (
          <div key={label} className="stat-tile">
            {/* Text on top: label leads. */}
            <div className="flex items-start justify-between gap-2">
              <span className="text-[15px] font-semibold text-gray-900 leading-snug">{label}</span>
            </div>
            <span className="text-xs text-gray-500">{sub}</span>
            {/* Number at the bottom, smaller than the label — it supports. */}
            <span className="text-[14px] font-bold text-gray-800 tabular-nums">{value}</span>
          </div>
        ))}
      </div>

      {/* ── 2. Exposure Overview ── */}
      <section>
        <div className="section-head">
          <div>
            <span className="eyebrow">Risk at a glance</span>
            <h2 className="section-title mt-1.5">Exposure Overview</h2>
          </div>
          <Link to="/scans" className="btn-ghost text-xs">View all</Link>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <ExposureCard label="Critical Findings"  value={ins.criticalCount}         color="red"    />
          <ExposureCard label="High Risk Findings"  value={ins.highCount}             color="orange" />
          <ExposureCard label="Domains Tracked"     value={ins.domains.length}        color="amber"  />
          <ExposureCard label="Scans In Progress"   value={ins.active}                color="brand"  />
        </div>
      </section>

      {/* ── 3. Security Health + 5. Top Findings ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

        {/* Security Health */}
        <div className="lg:col-span-2 card p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-base font-bold text-gray-900">Security Health</h2>
            {report && (
              <span className="text-xs text-gray-400 font-medium">{report.domain}</span>
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
                Executive Report
              </Link>
            )}
          </div>
          {ins.findings.length === 0 ? (
            ins.postureEstablished ? (
              <div className="flex flex-col items-center gap-3 py-12 text-center px-6">
                <p className="text-sm font-semibold text-gray-900">No findings</p>
                <p className="text-xs text-gray-400">Nothing was found in what the latest complete scan checked. That is not proof of no risk.</p>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3 py-12 text-center px-6">
                <p className="text-sm font-semibold text-gray-900">No findings recorded</p>
                <p className="text-xs text-gray-400">The latest scan's coverage was incomplete — this is not a clean bill of health.</p>
              </div>
            )
          ) : (
            <ul className="divide-y divide-gray-50">
              {ins.findings.map((f, i) => (
                <li
                  key={f.id}
                  onClick={() => f.scanId ? navigate(`/scans/${f.scanId}`) : navigate('/scans')}
                  className="flex items-start gap-4 px-6 py-4 hover:bg-gray-50 cursor-pointer transition-colors"
                >
                  <div className={`w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold text-white flex-shrink-0 mt-0.5 ${
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
                ? 'Cyber Metrics Score across fully assessed scans'
                : 'Score history will appear after fully assessed scans'}
            </p>
          </div>
          <span className="flex items-center gap-1.5 text-xs text-brand-600 font-semibold">
            Last {ins.trend.length} scans
          </span>
        </div>
        <TrendChart points={ins.trend} />
      </div>

      {/* ── 6. Recommended Actions ── */}
      {ins.actions.length > 0 && (
        <section>
          <div className="section-head">
            <div>
              <span className="eyebrow">Next steps</span>
              <h2 className="section-title mt-1.5">Recommended Actions</h2>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {ins.actions.slice(0, 3).map((action, i) => (
              <div key={action.id} className="card p-5 flex flex-col gap-4 hover:shadow-card-md transition-shadow">
                <div className="flex items-start gap-3">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0 mt-0.5 ${
                    i === 0 ? 'bg-red-500' : i === 1 ? 'bg-amber-500' : 'bg-brand-600'
                  }`}>{action.priority}</div>
                  <div>
                    <p className="text-sm font-bold text-gray-900">{action.title}</p>
                    <p className="text-xs text-gray-400 mt-1 leading-relaxed">{action.desc}</p>
                  </div>
                </div>
                <Link to={action.href} className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-600 hover:text-brand-700 transition-colors">
                  {action.cta}
                </Link>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── First Results Guide — shown after first completed scan, dismissible ── */}
      {showGuide && <FirstResultsGuide />}

      {/* Recent Scans (compact) */}
      {scans.length > 0 && (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <h2 className="text-base font-bold text-gray-900">Recent Scans</h2>
            <Link to="/scans" className="btn-ghost text-xs">View all</Link>
          </div>
          <ul className="divide-y divide-gray-50">
            {scans.slice(0, 5).map(scan => {
              const scanAssessment = assessedScan(scan)
              return (
              <li
                key={scan.id}
                onClick={() => navigate(`/scans/${scan.id}`)}
                className="flex items-center gap-4 px-6 py-3.5 hover:bg-gray-50 cursor-pointer transition-colors group"
              >
                <span className="text-sm font-semibold text-gray-900 flex-1 truncate">{scan.domain}</span>
                {/* Show real score if available */}
                {scanAssessment.score !== null && (
                  <span className={`text-sm font-bold flex-shrink-0 ${scanAssessment.authoritative ? 'text-brand-600' : 'text-amber-700'}`}>
                    {scanAssessment.score}{scanAssessment.authoritative ? '' : ' provisional'}
                  </span>
                )}
                <span className="flex items-center gap-1.5 text-xs text-gray-500">
                  <span>{scan.status === 'completed' && !scanAssessment.authoritative
                    ? scan.scan_quality === 'complete' ? 'Provisional result' : 'Partial results'
                    : scan.status}</span>
                </span>
                <span className="text-xs text-gray-400 hidden sm:block flex-shrink-0">{formatDate(scan.created_at)}</span>
              </li>
              )
            })}
          </ul>
        </div>
      )}

    </div>
  )
}
