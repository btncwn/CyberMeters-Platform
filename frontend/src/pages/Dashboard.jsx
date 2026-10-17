import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import PostureCard          from '../components/overview/PostureCard'
import { NextActionCard } from '../components/overview/SecurityOverview'

// The home screen (founder, 16 Oct 2026): the question, the last assessment,
// the scan input, the "Your external posture" card (every area with the
// backend's word), the recommended next action and the recent scans — nothing
// else. The score and its trend live in Reports; the eight-area overview with
// its counts lives on the workspace overview (/ws/dashboard).

/* ─── Helpers ──────────────────────────────────────────────────────────── */

function formatDate(str) {
  if (!str) return '—'
  return new Date(str.replace(' ', 'T') + 'Z')
    .toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// Relative age of a stored timestamp, or '' when the value is missing or
// cannot be parsed — the hero drops the "· … ago" part rather than render
// "NaNd ago". Exported for its test.
export function relativeTime(str, nowMs = Date.now()) {
  if (typeof str !== 'string' || !str.trim()) return ''
  const iso = str.includes('T') ? str : str.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(str) ? '' : 'Z')
  const ms = new Date(iso).getTime()
  if (!Number.isFinite(ms)) return ''
  const diff = Math.max(0, nowMs - ms)
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

/* ─── No-workspace / create-workspace states ───────────────────────────── */

/**
 * Shown when the user has 0 workspaces — the true "brand new user" state.
 * Replaces the old forced navigate('/onboarding') redirect so the user stays
 * oriented inside the app.
 */
function CreateFirstWorkspaceState() {
  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Security overview</h1>
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
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">
      <div className="flex items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security overview</h1>
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

/* ─── Main Dashboard ───────────────────────────────────────────────────── */

export default function Dashboard() {
  const [scans,         setScans]         = useState([])
  const [report,        setReport]        = useState(null)
  const [motDomains,    setMotDomains]    = useState([])   // server-resolved eight-domain states (always 8)
  const [scorecard,     setScorecard]     = useState(null)
  const [motRequest,    setMotRequest]    = useState('loading') // how the eight-domain read went
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [refreshing,    setRefreshing]    = useState(false)
  const [domainCount,   setDomainCount]   = useState(null)
  // null = unknown (still loading), true/false once resolved
  const [hasWorkspaces, setHasWorkspaces] = useState(null)
  const [scanInput,     setScanInput]     = useState('')

  // Workspace isolation — read from localStorage; re-derive on storage events
  const [activeWorkspaceId,   setActiveWorkspaceId]   = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [activeWorkspaceName, setActiveWorkspaceName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))
  const [loadedWorkspaceId,   setLoadedWorkspaceId]   = useState(null)

  const reportFetchedForRef = useRef(null) // tracks which scan ID we fetched report for
  const requestGeneration = useRef(0)
  const navigate = useNavigate()

  // Keep workspace state in sync when the nav selector changes it
  useEffect(() => {
    function onStorage(e) {
      if (e.key === 'cybermeters_workspace_id') {
        setActiveWorkspaceId(e.newValue)
      }
      if (e.key === 'cybermeters_workspace_name') {
        setActiveWorkspaceName(e.newValue)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const loadReport = useCallback(async (scanId, generation) => {
    if (reportFetchedForRef.current === scanId) return
    reportFetchedForRef.current = scanId
    try {
      const r = await api.getScanReport(scanId)
      if (requestGeneration.current !== generation) return
      if (r.status === 'completed' && (r.findings?.length > 0 || r.cyber_metrics_score > 0)) {
        setReport(r)
      }
    } catch {
      // silently fail — dashboard degrades gracefully without the report
    }
  }, [])

  const load = useCallback(async (silent = false) => {
    const generation = ++requestGeneration.current
    // Pending invite redirect — if user signed up then landed on Dashboard,
    // pick up the stored invite token and send them to the landing page to accept.
    const pendingInvite = localStorage.getItem('cybermeters_pending_invite')
    if (pendingInvite) {
      localStorage.removeItem('cybermeters_pending_invite')
      navigate(`/invitations/${pendingInvite}`)
      return
    }

    const wsId = activeWorkspaceId
    setScans([])
    setReport(null)
    setMotDomains([])
    setScorecard(null)
    setMotRequest('loading')
    setDomainCount(null)
    setHasWorkspaces(null)
    setError(null)
    setLoadedWorkspaceId(null)
    reportFetchedForRef.current = null
    setLoading(true)
    setRefreshing(silent)

    // Security gate — never call global /api/scans when a workspace is set.
    // If no workspace is selected, resolve hasWorkspaces to show the right empty state.
    if (!wsId) {
      try {
        const data = await api.getWorkspaces()
        if (requestGeneration.current === generation) setHasWorkspaces((data.workspaces || []).length > 0)
      } catch {
        // Fall through — show select-workspace state (neutral)
        if (requestGeneration.current === generation) setHasWorkspaces(null)
      }
      if (requestGeneration.current === generation) {
        setLoadedWorkspaceId(wsId)
        setLoading(false)
        setRefreshing(false)
      }
      return
    }
    // User has a workspace selected — they definitely have workspaces
    setHasWorkspaces(true)

    try {
      const [data, domainsData, scorecardData, motData] = await Promise.all([
        api.getWorkspaceScans(wsId),
        api.getWorkspaceDomains(wsId).catch(() => null),
        api.getWorkspaceScorecard(wsId).catch(() => null), // optional; feeds the recommended next action
        api.getCyberMotDomains(wsId).catch(() => null),    // canonical eight-domain states (server-resolved)
      ])
      if (requestGeneration.current !== generation) return
      const list = data.scans || []
      setScans(list)
      setDomainCount(Array.isArray(domainsData?.domains) ? domainsData.domains.length : null)
      setScorecard(scorecardData)
      // Always eight; the endpoint returns canonical no-scan states when no scan exists.
      setMotDomains(Array.isArray(motData?.cyber_mot_domains) ? motData.cyber_mot_domains : [])
      setMotRequest(Array.isArray(motData?.cyber_mot_domains) ? 'ok' : 'error')

      // Fetch report for the latest completed scan in this workspace
      const latestCompleted = list.find(s => s.status === 'completed')
      if (latestCompleted && reportFetchedForRef.current !== latestCompleted.id) {
        loadReport(latestCompleted.id, generation)
      }
    } catch (e) {
      if (requestGeneration.current === generation) {
        setMotRequest('error')
        setError(e.message)
      }
    } finally {
      if (requestGeneration.current === generation) {
        setLoadedWorkspaceId(wsId)
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [activeWorkspaceId, loadReport, navigate])

  useEffect(() => {
    load()
    return () => { requestGeneration.current += 1 }
  }, [load])

  const ins        = deriveInsights(scans, report)
  const latestScan = scans[0] || null

  if (loading || loadedWorkspaceId !== activeWorkspaceId) {
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

  const hasCompletedScan = ins.completed.length > 0

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8 space-y-8">

      {/* Home (founder, 16 Oct 2026): the question, the last assessment, the
          scan input, then what the latest assessment could establish. */}
      <section className="text-center pt-4 sm:pt-10 pb-2" aria-labelledby="home-question">
        <h1 id="home-question" className="cm-hero-title">Where is {activeWorkspaceName || 'your organisation'} exposed today?</h1>
        <p className="text-[15px] text-gray-500 mt-3">
          {latestScan
            ? [`Last assessment of ${latestScan.domain}`, relativeTime(latestScan.created_at)].filter(Boolean).join(' · ')
            : 'No assessment has been recorded in this workspace yet.'}
        </p>
        <form
          className="cm-hero-input mt-6"
          aria-label="Start a scan"
          onSubmit={(e) => {
            e.preventDefault()
            const value = scanInput.trim()
            navigate(value ? `/scans/new?domain=${encodeURIComponent(value)}` : '/scans/new')
          }}
        >
          <input
            type="text"
            inputMode="url"
            autoComplete="off"
            value={scanInput}
            onChange={(e) => setScanInput(e.target.value)}
            aria-label="Domain to scan"
            placeholder="Enter a domain to scan, e.g. example.co.uk"
          />
          <button type="submit" className="btn-primary rounded-full px-5 py-2">Scan</button>
        </form>
        <div className="mt-4 flex justify-center">
          <button onClick={() => load(true)} disabled={refreshing} className="btn-ghost text-xs">
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </section>

      <PostureCard
        domains={motDomains.length ? motDomains : report?.cyber_mot_domains}
        request={motRequest}
        workspaceName={activeWorkspaceName}
      />

      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          {error}
        </div>
      )}

      {/* The next thing to do, from real signals only — the same ladder the
          workspace overview uses (one component, one place). */}
      <NextActionCard signals={{ domainCount, hasCompletedScan, scorecard, critical: ins.criticalCount ?? 0, high: ins.highCount ?? 0 }} />

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
                {/* Explanation first: the state word leads; a provisional number
                    follows small and labelled, never as a headline. */}
                <span className="flex items-center gap-1.5 text-xs text-gray-500">
                  <span>{scan.status === 'completed' && !scanAssessment.authoritative
                    ? scan.scan_quality === 'complete' ? 'Provisional result' : 'Partial results'
                    : scan.status}</span>
                </span>
                {scanAssessment.score !== null && (
                  <span className={`shrink-0 ${scanAssessment.authoritative ? 'text-sm font-bold text-brand-700' : 'text-xs font-medium text-brand-700 rounded-md border-[1.5px] border-brand-700 px-1.5 py-0.5'}`}>
                    {scanAssessment.score}{scanAssessment.authoritative ? '' : ' provisional'}
                  </span>
                )}
                <span className="text-xs text-gray-400 hidden sm:block shrink-0">{formatDate(scan.created_at)}</span>
              </li>
              )
            })}
          </ul>
        </div>
      )}

    </div>
  )
}
