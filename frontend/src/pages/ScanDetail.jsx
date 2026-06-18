import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, RefreshCw, Globe, Hash, AlertCircle, ScanLine,
  ChevronRight, Shield, FileText, CheckCircle, XCircle, Mail,
  Lock, Server, Clock,
} from 'lucide-react'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'

const ACTIVE  = new Set(['queued', 'running', 'processing'])
const POLL_MS = 4000

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  const d = new Date(str.includes('T') ? str : str.replace(' ', 'T') + 'Z')
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function durationSeconds(start, end) {
  if (!start || !end) return null
  const s = Math.round((new Date(end) - new Date(start)) / 1000)
  return `${s}s`
}

// ── Risk level config ────────────────────────────────────────────────────────

const RISK_CFG = {
  excellent: { color: '#00876A', cls: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Excellent' },
  good:      { color: '#00876A', cls: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Good'      },
  moderate:  { color: '#F59E0B', cls: 'text-amber-500', pill: 'bg-amber-50 text-amber-700 border-amber-100', label: 'Moderate'  },
  high:      { color: '#F97316', cls: 'text-orange-500',pill: 'bg-orange-50 text-orange-700 border-orange-100',label: 'High Risk'},
  critical:  { color: '#EF4444', cls: 'text-red-500',   pill: 'bg-red-50 text-red-700 border-red-100',       label: 'Critical'  },
  unknown:   { color: '#D1D5DB', cls: 'text-gray-400',  pill: 'bg-gray-100 text-gray-500 border-gray-200',   label: 'Unknown'   },
}

// ── Severity config ──────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEV_STYLE = {
  critical: 'bg-red-500 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-amber-400 text-white',
  low:      'bg-blue-400 text-white',
  info:     'bg-gray-300 text-gray-700',
}
const SEV_BADGE = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'text-xs font-semibold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 border border-gray-200',
}

// ── Components ───────────────────────────────────────────────────────────────

function SectionHeader({ icon: Icon, title, aside }) {
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 bg-gray-50">
      <div className="flex items-center gap-2.5">
        <div className="w-6 h-6 rounded-md bg-brand-100 flex items-center justify-center">
          <Icon className="w-3.5 h-3.5 text-brand-700" />
        </div>
        <h2 className="text-sm font-bold text-gray-900">{title}</h2>
      </div>
      {aside && <div>{aside}</div>}
    </div>
  )
}

function KV({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 px-6 py-3 border-b border-gray-50 last:border-0">
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide min-w-[130px] pt-0.5">{label}</span>
      <span className="text-sm text-gray-900 text-right flex-1 font-medium">{value ?? '—'}</span>
    </div>
  )
}

// ── Score Ring (compact) ─────────────────────────────────────────────────────

function ScoreRing({ score, riskLevel }) {
  const r    = 54
  const circ = 2 * Math.PI * r
  const fill = score != null ? circ * (score / 100) : 0
  const cfg  = RISK_CFG[riskLevel] || RISK_CFG.unknown

  return (
    <div className="flex flex-col items-center select-none">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          <circle cx="64" cy="64" r={r} fill="none" stroke="#F3F4F6" strokeWidth="10" />
          {score != null && (
            <circle
              cx="64" cy="64" r={r} fill="none"
              stroke={cfg.color} strokeWidth="10" strokeLinecap="round"
              strokeDasharray={`${fill} ${circ - fill}`}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score != null
            ? <><span className={`text-3xl font-bold ${cfg.cls}`}>{score}</span><span className="text-[10px] text-gray-300 font-semibold">/100</span></>
            : <span className="text-gray-300 text-xs">—</span>
          }
        </div>
      </div>
      {riskLevel && riskLevel !== 'unknown' && (
        <span className={`text-xs font-bold px-3 py-1 rounded-full border mt-1 ${cfg.pill}`}>
          {cfg.label}
        </span>
      )}
    </div>
  )
}

// ── Findings Panel ───────────────────────────────────────────────────────────

function FindingsPanel({ findings }) {
  const sorted = [...(findings || [])].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  )

  if (sorted.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-10 text-center">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 flex items-center justify-center">
          <CheckCircle className="w-5 h-5 text-brand-600" />
        </div>
        <p className="text-sm font-semibold text-gray-700">No findings detected</p>
        <p className="text-xs text-gray-400">This domain passed all checks.</p>
      </div>
    )
  }

  return (
    <ul className="divide-y divide-gray-50">
      {sorted.map((f, i) => (
        <li key={f.id || i} className="flex items-start gap-4 px-6 py-4">
          <div className={`w-6 h-6 rounded-lg flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5 ${SEV_STYLE[f.severity] || SEV_STYLE.info}`}>
            {i + 1}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-gray-900">{f.title}</p>
            <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{f.description}</p>
            {f.score_impact != null && (
              <span className="text-[10px] font-semibold text-red-400 mt-1 inline-block">
                Score impact: {f.score_impact}
              </span>
            )}
          </div>
          <span className={`flex-shrink-0 ${SEV_BADGE[f.severity] || SEV_BADGE.info}`}>
            {f.severity}
          </span>
        </li>
      ))}
    </ul>
  )
}

// ── Recommendations Panel ────────────────────────────────────────────────────

function RecommendationsPanel({ recommendations }) {
  if (!recommendations?.length) {
    return (
      <div className="px-6 py-6 text-sm text-gray-400">No recommendations.</div>
    )
  }
  return (
    <ul className="divide-y divide-gray-50">
      {recommendations.map((r, i) => (
        <li key={i} className="flex items-start gap-4 px-6 py-4">
          <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0 mt-0.5 bg-brand-600">
            {r.priority || i + 1}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-gray-900">{r.title}</p>
            <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{r.description}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}

// ── Boolean Check Row ────────────────────────────────────────────────────────

function CheckRow({ label, value, trueLabel = 'Yes', falseLabel = 'No' }) {
  return (
    <div className="flex items-center justify-between px-6 py-3 border-b border-gray-50 last:border-0">
      <span className="text-sm text-gray-600">{label}</span>
      {value == null
        ? <span className="text-xs text-gray-300">—</span>
        : value
          ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full">
              <CheckCircle className="w-3 h-3" /> {trueLabel}
            </span>
          : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full">
              <XCircle className="w-3 h-3" /> {falseLabel}
            </span>
      }
    </div>
  )
}

// ── DNS Module Panel ─────────────────────────────────────────────────────────

function DnsPanel({ dns }) {
  if (!dns || dns.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{dns?.error || 'No DNS data'}</div>
  }
  return (
    <div className="divide-y divide-gray-50">
      <CheckRow label="Domain resolves (A/AAAA)"  value={dns.resolves} trueLabel="Resolves" falseLabel="Does not resolve" />
      <CheckRow label="IPv6 support (AAAA record)" value={dns.has_ipv6}  trueLabel="Enabled"  falseLabel="Not enabled" />
      <CheckRow label="MX records present"          value={dns.has_mx}   trueLabel="Present"  falseLabel="Not found" />
      {dns.nameservers?.length > 0 && (
        <div className="px-6 py-3 border-b border-gray-50">
          <p className="text-sm text-gray-600 mb-1">Nameservers</p>
          <p className="text-xs text-gray-400 mono">{dns.nameservers.join(', ')}</p>
        </div>
      )}
      {dns.a_records?.length > 0 && (
        <div className="px-6 py-3 border-b border-gray-50">
          <p className="text-sm text-gray-600 mb-1">A records</p>
          <p className="text-xs text-gray-400 mono">{dns.a_records.map(r => r.value).join(', ')}</p>
        </div>
      )}
      {dns.aaaa_records?.length > 0 && (
        <div className="px-6 py-3">
          <p className="text-sm text-gray-600 mb-1">AAAA records</p>
          <p className="text-xs text-gray-400 mono">{dns.aaaa_records.map(r => r.value).join(', ')}</p>
        </div>
      )}
    </div>
  )
}

// ── SSL Module Panel ─────────────────────────────────────────────────────────

function SslPanel({ ssl }) {
  if (!ssl || ssl.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{ssl?.error || 'No SSL data'}</div>
  }
  return (
    <div className="divide-y divide-gray-50">
      <CheckRow label="HTTPS available"              value={ssl.https_available}       trueLabel="Available"    falseLabel="Not available" />
      <CheckRow label="HTTP redirects to HTTPS"      value={ssl.http_redirects_to_https} trueLabel="Redirects" falseLabel="No redirect" />
      {ssl.www_fallback_used && (
        <div className="px-6 py-3 text-xs text-amber-600 bg-amber-50">
          HTTPS only available via www. subdomain — bare domain did not respond.
        </div>
      )}
    </div>
  )
}

// ── Headers Module Panel ─────────────────────────────────────────────────────

const HEADER_LABELS = {
  'strict-transport-security': 'Strict-Transport-Security (HSTS)',
  'content-security-policy':   'Content-Security-Policy',
  'x-frame-options':           'X-Frame-Options',
  'x-content-type-options':    'X-Content-Type-Options',
  'referrer-policy':           'Referrer-Policy',
  'permissions-policy':        'Permissions-Policy',
}

function HeadersPanel({ headers }) {
  if (!headers || headers.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{headers?.error || 'No header data'}</div>
  }
  if (!headers.accessible) {
    return <div className="px-6 py-4 text-sm text-gray-400">Site was not reachable for header analysis.</div>
  }

  const allHeaders = Object.keys(HEADER_LABELS)
  return (
    <div className="divide-y divide-gray-50">
      {allHeaders.map(h => {
        const present = headers.present?.includes(h)
        const val     = headers.values?.[h]
        return (
          <div key={h} className="px-6 py-3">
            <div className="flex items-center justify-between mb-0.5">
              <span className="text-sm text-gray-700 font-medium">{HEADER_LABELS[h]}</span>
              {present
                ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Present</span>
                : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full"><XCircle className="w-3 h-3" />Missing</span>
              }
            </div>
            {val && <p className="text-[11px] text-gray-400 mono mt-1 break-all">{val}</p>}
          </div>
        )
      })}
    </div>
  )
}

// ── Email Security Panel ─────────────────────────────────────────────────────

function EmailPanel({ email }) {
  if (!email || email.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{email?.error || 'No email security data'}</div>
  }
  const { spf, dmarc, dkim } = email

  const dmarcPolicyColor =
    dmarc?.policy === 'reject'      ? 'text-brand-700 bg-brand-50 border-brand-100' :
    dmarc?.policy === 'quarantine'  ? 'text-amber-700 bg-amber-50 border-amber-100' :
    dmarc?.policy === 'none'        ? 'text-red-700 bg-red-50 border-red-100'       :
    'text-gray-500 bg-gray-100 border-gray-200'

  return (
    <div className="divide-y divide-gray-50">
      {/* SPF */}
      <div className="px-6 py-3">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-sm text-gray-700 font-medium">SPF Record</span>
          {spf?.present
            ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Present</span>
            : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full"><XCircle className="w-3 h-3" />Missing</span>
          }
        </div>
        {spf?.record && <p className="text-[11px] text-gray-400 mono mt-1 break-all">{spf.record}</p>}
      </div>

      {/* DMARC */}
      <div className="px-6 py-3">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-sm text-gray-700 font-medium">DMARC Policy</span>
          <div className="flex items-center gap-2">
            {dmarc?.policy && (
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${dmarcPolicyColor}`}>
                p={dmarc.policy}
              </span>
            )}
            {dmarc?.present
              ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Present</span>
              : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full"><XCircle className="w-3 h-3" />Missing</span>
            }
          </div>
        </div>
        {dmarc?.record && <p className="text-[11px] text-gray-400 mono mt-1 break-all">{dmarc.record}</p>}
      </div>

      {/* DKIM */}
      <div className="px-6 py-3">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-sm text-gray-700 font-medium">DKIM Signing</span>
          {dkim?.present
            ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Detected</span>
            : <span className="inline-flex items-center gap-1 text-xs font-semibold text-amber-700 bg-amber-50 border border-amber-100 px-2 py-0.5 rounded-full"><AlertCircle className="w-3 h-3" />Not detected</span>
          }
        </div>
        {dkim?.selector && (
          <p className="text-[11px] text-gray-400 mt-1">Selector: <span className="mono">{dkim.selector}</span></p>
        )}
        {!dkim?.present && (
          <p className="text-[11px] text-gray-400 mt-1">Common selectors probed — custom selector may be in use.</p>
        )}
      </div>
    </div>
  )
}

// ── Report View ──────────────────────────────────────────────────────────────

function ReportView({ report }) {
  const { cyber_metrics_score: score, risk_level, findings, recommendations, modules } = report
  const duration = durationSeconds(report.started_at, report.completed_at)

  return (
    <div className="space-y-4">

      {/* Score hero */}
      <div className="card-md overflow-hidden">
        <div className="flex flex-col sm:flex-row items-center sm:items-stretch">
          {/* Ring */}
          <div className="flex flex-col items-center justify-center gap-2 px-8 py-6 sm:border-r border-gray-100 sm:min-w-[180px]">
            <span className="label text-[10px]">Cyber Metrics Score</span>
            <ScoreRing score={score} riskLevel={risk_level} />
          </div>

          {/* Quick counts */}
          <div className="flex-1 grid grid-cols-3 divide-x divide-gray-100">
            {[
              { label: 'Findings',      value: findings?.length ?? 0 },
              { label: 'Actions',       value: recommendations?.length ?? 0 },
              { label: 'Scan Duration', value: duration ?? '—' },
            ].map(({ label, value }) => (
              <div key={label} className="flex flex-col items-center justify-center py-6 gap-1">
                <span className="text-2xl font-bold text-gray-900">{value}</span>
                <span className="text-xs font-medium text-gray-400">{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="card overflow-hidden">
        <SectionHeader icon={AlertCircle} title={`Findings (${findings?.length ?? 0})`} />
        <FindingsPanel findings={findings} />
      </div>

      {/* Recommendations */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Shield} title={`Recommended Actions (${recommendations?.length ?? 0})`} />
        <RecommendationsPanel recommendations={recommendations} />
      </div>

      {/* DNS */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Server} title="DNS Analysis" />
        <DnsPanel dns={modules?.dns} />
      </div>

      {/* SSL */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Lock} title="SSL / HTTPS" />
        <SslPanel ssl={modules?.ssl} />
      </div>

      {/* Security Headers */}
      <div className="card overflow-hidden">
        <SectionHeader icon={FileText} title="Security Headers" />
        <HeadersPanel headers={modules?.headers} />
      </div>

      {/* Email Security */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Mail} title="Email Security (SPF · DMARC · DKIM)" />
        <EmailPanel email={modules?.email_security} />
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function ScanDetail() {
  const { id }  = useParams()
  const navigate = useNavigate()

  const [scan,          setScan]          = useState(null)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [refreshing,    setRefreshing]    = useState(false)
  const [report,        setReport]        = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError,   setReportError]   = useState(null)
  const pollRef = useRef(null)

  const loadReport = useCallback(async () => {
    setReportLoading(true)
    setReportError(null)
    try {
      const r = await api.getScanReport(id)
      setReport(r)
    } catch (e) {
      setReportError(e.message)
    } finally {
      setReportLoading(false)
    }
  }, [id])

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getScan(id)
      const s    = data.scan || data
      setScan(s)
      if (s.status === 'completed' && !report) {
        loadReport()
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [id, report, loadReport])

  useEffect(() => { load() }, [load])

  // Auto-poll while active; fetch report when transitioning to completed
  useEffect(() => {
    if (!scan) return
    if (ACTIVE.has(scan.status)) {
      pollRef.current = setInterval(() => load(true), POLL_MS)
    } else {
      clearInterval(pollRef.current)
      if (scan.status === 'completed' && !report && !reportLoading) {
        loadReport()
      }
    }
    return () => clearInterval(pollRef.current)
  }, [scan?.status]) // eslint-disable-line react-hooks/exhaustive-deps

  const isActive = scan && ACTIVE.has(scan.status)

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
      <Link to="/scans" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-brand-600 transition-colors font-medium">
        <ArrowLeft className="w-4 h-4" />
        Back to Scans
      </Link>

      {loading ? (
        <div className="flex items-center justify-center py-32"><Spinner size="lg" /></div>
      ) : error ? (
        <ErrorAlert message={error} onRetry={() => load()} />
      ) : !scan ? null : (
        <>
          {/* Page header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h1 className="text-xl font-bold text-gray-900 truncate">{scan.domain}</h1>
                <StatusBadge status={scan.status} />
              </div>
              <p className="mono text-xs text-gray-300">{scan.id}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <button onClick={() => navigate(`/domain/${encodeURIComponent(scan.domain)}/history`)} className="btn-secondary">
                <Globe className="w-4 h-4" />
                Domain History
              </button>
              <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>

          {/* Active banner */}
          {isActive && (
            <div className="flex items-center gap-3 px-4 py-3 bg-amber-50 border border-amber-100 rounded-xl text-sm">
              <Spinner size="sm" />
              <span className="text-amber-800 font-medium">
                Scan is {scan.status} — auto-refreshing every {POLL_MS / 1000}s
              </span>
            </div>
          )}

          {/* Main grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Report panel — 2/3 width */}
            <div className="lg:col-span-2">
              {scan.status === 'completed' ? (
                reportLoading ? (
                  <div className="card flex items-center justify-center py-24">
                    <Spinner size="lg" />
                  </div>
                ) : reportError ? (
                  <ErrorAlert message={reportError} onRetry={loadReport} />
                ) : report ? (
                  <ReportView report={report} />
                ) : null
              ) : scan.status === 'failed' ? (
                <div className="card flex items-start gap-3 px-6 py-6 text-red-700">
                  <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-bold text-sm">Scan failed</p>
                    <p className="text-xs text-red-400 mt-1">The scan engine encountered an error. Try re-scanning this domain.</p>
                  </div>
                </div>
              ) : (
                <div className="card flex flex-col items-center gap-4 py-20 text-center">
                  <div className="w-12 h-12 rounded-2xl bg-brand-50 flex items-center justify-center">
                    <ScanLine className="w-5 h-5 text-brand-600" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-gray-900">Scan in progress</p>
                    <p className="text-xs text-gray-400 mt-1">Results will appear here once complete</p>
                  </div>
                  <Spinner />
                </div>
              )}
            </div>

            {/* Sidebar */}
            <div className="space-y-4">

              {/* Scan info */}
              <div className="card overflow-hidden">
                <SectionHeader icon={Hash} title="Scan Information" />
                <div>
                  <KV label="Scan ID"   value={<span className="mono text-xs text-brand-600">{scan.id}</span>} />
                  <KV label="Domain"    value={scan.domain} />
                  <KV label="Status"    value={<StatusBadge status={scan.status} />} />
                  <KV label="Score"     value={
                    scan.score != null
                      ? <span className="font-bold text-brand-600">{scan.score} / 100</span>
                      : '—'
                  } />
                  <KV label="Risk Level" value={
                    scan.rating
                      ? <span className={`text-xs font-bold px-2 py-0.5 rounded-full border capitalize ${(RISK_CFG[scan.rating] || RISK_CFG.unknown).pill}`}>
                          {scan.rating}
                        </span>
                      : '—'
                  } />
                  <KV label="Created"   value={formatDate(scan.created_at)} />
                  {report?.started_at   && <KV label="Started"   value={formatDate(report.started_at)} />}
                  {report?.completed_at && <KV label="Completed" value={formatDate(report.completed_at)} />}
                </div>
              </div>

              {/* Quick actions */}
              <div className="card overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100">
                  <h3 className="text-sm font-bold text-gray-900">Quick Actions</h3>
                </div>
                <div className="divide-y divide-gray-50">
                  {[
                    { icon: Globe,    label: 'View domain history',    action: () => navigate(`/domain/${encodeURIComponent(scan.domain)}/history`), color: 'bg-blue-50 text-blue-600'   },
                    { icon: ScanLine, label: 'Scan this domain again', action: () => navigate('/scans/new'), color: 'bg-brand-50 text-brand-600'  },
                    { icon: Clock,    label: 'Back to all scans',      action: () => navigate('/scans'),     color: 'bg-gray-100 text-gray-500'   },
                    { icon: Shield,   label: 'Back to dashboard',      action: () => navigate('/dashboard'), color: 'bg-gray-100 text-gray-500'   },
                  ].map(({ icon: Icon, label, action, color }) => (
                    <button key={label} onClick={action} className="w-full flex items-center gap-3 px-6 py-3.5 text-sm text-gray-700 hover:bg-brand-50 transition-colors group">
                      <div className={`w-7 h-7 rounded-lg ${color} flex items-center justify-center`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <span className="flex-1 text-left">{label}</span>
                      <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500" />
                    </button>
                  ))}
                </div>
              </div>

            </div>
          </div>
        </>
      )}
    </div>
  )
}
