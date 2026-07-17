import { parseServerDate } from '../../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle, AlertCircle, XCircle, HelpCircle, ArrowRight,
} from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import CyberMotDomains from '../../components/CyberMotDomains'
import { bandMeta } from '../../lib/score-presentation'

// ── RatingBadge — posture rating (score-derived, distinct from finding severity) ──
const RATING_CFG = {
  excellent: { label: bandMeta('excellent').label, cls: 'bg-brand-50 text-brand-700 border-brand-100'  },
  good:      { label: bandMeta('good').label,      cls: 'bg-green-50 text-green-700 border-green-100'  },
  moderate:  { label: bandMeta('moderate').label,  cls: 'bg-amber-50 text-amber-700 border-amber-100'  },
  high:      { label: bandMeta('high').label,      cls: 'bg-orange-50 text-orange-700 border-orange-100' },
  critical:  { label: bandMeta('critical').label,  cls: 'bg-red-50 text-red-700 border-red-100'        },
}
function RatingBadge({ rating }) {
  if (!rating) return <span className="text-gray-300 text-xs">—</span>
  const cfg = RATING_CFG[rating.toLowerCase()] ?? { label: rating, cls: 'bg-gray-50 text-gray-500 border-gray-100' }
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded-full border capitalize ${cfg.cls}`}>
      {cfg.label}
    </span>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function statusColors(status) {
  return {
    good:     { ring: 'ring-brand-200',  bg: 'bg-brand-50',  text: 'text-brand-700',  bar: '#00876A' },
    fair:     { ring: 'ring-blue-200',   bg: 'bg-blue-50',   text: 'text-blue-700',   bar: '#3B82F6' },
    warning:  { ring: 'ring-amber-200',  bg: 'bg-amber-50',  text: 'text-amber-700',  bar: '#F59E0B' },
    critical: { ring: 'ring-red-200',    bg: 'bg-red-50',    text: 'text-red-700',    bar: '#EF4444' },
    unknown:  { ring: 'ring-gray-200',   bg: 'bg-gray-50',   text: 'text-gray-500',   bar: '#D1D5DB' },
  }[status] ?? { ring: 'ring-gray-200', bg: 'bg-gray-50', text: 'text-gray-500', bar: '#D1D5DB' }
}

function StatusIcon({ status, className = 'w-5 h-5 flex-shrink-0' }) {
  if (status === 'good')     return <CheckCircle className={`${className} text-brand-500`} />
  if (status === 'fair')     return <CheckCircle className={`${className} text-blue-400`} />
  if (status === 'warning')  return <AlertCircle className={`${className} text-amber-400`} />
  if (status === 'critical') return <XCircle     className={`${className} text-red-500`} />
  return <HelpCircle className={`${className} text-gray-300`} />
}

function StatusBadge({ status }) {
  const c = statusColors(status)
  return (
    <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full ${c.bg} ${c.text}`}>
      {status ?? 'unknown'}
    </span>
  )
}

// ── Executive summary blocks ──────────────────────────────────────────────────

function SummaryBlock({ label, items, accent }) {
  if (!items?.length) return null
  const colors = {
    good:    { dot: 'bg-brand-500', text: 'text-gray-700' },
    warning: { dot: 'bg-amber-400', text: 'text-amber-800' },
    urgent:  { dot: 'bg-red-500',   text: 'text-red-700'  },
  }[accent] ?? { dot: 'bg-gray-400', text: 'text-gray-600' }

  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-3">
        <div className={`w-2 h-2 rounded-full ${colors.dot}`} />
        <h3 className="font-semibold text-sm text-gray-900">{label}</h3>
        <span className="ml-auto text-xs text-gray-400 font-medium">{items.length}</span>
      </div>
      <ul className="space-y-1.5">
        {items.map((s, i) => (
          <li key={i} className={`text-xs leading-relaxed ${colors.text}`}>{s}</li>
        ))}
      </ul>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function WorkspaceScorecard() {
  const { wsId, wsName } = useWorkspace()
  const [report, setReport]   = useState(null)
  const [motDomains, setMotDomains] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const [r, mot] = await Promise.allSettled([
        api.getWorkspaceScorecardReport(wsId),
        api.getCyberMotDomains(wsId),
      ])
      if (r.status === 'fulfilled') setReport(r.value)
      else throw r.reason
      setMotDomains(mot.status === 'fulfilled' ? (mot.value?.cyber_mot_domains ?? []) : [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const sc      = report?.scorecard
  const sum     = report?.executive_summary

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* ── Header ── */}
      <div className="flex items-start justify-between mb-8 gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Executive Scorecard</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {wsName} · Generated {report ? parseServerDate(report.generated_at).toLocaleString() : '—'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {sc?.security_score != null && (
            <div className="card px-5 py-3 text-center">
              <p className="label mb-1">Overall Score</p>
              <p className="text-3xl font-black text-brand-600">{sc.security_score}</p>
            </div>
          )}
          {sc?.risk_rating && (
            <div className="card px-5 py-3 text-center">
              <p className="label mb-1">Security Rating</p>
              <RatingBadge rating={sc.risk_rating} />
            </div>
          )}
        </div>
      </div>

      <div className="mb-8">
        <CyberMotDomains domains={motDomains} />
      </div>

      {/* ── Section grid ── */}
      {report?.sections?.length > 0 && (
        <div className="mb-8">
          <h2 className="font-semibold text-gray-900 mb-4">Security Sections</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {report.sections.map(sec => (
              <div key={sec.title} className="card p-5">
                <div className="flex items-start gap-3">
                  <StatusIcon status={sec.status} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <h3 className="font-semibold text-sm text-gray-900">{sec.title}</h3>
                      <StatusBadge status={sec.status} />
                    </div>
                    <p className="text-xs text-gray-500 leading-relaxed">{sec.summary}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Executive Summary ── */}
      {sum && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <SummaryBlock label="Good"               items={sum.good}               accent="good"    />
          <SummaryBlock label="Attention Required" items={sum.attention_required} accent="warning" />
          <SummaryBlock label="Urgent"             items={sum.urgent}             accent="urgent"  />
        </div>
      )}

      {/* ── Top Recommendations ── */}
      {report?.recommendations?.length > 0 && (
        <div className="card p-6">
          <h2 className="font-semibold text-gray-900 mb-4">Top Recommendations</h2>
          <div className="space-y-3">
            {report.recommendations.map((r, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-gray-50">
                <span className="w-6 h-6 rounded-full bg-brand-600 text-white text-xs font-bold flex items-center justify-center flex-shrink-0 mt-0.5">
                  {r.priority}
                </span>
                <div>
                  <p className="text-sm font-semibold text-gray-900">{r.title}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{r.description}</p>
                </div>
                <ArrowRight className="w-4 h-4 text-gray-300 flex-shrink-0 mt-0.5 ml-auto" />
              </div>
            ))}
          </div>
        </div>
      )}

    </WsPage>
  )
}
