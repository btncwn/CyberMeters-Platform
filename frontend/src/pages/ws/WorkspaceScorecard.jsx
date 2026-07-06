import { parseServerDate } from '../../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle, AlertCircle, XCircle, HelpCircle, ArrowRight,
  Mail, Lock, Globe, Package, Terminal,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, ReferenceLine,
} from 'recharts'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'

// ── RatingBadge — posture rating (score-derived, distinct from finding severity) ──
const RATING_CFG = {
  excellent: { label: 'Excellent', cls: 'bg-brand-50 text-brand-700 border-brand-100'  },
  good:      { label: 'Good',      cls: 'bg-green-50 text-green-700 border-green-100'  },
  moderate:  { label: 'Moderate',  cls: 'bg-amber-50 text-amber-700 border-amber-100'  },
  high:      { label: 'Poor',      cls: 'bg-orange-50 text-orange-700 border-orange-100' },
  critical:  { label: 'Critical',  cls: 'bg-red-50 text-red-700 border-red-100'        },
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

const WEIGHTS = {
  email_security:   { label: 'Email Security',     pct: 20, Icon: Mail      },
  ssl_certificates: { label: 'SSL & Certificates', pct: 20, Icon: Lock      },
  attack_surface:   { label: 'Attack Surface',     pct: 25, Icon: Globe     },
  third_party_risk: { label: 'Third-Party Risk',   pct: 15, Icon: Package   },
  admin_exposure:   { label: 'Admin Exposure',     pct: 20, Icon: Terminal  },
}

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

// ── Posture chart ─────────────────────────────────────────────────────────────

function PostureBar({ data }) {
  const chartData = Object.entries(WEIGHTS).map(([key, meta]) => ({
    category:  meta.label,
    score:     data?.[key]?.score ?? 0,
    status:    data?.[key]?.status ?? 'unknown',
    weight:    meta.pct,
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} margin={{ top: 8, right: 16, left: -8, bottom: 8 }} barSize={36}>
        <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6" vertical={false} />
        <XAxis
          dataKey="category"
          tick={{ fontSize: 11, fill: '#6B7280' }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fontSize: 11, fill: '#9CA3AF' }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: '#F9FAFB' }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload
            return (
              <div className="bg-white border border-gray-100 rounded-xl shadow-lg px-3 py-2 text-xs">
                <p className="font-semibold text-gray-900">{d.category}</p>
                <p className="text-gray-500">Score: <span className="font-bold text-gray-900">{d.score}/100</span></p>
                <p className="text-gray-500">Weight: {d.weight}%</p>
              </div>
            )
          }}
        />
        <ReferenceLine y={80} stroke="#00876A" strokeDasharray="4 4" strokeOpacity={0.3} />
        <Bar dataKey="score" radius={[6, 6, 0, 0]}>
          {chartData.map((d, i) => (
            <Cell key={i} fill={statusColors(d.status).bar} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

// ── Category card ─────────────────────────────────────────────────────────────

function PostureCard({ catKey, data }) {
  const meta    = WEIGHTS[catKey]
  const cat     = data?.[catKey]
  const score   = cat?.score  ?? null
  const status  = cat?.status ?? 'unknown'
  const reasons = cat?.reasons ?? []
  const c       = statusColors(status)
  const Icon    = meta.Icon

  return (
    <div className={`card p-5 ring-1 ${c.ring}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg ${c.bg} flex items-center justify-center`}>
            <Icon className={`w-4 h-4 ${c.text}`} />
          </div>
          <div>
            <p className="text-sm font-semibold text-gray-900">{meta.label}</p>
            <p className="text-[10px] text-gray-400">Weight: {meta.pct}%</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-black text-gray-900">
            {score !== null ? score : '—'}
          </p>
          <p className="text-[10px] text-gray-400">/100</p>
        </div>
      </div>

      <div className="mb-3">
        <StatusBadge status={status} />
      </div>

      {/* Score bar */}
      {score !== null && (
        <div className="h-1.5 bg-gray-100 rounded-full mb-3 overflow-hidden">
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${score}%`, backgroundColor: c.bar }}
          />
        </div>
      )}

      {/* Reasons */}
      {reasons.length > 0 && (
        <ul className="space-y-1 mt-2">
          {reasons.map((r, i) => (
            <li key={i} className="flex items-start gap-1.5 text-[11px] text-gray-500 leading-relaxed">
              <span className={`w-1 h-1 rounded-full mt-1.5 flex-shrink-0 ${
                status === 'critical' ? 'bg-red-400' :
                status === 'warning'  ? 'bg-amber-400' :
                status === 'fair'     ? 'bg-blue-400' :
                                        'bg-brand-400'
              }`} />
              {r}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// ── Weight legend ─────────────────────────────────────────────────────────────

function WeightLegend() {
  return (
    <div className="flex flex-wrap gap-3">
      {Object.entries(WEIGHTS).map(([, meta]) => (
        <div key={meta.label} className="flex items-center gap-1.5 text-xs text-gray-500">
          <span className="font-semibold text-gray-700">{meta.pct}%</span>
          {meta.label}
        </div>
      ))}
    </div>
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
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const r = await api.getWorkspaceScorecardReport(wsId)
      setReport(r)
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
  const posture = sc?.security_posture ?? null

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
          {posture?.overall_score != null && posture.overall_score !== sc?.security_score && (
            <div className="card px-5 py-3 text-center">
              <p className="label mb-1">Posture Score</p>
              <p className="text-3xl font-black text-gray-800">{posture.overall_score}</p>
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

      {/* ── Security Posture Breakdown ── */}
      <div className="card p-6 mb-8">
        <div className="flex items-start justify-between mb-1 gap-4 flex-wrap">
          <div>
            <h2 className="font-semibold text-gray-900">Security Posture Breakdown</h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Your overall score is calculated from five weighted categories.
            </p>
          </div>
          {posture?.overall_score != null && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400">Posture score</span>
              <span className="text-xl font-black text-gray-900">{posture.overall_score}<span className="text-sm font-normal text-gray-400">/100</span></span>
            </div>
          )}
        </div>

        <div className="mb-4 mt-2">
          <WeightLegend />
        </div>

        {posture ? (
          <>
            {/* Bar chart */}
            <div className="mb-6">
              <PostureBar data={posture} />
            </div>

            {/* Category cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.keys(WEIGHTS).map(key => (
                <PostureCard key={key} catKey={key} data={posture} />
              ))}
            </div>
          </>
        ) : (
          <div className="py-10 text-center text-sm text-gray-400">
            Security posture breakdown will appear after the next completed scan.
          </div>
        )}
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
