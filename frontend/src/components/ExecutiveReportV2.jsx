import { useState } from 'react'
import {
  Shield, Globe, Mail, Fingerprint, Eye, TrendingUp, TrendingDown,
  Minus, AlertCircle, CheckCircle, ChevronDown, Target, Clock,
  Sparkles, FileText, Lock,
} from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// Executive Report V2 — Intelligence Engine presentation.
//
// Renders the GET /api/scans/:id/executive-report-v2 contract as an executive
// risk assessment rather than a collection of scanner modules. Each Intelligence
// Engine becomes a first-class section; engines that are not enabled or have no
// evidence render a deliberate "Not Enabled" / "Coming Soon" state instead of an
// empty panel.
// ─────────────────────────────────────────────────────────────────────────────

const RATING_CFG = {
  excellent: { color: '#00876A', text: 'text-brand-600', ring: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Excellent' },
  good:      { color: '#00876A', text: 'text-brand-600', ring: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Good' },
  moderate:  { color: '#F59E0B', text: 'text-amber-500', ring: 'text-amber-500', pill: 'bg-amber-50 text-amber-700 border-amber-100', label: 'Moderate' },
  high:      { color: '#F97316', text: 'text-orange-500', ring: 'text-orange-500', pill: 'bg-orange-50 text-orange-700 border-orange-100', label: 'Needs Attention' },
  critical:  { color: '#EF4444', text: 'text-red-500', ring: 'text-red-500', pill: 'bg-red-50 text-red-700 border-red-100', label: 'Critical' },
  unknown:   { color: '#D1D5DB', text: 'text-gray-400', ring: 'text-gray-300', pill: 'bg-gray-100 text-gray-500 border-gray-200', label: 'Unrated' },
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 }
const SEV_BADGE = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'text-xs font-semibold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 border border-gray-200',
}
const PRIORITY_PILL = {
  P1: 'bg-red-50 text-red-700 border-red-100',
  P2: 'bg-orange-50 text-orange-700 border-orange-100',
  P3: 'bg-amber-50 text-amber-700 border-amber-100',
}

function fmtDate(str) {
  if (!str) return '—'
  const d = new Date(str.includes('T') ? str : str.replace(' ', 'T') + 'Z')
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// ── Score Ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, rating, size = 132 }) {
  const r = (size / 2) - 10
  const circ = 2 * Math.PI * r
  const pct = score != null ? Math.max(0, Math.min(100, score)) : 0
  const fill = circ * (pct / 100)
  const cfg = RATING_CFG[rating] || RATING_CFG.unknown

  return (
    <div className="flex flex-col items-center select-none">
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`} className="w-full h-full -rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#F3F4F6" strokeWidth="10" />
          {score != null && (
            <circle
              cx={size / 2} cy={size / 2} r={r} fill="none"
              stroke={cfg.color} strokeWidth="10" strokeLinecap="round"
              strokeDasharray={`${fill} ${circ - fill}`}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score != null
            ? <><span className={`text-4xl font-bold ${cfg.text}`}>{score}</span><span className="text-[10px] text-gray-300 font-semibold">/ 100</span></>
            : <span className="text-gray-300 text-sm">—</span>}
        </div>
      </div>
      <span className={`text-xs font-bold px-3 py-1 rounded-full border mt-2 ${cfg.pill}`}>
        {cfg.label}
      </span>
    </div>
  )
}

// ── Trend pill ──────────────────────────────────────────────────────────────

function TrendPill({ trend }) {
  if (!trend || trend.status !== 'available' || trend.direction === 'not_available') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-400 bg-gray-50 border border-gray-100 rounded-full px-3 py-1">
        <Minus className="w-3.5 h-3.5" /> No prior scan to compare
      </span>
    )
  }
  const change = trend.score_change
  const cfg = trend.direction === 'improved'
    ? { Icon: TrendingUp, cls: 'text-brand-700 bg-brand-50 border-brand-100', sign: change > 0 ? `+${change}` : change }
    : trend.direction === 'declined'
      ? { Icon: TrendingDown, cls: 'text-red-600 bg-red-50 border-red-100', sign: change }
      : { Icon: Minus, cls: 'text-gray-500 bg-gray-50 border-gray-100', sign: '0' }
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-bold rounded-full px-3 py-1 border ${cfg.cls}`}>
      <cfg.Icon className="w-3.5 h-3.5" />
      {cfg.sign} pts vs last scan
    </span>
  )
}

// ── Compact finding / observation row ─────────────────────────────────────────

function ItemRow({ item, index, muted = false }) {
  const sev = item.severity || 'info'
  return (
    <li className="flex items-start gap-3 px-5 py-3">
      <div className={`w-5 h-5 rounded-md flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5 ${muted ? 'bg-gray-100 text-gray-500' : 'bg-brand-50 text-brand-700'}`}>
        {index + 1}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <p className="text-sm font-semibold text-gray-900 leading-snug">{item.title}</p>
          {!muted && <span className={`flex-shrink-0 ${SEV_BADGE[sev] || SEV_BADGE.info}`}>{sev}</span>}
        </div>
        {item.description && (
          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed line-clamp-2">{item.description}</p>
        )}
      </div>
    </li>
  )
}

function ItemList({ items, muted = false, emptyLabel }) {
  const sorted = [...(items || [])].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  )
  if (sorted.length === 0) {
    return (
      <div className="flex items-center gap-2 px-5 py-6 text-sm text-gray-400">
        <CheckCircle className="w-4 h-4 text-brand-500 flex-shrink-0" />
        {emptyLabel || 'Nothing to report here.'}
      </div>
    )
  }
  return (
    <ul className="divide-y divide-gray-50">
      {sorted.map((item, i) => (
        <ItemRow key={item.id || i} item={item} index={i} muted={muted} />
      ))}
    </ul>
  )
}

// ── Engine section ────────────────────────────────────────────────────────────

const ENGINE_META = {
  attack_surface: { icon: Globe, title: 'Attack Surface Intelligence', blurb: 'Externally exposed assets, services and infrastructure.' },
  business_email: { icon: Mail, title: 'Business Email Intelligence', blurb: 'Email authentication and deliverability posture.' },
  identity:       { icon: Fingerprint, title: 'Identity Intelligence', blurb: 'Externally observable identity and login surfaces.' },
  brand:          { icon: Shield, title: 'Brand Intelligence', blurb: 'Lookalike domains and brand abuse signals.' },
}

// Engine that is not enabled / has no evidence — deliberate state, never an empty panel.
function EngineUnavailable({ meta, engine, comingSoon }) {
  const Icon = meta.icon
  return (
    <div className="card p-6 flex items-start gap-4">
      <div className="w-11 h-11 rounded-xl bg-gray-50 border border-gray-100 flex items-center justify-center flex-shrink-0">
        <Icon className="w-5 h-5 text-gray-300" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="text-sm font-bold text-gray-700">{meta.title}</h3>
          <span className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full border ${comingSoon ? 'bg-brand-50 text-brand-700 border-brand-100' : 'bg-gray-100 text-gray-500 border-gray-200'}`}>
            {comingSoon ? <><Sparkles className="w-3 h-3" /> Coming Soon</> : <><Lock className="w-3 h-3" /> Not Enabled</>}
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1 leading-relaxed">
          {engine.summary || meta.blurb}
        </p>
      </div>
    </div>
  )
}

function EngineSection({ engineKey, engine }) {
  const [open, setOpen] = useState(true)
  const meta = ENGINE_META[engineKey]
  if (!meta || !engine) return null

  const status = engine.status
  // Not enabled / no evidence → deliberate state, not an empty panel.
  if (status === 'not_available') {
    // Identity is a future capability ("Coming Soon"); brand without evidence is "Not Enabled".
    const comingSoon = engineKey === 'identity'
    return <EngineUnavailable meta={meta} engine={engine} comingSoon={comingSoon} />
  }

  const Icon = meta.icon
  const findings = engine.findings || []
  const observations = engine.observations || []
  const recommendations = engine.recommendations || []
  const isPartial = status === 'partial'

  return (
    <div className="card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-6 py-4 border-b border-gray-100 bg-gray-50 text-left hover:bg-gray-100/70 transition-colors"
        aria-expanded={open}
      >
        <div className="w-8 h-8 rounded-lg bg-brand-100 flex items-center justify-center flex-shrink-0">
          <Icon className="w-4 h-4 text-brand-700" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-gray-900">{meta.title}</h3>
            {isPartial && (
              <span className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-100">
                Partial Coverage
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed line-clamp-1">{engine.summary || meta.blurb}</p>
        </div>
        <div className="hidden sm:flex items-center gap-3 flex-shrink-0 text-xs">
          <span className="text-gray-500"><span className="font-bold text-gray-900">{findings.length}</span> findings</span>
          <span className="text-gray-500"><span className="font-bold text-gray-900">{observations.length}</span> observations</span>
        </div>
        <ChevronDown className={`w-4 h-4 text-gray-300 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div>
          {findings.length > 0 && (
            <div>
              <p className="px-5 pt-4 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-400">Verified Findings</p>
              <ItemList items={findings} />
            </div>
          )}

          {findings.length === 0 && (
            <div className="flex items-center gap-2 px-5 py-5 text-sm text-gray-500">
              <CheckCircle className="w-4 h-4 text-brand-500 flex-shrink-0" />
              No actionable findings from this engine.
            </div>
          )}

          {observations.length > 0 && (
            <div className="border-t border-gray-50">
              <p className="px-5 pt-4 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-400">Observations</p>
              <ItemList items={observations} muted />
            </div>
          )}

          {recommendations.length > 0 && (
            <div className="border-t border-gray-50 px-5 py-4">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-2">Recommended Actions</p>
              <ul className="space-y-2">
                {recommendations.map((r, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <Target className="w-3.5 h-3.5 text-brand-500 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-gray-800 leading-snug">{r.title}</p>
                      {r.description && <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{r.description}</p>}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Prioritized remediation ───────────────────────────────────────────────────

function RemediationList({ items }) {
  if (!items?.length) {
    return (
      <div className="flex items-center gap-2 px-6 py-6 text-sm text-gray-400">
        <CheckCircle className="w-4 h-4 text-brand-500 flex-shrink-0" />
        No prioritized remediation required at this time.
      </div>
    )
  }
  return (
    <ol className="divide-y divide-gray-50">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-3 px-6 py-4">
          <span className={`flex-shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-full border mt-0.5 ${PRIORITY_PILL[item.priority] || 'bg-gray-100 text-gray-500 border-gray-200'}`}>
            {item.priority || '—'}
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-gray-900 leading-snug">{item.title}</p>
            {item.action && <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{item.action}</p>}
            {item.reason && <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{item.reason}</p>}
            {item.due_date && (
              <p className="text-[11px] text-gray-400 mt-1 inline-flex items-center gap-1">
                <Clock className="w-3 h-3" /> Target: {fmtDate(item.due_date)}
              </p>
            )}
          </div>
        </li>
      ))}
    </ol>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function ExecutiveReportV2({ report }) {
  if (!report) return null

  const score = report.cyber_metrics_score || {}
  const summary = report.executive_summary || {}
  const engines = report.intelligence_engines || {}
  const trend = report.historical_trends || summary.trend || {}
  const remediation = report.prioritized_remediation || []
  const verified = report.verified_findings || []
  const observations = report.observations || []
  const priorityActions = summary.priority_actions || []
  const topRisks = summary.top_risks || []

  return (
    <div className="space-y-5">

      {/* Executive Summary hero */}
      <section className="card-md overflow-hidden">
        <div className="px-6 pt-5 pb-2 flex items-center gap-2 border-b border-gray-50">
          <Sparkles className="w-4 h-4 text-brand-600" />
          <h2 className="text-sm font-bold text-gray-900">Executive Summary</h2>
        </div>
        <div className="flex flex-col lg:flex-row">
          {/* Score */}
          <div className="flex flex-col items-center justify-center gap-2 px-8 py-6 lg:border-r border-gray-100 lg:min-w-[210px]">
            <span className="label text-[10px]">Cyber Metrics Score</span>
            <ScoreRing score={score.value} rating={score.rating} />
            <p className="text-[11px] text-gray-400 text-center leading-relaxed max-w-[180px]">
              Your overall external security health, from 0 to 100. Higher is safer.
            </p>
          </div>
          {/* Narrative + signals */}
          <div className="flex-1 px-6 py-6 flex flex-col gap-4">
            <p className="text-[15px] text-gray-700 leading-relaxed">{summary.risk_narrative}</p>
            <div className="flex flex-wrap items-center gap-2">
              <TrendPill trend={trend} />
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-600 bg-gray-50 border border-gray-100 rounded-full px-3 py-1">
                <AlertCircle className="w-3.5 h-3.5 text-orange-400" />
                {summary.verified_findings_count ?? verified.length} verified findings
              </span>
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-600 bg-gray-50 border border-gray-100 rounded-full px-3 py-1">
                <Eye className="w-3.5 h-3.5 text-gray-400" />
                {summary.observations_count ?? observations.length} observations
              </span>
            </div>
          </div>
        </div>

        {/* Top priority actions */}
        {priorityActions.length > 0 && (
          <div className="border-t border-gray-100 px-6 py-4">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-2.5">Where to focus first</p>
            <ol className="space-y-2">
              {priorityActions.map((a, i) => (
                <li key={i} className="flex items-start gap-2.5">
                  <span className={`flex-shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-full border mt-0.5 ${PRIORITY_PILL[a.priority] || 'bg-brand-50 text-brand-700 border-brand-100'}`}>
                    {a.priority || i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-gray-900 leading-snug">{a.title}</p>
                    {a.action && <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{a.action}</p>}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}
      </section>

      {/* Top risks at a glance */}
      {topRisks.length > 0 && (
        <section className="card overflow-hidden">
          <div className="flex items-center gap-2.5 px-6 py-4 border-b border-gray-100 bg-gray-50">
            <div className="w-6 h-6 rounded-md bg-red-50 flex items-center justify-center">
              <AlertCircle className="w-3.5 h-3.5 text-red-500" />
            </div>
            <h2 className="text-sm font-bold text-gray-900">Top Risks</h2>
          </div>
          <ItemList items={topRisks} />
        </section>
      )}

      {/* Intelligence Engines */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 px-1">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-400">Intelligence Engines</h2>
          <div className="flex-1 h-px bg-gray-100" />
        </div>
        <EngineSection engineKey="attack_surface" engine={engines.attack_surface} />
        <EngineSection engineKey="business_email" engine={engines.business_email} />
        <EngineSection engineKey="identity"       engine={engines.identity} />
        <EngineSection engineKey="brand"          engine={engines.brand} />
      </section>

      {/* Prioritized remediation */}
      <section className="card overflow-hidden">
        <div className="flex items-center gap-2.5 px-6 py-4 border-b border-gray-100 bg-gray-50">
          <div className="w-6 h-6 rounded-md bg-brand-100 flex items-center justify-center">
            <Target className="w-3.5 h-3.5 text-brand-700" />
          </div>
          <h2 className="text-sm font-bold text-gray-900">Prioritized Remediation</h2>
        </div>
        <RemediationList items={remediation} />
      </section>

      {/* Observations (full) */}
      {observations.length > 0 && (
        <section className="card overflow-hidden">
          <div className="flex items-center gap-2.5 px-6 py-4 border-b border-gray-100 bg-gray-50">
            <div className="w-6 h-6 rounded-md bg-gray-100 flex items-center justify-center">
              <Eye className="w-3.5 h-3.5 text-gray-500" />
            </div>
            <h2 className="text-sm font-bold text-gray-900">Observations ({observations.length})</h2>
          </div>
          <ItemList items={observations} muted />
        </section>
      )}

      {/* Report meta footer */}
      <p className="text-[11px] text-gray-400 px-1 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="inline-flex items-center gap-1"><FileText className="w-3 h-3" /> Executive Intelligence Report v{report.version || '2.0'}</span>
        {report.domain?.name && <span>· {report.domain.name}</span>}
        {report.generated_at && <span>· Generated {fmtDate(report.generated_at)}</span>}
      </p>
    </div>
  )
}
