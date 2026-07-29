import { parseServerDate } from '../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Brain, Briefcase, CheckCircle, XCircle, AlertCircle, AlertTriangle,
  Shield, ShieldAlert, Mail, Cpu, Bug, Flame, RefreshCw,
  ChevronRight, TrendingUp, TrendingDown, Info, Globe, Lock,
  ExternalLink,
} from 'lucide-react'
import DmarcPolicyEvidenceCard from '../components/DmarcPolicyEvidenceCard'
import { api } from '../api'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'
import {
  isPhase5EvidenceAvailable,
  phase5KnownCount,
} from '../lib/phase5EvidencePresentation'

// ── Design-system helpers ─────────────────────────────────────────────────────

const SEV_BADGE = {
  critical:      'badge-critical',
  high:          'badge-high',
  medium:        'badge-medium',
  low:           'badge-low',
  informational: 'text-xs font-semibold px-2.5 py-0.5 rounded-full bg-gray-100 text-gray-500 border border-gray-200',
}

const SEV_DOT = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-amber-400',
  low:      'bg-blue-400',
}

const RISK_LEVEL_STYLE = {
  Critical:  { pill: 'bg-red-50 text-red-700 border-red-100',           dot: 'bg-red-500'    },
  High:      { pill: 'bg-orange-50 text-orange-700 border-orange-100',  dot: 'bg-orange-500' },
  Moderate:  { pill: 'bg-amber-50 text-amber-700 border-amber-100',     dot: 'bg-amber-400'  },
  Low:       { pill: 'bg-brand-50 text-brand-700 border-brand-100',     dot: 'bg-brand-500'  },
  Excellent: { pill: 'bg-brand-50 text-brand-700 border-brand-100',     dot: 'bg-brand-500'  },
}

const BIZ_RISK_STYLE = {
  Low:      { text: 'text-brand-600', bg: 'bg-brand-50 text-brand-700 border-brand-100' },
  Moderate: { text: 'text-amber-600', bg: 'bg-amber-50 text-amber-700 border-amber-100' },
  High:     { text: 'text-orange-600', bg: 'bg-orange-50 text-orange-700 border-orange-100' },
  Critical: { text: 'text-red-600',   bg: 'bg-red-50 text-red-700 border-red-100'       },
}

const EMAIL_SCORE_STYLE = {
  EXCELLENT: { color: '#00876A', label: 'Excellent', cls: 'text-brand-600' },
  GOOD:      { color: '#00876A', label: 'Good',      cls: 'text-brand-600' },
  FAIR:      { color: '#F59E0B', label: 'Fair',      cls: 'text-amber-500' },
  POOR:      { color: '#F97316', label: 'Poor',      cls: 'text-orange-500' },
  CRITICAL:  { color: '#EF4444', label: 'Critical',  cls: 'text-red-500'   },
}

const DMARC_STATUS_STYLE = {
  FULLY_PROTECTED:   'bg-brand-50 text-brand-700 border-brand-100',
  PARTIAL_PROTECTED: 'bg-amber-50 text-amber-700 border-amber-100',
  REPORTING_ONLY:    'bg-orange-50 text-orange-700 border-orange-100',
  MISSING:           'bg-red-50 text-red-700 border-red-100',
  ERROR:             'bg-gray-100 text-gray-500 border-gray-200',
}

const SPF_STATUS_STYLE = {
  PASS:    'bg-brand-50 text-brand-700 border-brand-100',
  SOFTFAIL:'bg-amber-50 text-amber-700 border-amber-100',
  PARTIAL: 'bg-amber-50 text-amber-700 border-amber-100',
  FAIL:    'bg-red-50 text-red-700 border-red-100',
  MISSING: 'bg-red-50 text-red-700 border-red-100',
}

const P_COLOR = {
  p1: { bg: 'bg-red-50',    border: 'border-red-100',    text: 'text-red-700',    badge: 'bg-red-500 text-white'    },
  p2: { bg: 'bg-orange-50', border: 'border-orange-100', text: 'text-orange-700', badge: 'bg-orange-500 text-white' },
  p3: { bg: 'bg-gray-50',   border: 'border-gray-200',   text: 'text-gray-600',   badge: 'bg-gray-400 text-white'   },
}

const CVE_SEV_STYLE = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH:     'bg-orange-100 text-orange-700',
  MEDIUM:   'bg-amber-100 text-amber-700',
  LOW:      'bg-blue-100 text-blue-700',
  UNKNOWN:  'bg-gray-100 text-gray-500',
}

// ── Shared primitives ─────────────────────────────────────────────────────────

function SectionHeader({ icon: Icon, title, aside, iconBg = 'bg-brand-100', iconColor = 'text-brand-700' }) {
  return (
    <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100 bg-gray-50/80">
      <div className="flex items-center gap-2">
        <div className={`w-6 h-6 rounded-md ${iconBg} flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-3.5 h-3.5 ${iconColor}`} />
        </div>
        <h2 className="text-sm font-bold text-gray-900">{title}</h2>
      </div>
      {aside && <div className="flex-shrink-0">{aside}</div>}
    </div>
  )
}

function StatusPill({ value, trueLabel = 'Yes', falseLabel = 'No' }) {
  return value
    ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full">
        <CheckCircle className="w-3 h-3" />{trueLabel}
      </span>
    : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full">
        <XCircle className="w-3 h-3" />{falseLabel}
      </span>
}

function EmptyState({ icon: Icon = Info, title, subtitle }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center px-6">
      <div className="w-10 h-10 rounded-2xl bg-gray-100 flex items-center justify-center">
        <Icon className="w-5 h-5 text-gray-300" />
      </div>
      <p className="text-sm font-semibold text-gray-500">{title}</p>
      {subtitle && <p className="text-xs text-gray-400">{subtitle}</p>}
    </div>
  )
}

// ── Score ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, status, size = 'md' }) {
  const cfg   = EMAIL_SCORE_STYLE[status] || EMAIL_SCORE_STYLE.FAIR
  const r     = size === 'sm' ? 36 : 48
  const vb    = size === 'sm' ? 84 : 108
  const sw    = size === 'sm' ? 8  : 9
  const circ  = 2 * Math.PI * r
  const fill  = score != null ? circ * (score / 100) : 0

  return (
    <div className="flex flex-col items-center select-none">
      <div className={size === 'sm' ? 'relative w-[84px] h-[84px]' : 'relative w-[108px] h-[108px]'}>
        <svg viewBox={`0 0 ${vb} ${vb}`} className="w-full h-full -rotate-90">
          <circle cx={vb/2} cy={vb/2} r={r} fill="none" stroke="#F3F4F6" strokeWidth={sw} />
          {score != null && (
            <circle cx={vb/2} cy={vb/2} r={r} fill="none"
              stroke={cfg.color} strokeWidth={sw} strokeLinecap="round"
              strokeDasharray={`${fill} ${circ - fill}`} />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score != null
            ? <><span className={`${size === 'sm' ? 'text-xl' : 'text-2xl'} font-bold ${cfg.cls}`}>{score}</span>
                <span className="text-[9px] text-gray-300 font-semibold">/100</span></>
            : <span className="text-gray-300 text-xs">—</span>}
        </div>
      </div>
      {status && (
        <span className="text-xs font-bold px-2.5 py-0.5 rounded-full mt-1"
              style={{ background: cfg.color + '18', color: cfg.color }}>
          {cfg.label}
        </span>
      )}
    </div>
  )
}

// ── Score bar (weighted breakdown) ───────────────────────────────────────────

function ScoreBar({ label, value, max }) {
  const pct   = max > 0 ? Math.round((value / max) * 100) : 0
  const color = pct >= 80 ? '#00876A' : pct >= 50 ? '#F59E0B' : '#EF4444'
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-500 w-16 text-right flex-shrink-0">{label}</span>
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs font-bold text-gray-700 w-12 flex-shrink-0">{value}/{max}</span>
    </div>
  )
}

// ── No workspace state ────────────────────────────────────────────────────────

function NoWorkspaceState() {
  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="card p-12 flex flex-col items-center text-center gap-4">
        <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center">
          <Brain className="w-7 h-7 text-brand-600" />
        </div>
        <div>
          <h3 className="text-base font-bold text-gray-900 mb-1">No workspace selected</h3>
          <p className="text-sm text-gray-400 max-w-xs">
            Intelligence data is scoped to your active workspace. Select one to view threat intelligence.
          </p>
        </div>
        <Link to="/workspaces" className="btn-primary">
          <Briefcase className="w-4 h-4" />
          Go to Workspaces
        </Link>
      </div>
    </div>
  )
}

// ── Summary cards (6 key metrics) ────────────────────────────────────────────

function SummaryBar({ scan, risk, emailIntel, remPlan, kev, cve }) {
  const cmsScore  = scan?.score ?? null
  const cmsRating = scan?.rating ?? null
  const domain    = scan?.domain ?? null

  const scoreColor = cmsScore == null ? '#9CA3AF'
    : cmsScore >= 80 ? '#00876A'
    : cmsScore >= 60 ? '#F59E0B'
    : '#EF4444'

  const emailPublishable = isPhase5EvidenceAvailable(emailIntel)
  const cvePublishable   = isPhase5EvidenceAvailable(cve)
  const emailScore  = emailPublishable ? (emailIntel?.email_security_score ?? null) : null
  const emailStatus = emailPublishable ? emailIntel?.email_score_breakdown?.status : null
  const emailCfg    = EMAIL_SCORE_STYLE[emailStatus] || EMAIL_SCORE_STYLE.FAIR

  const bizRisk  = emailPublishable ? emailIntel?.business_email_risk : null
  const bizStyle = BIZ_RISK_STYLE[bizRisk] || { text: 'text-gray-300' }

  const riskLvl = risk?.overall_risk_level || '—'
  const rlStyle = RISK_LEVEL_STYLE[riskLvl] || { pill: 'bg-gray-100 text-gray-500 border-gray-200' }

  const p1Known  = remPlan?.incomplete !== true || (remPlan?.summary?.p1_count ?? 0) > 0
  const p1Count  = p1Known ? (remPlan?.summary?.p1_count ?? 0) : null
  const kevCount = phase5KnownCount(kev, kev?.matched)
  const cveCrit  = phase5KnownCount(cve, cve?.critical_count)
  const cveHigh  = phase5KnownCount(cve, cve?.high_count)
  const cveTotal = cvePublishable ? cveCrit + cveHigh : null

  const stats = [
    {
      label:   'Cyber Metrics Score',
      value:   cmsScore != null ? String(cmsScore) : '—',
      sub:     cmsRating ? `${cmsRating} · ${domain || '/100'}` : (domain || '/100'),
      color:   scoreColor,
      mono:    false,
    },
    {
      label:   'Email Security',
      value:   emailScore != null ? String(emailScore) : '—',
      sub:     emailPublishable ? emailCfg.label : 'Assessment incomplete',
      color:   emailScore != null ? emailCfg.color : '#9CA3AF',
      mono:    false,
    },
    {
      label:   'Business Risk',
      value:   bizRisk || '—',
      sub:     'Email exposure',
      color:   bizStyle.text?.replace('text-', '') === 'brand-600' ? '#00876A'
               : bizStyle.text?.includes('amber')  ? '#D97706'
               : bizStyle.text?.includes('orange') ? '#EA580C'
               : bizStyle.text?.includes('red')    ? '#DC2626'
               : '#9CA3AF',
      isText: true,
    },
    {
      label:   'CyberMeters assessment band',
      isPill:  true,
      pillCls: rlStyle.pill,
      pillTxt: riskLvl,
      sub:     'Posture Rating',
    },
    {
      label:   'P1 Actions',
      value:   p1Count == null ? '—' : String(p1Count),
      sub:     'Immediate',
      color:   p1Count == null ? '#9CA3AF' : (p1Count > 0 ? '#DC2626' : '#00876A'),
    },
    {
      label:   'CVE / KEV',
      value:   cveTotal == null ? '—' : String(cveTotal),
      sub:     kevCount == null ? 'Assessment incomplete' : (kevCount > 0 ? `+${kevCount} in CISA KEV` : 'High+ severity'),
      color:   cveTotal == null ? '#9CA3AF' : (cveTotal > 0 ? (cveCrit > 0 ? '#DC2626' : '#EA580C') : '#00876A'),
      kevBadge: kevCount > 0,
      kevCount,
    },
  ]

  return (
    <div className="card-md overflow-hidden">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-px bg-gray-100">
        {stats.map((s, i) => (
          <div key={i} className="bg-white flex flex-col items-center justify-center py-5 px-3 gap-1 text-center">
            <span className="label text-[9px] text-gray-400">{s.label}</span>

            {s.isPill ? (
              <>
                <span className={`text-xs font-bold px-3 py-1 rounded-full border mt-0.5 ${s.pillCls}`}>
                  {s.pillTxt}
                </span>
                <span className="text-[10px] font-semibold text-gray-400 mt-0.5">{s.sub}</span>
              </>
            ) : (
              <>
                <div className="flex items-center gap-1.5">
                  <span className={`text-2xl font-bold leading-none`} style={{ color: s.color }}>
                    {s.value}
                  </span>
                  {s.kevBadge && (
                    <span className="text-[9px] font-bold text-red-600 bg-red-50 border border-red-200 px-1.5 py-0.5 rounded leading-none">
                      +{s.kevCount} KEV
                    </span>
                  )}
                </div>
                <span className="text-[10px] font-semibold text-gray-400 truncate max-w-[120px]" title={s.sub}>
                  {s.sub}
                </span>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Section: Risk Intelligence ────────────────────────────────────────────────

function RiskIntelligenceSection({ risk, assessmentMessage = null }) {
  if (!risk || risk.error) {
    return (
      <div className="card overflow-hidden">
        <SectionHeader icon={TrendingUp} title="Risk Intelligence" iconBg="bg-red-50" iconColor="text-red-500" />
        <EmptyState icon={Info} title="No risk data" subtitle={risk?.error} />
      </div>
    )
  }

  const lvlStyle = RISK_LEVEL_STYLE[risk.overall_risk_level] || RISK_LEVEL_STYLE.Moderate
  const counts   = risk.finding_counts || {}
  const cats     = risk.risk_categories || {}

  const catIcons = {
    'Data Security':  { icon: Lock,          bg: 'bg-red-50',    color: 'text-red-500'    },
    'Web Security':   { icon: Globe,         bg: 'bg-orange-50', color: 'text-orange-500' },
    'Brand Risk':     { icon: AlertTriangle, bg: 'bg-amber-50',  color: 'text-amber-500'  },
    'Availability':   { icon: TrendingDown,  bg: 'bg-blue-50',   color: 'text-blue-500'   },
    'Reconnaissance': { icon: Bug,           bg: 'bg-purple-50', color: 'text-purple-500' },
    'Other':          { icon: Info,          bg: 'bg-gray-100',  color: 'text-gray-400'   },
  }

  return (
    <div className="card overflow-hidden">
      <SectionHeader
        icon={TrendingUp}
        title="Risk Intelligence"
        iconBg="bg-red-50"
        iconColor="text-red-500"
        aside={risk.overall_risk_level ? (
          <span className={`text-xs font-bold px-3 py-1 rounded-full border ${lvlStyle.pill}`}>
            {risk.overall_risk_level} Risk
          </span>
        ) : null}
      />

      {risk.incomplete && assessmentMessage && (
        <div className="px-5 py-4 border-b border-amber-100 bg-amber-50/60">
          <p className="text-sm text-amber-800 leading-relaxed">{assessmentMessage}</p>
        </div>
      )}

      {/* Narrative */}
      {risk.narrative && (
        <div className="px-5 py-4 border-b border-gray-50 bg-gray-50/40">
          <p className="text-sm text-gray-700 leading-relaxed">{risk.narrative}</p>
        </div>
      )}

      {/* Finding counts */}
      <div className="grid grid-cols-4 divide-x divide-gray-100 border-b border-gray-100">
        {[
          { label: 'Critical', count: counts.critical, cls: 'text-red-600'    },
          { label: 'High',     count: counts.high,     cls: 'text-orange-600' },
          { label: 'Medium',   count: counts.medium,   cls: 'text-amber-600'  },
          { label: 'Low',      count: counts.low,      cls: 'text-blue-600'   },
        ].map(({ label, count, cls }) => (
          <div key={label} className="flex flex-col items-center py-4 gap-0.5">
            <span className={`text-xl font-bold ${cls}`}>
              {risk.incomplete && !(count > 0) ? '—' : (count ?? 0)}
            </span>
            <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wide">{label}</span>
          </div>
        ))}
      </div>

      {/* Risk categories with enriched findings */}
      {Object.entries(cats).length > 0 && (
        <div className="divide-y divide-gray-50">
          {Object.entries(cats).map(([cat, items]) => {
            const cfg    = catIcons[cat] || catIcons.Other
            const CatIcon = cfg.icon
            const shown  = items.slice(0, 5)
            const more   = items.length - shown.length
            return (
              <div key={cat} className="px-5 py-4">
                <div className="flex items-center gap-2 mb-3">
                  <div className={`w-5 h-5 rounded-md ${cfg.bg} flex items-center justify-center`}>
                    <CatIcon className={`w-3 h-3 ${cfg.color}`} />
                  </div>
                  <span className="text-xs font-bold text-gray-700 uppercase tracking-wide">{cat}</span>
                  <span className="text-xs text-gray-300 ml-auto">{items.length} finding{items.length !== 1 ? 's' : ''}</span>
                </div>
                <div className="space-y-2.5">
                  {shown.map((f, i) => (
                    <div key={f.id || i} className="flex items-start gap-3">
                      <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${SEV_DOT[f.severity?.toLowerCase()] || 'bg-gray-300'}`} />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold text-gray-800 leading-snug">{f.title}</p>
                        {f.business_impact && (
                          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{f.business_impact}</p>
                        )}
                      </div>
                      <span className={`flex-shrink-0 mt-0.5 ${SEV_BADGE[f.severity?.toLowerCase()] || SEV_BADGE.informational}`}>
                        {f.severity}
                      </span>
                    </div>
                  ))}
                  {more > 0 && (
                    <p className="text-xs text-gray-400 pl-4">+{more} more finding{more !== 1 ? 's' : ''}</p>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Section: Remediation Plan ─────────────────────────────────────────────────

function RemediationItem({ item, index, tier }) {
  const c = P_COLOR[tier]
  return (
    <div className={`flex items-start gap-3 p-3 rounded-xl border ${c.bg} ${c.border}`}>
      <div className={`w-5 h-5 rounded-full ${c.badge} flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5`}>
        {index + 1}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs font-semibold text-gray-900 leading-snug">{item.title}</p>
        {item.reason && <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">{item.reason}</p>}
        {item.action && (
          <p className={`text-[11px] font-medium mt-1 leading-relaxed ${c.text}`}>{item.action}</p>
        )}
        {item.due_date && (
          <p className="text-[10px] text-gray-400 mt-0.5">Due: {item.due_date}</p>
        )}
      </div>
    </div>
  )
}

function RemediationSection({ plan, assessmentMessage = null }) {
  const [activeTab, setActiveTab] = useState('p1')

  if (!plan || plan.error) {
    return (
      <div className="card overflow-hidden">
        <SectionHeader icon={Shield} title="Remediation Plan" iconBg="bg-orange-50" iconColor="text-orange-500" />
        <EmptyState icon={Info} title="No remediation plan" subtitle={plan?.error} />
      </div>
    )
  }

  const summary = plan.summary || {}
  const tiers   = [
    { key: 'p1', label: 'P1 — Immediate', count: summary.p1_count || 0, items: plan.p1_immediate  || [], ...P_COLOR.p1 },
    { key: 'p2', label: 'P2 — High',      count: summary.p2_count || 0, items: plan.p2_high       || [], ...P_COLOR.p2 },
    { key: 'p3', label: 'P3 — Planned',   count: summary.p3_count || 0, items: plan.p3_medium_low || [], ...P_COLOR.p3 },
  ]
  const active = tiers.find(t => t.key === activeTab)

  return (
    <div className="card overflow-hidden">
      <SectionHeader
        icon={Shield}
        title="Remediation Plan"
        iconBg="bg-orange-50"
        iconColor="text-orange-500"
        aside={<span className="text-xs text-gray-400">{summary.total ?? 0} total actions</span>}
      />

      {plan.incomplete && assessmentMessage && (
        <div className="px-5 py-4 border-b border-amber-100 bg-amber-50/60">
          <p className="text-sm text-amber-800 leading-relaxed">{assessmentMessage}</p>
        </div>
      )}

      {/* Tier tabs */}
      <div className="flex border-b border-gray-100">
        {tiers.map(t => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 text-xs font-semibold transition-colors
              ${activeTab === t.key
                ? `${t.bg} ${t.text} border-b-2 ${t.border.replace('border-', 'border-b-')}`
                : 'text-gray-500 hover:bg-gray-50'}`}
          >
            <span className={`w-4 h-4 rounded-full ${t.badge} flex items-center justify-center text-[9px] font-bold`}>
              {t.count}
            </span>
            {t.label}
          </button>
        ))}
      </div>

      <div className="p-4 space-y-2.5 max-h-[480px] overflow-y-auto">
        {!active?.items?.length ? (
          <div className="flex items-center gap-2 py-6 justify-center text-sm text-gray-400">
            {plan.incomplete ? (
              <>
                <Info className="w-4 h-4 text-amber-500" />
                {assessmentMessage || 'Assessment incomplete'}
              </>
            ) : (
              <>
                <CheckCircle className="w-4 h-4 text-brand-500" />
                No {activeTab.toUpperCase()} items
              </>
            )}
          </div>
        ) : (
          active.items.map((item, i) => (
            <RemediationItem key={i} item={item} index={i} tier={activeTab} />
          ))
        )}
      </div>
    </div>
  )
}

// ── Section: Email Security Intelligence ─────────────────────────────────────

function EmailControl({ label, status, statusCls, detail, mono, warning }) {
  return (
    <div className="px-5 py-3 flex items-start gap-3 border-b border-gray-50 last:border-0">
      <span className="text-xs font-semibold text-gray-500 w-16 flex-shrink-0 pt-0.5">{label}</span>
      <div className="flex-1 min-w-0">
        {detail && <p className={`text-[11px] ${mono ? 'mono text-gray-500 break-all' : 'text-gray-500'} leading-snug`}>{detail}</p>}
        {warning && <p className="text-[11px] text-amber-600 mt-0.5 leading-snug">{warning}</p>}
      </div>
      <div className="flex-shrink-0">
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${statusCls}`}>{status}</span>
      </div>
    </div>
  )
}

function EmailIntelSection({ intel, dmarcPresentation = null, assessmentMessage = null }) {
  if (!intel || intel.error || !isPhase5EvidenceAvailable(intel)) {
    return (
      <div className="card overflow-hidden">
        <SectionHeader icon={Mail} title="Email Security Intelligence" iconBg="bg-blue-50" iconColor="text-blue-600" />
        <EmptyState
          icon={Mail}
          title="No email intelligence data"
          subtitle={!isPhase5EvidenceAvailable(intel) ? assessmentMessage : intel?.error}
        />
      </div>
    )
  }

  const { spf, dkim, dmarc, mta_sts, tls_rpt, starttls } = intel
  const score     = intel.email_security_score
  const breakdown = intel.email_score_breakdown || {}
  const W         = { spf: 20, dkim: 20, dmarc: 50, mta_sts: 5, tls_rpt: 5 }

  const bizRisk      = intel.business_email_risk
  const bizBadgeCls  = BIZ_RISK_STYLE[bizRisk]?.bg || 'bg-gray-100 text-gray-500 border-gray-200'
  const dmarcStyle   = DMARC_STATUS_STYLE[dmarc?.status]   || DMARC_STATUS_STYLE.ERROR
  const spfStyle     = SPF_STATUS_STYLE[spf?.status]        || SPF_STATUS_STYLE.MISSING

  // Build a human-readable DMARC detail line
  const dmarcDetail = [
    dmarc?.policy          && `Legacy exact p: ${dmarc.policy}`,
    dmarc?.pct != null     && `Legacy pct=${dmarc.pct}% (not applied by DMARCbis)`,
    dmarc?.subdomain_policy && `sp=${dmarc.subdomain_policy}`,
    dmarc?.rua             && `Reports → ${dmarc.rua}`,
  ].filter(Boolean).join(' · ')

  return (
    <div className="card overflow-hidden">
      <SectionHeader
        icon={Mail}
        title="Email Security Intelligence"
        iconBg="bg-blue-50"
        iconColor="text-blue-600"
        aside={
          <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${bizBadgeCls}`}>
            {bizRisk || '—'} Business Risk
          </span>
        }
      />
      {dmarcPresentation && (
        <div className="border-b border-gray-100 p-4">
          <DmarcPolicyEvidenceCard
            presentation={dmarcPresentation}
            showTechnical
          />
        </div>
      )}

      {/* Score + breakdown */}
      <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-gray-100">
        <div className="flex flex-col items-center justify-center py-6 gap-4">
          <ScoreRing score={score} status={breakdown.status} />
          <div className="w-full max-w-[200px] space-y-2">
            <ScoreBar label="DMARC"   value={breakdown.dmarc   ?? 0} max={W.dmarc}   />
            <ScoreBar label="SPF"     value={breakdown.spf     ?? 0} max={W.spf}     />
            <ScoreBar label="DKIM"    value={breakdown.dkim    ?? 0} max={W.dkim}    />
            <ScoreBar label="MTA-STS" value={breakdown.mta_sts ?? 0} max={W.mta_sts} />
            <ScoreBar label="TLS-RPT" value={breakdown.tls_rpt ?? 0} max={W.tls_rpt} />
          </div>
        </div>

        {/* Protocol controls */}
        <div className="divide-y divide-gray-50">
          <EmailControl
            label="SPF"
            status={spf?.status || 'MISSING'}
            statusCls={spfStyle}
            detail={spf?.record || undefined}
            warning={spf?.issue || undefined}
            mono
          />
          <EmailControl
            label="DMARC"
            status={dmarc?.status?.replace('_', ' ') || 'MISSING'}
            statusCls={dmarcStyle}
            detail={dmarcDetail || dmarc?.message || undefined}
          />
          <div className="px-5 py-3 flex items-center justify-between border-b border-gray-50">
            <span className="text-xs font-semibold text-gray-500">DKIM</span>
            {dkim ? (
              <StatusPill value={dkim.status === 'VERIFIED'} trueLabel="Verified" falseLabel="Not verified" />
            ) : (
              <StatusPill value={false} trueLabel="Verified" falseLabel="Not verified" />
            )}
          </div>
          <div className="px-5 py-3 flex items-center justify-between border-b border-gray-50">
            <div>
              <span className="text-xs font-semibold text-gray-500">MTA-STS</span>
              {mta_sts?.policy_mode && (
                <span className="text-[10px] text-gray-400 ml-2">Mode: {mta_sts.policy_mode}</span>
              )}
            </div>
            <StatusPill value={mta_sts?.enabled} trueLabel="Enabled" falseLabel="Not configured" />
          </div>
          <div className="px-5 py-3 flex items-center justify-between border-b border-gray-50">
            <span className="text-xs font-semibold text-gray-500">TLS-RPT</span>
            <StatusPill value={tls_rpt?.enabled} trueLabel="Configured" falseLabel="Not configured" />
          </div>
          <div className="px-5 py-3 flex items-center justify-between">
            <div>
              <span className="text-xs font-semibold text-gray-500">STARTTLS</span>
              {starttls?.mx_records?.length > 0 && (
                <p className="text-[10px] text-gray-400 mt-0.5">
                  MX: {starttls.mx_records.slice(0, 2).map(r => r.host).join(', ')}
                  {starttls.mx_records.length > 2 && ` +${starttls.mx_records.length - 2}`}
                </p>
              )}
            </div>
            <span className="text-[10px] text-gray-400 italic">Cannot probe from cloud</span>
          </div>
        </div>
      </div>

      {/* Strengths */}
      {intel.strengths?.length > 0 && (
        <div className="px-5 py-3 border-t border-gray-100 bg-brand-50/40">
          <p className="text-[10px] font-bold text-brand-700 uppercase tracking-widest mb-2">Strengths</p>
          <ul className="space-y-1">
            {intel.strengths.map((s, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-brand-800">
                <CheckCircle className="w-3 h-3 flex-shrink-0 mt-0.5 text-brand-600" />
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Business Impacts */}
      {intel.business_impacts?.length > 0 && (
        <div className="border-t border-gray-100">
          <div className="px-5 py-3 bg-gray-50">
            <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Business Impacts</p>
          </div>
          {intel.business_impacts.map((imp, i) => {
            const rlBadge = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' }
            const iconCls = imp.risk_level === 'CRITICAL' ? 'text-red-500'
                          : imp.risk_level === 'HIGH'     ? 'text-orange-500'
                          : imp.risk_level === 'MEDIUM'   ? 'text-amber-500' : 'text-blue-400'
            return (
              <div key={i} className="px-5 py-3 flex items-start gap-3 border-t border-gray-50">
                <AlertCircle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${iconCls}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-start gap-2 justify-between">
                    <p className="text-xs font-semibold text-gray-800">{imp.technical}</p>
                    <span className={`flex-shrink-0 ${rlBadge[imp.risk_level] || rlBadge.LOW}`}>{imp.risk_level}</span>
                  </div>
                  <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">{imp.business_impact}</p>
                  {imp.recommendation && (
                    <p className="text-[11px] text-brand-600 font-medium mt-1 leading-relaxed">→ {imp.recommendation}</p>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Email findings */}
      {intel.findings?.length > 0 && (
        <div className="border-t border-gray-100">
          <div className="px-5 py-3 bg-gray-50">
            <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Email Security Findings</p>
          </div>
          <ul className="divide-y divide-gray-50">
            {intel.findings.map((f, i) => (
              <li key={f.id || i} className="flex items-start gap-3 px-5 py-3">
                <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${SEV_DOT[f.severity] || 'bg-gray-300'}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-gray-800">{f.title}</p>
                  <p className="text-[11px] text-gray-400 mt-0.5 leading-relaxed">{f.description}</p>
                  {f.recommendation && (
                    <p className="text-[11px] text-brand-600 font-medium mt-1">→ {f.recommendation}</p>
                  )}
                </div>
                <span className={`flex-shrink-0 ${SEV_BADGE[f.severity] || SEV_BADGE.informational}`}>{f.severity}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// ── Section: Technology Detection ─────────────────────────────────────────────

const TECH_PILL = {
  'Cloudflare':    'bg-orange-50 text-orange-700 border-orange-200',
  'nginx':         'bg-green-50 text-green-700 border-green-200',
  'Apache':        'bg-red-50 text-red-700 border-red-200',
  'Microsoft IIS': 'bg-blue-50 text-blue-700 border-blue-200',
  'Express':       'bg-gray-100 text-gray-700 border-gray-200',
  'PHP':           'bg-violet-50 text-violet-700 border-violet-200',
  'ASP.NET':       'bg-blue-50 text-blue-700 border-blue-200',
  'React/Vite':    'bg-cyan-50 text-cyan-700 border-cyan-200',
  'Next.js':       'bg-gray-900 text-white border-gray-700',
  'WordPress':     'bg-sky-50 text-sky-700 border-sky-200',
  'Drupal':        'bg-indigo-50 text-indigo-700 border-indigo-200',
  'Joomla':        'bg-orange-50 text-orange-700 border-orange-200',
  'OpenResty':     'bg-green-50 text-green-700 border-green-200',
  'LiteSpeed':     'bg-amber-50 text-amber-700 border-amber-200',
}

function TechDetectionSection({ tech }) {
  if (!tech || tech.error) {
    return (
      <div className="card overflow-hidden">
        <SectionHeader icon={Cpu} title="Technology Stack" iconBg="bg-purple-50" iconColor="text-purple-600" />
        <EmptyState icon={Cpu} title="No technology data" subtitle={tech?.error} />
      </div>
    )
  }

  const techs = tech.technologies || []

  const headerRows = [
    { label: 'Server',       value: tech.server              },
    { label: 'X-Powered-By', value: tech.x_powered_by        },
    { label: 'Content-Type', value: tech.content_type?.split(';')[0] },
    { label: 'HSTS',         value: tech.strict_transport_security ? 'Present ✓' : 'Missing ✗' },
    { label: 'CSP',          value: tech.content_security_policy   ? 'Present ✓' : 'Missing ✗' },
    { label: 'X-Frame-Opt.', value: tech.x_frame_options           },
    { label: 'Status',       value: tech.status_code != null ? String(tech.status_code) : null },
  ].filter(r => r.value != null)

  return (
    <div className="card overflow-hidden">
      <SectionHeader
        icon={Cpu}
        title="Technology Stack"
        iconBg="bg-purple-50"
        iconColor="text-purple-600"
        aside={<span className="text-xs text-gray-400">{techs.length} detected</span>}
      />

      {/* Tech pills */}
      <div className="px-5 py-4 border-b border-gray-100">
        {techs.length === 0 ? (
          <p className="text-xs text-gray-400">No technologies identified from response headers.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {techs.map((t, i) => (
              <span key={i} className={`text-xs font-semibold px-3 py-1 rounded-full border ${TECH_PILL[t] || 'bg-gray-100 text-gray-600 border-gray-200'}`}>
                {t}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Header details */}
      <div className="divide-y divide-gray-50">
        {headerRows.map(({ label, value }) => (
          <div key={label} className="flex items-start justify-between gap-3 px-5 py-2">
            <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wide flex-shrink-0 pt-0.5 w-20">{label}</span>
            <span className={`text-xs text-right break-all leading-relaxed ${
              value?.includes('✓') ? 'text-brand-600 font-medium' :
              value?.includes('✗') ? 'text-red-500 font-medium'  : 'text-gray-700 mono'
            }`}>{value}</span>
          </div>
        ))}
      </div>

      {/* Version disclosure findings */}
      {tech.info_findings?.length > 0 && (
        <div className="border-t border-gray-100">
          <div className="px-5 py-2.5 bg-amber-50/60 border-b border-amber-100">
            <p className="text-[10px] font-bold text-amber-700 uppercase tracking-widest">
              Version Disclosure ({tech.info_findings.length})
            </p>
          </div>
          {tech.info_findings.map((f, i) => (
            <div key={i} className="px-5 py-3 border-t border-gray-50 flex items-start gap-3">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-gray-800">{f.title}</p>
                <p className="text-[11px] text-gray-400 mt-0.5 leading-relaxed">{f.description}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Section: CVE Intelligence ─────────────────────────────────────────────────

function CveIntelSection({ cve, assessmentMessage = null }) {
  if (!cve || cve.error || !isPhase5EvidenceAvailable(cve)) {
    return (
      <div className="card overflow-hidden">
        <SectionHeader icon={Bug} title="CVE Intelligence" iconBg="bg-red-50" iconColor="text-red-500" />
        <EmptyState
          icon={Bug}
          title="No CVE data"
          subtitle={!isPhase5EvidenceAvailable(cve) ? assessmentMessage : cve?.error}
        />
      </div>
    )
  }

  const results = cve.results || {}
  const checked = cve.technologies_checked || []

  return (
    <div className="card overflow-hidden">
      <SectionHeader
        icon={Bug}
        title="CVE Intelligence"
        iconBg="bg-red-50"
        iconColor="text-red-500"
        aside={
          <div className="flex items-center gap-3 text-xs">
            {(cve.critical_count ?? 0) > 0 && (
              <span><span className="font-bold text-red-600">{cve.critical_count}</span> <span className="text-gray-400">critical</span></span>
            )}
            {(cve.high_count ?? 0) > 0 && (
              <span><span className="font-bold text-orange-600">{cve.high_count}</span> <span className="text-gray-400">high</span></span>
            )}
            <span className="text-gray-300">{cve.total_cves ?? 0} total</span>
          </div>
        }
      />

      {checked.length === 0 ? (
        <EmptyState
          icon={CheckCircle}
          title="No technologies matched CVE allow-list"
          subtitle="Technology detection did not identify any software in the CVE query list."
        />
      ) : (
        <div className="divide-y divide-gray-100">
          {checked.map(tech => {
            const cves = results[tech] || []
            return (
              <div key={tech}>
                <div className="px-5 py-2.5 bg-gray-50 flex items-center justify-between">
                  <span className="text-xs font-bold text-gray-700 capitalize">{tech}</span>
                  <span className="text-[10px] text-gray-400">{cves.length} CVE{cves.length !== 1 ? 's' : ''} (High+)</span>
                </div>
                {cves.length === 0 ? (
                  <div className="px-5 py-3 flex items-center gap-2 text-xs text-brand-600">
                    <CheckCircle className="w-3.5 h-3.5" />
                    No HIGH+ CVEs found for this technology
                  </div>
                ) : (
                  <div className="divide-y divide-gray-50">
                    {cves.map(c => (
                      <div key={c.cve_id} className="flex items-start gap-3 px-5 py-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded mono flex-shrink-0 mt-0.5 ${CVE_SEV_STYLE[c.severity] || CVE_SEV_STYLE.UNKNOWN}`}>
                          {c.cve_id}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="text-[11px] text-gray-600 leading-relaxed">{c.description}</p>
                        </div>
                        <div className="flex flex-col items-end gap-1 flex-shrink-0">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${CVE_SEV_STYLE[c.severity] || CVE_SEV_STYLE.UNKNOWN}`}>
                            {c.severity}
                          </span>
                          {c.cvss_score != null && (
                            <span className="text-[10px] text-gray-400 mono">{c.cvss_score}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Section: Known Exploited Vulnerabilities (CISA KEV) ──────────────────────

function KevSection({ kev, assessmentMessage = null }) {
  if (!kev || kev.error || !isPhase5EvidenceAvailable(kev)) {
    return (
      <div className="card overflow-hidden">
        <SectionHeader icon={Flame} title="CISA KEV Matches" iconBg="bg-red-50" iconColor="text-red-500" />
        <EmptyState
          icon={Flame}
          title="No KEV data"
          subtitle={!isPhase5EvidenceAvailable(kev) ? assessmentMessage : kev?.error}
        />
      </div>
    )
  }

  const matches = kev.matches || []

  return (
    <div className="card overflow-hidden">
      <SectionHeader
        icon={Flame}
        title="CISA KEV Matches"
        iconBg="bg-red-50"
        iconColor="text-red-500"
        aside={
          matches.length > 0
            ? <span className="badge-critical">{matches.length} match{matches.length !== 1 ? 'es' : ''}</span>
            : <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-600">
                <CheckCircle className="w-3.5 h-3.5" />No matches
              </span>
        }
      />

      <div className="px-5 py-2 border-b border-gray-100 bg-gray-50 flex items-center justify-between">
        <span className="text-[10px] text-gray-400">Catalog: {kev.checked?.toLocaleString() ?? '—'} entries</span>
        <span className="text-[10px] text-gray-400">Source: CISA KEV</span>
      </div>

      {matches.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-8 text-center px-5">
          <div className="w-9 h-9 rounded-2xl bg-brand-50 flex items-center justify-center">
            <CheckCircle className="w-5 h-5 text-brand-600" />
          </div>
          <p className="text-sm font-semibold text-gray-700">No KEV matches</p>
          <p className="text-xs text-gray-400 leading-relaxed">
            Detected technologies did not match any entries in the CISA Known Exploited Vulnerabilities catalog.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-gray-50">
          {matches.map((m, i) => (
            <li key={m.cve_id || i} className="px-5 py-4">
              <div className="flex items-start gap-3">
                <ShieldAlert className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs font-bold mono text-red-700 bg-red-50 border border-red-200 px-2 py-0.5 rounded">
                      {m.cve_id}
                    </span>
                    {m.vendor_project && (
                      <span className="text-xs text-gray-500 font-medium">
                        {m.vendor_project}{m.product ? ` — ${m.product}` : ''}
                      </span>
                    )}
                  </div>
                  {m.vulnerability_name && (
                    <p className="text-xs font-semibold text-gray-800 leading-snug">{m.vulnerability_name}</p>
                  )}
                  {m.short_description && (
                    <p className="text-[11px] text-gray-400 mt-0.5 leading-relaxed">{m.short_description}</p>
                  )}
                  {m.required_action && (
                    <p className="text-[11px] text-red-600 font-medium mt-1 leading-relaxed">
                      Required: {m.required_action}
                    </p>
                  )}
                  <div className="flex items-center gap-3 mt-1.5 text-[10px] text-gray-400">
                    {m.date_added && <span>Added: {m.date_added}</span>}
                    {m.due_date   && <span className="text-red-500 font-semibold">Due: {m.due_date}</span>}
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function IntelligencePage() {
  const navigate = useNavigate()

  const [activeWorkspaceId,   setActiveWorkspaceId]   = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const [activeWorkspaceName, setActiveWorkspaceName] = useState(() => localStorage.getItem('cybermeters_workspace_name'))
  const [scans,      setScans]      = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [report,     setReport]     = useState(null)
  const [loading,    setLoading]    = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error,      setError]      = useState(null)

  // Sync workspace changes from Layout selector
  useEffect(() => {
    function onStorage() {
      setActiveWorkspaceId(localStorage.getItem('cybermeters_workspace_id'))
      setActiveWorkspaceName(localStorage.getItem('cybermeters_workspace_name'))
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const load = useCallback(async (silent = false) => {
    const wsId = localStorage.getItem('cybermeters_workspace_id')
    if (!wsId) return
    if (!silent) setLoading(true)
    else         setRefreshing(true)
    setError(null)
    try {
      const data = await api.getWorkspaceScans(wsId)
      const all  = (data.scans || data || []).filter(s => s.status === 'completed')
      setScans(all)
      if (all[0]) setSelectedId(prev => prev || all[0].id)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { if (activeWorkspaceId) load() }, [activeWorkspaceId, load])

  // Load report whenever selected scan changes
  useEffect(() => {
    if (!selectedId) return
    let cancelled = false
    setReport(null)
    setError(null)
    setLoading(true)
    api.getScanReport(selectedId)
      .then(r  => { if (!cancelled) setReport(r) })
      .catch(e  => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [selectedId])

  if (!activeWorkspaceId) return <NoWorkspaceState />

  const modules = report?.modules || {}
  const scanObj = scans.find(s => s.id === selectedId)

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-7 h-7 rounded-lg bg-brand-50 flex items-center justify-center">
              <Brain className="w-4 h-4 text-brand-600" />
            </div>
            <h1 className="text-xl font-bold text-gray-900">Intelligence Dashboard</h1>
          </div>
          <p className="text-sm text-gray-400">
            {activeWorkspaceName
              ? <><span className="font-medium text-gray-600">{activeWorkspaceName}</span> — threat intelligence from latest completed scan</>
              : 'Threat intelligence scoped to your active workspace'}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {scans.length > 1 && (
            <select
              value={selectedId || ''}
              onChange={e => setSelectedId(e.target.value)}
              className="input text-sm py-1.5 max-w-[240px]"
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.domain} — {parseServerDate(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          )}
          <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error */}
      {error && <ErrorAlert message={error} onRetry={() => load()} />}

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-32">
          <Spinner size="lg" />
        </div>
      )}

      {/* No completed scans */}
      {!loading && !error && scans.length === 0 && (
        <div className="card p-12 flex flex-col items-center text-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-gray-100 flex items-center justify-center">
            <Brain className="w-7 h-7 text-gray-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-gray-900 mb-1">No completed scans</h3>
            <p className="text-sm text-gray-400">Run a scan in this workspace to see intelligence data.</p>
          </div>
          <button onClick={() => navigate('/scans/new')} className="btn-primary">
            <ChevronRight className="w-4 h-4" />
            Start a Scan
          </button>
        </div>
      )}

      {/* Main content — only when report is loaded */}
      {!loading && !error && report && (
        <>
          {/* Scan context strip */}
          {scanObj && (
            <div className="flex items-center gap-3 text-sm bg-white border border-gray-100 rounded-xl px-4 py-2.5 shadow-sm">
              <Globe className="w-4 h-4 text-gray-400 flex-shrink-0" />
              <span className="font-semibold text-gray-800">{scanObj.domain}</span>
              {scanObj.rating && (
                <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-brand-50 text-brand-700 border border-brand-100">
                  {scanObj.rating}
                </span>
              )}
              <span className="text-gray-300">·</span>
              <span className="text-gray-500">Score {scanObj.score ?? '—'}/100</span>
              <span className="text-gray-300">·</span>
              <span className="text-gray-400 text-xs">
                {parseServerDate(scanObj.created_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
              </span>
              <Link to={`/scans/${scanObj.id}`} className="btn-ghost ml-auto text-xs gap-1">
                Full Report <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
          )}

          {/* Summary cards: 6 key metrics */}
          <SummaryBar
            scan={scanObj}
            risk={modules.risk_intelligence}
            emailIntel={modules.email_security_intelligence}
            remPlan={modules.remediation_plan}
            kev={modules.known_exploited_vulnerabilities}
            cve={modules.cve_intelligence}
          />

          {/* Main grid: 2/3 left + 1/3 right sidebar */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            <div className="lg:col-span-2 space-y-6">
              <RiskIntelligenceSection
                risk={modules.risk_intelligence}
                assessmentMessage={report.assessment?.message}
              />
              <RemediationSection
                plan={modules.remediation_plan}
                assessmentMessage={report.assessment?.message}
              />
              <EmailIntelSection
                intel={modules.email_security_intelligence}
                dmarcPresentation={report.dmarc_policy_presentation}
                assessmentMessage={report.assessment?.message}
              />
              <CveIntelSection
                cve={modules.cve_intelligence}
                assessmentMessage={report.assessment?.message}
              />
            </div>

            <div className="space-y-6">
              <KevSection
                kev={modules.known_exploited_vulnerabilities}
                assessmentMessage={report.assessment?.message}
              />
              <TechDetectionSection tech={modules.technology_detection} />
            </div>

          </div>
        </>
      )}
    </div>
  )
}
