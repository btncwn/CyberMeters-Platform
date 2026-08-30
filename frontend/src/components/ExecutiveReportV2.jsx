import CyberMotDomains from './CyberMotDomains'
import DmarcPolicyEvidenceCard from './DmarcPolicyEvidenceCard'
import CertificateAssuranceSummary from './CertificateAssuranceSummary'
import { Minus, CheckCircle, Target, FileText, Lock, Eye, Info } from 'lucide-react'
import { bandMeta } from '../lib/score-presentation'
import {
  HOW_TO_READ_REPORT,
  customerEvidenceText,
  evidenceLimits,
  evidenceStrengthLabel,
} from '../lib/evidenceStrengthDisplay'

// ─────────────────────────────────────────────────────────────────────────────
// Executive Report — snapshot-native (M5.d).
//
// Renders the GET /api/scans/:id/executive-report-v2 v3 contract: a pure view
// over the canonical immutable reporting snapshot. Eight canonical domains are
// the only grouping (the five-pillar Intelligence Engine presentation is
// retired); "Observed Findings" is the section vocabulary; the Business Risk
// Indicator is a band with an explanation, never a second score. The frontend
// derives NO security state — every fact below is backend-owned.
// ─────────────────────────────────────────────────────────────────────────────

const RATING_CFG = {
  excellent: { color: '#00876A', text: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Excellent' },
  good:      { color: '#00876A', text: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Good' },
  moderate:  { color: '#F59E0B', text: 'text-amber-500', pill: 'bg-amber-50 text-amber-700 border-amber-100', label: 'Moderate' },
  high:      { color: '#F97316', text: 'text-orange-500', pill: 'bg-orange-50 text-orange-700 border-orange-100', label: bandMeta('high').label },
  critical:  { color: '#EF4444', text: 'text-red-500', pill: 'bg-red-50 text-red-700 border-red-100', label: 'Critical' },
  unknown:   { color: '#D1D5DB', text: 'text-gray-400', pill: 'bg-gray-100 text-gray-500 border-gray-200', label: 'Unrated' },
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 }
const SEV_BADGE = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'text-xs font-semibold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 border border-gray-200',
}
const BRI_PILL = {
  critical: 'bg-red-50 text-red-700 border-red-100',
  high:     'bg-orange-50 text-orange-700 border-orange-100',
  medium:   'bg-amber-50 text-amber-700 border-amber-100',
  low:      'bg-brand-50 text-brand-700 border-brand-100',
}

function fmtDate(str) {
  if (!str) return '—'
  const d = new Date(str.includes('T') ? str : str.replace(' ', 'T') + 'Z')
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function EvidenceBasis({ label, assertion, className = '' }) {
  if (!assertion?.grade) return null
  return (
    <p className={`text-[11px] leading-relaxed text-slate-500 ${className}`}>
      <span className="font-semibold text-slate-700">{label}:</span>
      {' '}{customerEvidenceText(assertion.basis) || 'No basis recorded.'}
    </p>
  )
}

function EvidenceStrengthSummary({ assertions, className = '' }) {
  const primary = assertions.find((assertion) => assertion?.grade)
  const limits = evidenceLimits(assertions)
  return (
    <div className={`rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 ${className}`}>
      <p className="text-xs font-semibold text-slate-800">
        Evidence strength: {primary ? evidenceStrengthLabel(primary) : 'Not recorded'}
      </p>
      <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">
        <span className="font-semibold text-slate-700">Limits:</span>
        {' '}{limits.length
          ? limits.join(' ')
          : (primary
              ? 'No additional limit was recorded.'
              : 'Evidence-Grade metadata was not recorded in this historical snapshot.')}
      </p>
    </div>
  )
}

function HowToReadReport() {
  return (
    <div className="rounded-xl border border-blue-200 bg-blue-50/70 px-4 py-3">
      <p className="text-xs font-bold text-blue-900">How to read this report</p>
      <p className="mt-1 text-xs leading-relaxed text-blue-800">{HOW_TO_READ_REPORT}</p>
    </div>
  )
}

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
      <span className="mt-1 text-[10px] font-semibold text-gray-400">CyberMeters assessment band</span>
    </div>
  )
}

function ItemRow({ item, index, muted = false }) {
  const explicitSeverity = typeof item.severity === 'string' && item.severity.trim()
    ? item.severity.trim()
    : null
  const severityStyleKey = explicitSeverity?.toLowerCase()
  const evidenceGrade = typeof item.evidence_grade === 'string'
    ? item.evidence_grade
    : item.evidence_grade?.grade
  return (
    <li className="flex items-start gap-3 px-5 py-3">
      <div className={`w-5 h-5 rounded-md flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5 ${muted ? 'bg-gray-100 text-gray-500' : 'bg-brand-50 text-brand-700'}`}>
        {index + 1}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <p className="text-sm font-semibold text-gray-900 leading-snug">{item.title}</p>
          {explicitSeverity && (
            <span
              className={`flex-shrink-0 ${SEV_BADGE[severityStyleKey] || SEV_BADGE.info}`}
              aria-label={`${muted ? 'Observation severity' : 'Severity'}: ${explicitSeverity}`}
            >
              {explicitSeverity}
            </span>
          )}
        </div>
        {(item.explanation || item.description) && (
          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed line-clamp-2">
            {customerEvidenceText(item.explanation || item.description)}
          </p>
        )}
        {(item.confidence != null || evidenceGrade) && (
          <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
            {item.confidence != null && <span>Confidence: {String(item.confidence)}</span>}
            {item.confidence != null && evidenceGrade && <span aria-hidden="true"> · </span>}
            {evidenceGrade && <span>Evidence grade: {evidenceGrade}</span>}
          </p>
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
      <div className="flex items-center gap-2 px-6 py-6 text-sm text-gray-400">
        <CheckCircle className="w-4 h-4 text-brand-500 flex-shrink-0" />
        {emptyLabel}
      </div>
    )
  }
  return (
    <ul className="divide-y divide-gray-50">
      {sorted.map((item, i) => <ItemRow key={item.finding_id || i} item={item} index={i} muted={muted} />)}
    </ul>
  )
}

function ActionList({ items }) {
  if (!items?.length) {
    return (
      <div className="flex items-center gap-2 px-6 py-6 text-sm text-gray-400">
        <CheckCircle className="w-4 h-4 text-brand-500 flex-shrink-0" />
        No recommended actions for this assessment.
      </div>
    )
  }
  return (
    <ol className="divide-y divide-gray-50">
      {items.map((item, i) => (
        <li key={item.remediation_id || i} className="flex items-start gap-3 px-6 py-4">
          <span className={`flex-shrink-0 ${SEV_BADGE[item.priority] || SEV_BADGE.info} mt-0.5`}>
            {item.priority || 'info'}
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-gray-900 leading-snug">{item.title}</p>
            {item.action && (
              <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
                {customerEvidenceText(item.action)}
              </p>
            )}
            {item.finding_ids?.length > 1 && (
              <p className="text-[11px] text-gray-400 mt-1">Resolves {item.finding_ids.length} related findings.</p>
            )}
            {item.verification_ceiling && (
              <p className="text-[11px] text-gray-400 mt-1 inline-flex items-center gap-1">
                <Lock className="w-3 h-3" /> {item.verification_ceiling}
              </p>
            )}
          </div>
        </li>
      ))}
    </ol>
  )
}

function AssessmentCoverage({ coverage }) {
  if (!coverage) return null
  const facts = [
    ['Scan quality', coverage.scan_quality],
    ['Assessment quality', coverage.assessment_quality],
    ['Monitoring state', coverage.monitoring_state],
  ].filter(([, value]) => value != null && value !== '')
  const skipped = Array.isArray(coverage.modules_skipped) ? coverage.modules_skipped : []
  const skippedScoreBearing = Array.isArray(coverage.skipped_score_bearing_modules)
    ? coverage.skipped_score_bearing_modules
    : []
  const degradedSignals = Array.isArray(coverage.monitoring_degraded_signals)
    ? coverage.monitoring_degraded_signals
    : []

  if (!facts.length && !skipped.length && !skippedScoreBearing.length && !degradedSignals.length) return null

  return (
    <section aria-label="Assessment coverage" className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
      <h3 className="text-xs font-bold text-slate-800">Assessment coverage</h3>
      {facts.length > 0 && (
        <dl className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3">
          {facts.map(([label, value]) => (
            <div key={label}>
              <dt className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">{label}</dt>
              <dd className="mt-0.5 text-xs font-semibold text-slate-700">{String(value)}</dd>
            </div>
          ))}
        </dl>
      )}
      {skipped.length > 0 && (
        <p className="mt-2 text-xs leading-relaxed text-amber-700">
          <span className="font-semibold">Modules skipped:</span> {skipped.join(', ')}
        </p>
      )}
      {skippedScoreBearing.length > 0 && (
        <p className="mt-1 text-xs leading-relaxed text-amber-700">
          <span className="font-semibold">Score-bearing modules skipped:</span> {skippedScoreBearing.join(', ')}
        </p>
      )}
      {degradedSignals.map((entry, index) => (
        <p key={`${entry?.signal || 'signal'}-${index}`} className="mt-1 text-xs leading-relaxed text-slate-500">
          <span className="font-semibold text-slate-700">{entry?.signal || 'Monitoring signal'}:</span>
          {' '}{entry?.state || 'not_recorded'}{entry?.message ? ` — ${customerEvidenceText(entry.message)}` : ''}
        </p>
      ))}
    </section>
  )
}

function SectionCard({ icon: Icon, title, count, children }) {
  return (
    <section className="bg-white border border-gray-100 rounded-2xl shadow-sm overflow-hidden">
      <header className="flex items-center gap-2 px-6 pt-5 pb-3">
        <Icon className="w-4 h-4 text-brand-600" />
        <h3 className="text-sm font-bold text-gray-900">{title}</h3>
        {count != null && <span className="text-xs text-gray-400 font-semibold">({count})</span>}
      </header>
      {children}
    </section>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function ExecutiveReportV2({ report }) {
  if (!report) return null
  if (report.report_availability?.status === 'historical_scan_no_canonical_snapshot') {
    return (
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6" role="status">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl bg-white text-slate-500 shadow-sm">
            <Info className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-900">Historical scan report</h2>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">
              {report.report_availability.message}
            </p>
            <p className="mt-2 text-xs text-slate-400">
              The original scan record remains available; this is a reporting-format boundary, not data loss.
            </p>
          </div>
        </div>
      </div>
    )
  }
  const cms = report.cyber_metrics_score || {}
  const bri = report.business_risk_indicator || {}
  const summary = report.executive_summary || {}
  const branding = report.branding
  const methodology = report.methodology || {}
  const canonicalActions = Array.isArray(report.remediation_actions)
    ? report.remediation_actions
    : (summary.priority_actions || [])
  const priorityActions = canonicalActions.slice(0, 3)

  return (
    <div className="space-y-5">
      {/* Header: identity + one score + the indicator */}
      <div className="bg-white border border-gray-100 rounded-2xl shadow-sm p-6">
        <HowToReadReport />
        <EvidenceStrengthSummary
          assertions={[
            summary.evidence_grade,
            cms.evidence_grade,
            bri.evidence_grade,
          ]}
          className="mt-4"
        />
        <div className="mt-4 flex flex-wrap items-start justify-between gap-6">
          <div className="min-w-0">
            {branding?.logo
              ? <img src={branding.logo} alt={branding.company_name || 'logo'} className="h-8 mb-2 object-contain" />
              : <p className="text-sm font-bold text-brand-700 mb-1">{branding?.company_name || 'CyberMeters'}</p>}
            <h2 className="text-lg font-bold text-gray-900">Executive Security Report</h2>
            <p className="text-sm text-gray-500">{report.domain?.name}</p>
            <p className="text-xs text-gray-400 mt-1">Assessed on {fmtDate(report.assessed_at)}</p>
            {report.provenance === 'reconstructed_on_demand' && (
              <p className="text-[11px] text-amber-600 mt-1">
                Reconstructed on {fmtDate(report.generated_at)} from the evidence recorded at assessment time.
              </p>
            )}
            {cms.message && <p className="text-xs text-amber-600 mt-2">{customerEvidenceText(cms.message)}</p>}
            <EvidenceBasis label="Score basis" assertion={cms.evidence_grade} className="mt-3 max-w-xl" />
          </div>
          <div className="flex items-center gap-8">
            <ScoreRing score={cms.value} rating={cms.rating} />
            <div className="max-w-xs">
              <p className="text-[11px] font-bold text-gray-400 uppercase tracking-wide mb-1">Business Risk Indicator</p>
              <EvidenceBasis label="Business Risk Indicator basis" assertion={bri.evidence_grade} className="mb-2" />
              {bri.band
                ? <span className={`text-xs font-bold px-3 py-1 rounded-full border ${BRI_PILL[bri.band] || 'bg-gray-100 text-gray-500 border-gray-200'}`}>{String(bri.band).toUpperCase()}</span>
                : <span className="text-xs text-gray-400">Not available</span>}
              {bri.explanation && <p className="text-xs text-gray-500 mt-2 leading-relaxed">{customerEvidenceText(bri.explanation)}</p>}
            </div>
          </div>
        </div>
        {summary.summary && (
          <div className="mt-4">
            <EvidenceBasis label="Eight-domain summary basis" assertion={summary.evidence_grade} className="mb-2" />
            <p className="text-sm text-gray-600 leading-relaxed">{customerEvidenceText(summary.summary)}</p>
          </div>
        )}
        <AssessmentCoverage coverage={report.evidence_completeness} />
      </div>

      {priorityActions.length > 0 && (
        <SectionCard icon={Target} title="Priority Actions" count={priorityActions.length}>
          <ActionList items={priorityActions} />
        </SectionCard>
      )}

      {/* Eight canonical domains — backend-owned states, rendered verbatim */}
      <CyberMotDomains domains={report.cyber_mot_domains} />

      <CertificateAssuranceSummary
        presentation={report.certificate_assurance}
        showEvidence
      />

      {report.dmarc_policy_presentation && (
        <DmarcPolicyEvidenceCard
          presentation={report.dmarc_policy_presentation}
          showTechnical
        />
      )}

      <SectionCard icon={FileText} title="Observed Findings" count={summary.observed_findings_count ?? report.observed_findings?.length ?? 0}>
        <ItemList items={report.observed_findings} emptyLabel="No material findings were observed in this assessment." />
      </SectionCard>

      <SectionCard icon={Eye} title="Observations" count={summary.observations_count ?? report.observations?.length ?? 0}>
        <ItemList items={report.observations} muted emptyLabel="No additional observations." />
      </SectionCard>

      <SectionCard icon={Target} title="Recommended Actions" count={report.remediation_actions?.length ?? 0}>
        <ActionList items={report.remediation_actions} />
      </SectionCard>

      {/* Methodology + limitations — honesty footer */}
      <div className="bg-gray-50 border border-gray-100 rounded-2xl p-5">
        <p className="text-[11px] text-gray-400 font-semibold uppercase tracking-wide mb-2">Methodology & Limitations</p>
        <p className="text-[11px] text-gray-400">
          Resolver {methodology.cyber_mot_resolver_version || '—'} · Score methodology {methodology.cyber_metrics_score_methodology_version || '—'} · Risk indicator methodology {methodology.business_risk_methodology_version || '—'}
        </p>
        <ul className="mt-2 space-y-1">
          {(report.limitations || []).map((l, i) => (
            <li key={i} className="text-[11px] text-gray-400 leading-relaxed flex gap-1.5">
              <Minus className="w-3 h-3 flex-shrink-0 mt-0.5" />{customerEvidenceText(l)}
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
