import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  HelpCircle,
  Loader2,
  RefreshCw,
  Save,
  ShieldCheck,
} from 'lucide-react'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { useWorkspace } from '../../hooks/useWorkspace'
import { PlanGate } from '../../components/PlanUsageCard'

const CONTROL_LABELS = {
  boundary_protection: 'Boundary protection',
  secure_configuration: 'Secure configuration',
  access_control: 'Access control',
  malware_protection: 'Malware protection',
  patch_management_readiness: 'Patch management readiness',
}

const ANSWER_OPTIONS = [
  { value: 'yes', label: 'Yes', helper: 'This is in place across the business.' },
  { value: 'partial', label: 'Partial', helper: 'This is in place for some users, devices or services, but not all.' },
  { value: 'no', label: 'No', helper: 'This is not currently in place.' },
  { value: 'unknown', label: 'Not sure', helper: 'Confirm this with your IT provider or internal owner.' },
]

const READINESS_STYLES = {
  ready: 'bg-brand-50 text-brand-700 border-brand-100',
  incomplete: 'bg-blue-50 text-blue-700 border-blue-100',
  gaps: 'bg-amber-50 text-amber-700 border-amber-100',
}

const FINAL_DISCLAIMER = 'CyberMeters provides readiness guidance only. It does not issue Cyber Essentials certification and cannot fully verify internal controls such as MFA, admin account separation, endpoint protection or patching across your devices. Formal Cyber Essentials certification is handled through IASME and approved Certification Bodies.'

function titleCaseStatus(value) {
  return String(value || 'unknown').replace(/_/g, ' ')
}

function answerLabel(value) {
  return ANSWER_OPTIONS.find(option => option.value === value)?.label || 'Not answered'
}

function controlLabel(controlKey, fallback) {
  return CONTROL_LABELS[controlKey] || fallback || String(controlKey || '').replace(/_/g, ' ')
}

function flattenAnswers(answersByControl = {}) {
  return Object.entries(answersByControl).flatMap(([controlKey, answers]) =>
    Object.entries(answers || {}).map(([questionKey, answer]) => ({
      control_key: controlKey,
      question_key: questionKey,
      answer,
    }))
  )
}

function answeredCount(questionSet = [], answersByControl = {}) {
  return questionSet.reduce((sum, control) => (
    sum + (control.questions || []).filter(question => answersByControl?.[control.control_key]?.[question.key]).length
  ), 0)
}

function totalQuestionCount(questionSet = []) {
  return questionSet.reduce((sum, control) => sum + (control.questions || []).length, 0)
}

function evidenceMeta(control) {
  const evidence = control?.evidence

  if (evidence === 'contradicted_by_scan') {
    return {
      label: 'Cyber MOT disagrees ⚠',
      helper: 'Your answer suggests this area is in place, but CyberMeters found external evidence that may conflict with it. Review this before applying for Cyber Essentials.',
      className: 'bg-amber-50 text-amber-800 border-amber-200',
    }
  }

  if (evidence === 'externally_corroborated') {
    return {
      label: 'Checked by Cyber MOT ✓',
      helper: 'CyberMeters found supporting external evidence from your domain, website, email, DNS or TLS posture.',
      className: 'bg-brand-50 text-brand-700 border-brand-100',
    }
  }

  if (evidence === 'externally_confirmed_gap') {
    return {
      label: 'Checked by Cyber MOT ✓',
      helper: 'Cyber MOT evidence found a gap in this control area. Review the gap before applying for Cyber Essentials.',
      className: 'bg-amber-50 text-amber-800 border-amber-200',
    }
  }

  if (evidence === 'self_attested_only') {
    return {
      label: 'Self-declared',
      helper: 'Not externally checked. This control depends on internal users, devices and processes that CyberMeters cannot fully see from outside your business.',
      className: 'bg-blue-50 text-blue-700 border-blue-100',
    }
  }

  return {
    label: 'Not externally checked',
    helper: 'This is an internal control area. CyberMeters can guide your readiness, but your organisation must confirm the answer.',
    className: 'bg-gray-50 text-gray-700 border-gray-200',
  }
}

function readinessBadgeClass(readiness) {
  return READINESS_STYLES[readiness] || 'bg-gray-50 text-gray-700 border-gray-200'
}

function overallTone(readiness) {
  const score = readiness?.score ?? 0
  if (score >= 80) return 'border-brand-100 bg-brand-50 text-brand-800'
  if (score >= 55) return 'border-amber-100 bg-amber-50 text-amber-800'
  return 'border-red-100 bg-red-50 text-red-800'
}

function QuestionCard({ control, question, value, onChange }) {
  return (
    <div className="rounded-2xl border border-gray-100 bg-gray-50 p-4">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <h3 className="text-sm font-bold leading-snug text-gray-900">{question.text}</h3>
          {question.why && (
            <p className="mt-1 text-xs leading-relaxed text-gray-500">
              <span className="font-semibold text-gray-700">Why this matters:</span> {question.why}
            </p>
          )}
        </div>
        <div className="grid min-w-full gap-2 sm:grid-cols-2 xl:min-w-[520px] xl:grid-cols-4">
          {ANSWER_OPTIONS.map(option => (
            <button
              key={option.value}
              type="button"
              onClick={() => onChange(control.control_key, question.key, option.value)}
              className={`rounded-xl border p-3 text-left transition-all ${
                value === option.value
                  ? 'border-brand-300 bg-brand-50 ring-2 ring-brand-500/20'
                  : 'border-gray-200 bg-white hover:border-brand-200 hover:bg-brand-50/40'
              }`}
            >
              <span className="text-sm font-bold text-gray-900">{option.label}</span>
              <span className="mt-1 block text-xs leading-relaxed text-gray-500">{option.helper}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

function QuestionnaireSection({ control, answers, onChange }) {
  const answered = (control.questions || []).filter(question => answers?.[control.control_key]?.[question.key]).length
  const total = (control.questions || []).length

  return (
    <section className="card p-5">
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-lg font-bold text-gray-900">{controlLabel(control.control_key, control.label)}</h2>
          <p className="mt-1 text-sm leading-relaxed text-gray-500">
            Some controls can be supported by Cyber MOT evidence. Others depend on your internal users, devices and processes, so they must be self-declared.
          </p>
        </div>
        <span className="rounded-full border border-gray-200 bg-gray-50 px-3 py-1 text-xs font-bold text-gray-600">
          {answered}/{total} answered
        </span>
      </div>
      <div className="space-y-3">
        {(control.questions || []).map(question => (
          <QuestionCard
            key={question.key}
            control={control}
            question={question}
            value={answers?.[control.control_key]?.[question.key]}
            onChange={onChange}
          />
        ))}
      </div>
    </section>
  )
}

function EvidenceBadge({ control }) {
  const meta = evidenceMeta(control)
  return (
    <div className={`rounded-xl border px-3 py-2 ${meta.className}`}>
      <p className="text-xs font-bold">{meta.label}</p>
      <p className="mt-0.5 text-[11px] leading-relaxed opacity-80">{meta.helper}</p>
    </div>
  )
}

function ControlResultCard({ control }) {
  const measuredGaps = control.measured_gaps || []
  const selfGaps = control.self_attestation?.gaps || []

  return (
    <div className="card p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h3 className="text-base font-bold text-gray-900">{controlLabel(control.control_key, control.label)}</h3>
          <p className="mt-1 text-sm leading-relaxed text-gray-500">
            {control.external_coverage === 'none'
              ? 'This area is based on self-declared answers because it depends on internal users, devices and processes.'
              : 'This area can be supported by external Cyber MOT evidence and your saved answers.'}
          </p>
        </div>
        <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-bold capitalize ${readinessBadgeClass(control.readiness)}`}>
          {titleCaseStatus(control.readiness)}
        </span>
      </div>

      <div className="mt-4">
        <EvidenceBadge control={control} />
      </div>

      {control.contradiction && (
        <div className="mt-4 rounded-xl border border-amber-100 bg-amber-50 p-3">
          <div className="flex gap-2">
            <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-600" />
            <p className="text-sm leading-relaxed text-amber-800">{control.contradiction.message}</p>
          </div>
        </div>
      )}

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-gray-100 bg-gray-50 p-3">
          <p className="text-[11px] font-bold uppercase tracking-wide text-gray-400">Readiness score</p>
          <p className="mt-1 text-lg font-bold text-gray-900">{control.measured_score ?? '—'}<span className="text-xs text-gray-400">/100</span></p>
        </div>
        <div className="rounded-xl border border-gray-100 bg-gray-50 p-3">
          <p className="text-[11px] font-bold uppercase tracking-wide text-gray-400">Self-declared answers</p>
          <p className="mt-1 text-lg font-bold text-gray-900">
            {control.self_attestation?.answered ?? 0}<span className="text-xs text-gray-400">/{control.self_attestation?.total ?? 0}</span>
          </p>
        </div>
        <div className="rounded-xl border border-gray-100 bg-gray-50 p-3">
          <p className="text-[11px] font-bold uppercase tracking-wide text-gray-400">Gaps noted</p>
          <p className="mt-1 text-lg font-bold text-gray-900">{measuredGaps.length + selfGaps.length}</p>
        </div>
      </div>

      {(measuredGaps.length > 0 || selfGaps.length > 0) && (
        <div className="mt-4">
          <p className="mb-2 text-xs font-bold uppercase tracking-wide text-gray-400">Gap analysis</p>
          <ul className="space-y-2">
            {measuredGaps.map((gap, index) => (
              <li key={`measured-${index}`} className="flex gap-2 text-sm leading-relaxed text-gray-600">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
                <span>{gap}</span>
              </li>
            ))}
            {selfGaps.map((gap, index) => (
              <li key={`self-${gap}-${index}`} className="flex gap-2 text-sm leading-relaxed text-gray-600">
                <HelpCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-blue-500" />
                <span>Self-declared answer needs review: {String(gap).replace(/_/g, ' ')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function PriorityGaps({ readiness }) {
  const topGaps = readiness?.top_gaps || []
  const selfControls = readiness?.self_assessment?.controls || []
  const controlGaps = selfControls.flatMap(control => [
    ...(control.measured_gaps || []).map(gap => ({
      source: evidenceMeta(control).label,
      control: controlLabel(control.control_key, control.label),
      text: gap,
    })),
    ...((control.self_attestation?.gaps || []).map(gap => ({
      source: 'Self-declared',
      control: controlLabel(control.control_key, control.label),
      text: `Review answer for ${String(gap).replace(/_/g, ' ')}`,
    }))),
  ])
  const gaps = controlGaps.length > 0 ? controlGaps : topGaps.map(gap => ({ source: 'Readiness gap', text: gap }))

  return (
    <div className="card p-6">
      <h2 className="font-semibold text-gray-900">Priority gaps to review</h2>
      <p className="mt-1 text-sm leading-relaxed text-gray-500">
        Start with gaps supported by Cyber MOT evidence, then review self-declared areas with your IT provider or internal owner.
      </p>
      {gaps.length > 0 ? (
        <ul className="mt-4 space-y-3">
          {gaps.map((gap, index) => (
            <li key={`${gap.control || 'gap'}-${index}`} className="rounded-xl border border-gray-100 bg-gray-50 p-3">
              <div className="flex gap-3">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
                <div>
                  <p className="text-xs font-bold uppercase tracking-wide text-gray-400">{gap.source}{gap.control ? ` · ${gap.control}` : ''}</p>
                  <p className="mt-1 text-sm leading-relaxed text-gray-600">{gap.text}</p>
                </div>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <div className="mt-4 rounded-xl border border-brand-100 bg-brand-50 p-4">
          <div className="flex gap-3">
            <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-brand-600" />
            <p className="text-sm leading-relaxed text-brand-800">
              No major readiness gaps found. Review the self-declared areas carefully and keep evidence before starting the formal Cyber Essentials process.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

function Recommendations({ readiness }) {
  return (
    <div className="card p-6">
      <h2 className="font-semibold text-gray-900">Recommended actions</h2>
      {(readiness?.recommendations || []).length > 0 ? (
        <ul className="mt-4 space-y-3">
          {readiness.recommendations.map((item, index) => (
            <li key={index} className="flex gap-3 text-sm leading-relaxed text-gray-600">
              <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-brand-600 text-xs font-bold text-white">
                {index + 1}
              </span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-sm leading-relaxed text-gray-500">
          Keep your answers current and rerun your Cyber MOT after making changes.
        </p>
      )}
    </div>
  )
}

function ResultSummary({ readiness }) {
  return (
    <section className={`rounded-2xl border p-5 ${overallTone(readiness)}`}>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-0.5 h-7 w-7 flex-shrink-0" />
          <div>
            <p className="text-sm font-bold uppercase tracking-wide opacity-70">Overall readiness status</p>
            <h2 className="mt-1 text-2xl font-bold">
              {readiness?.score ?? '—'}<span className="text-base opacity-70">/100</span>
              {readiness?.grade ? <span className="ml-3">Grade {readiness.grade}</span> : null}
            </h2>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed">{readiness?.summary || 'Complete the questionnaire to improve the readiness view for this workspace.'}</p>
          </div>
        </div>
        <span className="rounded-full border border-current/20 px-3 py-1 text-sm font-bold capitalize">
          {titleCaseStatus(readiness?.status)}
        </span>
      </div>
    </section>
  )
}

export default function WorkspaceCyberEssentialsPage() {
  const { wsId, wsName } = useWorkspace()
  const [questionSet, setQuestionSet] = useState([])
  const [answers, setAnswers] = useState({})
  const [readiness, setReadiness] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [saveError, setSaveError] = useState(null)
  const [savedAt, setSavedAt] = useState(null)

  const progress = useMemo(() => {
    const answered = answeredCount(questionSet, answers)
    const total = totalQuestionCount(questionSet)
    return { answered, total, pct: total ? Math.round((answered / total) * 100) : 0 }
  }, [answers, questionSet])

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true)
    setError(null)
    try {
      const [answerData, readinessData] = await Promise.all([
        api.getWorkspaceCyberEssentialsAnswers(wsId),
        api.getWorkspaceCyberEssentialsReadiness(wsId),
      ])
      setQuestionSet(answerData?.questions || [])
      setAnswers(answerData?.answers || {})
      setReadiness(readinessData)
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  function updateAnswer(controlKey, questionKey, answer) {
    setAnswers(current => ({
      ...current,
      [controlKey]: {
        ...(current[controlKey] || {}),
        [questionKey]: answer,
      },
    }))
    setSaveError(null)
  }

  async function saveAnswers() {
    if (!wsId) return
    setSaving(true)
    setSaveError(null)
    try {
      const payload = flattenAnswers(answers)
      const answerData = await api.saveWorkspaceCyberEssentialsAnswers(wsId, payload)
      const readinessData = await api.getWorkspaceCyberEssentialsReadiness(wsId)
      setQuestionSet(answerData?.questions || questionSet)
      setAnswers(answerData?.answers || answers)
      setReadiness(readinessData)
      setSavedAt(new Date())
    } catch (err) {
      setSaveError(err)
    } finally {
      setSaving(false)
    }
  }

  if (!wsId) return <NoWorkspaceSelected />

  const planError = error?.error === 'plan_feature_required' ? null : error?.message
  const selfControls = readiness?.self_assessment?.controls || []

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={planError} onRetry={load}>
      <PlanGate error={error}>
        <div className="mb-8 flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <span className="eyebrow">Paid workspace service</span>
            <h1 className="mt-1 text-2xl font-bold text-gray-900">Cyber Essentials Readiness</h1>
            <p className="mt-1 max-w-3xl text-sm leading-relaxed text-gray-500">
              Save self-declared answers for this workspace and combine them with external Cyber MOT evidence for readiness guidance and gap analysis.
            </p>
          </div>
          <div className="card min-w-full p-4 xl:min-w-[360px]">
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="text-sm font-semibold text-gray-900">Question progress</span>
              <span className="text-sm font-bold tabular-nums text-brand-700">{progress.answered}/{progress.total}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-gray-100">
              <div className="h-full rounded-full bg-brand-600 transition-all" style={{ width: `${progress.pct}%` }} />
            </div>
            {savedAt && <p className="mt-2 text-xs text-gray-400">Saved {savedAt.toLocaleTimeString('en-GB')}</p>}
          </div>
        </div>

        <div className="mb-6 rounded-2xl border border-blue-100 bg-blue-50 p-4">
          <div className="flex gap-3">
            <HelpCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-blue-600" />
            <p className="text-sm leading-relaxed text-blue-800">
              Some controls can be supported by Cyber MOT evidence. Others depend on your internal users, devices and processes, so they must be self-declared.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6">
          <section className="space-y-5">
            {questionSet.length > 0 ? (
              questionSet.map(control => (
                <QuestionnaireSection
                  key={control.control_key}
                  control={control}
                  answers={answers}
                  onChange={updateAnswer}
                />
              ))
            ) : (
              <div className="card p-6 text-center">
                <ClipboardCheck className="mx-auto h-10 w-10 text-gray-300" />
                <h2 className="mt-3 text-base font-bold text-gray-900">No readiness questions available</h2>
                <p className="mx-auto mt-2 max-w-lg text-sm text-gray-500">
                  CyberMeters could not load the Cyber Essentials question set for this workspace. Try again in a moment.
                </p>
                <button type="button" onClick={load} className="btn-secondary mt-5">
                  <RefreshCw className="h-4 w-4" />
                  Retry
                </button>
              </div>
            )}

            {saveError && (
              <div className="rounded-2xl border border-red-100 bg-red-50 p-4 text-sm text-red-700">
                {saveError.message || 'Answers could not be saved. Please try again.'}
              </div>
            )}

            {questionSet.length > 0 && (
              <div className="sticky bottom-4 z-20 rounded-2xl border border-gray-200 bg-white/95 p-4 shadow-card-md backdrop-blur">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm font-semibold text-gray-900">Save self-declared answers</p>
                    <p className="text-xs text-gray-500">Readiness output refreshes after save.</p>
                  </div>
                  <button type="button" onClick={saveAnswers} disabled={saving} className="btn-primary disabled:cursor-not-allowed disabled:opacity-50">
                    {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                    {saving ? 'Saving...' : 'Save answers'}
                  </button>
                </div>
              </div>
            )}
          </section>

          <section className="space-y-6">
            <ResultSummary readiness={readiness} />

            {selfControls.length > 0 ? (
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                {selfControls.map(control => (
                  <ControlResultCard key={control.control_key} control={control} />
                ))}
              </div>
            ) : (
              <div className="card p-6 text-center">
                <ShieldCheck className="mx-auto h-10 w-10 text-gray-300" />
                <h2 className="mt-3 text-base font-bold text-gray-900">Readiness result not available yet</h2>
                <p className="mx-auto mt-2 max-w-lg text-sm leading-relaxed text-gray-500">
                  Save your answers to refresh the workspace Cyber Essentials readiness view.
                </p>
              </div>
            )}

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <PriorityGaps readiness={readiness} />
              <Recommendations readiness={readiness} />
            </div>

            <div className="rounded-2xl border border-gray-200 bg-white p-5">
              <div className="flex items-start gap-3">
                <HelpCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-gray-400" />
                <p className="text-sm leading-relaxed text-gray-600">{FINAL_DISCLAIMER}</p>
              </div>
            </div>
          </section>
        </div>
      </PlanGate>
    </WsPage>
  )
}
