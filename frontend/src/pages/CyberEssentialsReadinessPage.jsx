import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  HelpCircle,
  Lock,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  UserCheck,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'

const ANSWER_OPTIONS = [
  { value: 'yes', label: 'Yes', helper: 'Yes — this is in place across the business.' },
  { value: 'partial', label: 'Partial', helper: 'Partial — this is in place for some users, devices or services, but not all.' },
  { value: 'no', label: 'No', helper: 'No — this is not currently in place.' },
  { value: 'not_sure', label: 'Not sure', helper: 'Not sure — you need to confirm this with your IT provider or internal owner.' },
]

const EVIDENCE_LABELS = {
  checked_by_cyber_mot: {
    label: 'Checked by Cyber MOT ✓',
    helper: 'CyberMeters found supporting external evidence from your domain, website, email, DNS or TLS posture.',
    className: 'bg-brand-50 text-brand-700 border-brand-100',
  },
  self_declared: {
    label: 'Self-declared',
    helper: 'This control depends on internal settings, devices, users or processes that CyberMeters cannot fully see from outside your business.',
    className: 'bg-blue-50 text-blue-700 border-blue-100',
  },
  cyber_mot_disagrees: {
    label: 'Cyber MOT disagrees ⚠',
    helper: 'Your answer suggests this area is in place, but CyberMeters found external evidence that may conflict with it. Review this before applying for Cyber Essentials.',
    className: 'bg-amber-50 text-amber-700 border-amber-100',
  },
  not_externally_checked: {
    label: 'Not externally checked',
    helper: 'This is an internal control area. CyberMeters can guide your readiness, but your organisation must confirm the answer.',
    className: 'bg-gray-50 text-gray-700 border-gray-200',
  },
}

const STATUS_COPY = {
  strong_readiness: {
    title: 'Strong readiness',
    body: 'Your answers and external Cyber MOT evidence suggest you are in a good position to prepare for Cyber Essentials. Review the remaining self-declared areas and keep evidence before starting the formal process.',
    cta: 'Review remaining checks',
    className: 'bg-brand-50 text-brand-800 border-brand-100',
  },
  some_gaps_to_fix: {
    title: 'Some gaps to fix',
    body: 'You have several areas that may need attention before applying for Cyber Essentials. Start with the gaps marked by Cyber MOT evidence, then review the self-declared controls with your IT provider or internal owner.',
    cta: 'View fix list',
    className: 'bg-amber-50 text-amber-800 border-amber-100',
  },
  needs_attention: {
    title: 'Needs attention',
    body: 'CyberMeters found readiness gaps that should be reviewed before you apply. Fix the highest-impact issues first, especially where external Cyber MOT evidence conflicts with your answers.',
    cta: 'Fix priority gaps',
    className: 'bg-red-50 text-red-800 border-red-100',
  },
}

const GAP_COPY = {
  cyber_mot_mismatch: {
    title: 'Cyber MOT found a possible mismatch',
    text: 'Your answer suggests this control is in place, but CyberMeters found external evidence that may conflict with it. Review this before applying.',
  },
  self_declared_gap: {
    title: 'Self-declared gap',
    text: 'Your answer suggests this control may not be fully in place. Confirm the current setup and decide who owns the fix.',
  },
  needs_confirmation: {
    title: 'Needs confirmation',
    text: 'You selected “Not sure”. This should be confirmed before you apply for Cyber Essentials.',
  },
  partially_in_place: {
    title: 'Partially in place',
    text: 'This control appears to be partly implemented. Check whether it applies across all relevant users, devices and services.',
  },
}

const CONTROLS = [
  {
    id: 'boundary_protection',
    title: 'Boundary protection',
    icon: ShieldCheck,
    externalEvidenceCapable: true,
    description: 'Checks whether your business has basic protection between your devices, services and the internet.',
    why: 'Firewalls and boundary controls help block unwanted access to business devices, admin pages and services.',
    recommendedAction: 'Confirm your router, firewall and admin access settings with your IT provider. Remove or restrict any access that is not required.',
    questions: [
      {
        id: 'default_inbound_block',
        question: 'Do all business devices connect to the internet through a router, firewall or built-in security control that blocks unwanted inbound access by default?',
        why: 'Firewalls create a security filter between your business and the internet.',
      },
      {
        id: 'documented_inbound_services',
        question: 'Are any open inbound services documented with a clear business reason?',
        why: 'Unnecessary open access increases risk and should not exist unless the business genuinely needs it.',
      },
      {
        id: 'network_default_passwords_changed',
        question: 'Have default admin passwords been changed on routers, firewalls and internet-facing services?',
        why: 'Default passwords are one of the easiest ways for attackers to gain access.',
      },
      {
        id: 'admin_pages_protected',
        question: 'Are firewall or router admin pages protected from public internet access unless there is a clear, controlled business need?',
        why: 'Management pages should not be casually reachable from outside the business.',
      },
    ],
  },
  {
    id: 'secure_configuration',
    title: 'Secure configuration',
    icon: Lock,
    externalEvidenceCapable: true,
    description: 'Checks whether devices, accounts and services are set up safely rather than left in risky default settings.',
    why: 'Poor default settings, unused services and weak configurations make avoidable cyber incidents more likely.',
    recommendedAction: 'Review default settings, remove unused services and confirm that business devices follow a standard secure setup.',
    questions: [
      {
        id: 'all_default_passwords_changed',
        question: 'Have default passwords been changed on laptops, routers, cloud services and business applications?',
        why: 'Secure configuration means systems are set up safely rather than left in risky default states.',
      },
      {
        id: 'unused_items_removed',
        question: 'Are unused apps, services, browser extensions and accounts removed when they are no longer needed?',
        why: 'The fewer unnecessary parts you run, the fewer opportunities there are for mistakes or compromise.',
      },
      {
        id: 'device_security_settings',
        question: 'Are staff devices configured with screen lock, encryption where available and automatic security updates?',
        why: 'Basic device settings reduce the chance that a lost or unattended device becomes a business incident.',
      },
      {
        id: 'asset_list',
        question: 'Do you keep a basic list of business devices and important cloud services?',
        why: 'You cannot secure what you do not know you use.',
      },
    ],
  },
  {
    id: 'access_control',
    title: 'Access control',
    icon: UserCheck,
    externalEvidenceCapable: false,
    description: 'Checks whether users only have the access they need and whether important accounts are protected with MFA.',
    why: 'Strong access control reduces the damage caused by stolen passwords, compromised accounts or unnecessary admin access.',
    recommendedAction: 'Enable MFA for important services, separate admin accounts from daily accounts and review user access regularly.',
    questions: [
      {
        id: 'mfa_enabled',
        question: 'Is multi-factor authentication enabled for important cloud services such as Microsoft 365, Google Workspace, accounting tools, CRM and admin portals?',
        why: 'MFA reduces the risk of password-only compromise.',
      },
      {
        id: 'separate_admin_accounts',
        question: 'Do admin users have separate admin accounts rather than using admin privileges for everyday email and web browsing?',
        why: 'Separating admin activity reduces the damage if a normal working account is compromised.',
      },
      {
        id: 'joiners_movers_leavers',
        question: 'Are new starters, leavers and role changes handled with a clear access process?',
        why: 'Old or excessive access creates avoidable risk.',
      },
      {
        id: 'least_privilege',
        question: 'Are staff only given access to the systems and data they need for their role?',
        why: 'Least-privilege access limits mistakes, misuse and the impact of account compromise.',
      },
    ],
  },
  {
    id: 'malware_protection',
    title: 'Malware protection',
    icon: ShieldAlert,
    externalEvidenceCapable: false,
    description: 'Checks whether business devices have suitable protection against malicious software.',
    why: 'Malware protection helps reduce the risk of malicious software affecting business devices, data and operations.',
    recommendedAction: 'Confirm anti-malware or built-in device protection is enabled and kept up to date across all business devices.',
    questions: [
      {
        id: 'endpoint_protection_enabled',
        question: 'Do all laptops and desktops used for business have malware protection enabled?',
        why: 'Malware protection helps stop malicious software before it causes harm.',
      },
      {
        id: 'endpoint_protection_updated',
        question: 'Is malware protection kept up to date automatically?',
        why: 'Outdated protection may miss newer threats.',
      },
      {
        id: 'approved_software_controls',
        question: 'Are users prevented from installing unapproved software where practical?',
        why: 'Limiting unapproved software reduces the chance of risky apps or malicious tools being installed.',
      },
      {
        id: 'mobile_device_protection',
        question: 'Are mobile devices protected through approved app stores, device settings or management controls?',
        why: 'Phones and tablets often hold business email and customer data, so they need basic protection too.',
      },
    ],
  },
  {
    id: 'patch_management_readiness',
    title: 'Patch management readiness',
    icon: RefreshCw,
    externalEvidenceCapable: false,
    description: 'Checks whether software, browsers, operating systems and services are kept up to date.',
    why: 'Known software issues are often exploited because updates are available but have not been applied.',
    recommendedAction: 'Turn on automatic updates where possible and remove unsupported software or devices from business use.',
    questions: [
      {
        id: 'automatic_updates',
        question: 'Are operating systems, browsers and business applications set to update automatically where possible?',
        why: 'Security updates help prevent criminals using known software issues as an access point.',
      },
      {
        id: 'unsupported_items_removed',
        question: 'Do you remove or replace software and devices that no longer receive security updates?',
        why: 'Unsupported systems become harder to defend because known issues may never be fixed.',
      },
      {
        id: 'regular_update_review',
        question: 'Do you have a regular process to check whether important business software is up to date?',
        why: 'Automatic updates are helpful, but someone still needs to confirm important systems are not being missed.',
      },
      {
        id: 'urgent_updates_applied',
        question: 'Are urgent security updates applied quickly when vendors or IT providers flag them as important?',
        why: 'Known high-risk issues are often used because fixes exist but have not been applied.',
      },
    ],
  },
]

function answerKey(controlId, questionId) {
  return `${controlId}.${questionId}`
}

function answerLabel(value) {
  return ANSWER_OPTIONS.find(option => option.value === value)?.label || 'Not answered'
}

function scoreAnswer(value) {
  if (value === 'yes') return 1
  if (value === 'partial') return 0.55
  return 0
}

function gapKindForAnswer(value) {
  if (value === 'partial') return 'partially_in_place'
  if (value === 'no') return 'self_declared_gap'
  if (value === 'not_sure') return 'needs_confirmation'
  return null
}

function deriveReadinessResult(answers, hasCyberMotEvidence = false) {
  const controls = CONTROLS.map(control => {
    const controlAnswers = control.questions.map(question => ({
      question,
      answer: answers[answerKey(control.id, question.id)],
    }))

    const answeredCount = controlAnswers.filter(item => item.answer).length
    const score = controlAnswers.reduce((sum, item) => sum + scoreAnswer(item.answer), 0)
    const ratio = control.questions.length ? score / control.questions.length : 0
    const gaps = controlAnswers
      .map(item => {
        const kind = gapKindForAnswer(item.answer)
        if (!kind) return null
        return {
          id: `${control.id}.${item.question.id}`,
          controlId: control.id,
          controlTitle: control.title,
          question: item.question.question,
          kind,
          title: GAP_COPY[kind].title,
          text: GAP_COPY[kind].text,
        }
      })
      .filter(Boolean)

    const evidenceLabel = control.externalEvidenceCapable
      ? hasCyberMotEvidence ? 'checked_by_cyber_mot' : 'not_externally_checked'
      : answeredCount > 0 ? 'self_declared' : 'not_externally_checked'

    return {
      controlId: control.id,
      title: control.title,
      description: control.description,
      why: control.why,
      recommendedAction: control.recommendedAction,
      evidenceLabel,
      status: ratio >= 0.88 ? 'strong' : ratio >= 0.55 ? 'partial' : 'needs_attention',
      score: Math.round(ratio * 100),
      answers: controlAnswers,
      gaps,
    }
  })

  const allGaps = controls.flatMap(control => control.gaps)
  const answeredTotal = Object.keys(answers).length
  const overallRatio = controls.length
    ? controls.reduce((sum, control) => sum + control.score, 0) / (controls.length * 100)
    : 0
  const overallStatus = overallRatio >= 0.85 && allGaps.length <= 2
    ? 'strong_readiness'
    : overallRatio >= 0.55
      ? 'some_gaps_to_fix'
      : 'needs_attention'

  return {
    overallStatus,
    controls,
    priorityGaps: allGaps.slice(0, 8),
    answeredTotal,
    totalQuestions: CONTROLS.reduce((sum, control) => sum + control.questions.length, 0),
  }
}

function Header() {
  return (
    <header className="sticky top-0 z-30 border-b border-gray-100 bg-white/95 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5">
        <Link to="/" aria-label="CyberMeters home">
          <CyberMetersLogo className="h-7" />
        </Link>
        <div className="flex items-center gap-3">
          <Link to="/free-scan" className="btn-secondary hidden sm:inline-flex">
            Run Cyber MOT first
          </Link>
          <Link to="/signup" className="btn-primary">
            Create account
          </Link>
        </div>
      </div>
    </header>
  )
}

function DisclaimerBox({ compact = false }) {
  return (
    <div className="rounded-2xl border border-amber-100 bg-amber-50 p-5">
      <div className="flex items-start gap-3">
        <HelpCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-600" />
        <div>
          <h2 className="text-sm font-bold text-amber-950">Readiness, not certification</h2>
          <p className={`mt-1 text-sm leading-relaxed text-amber-800 ${compact ? 'max-w-3xl' : ''}`}>
            CyberMeters helps you prepare for Cyber Essentials by highlighting likely gaps and areas to review. It does not issue Cyber Essentials certification. Formal certification is handled through IASME and approved Certification Bodies.
          </p>
        </div>
      </div>
    </div>
  )
}

function EmptyState({ type, onStart }) {
  const states = {
    cyberMot: {
      title: 'Run a Cyber MOT first',
      text: 'CyberMeters can give a stronger readiness view when it has external evidence from your domain.',
      cta: 'Run Cyber MOT',
      to: '/free-scan',
    },
    answers: {
      title: 'Complete the readiness questions',
      text: 'Answer a short set of plain-English questions covering the internal Cyber Essentials controls CyberMeters cannot confirm from outside your business.',
      cta: 'Start questions',
      onClick: onStart,
    },
    noGaps: {
      title: 'No major readiness gaps found',
      text: 'Your answers and external Cyber MOT evidence do not show major gaps at this stage. Review the self-declared areas carefully and keep evidence before starting the formal Cyber Essentials process.',
    },
  }
  const state = states[type]

  return (
    <div className="card p-6 text-center">
      <ClipboardCheck className="mx-auto h-10 w-10 text-brand-600" />
      <h3 className="mt-3 text-base font-bold text-gray-900">{state.title}</h3>
      <p className="mx-auto mt-2 max-w-lg text-sm leading-relaxed text-gray-500">{state.text}</p>
      {state.to && (
        <Link to={state.to} className="btn-primary mt-5">
          {state.cta}
          <ArrowRight className="h-4 w-4" />
        </Link>
      )}
      {state.onClick && (
        <button type="button" onClick={state.onClick} className="btn-primary mt-5">
          {state.cta}
          <ArrowRight className="h-4 w-4" />
        </button>
      )}
    </div>
  )
}

function EvidenceBadge({ type }) {
  const evidence = EVIDENCE_LABELS[type] || EVIDENCE_LABELS.not_externally_checked
  return (
    <div className={`rounded-xl border px-3 py-2 ${evidence.className}`}>
      <p className="text-xs font-bold">{evidence.label}</p>
      <p className="mt-0.5 text-[11px] leading-relaxed opacity-80">{evidence.helper}</p>
    </div>
  )
}

function ProgressBar({ answered, total }) {
  const pct = total ? Math.round((answered / total) * 100) : 0
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <span className="text-sm font-semibold text-gray-900">Question progress</span>
        <span className="text-sm font-bold tabular-nums text-brand-700">{answered}/{total}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-gray-100">
        <div className="h-full rounded-full bg-brand-600 transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function IntroView({ onStart }) {
  return (
    <main className="mx-auto max-w-6xl px-5 py-10 sm:py-14">
      <div className="grid gap-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-start">
        <div>
          <span className="eyebrow">Cyber Essentials Readiness</span>
          <h1 className="mt-2 text-[34px] font-bold leading-tight tracking-tight text-gray-900 sm:text-[44px]">
            Cyber Essentials Readiness
          </h1>
          <p className="mt-4 max-w-3xl text-base leading-relaxed text-gray-600 sm:text-lg">
            Check how prepared your business looks against the five Cyber Essentials control areas. CyberMeters combines external evidence from your Cyber MOT with your own answers for the internal controls we cannot see from outside.
          </p>
          <div className="mt-7 flex flex-col gap-3 sm:flex-row">
            <button type="button" onClick={onStart} className="btn-primary">
              Start readiness check
              <ArrowRight className="h-4 w-4" />
            </button>
            <Link to="/free-scan" className="btn-secondary">
              Run Cyber MOT first
            </Link>
          </div>
        </div>
        <DisclaimerBox />
      </div>

      <section className="mt-8 grid gap-5 lg:grid-cols-[1fr_0.9fr]">
        <div className="card p-6">
          <h2 className="text-lg font-bold text-gray-900">What this check covers</h2>
          <div className="mt-4 space-y-4 text-sm leading-relaxed text-gray-600">
            <p>
              Cyber Essentials includes controls that are partly visible from outside your business and partly internal to how you manage devices, users and software.
            </p>
            <p>
              CyberMeters can automatically check some external signals, such as website security, TLS, DNS and email protection. Other areas, such as staff access, MFA and endpoint protection, must be self-declared because they cannot be confirmed from outside your domain.
            </p>
            <p className="font-semibold text-gray-900">
              Answer honestly. The goal is not to look ready. The goal is to know what to fix before you apply.
            </p>
          </div>
        </div>
        <div className="space-y-5">
          <EmptyState type="cyberMot" />
          <EmptyState type="answers" onStart={onStart} />
        </div>
      </section>
    </main>
  )
}

function AnswerOption({ option, selected, onSelect }) {
  return (
    <button
      type="button"
      onClick={() => onSelect(option.value)}
      className={`rounded-xl border p-3 text-left transition-all ${
        selected
          ? 'border-brand-300 bg-brand-50 ring-2 ring-brand-500/20'
          : 'border-gray-200 bg-white hover:border-brand-200 hover:bg-brand-50/40'
      }`}
    >
      <span className="text-sm font-bold text-gray-900">{option.label}</span>
      <span className="mt-1 block text-xs leading-relaxed text-gray-500">{option.helper}</span>
    </button>
  )
}

function QuestionnaireView({ answers, onAnswer, onSubmit, onBack }) {
  const totalQuestions = CONTROLS.reduce((sum, control) => sum + control.questions.length, 0)
  const answered = Object.keys(answers).length
  const complete = answered === totalQuestions

  return (
    <main className="mx-auto max-w-6xl px-5 py-8 sm:py-10">
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <button type="button" onClick={onBack} className="btn-ghost mb-3">
            <ArrowLeft className="h-4 w-4" />
            Back to intro
          </button>
          <h1 className="text-2xl font-bold tracking-tight text-gray-900 sm:text-3xl">Cyber Essentials Readiness</h1>
          <p className="mt-1 max-w-3xl text-sm leading-relaxed text-gray-500">
            Work through each control area. You can change answers before viewing your readiness result.
          </p>
        </div>
        <div className="card min-w-full p-4 lg:min-w-[320px]">
          <ProgressBar answered={answered} total={totalQuestions} />
        </div>
      </div>

      <div className="space-y-5">
        {CONTROLS.map((control, controlIndex) => {
          const Icon = control.icon
          const controlAnswered = control.questions.filter(question => answers[answerKey(control.id, question.id)]).length
          return (
            <section key={control.id} className="card p-5 sm:p-6">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-brand-50 ring-1 ring-brand-100">
                    <Icon className="h-5 w-5 text-brand-600" />
                  </div>
                  <div>
                    <p className="text-[11px] font-bold uppercase tracking-wide text-gray-400">Control {controlIndex + 1}</p>
                    <h2 className="text-lg font-bold text-gray-900">{control.title}</h2>
                    <p className="mt-1 text-sm leading-relaxed text-gray-500">{control.description}</p>
                  </div>
                </div>
                <div className="rounded-full border border-gray-200 bg-gray-50 px-3 py-1 text-xs font-bold text-gray-600">
                  {controlAnswered}/{control.questions.length} answered
                </div>
              </div>

              <div className="mt-5 grid gap-4">
                {control.questions.map((question, questionIndex) => {
                  const key = answerKey(control.id, question.id)
                  return (
                    <div key={question.id} className="rounded-2xl border border-gray-100 bg-gray-50 p-4">
                      <div className="flex items-start gap-3">
                        <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-lg bg-white text-xs font-bold text-gray-500 ring-1 ring-gray-200">
                          {questionIndex + 1}
                        </span>
                        <div className="min-w-0 flex-1">
                          <h3 className="text-sm font-bold leading-snug text-gray-900">{question.question}</h3>
                          <p className="mt-1 text-xs leading-relaxed text-gray-500">
                            <span className="font-semibold text-gray-700">Why this matters:</span> {question.why}
                          </p>
                          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                            {ANSWER_OPTIONS.map(option => (
                              <AnswerOption
                                key={option.value}
                                option={option}
                                selected={answers[key] === option.value}
                                onSelect={value => onAnswer(key, value)}
                              />
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </section>
          )
        })}
      </div>

      <div className="sticky bottom-4 z-20 mt-6 rounded-2xl border border-gray-200 bg-white/95 p-4 shadow-card-md backdrop-blur">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <ProgressBar answered={answered} total={totalQuestions} />
          <button type="button" onClick={onSubmit} disabled={!complete} className="btn-primary disabled:cursor-not-allowed disabled:opacity-40">
            Show readiness result
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </main>
  )
}

function ControlResultCard({ control }) {
  const statusClass = control.status === 'strong'
    ? 'bg-brand-50 text-brand-700 border-brand-100'
    : control.status === 'partial'
      ? 'bg-amber-50 text-amber-700 border-amber-100'
      : 'bg-red-50 text-red-700 border-red-100'

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-gray-900">{control.title}</h3>
          <p className="mt-1 text-sm leading-relaxed text-gray-500">{control.description}</p>
        </div>
        <span className={`rounded-full border px-2.5 py-1 text-xs font-bold capitalize ${statusClass}`}>
          {control.status.replace('_', ' ')}
        </span>
      </div>
      <div className="mt-4">
        <EvidenceBadge type={control.evidenceLabel} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <p className="text-xs font-bold uppercase tracking-wide text-gray-400">Why this matters</p>
          <p className="mt-1 text-sm leading-relaxed text-gray-600">{control.why}</p>
        </div>
        <div>
          <p className="text-xs font-bold uppercase tracking-wide text-gray-400">Recommended action</p>
          <p className="mt-1 text-sm leading-relaxed text-gray-600">{control.recommendedAction}</p>
        </div>
      </div>
      <div className="mt-4 rounded-xl border border-gray-100 bg-gray-50 p-3">
        <p className="text-xs font-bold uppercase tracking-wide text-gray-400">User answer summary</p>
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          {control.answers.map(item => (
            <div key={item.question.id} className="flex items-center justify-between gap-3 rounded-lg bg-white px-3 py-2 text-xs">
              <span className="line-clamp-1 text-gray-500">{item.question.question}</span>
              <span className="flex-shrink-0 font-bold text-gray-800">{answerLabel(item.answer)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function GapList({ gaps }) {
  if (!gaps.length) return <EmptyState type="noGaps" />

  return (
    <section className="card p-5 sm:p-6">
      <h2 className="text-lg font-bold text-gray-900">Priority gaps to review</h2>
      <p className="mt-1 max-w-3xl text-sm leading-relaxed text-gray-500">
        These are the issues most likely to affect your Cyber Essentials readiness. Start with gaps supported by Cyber MOT evidence, then review the self-declared areas with your IT provider or internal owner.
      </p>
      <div className="mt-5 space-y-3">
        {gaps.map(gap => (
          <div key={gap.id} className="rounded-xl border border-gray-200 bg-white p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
              <div>
                <p className="text-sm font-bold text-gray-900">{gap.title}</p>
                <p className="mt-1 text-sm leading-relaxed text-gray-600">{gap.text}</p>
                <p className="mt-2 text-xs font-semibold text-gray-400">{gap.controlTitle}: {gap.question}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

function ResultView({ result, onEdit }) {
  const status = STATUS_COPY[result.overallStatus]

  return (
    <main className="mx-auto max-w-6xl px-5 py-8 sm:py-10">
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <span className="eyebrow">Readiness result</span>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-gray-900 sm:text-3xl">Cyber Essentials Readiness</h1>
          <p className="mt-1 max-w-3xl text-sm leading-relaxed text-gray-500">
            This result combines your self-declared answers with any available Cyber MOT context. Internal controls still need to be confirmed by your organisation.
          </p>
        </div>
        <button type="button" onClick={onEdit} className="btn-secondary justify-center">
          Edit answers
        </button>
      </div>

      <section className={`rounded-2xl border p-6 ${status.className}`}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 h-6 w-6 flex-shrink-0" />
            <div>
              <h2 className="text-xl font-bold">{status.title}</h2>
              <p className="mt-1 max-w-3xl text-sm leading-relaxed">{status.body}</p>
            </div>
          </div>
          <a href="#priority-gaps" className="btn-primary whitespace-nowrap">
            {status.cta}
          </a>
        </div>
      </section>

      <div className="mt-6 grid gap-5 lg:grid-cols-2">
        {result.controls.map(control => (
          <ControlResultCard key={control.controlId} control={control} />
        ))}
      </div>

      <div id="priority-gaps" className="mt-6 scroll-mt-24">
        <GapList gaps={result.priorityGaps} />
      </div>

      <div className="mt-6 rounded-2xl border border-gray-200 bg-white p-5">
        <div className="flex items-start gap-3">
          <HelpCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-gray-400" />
          <p className="text-sm leading-relaxed text-gray-600">
            CyberMeters provides readiness guidance only. It does not issue Cyber Essentials certification and cannot fully verify internal controls such as MFA, admin account separation, endpoint protection or patching across your devices. Formal Cyber Essentials certification is handled through IASME and approved Certification Bodies.
          </p>
        </div>
      </div>
    </main>
  )
}

export default function CyberEssentialsReadinessPage() {
  const [view, setView] = useState('intro')
  const [answers, setAnswers] = useState({})
  const hasCyberMotEvidence = false

  const result = useMemo(() => deriveReadinessResult(answers, hasCyberMotEvidence), [answers])

  function handleAnswer(key, value) {
    setAnswers(current => ({ ...current, [key]: value }))
  }

  return (
    <div className="min-h-screen bg-[#EEF1F6] text-gray-900">
      <Header />
      {view === 'intro' && <IntroView onStart={() => setView('questions')} />}
      {view === 'questions' && (
        <QuestionnaireView
          answers={answers}
          onAnswer={handleAnswer}
          onSubmit={() => setView('results')}
          onBack={() => setView('intro')}
        />
      )}
      {view === 'results' && <ResultView result={result} onEdit={() => setView('questions')} />}
    </div>
  )
}
