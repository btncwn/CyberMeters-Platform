import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, Radar, Globe, Lock, ArrowRight, Sparkles, CheckCircle, ClipboardCheck,
  MonitorCheck, KeyRound, Boxes,
} from 'lucide-react'
import { api } from '../api'
import { useWorkspace } from '../hooks/useWorkspace'

// ── Domain Launcher / first-run command center ────────────────────────────────
// The post-login home: what CyberMeters is, the eight Cyber MOT domains, a
// first-run checklist, and the single clearest next action. Frontend-only;
// derives state from light workspace data when available and falls back to
// neutral guidance.

const SERVICES = [
  {
    key: 'email', icon: Mail, title: 'Email Protection',
    copy: 'Protect against spoofing, invoice fraud and supplier impersonation using DMARC, sender intelligence and BEC Exposure.',
    cta: 'Open Email Protection', to: '/ws/email-protection',
  },
  {
    key: 'brand', icon: Radar, title: 'Brand Protection',
    copy: 'Find lookalike domains and classify impersonation candidates before they are used for fraud.',
    cta: 'Open Brand Protection', to: '/ws/brand-monitoring',
  },
  {
    key: 'surface', icon: Globe, title: 'Attack Surface',
    copy: 'Discover exposed domains, subdomains, assets, admin surfaces and risky external signals.',
    cta: 'Open Attack Surface', to: '/assets',
  },
  {
    key: 'certs', icon: Lock, title: 'Certificates & Trust',
    copy: 'Track HTTPS, TLS and certificate expiry so trust failures do not surprise the business.',
    cta: 'Open Certificates & Trust', to: '/ws/certificates',
  },
  {
    key: 'cyber_essentials', icon: ClipboardCheck, title: 'Cyber Essentials Readiness',
    copy: 'Review externally observable evidence and saved answers against the readiness workflow.',
    cta: 'Open Cyber Essentials', to: '/ws/cyber-essentials',
  },
  {
    key: 'website', icon: MonitorCheck, title: 'Website Security',
    copy: 'Check HTTPS, redirects, headers, cookie flags and externally visible website configuration.',
    cta: 'Open Website Security', to: '/ws/website-security',
  },
  {
    key: 'identity', icon: KeyRound, title: 'Identity Exposure',
    copy: 'Review provider relationships and possible identity-facing hostnames; endpoint reachability is not currently evaluated.',
    cta: 'Open Identity Exposure', to: '/ws/identity-exposure',
  },
  {
    key: 'shadow_it', icon: Boxes, title: 'Shadow IT & Unmanaged Technology',
    copy: 'Track externally observed SaaS, vendors, scripts and unmanaged technology signals.',
    cta: 'Open Shadow IT', to: '/ws/shadow-it',
  },
]

function ServiceCard({ service }) {
  const Icon = service.icon
  return (
    <Link
      to={service.to}
      className="group card p-6 flex flex-col items-start hover:border-brand-200 hover:shadow-card-md transition-all hover:-translate-y-0.5"
    >
      <div className="w-12 h-12 rounded-xl bg-brand-50 ring-1 ring-brand-100 flex items-center justify-center mb-4 group-hover:bg-brand-600 transition-colors">
        <Icon className="w-6 h-6 text-brand-600 group-hover:text-white transition-colors" />
      </div>
      <h2 className="text-lg font-bold text-gray-900">{service.title}</h2>
      <p className="text-sm text-gray-500 mt-1.5 leading-relaxed flex-1">{service.copy}</p>
      <span className="mt-5 inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-brand-200 text-brand-700 text-sm font-semibold bg-white group-hover:bg-brand-600 group-hover:text-white group-hover:border-brand-600 shadow-btn transition-all">
        {service.cta} <ArrowRight className="w-4 h-4" />
      </span>
    </Link>
  )
}

// Status pill for checklist items.
const STEP_STATUS = {
  done:        { label: 'Done',        cls: 'text-brand-700 bg-brand-50 border-brand-100' },
  next:        { label: 'Next',        cls: 'text-brand-700 bg-brand-50 border-brand-100' },
  recommended: { label: 'Recommended', cls: 'text-gray-500 bg-gray-50 border-gray-200' },
  waiting:     { label: 'Waiting',     cls: 'text-gray-400 bg-gray-50 border-gray-200' },
}
function StepRow({ n, title, explanation, status, actionLabel, to }) {
  const s = STEP_STATUS[status] || STEP_STATUS.recommended
  const done = status === 'done'
  return (
    <li className="flex items-start gap-3 py-3">
      {done
        ? <CheckCircle className="w-5 h-5 text-brand-600 flex-shrink-0 mt-0.5" />
        : <span className="w-5 h-5 rounded-full border border-gray-300 text-[11px] font-bold text-gray-400 flex items-center justify-center flex-shrink-0 mt-0.5">{n}</span>}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-sm font-semibold text-gray-900">{title}</p>
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full border ${s.cls}`}>{s.label}</span>
        </div>
        <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{explanation}</p>
      </div>
      <Link to={to} className="text-xs font-semibold text-brand-700 hover:text-brand-800 flex-shrink-0 mt-0.5 whitespace-nowrap">
        {actionLabel} →
      </Link>
    </li>
  )
}

export default function ServiceLauncher() {
  const { wsId, wsName } = useWorkspace()
  const [hasDomain, setHasDomain] = useState(null) // null = unknown
  const [hasScan, setHasScan]     = useState(null)

  useEffect(() => {
    let cancelled = false
    if (!wsId) { setHasDomain(null); setHasScan(null); return }
    Promise.allSettled([api.getWorkspaceSummary(wsId), api.getWorkspaceDomains(wsId)])
      .then(([s, d]) => {
        if (cancelled) return
        const summary = s.status === 'fulfilled' ? s.value : null
        const domainList = d.status === 'fulfilled' ? (d.value?.domains || []) : null
        const domainCount = domainList ? domainList.length : (typeof summary?.domains === 'number' ? summary.domains : null)
        setHasDomain(domainCount == null ? null : domainCount > 0)
        // A latest score (or any reports) only exists after a scan has run.
        setHasScan(summary == null ? null : (summary.latest_score != null || (summary.reports_count || 0) > 0))
      })
    return () => { cancelled = true }
  }, [wsId])

  // ── Recommended next action (clearest, honest, derived where possible) ──
  const next = !wsId
    ? { text: 'Create or select a workspace to get started.', cta: 'Go to workspaces', to: '/workspaces' }
    : hasDomain === false
      ? { text: 'Add your first domain so CyberMeters can start monitoring it.', cta: 'Add a domain', to: '/ws/dashboard' }
      : hasScan === false
        ? { text: 'Run your first Cyber MOT to check your website, email posture, certificates and visible external posture.', cta: 'Start Cyber MOT', to: '/scans/new' }
        : (hasDomain || hasScan)
          ? { text: 'Connect Email Protection to start receiving DMARC reports for your domain.', cta: 'Open Email Protection', to: '/ws/email-protection' }
          : { text: 'Recommended first step: run a Cyber MOT and connect Email Protection.', cta: 'Start Cyber MOT', to: '/scans/new' }

  // ── First-run checklist statuses (never invented) ──
  const st = (done, ready) => done ? 'done' : ready ? 'next' : 'waiting'
  const steps = [
    { n: 1, title: 'Add or confirm your primary domain', explanation: 'Tell CyberMeters which domain to protect.', status: hasDomain == null ? 'recommended' : st(hasDomain, !!wsId), actionLabel: 'Add domain', to: '/ws/dashboard' },
    { n: 2, title: 'Run your first Cyber MOT', explanation: 'Check your website, email posture, certificates and visible external posture.', status: hasScan == null ? 'recommended' : st(hasScan, hasDomain === true), actionLabel: 'Start Cyber MOT', to: '/scans/new' },
    { n: 3, title: 'Connect DMARC reporting', explanation: 'Start receiving reports on who is sending email using your domain.', status: hasScan ? 'recommended' : 'waiting', actionLabel: 'Set up', to: '/ws/email-protection' },
    { n: 4, title: 'Review BEC Exposure', explanation: 'See how exposed your domain is to spoofing and invoice fraud.', status: hasScan ? 'recommended' : 'waiting', actionLabel: 'Review', to: '/ws/email-protection' },
    { n: 5, title: 'Review Brand Protection candidates', explanation: 'Find lookalike domains that could impersonate your brand.', status: hasScan ? 'recommended' : 'waiting', actionLabel: 'Review', to: '/ws/brand-monitoring' },
    { n: 6, title: 'Schedule monitoring', explanation: 'Keep scans running automatically so nothing slips.', status: 'recommended', actionLabel: 'Schedule', to: '/schedules' },
  ]

  return (
    <div className="py-8">
      <div className="max-w-5xl mx-auto w-full px-2 space-y-6">

        {/* 1 · Welcome */}
        <header>
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-50 border border-brand-100 text-[11px] font-bold text-brand-700 uppercase tracking-[0.14em] mb-3">
            <span className="w-1.5 h-1.5 rounded-full bg-brand-500" /> Welcome to CyberMeters
          </span>
          <h1 className="page-title">Welcome to CyberMeters</h1>
          <p className="text-base text-gray-600 mt-2 max-w-2xl leading-relaxed">
            Start by adding a domain, running your first Cyber MOT, and connecting Email Protection.
          </p>
          <p className="text-sm text-gray-500 mt-1.5 max-w-2xl leading-relaxed">
            CyberMeters helps you monitor all eight Cyber MOT domains from one workspace.
          </p>
          {wsName && <p className="text-xs text-gray-400 mt-2">Current workspace: <span className="font-medium text-gray-600">{wsName}</span></p>}
        </header>

        {/* 2 · Recommended next action — the clearest section */}
        <div className="card p-5 border-brand-100 bg-brand-50/40 flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-white border border-brand-100 flex items-center justify-center flex-shrink-0">
            <Sparkles className="w-5 h-5 text-brand-600" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-brand-700 uppercase tracking-wide">Recommended next step</p>
            <p className="text-sm text-gray-800 mt-0.5 leading-relaxed">{next.text}</p>
          </div>
          <Link to={next.to} className="btn-primary text-sm flex-shrink-0">{next.cta} <ArrowRight className="w-4 h-4" /></Link>
        </div>

        {/* 3 · Cyber MOT domains */}
        <div>
          <h2 className="section-title mb-3">Your Cyber MOT domains</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {SERVICES.map(s => <ServiceCard key={s.key} service={s} />)}
          </div>
        </div>

        {/* 4 · First-run checklist */}
        <section className="card p-6">
          <h2 className="section-title">Get set up</h2>
          <p className="text-xs text-gray-500 mt-0.5 mb-2">A few steps to get the most from CyberMeters.</p>
          <ul className="divide-y divide-gray-100">
            {steps.map(s => <StepRow key={s.n} {...s} />)}
          </ul>
        </section>
      </div>
    </div>
  )
}
