import { Link } from 'react-router-dom'
import { Mail, Radar, Globe, Lock, ArrowRight } from 'lucide-react'

// ── Service Launcher ──────────────────────────────────────────────────────────
// A calm, near-full-page entry experience that presents CyberMeters as a clear
// security service family — deliberately quiet: lots of whitespace, four cards,
// one CTA each, no badges, no bullets, no dashboard stats. Uses CyberMeters'
// own design language (white canvas, brand-green accents). Frontend-only and
// navigation-only — existing routes, no API, no backend.
//
// NOT rendered inside WorkspaceDashboard. Intended for a future top-level
// /services (or /security) landing route — see ServiceLauncher delivery notes.

const SERVICES = [
  {
    key: 'email', icon: Mail, title: 'Email Protection',
    copy: 'Managed DMARC and sender intelligence.',
    cta: 'Open Email Protection', to: '/ws/email-protection',
  },
  {
    key: 'brand', icon: Radar, title: 'Brand Protection',
    copy: 'Monitor lookalike domains and impersonation risk.',
    cta: 'Open Brand Protection', to: '/ws/brand-monitoring',
  },
  {
    key: 'surface', icon: Globe, title: 'Attack Surface',
    copy: 'Discover exposed assets and external risk.',
    cta: 'Open Attack Surface', to: '/assets',
  },
  {
    key: 'certs', icon: Lock, title: 'Certificates & Trust',
    copy: 'Monitor SSL/TLS, expiry and transport trust.',
    cta: 'Open Certificates', to: '/ws/certificates',
  },
]

function ServiceCard({ service }) {
  const Icon = service.icon
  return (
    <Link
      to={service.to}
      className="group card p-8 flex flex-col items-start hover:shadow-card-md transition-all hover:-translate-y-0.5"
    >
      <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center mb-5 group-hover:bg-brand-100 transition-colors">
        <Icon className="w-7 h-7 text-brand-600" />
      </div>
      <h2 className="text-lg font-bold text-gray-900">{service.title}</h2>
      <p className="text-sm text-gray-500 mt-1.5 leading-relaxed">{service.copy}</p>
      <span className="mt-6 inline-flex items-center gap-1.5 text-sm font-semibold text-brand-700 group-hover:gap-2.5 transition-all">
        {service.cta} <ArrowRight className="w-4 h-4" />
      </span>
    </Link>
  )
}

export default function ServiceLauncher() {
  return (
    <div className="min-h-[72vh] flex flex-col justify-center py-10">
      <div className="max-w-4xl mx-auto w-full px-2">
        <header className="text-center mb-10">
          <span className="eyebrow">CyberMeters</span>
          <h1 className="text-3xl font-bold text-gray-900 mt-1">Your security services</h1>
          <p className="text-sm text-gray-500 mt-2 max-w-md mx-auto leading-relaxed">
            Choose where to focus. Open a service to dive into the detail.
          </p>
        </header>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {SERVICES.map(s => <ServiceCard key={s.key} service={s} />)}
        </div>
      </div>
    </div>
  )
}
