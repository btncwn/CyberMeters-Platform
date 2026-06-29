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
    copy: 'Managed DMARC, sender intelligence and enforcement guidance.',
    cta: 'Open Email Protection', to: '/ws/email-protection',
  },
  {
    key: 'brand', icon: Radar, title: 'Brand Protection',
    copy: 'Monitor lookalike domains, impersonation risk and brand-abuse signals.',
    cta: 'Open Brand Protection', to: '/ws/brand-monitoring',
  },
  {
    key: 'surface', icon: Globe, title: 'Attack Surface',
    copy: 'Discover exposed assets, admin surfaces, SaaS/cloud exposure and external risk.',
    cta: 'Open Attack Surface', to: '/assets',
  },
  {
    key: 'certs', icon: Lock, title: 'Certificates & Trust',
    copy: 'Monitor SSL/TLS certificates, expiry, HTTPS posture and transport trust.',
    cta: 'Open Certificates', to: '/ws/certificates',
  },
]

function ServiceCard({ service }) {
  const Icon = service.icon
  return (
    <Link
      to={service.to}
      className="group card p-7 flex flex-col items-start hover:border-brand-200 hover:shadow-card-md transition-all hover:-translate-y-0.5"
    >
      <div className="w-12 h-12 rounded-xl bg-brand-50 ring-1 ring-brand-100 flex items-center justify-center mb-5 group-hover:bg-brand-600 transition-colors">
        <Icon className="w-6 h-6 text-brand-600 group-hover:text-white transition-colors" />
      </div>
      <h2 className="text-lg font-bold text-gray-900">{service.title}</h2>
      <p className="text-sm text-gray-500 mt-1.5 leading-relaxed flex-1">{service.copy}</p>
      {/* CTA styled as a real action (button-like), filling on hover. */}
      <span className="mt-6 inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-brand-200 text-brand-700 text-sm font-semibold bg-white group-hover:bg-brand-600 group-hover:text-white group-hover:border-brand-600 shadow-btn transition-all">
        {service.cta} <ArrowRight className="w-4 h-4" />
      </span>
    </Link>
  )
}

export default function ServiceLauncher() {
  return (
    <div className="min-h-[72vh] flex flex-col justify-center py-10">
      <div className="max-w-4xl mx-auto w-full px-2">
        <header className="text-center mb-12">
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-50 border border-brand-100 text-[11px] font-bold text-brand-700 uppercase tracking-[0.14em] mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-brand-500" /> CyberMeters Security Platform
          </span>
          <h1 className="text-[34px] sm:text-[40px] font-bold text-gray-900 tracking-tight leading-tight">Choose where to start</h1>
          <p className="text-base text-gray-500 mt-3 max-w-xl mx-auto leading-relaxed">
            Protect your email, brand, certificates and external attack surface — all from one workspace.
          </p>
        </header>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          {SERVICES.map(s => <ServiceCard key={s.key} service={s} />)}
        </div>
      </div>
    </div>
  )
}
