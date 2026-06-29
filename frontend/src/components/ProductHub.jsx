import { Link } from 'react-router-dom'
import {
  Mail, Radar, Globe, Lock, ArrowRight, CheckCircle, AlertTriangle, Sparkles,
} from 'lucide-react'

// ── Product Hub / Service Selector ───────────────────────────────────────────
// A calm entry layer that presents CyberMeters as a clear service family before
// the user drops into detailed dashboards. Four service areas, each with a
// status chip derived from data already loaded on the workspace dashboard.
// Frontend-only — no new routes, no API calls. Uses CyberMeters' own design
// language (brand-green accents, soft cards, status chips).

const TONE = {
  ok:        'bg-brand-50 text-brand-700 border-brand-100',
  attention: 'bg-amber-50 text-amber-700 border-amber-200',
  neutral:   'bg-gray-50 text-gray-500 border-gray-200',
}

function StatusChip({ status }) {
  if (!status) return null
  const cls = TONE[status.tone] || TONE.neutral
  const Icon = status.tone === 'ok' ? CheckCircle : status.tone === 'attention' ? AlertTriangle : null
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${cls}`}>
      {Icon && <Icon className="w-3 h-3" />}
      {status.label}
    </span>
  )
}

// Derive a customer-safe status for each service from existing dashboard data.
function deriveStatuses(sc, summary, noScans) {
  // Email Protection — the dashboard has no DMARC connection signal, so this is
  // a neutral entry point; the Email Protection page shows the real state.
  const email = { label: 'Set up DMARC', tone: 'neutral' }

  const brandHigh   = sc?.brand_risks?.high ?? 0
  const brandActive = sc?.brand_risks?.active
  const brand = brandHigh > 0
    ? { label: 'New risks found', tone: 'attention' }
    : brandActive != null
      ? { label: 'Monitoring', tone: 'ok' }
      : { label: 'No brand profile', tone: 'neutral' }

  const exposure = (sc?.critical_findings ?? 0) > 0 || (sc?.admin_surfaces ?? 0) > 0 || (sc?.saas_exposures ?? 0) > 0
  const surface = noScans
    ? { label: 'Scan required', tone: 'neutral' }
    : exposure
      ? { label: 'High-risk exposure found', tone: 'attention' }
      : { label: 'Monitoring', tone: 'ok' }

  const cr = sc?.certificate_risks?.risk_level
  const certs = (cr === 'high' || cr === 'critical')
    ? { label: 'Needs review', tone: 'attention' }
    : cr === 'medium'
      ? { label: 'Expiring soon', tone: 'attention' }
      : cr
        ? { label: 'Healthy', tone: 'ok' }
        : { label: 'Review trust posture', tone: 'neutral' }

  return { email, brand, surface, certs }
}

// First applicable recommended next step, derived from current workspace state.
function recommendedStep(statuses, noScans) {
  if (noScans) return { text: 'Run your first attack surface scan to map exposed assets.', to: '/scans/new', cta: 'Start scan' }
  if (statuses.brand.label === 'No brand profile') return { text: 'Add brand keywords to start watching for impersonation.', to: '/ws/brand-monitoring', cta: 'Add brand keywords' }
  if (statuses.certs.tone === 'attention') return { text: 'Review certificate expiry and TLS posture.', to: '/ws/certificates', cta: 'Review certificates' }
  return { text: 'Complete DMARC setup to start receiving email reports.', to: '/ws/email-protection', cta: 'Complete DMARC setup' }
}

const SERVICES = [
  {
    key: 'email', icon: Mail, title: 'Email Protection',
    desc: 'Managed DMARC, SPF/DKIM readiness, sender intelligence and enforcement guidance.',
    to: '/ws/email-protection', cta: 'Go to Email Protection',
    secondary: { label: 'Configure DMARC', to: '/ws/email-protection' },
    bullets: ['Guided DMARC setup & verification', 'Sender inventory and alignment', 'A safe path toward enforcement'],
  },
  {
    key: 'brand', icon: Radar, title: 'Brand Protection',
    desc: 'Detect lookalike domains, impersonation risks and brand-abuse signals.',
    to: '/ws/brand-monitoring', cta: 'Go to Brand Protection',
    secondary: { label: 'View brand monitoring', to: '/ws/brand-monitoring' },
    bullets: ['Lookalike & typosquat detection', 'Impersonation risk signals', 'Ongoing brand monitoring'],
  },
  {
    key: 'surface', icon: Globe, title: 'Attack Surface',
    desc: 'Discover exposed assets, admin surfaces, and SaaS/cloud exposure across your external footprint.',
    to: '/assets', cta: 'Go to Attack Surface',
    secondary: { label: 'Start scan', to: '/scans/new' },
    bullets: ['External asset discovery', 'Admin & cloud exposure', 'SaaS exposure insights'],
    links: [
      { label: 'Admin surfaces', to: '/ws/admin-surfaces' },
      { label: 'Cloud assets',   to: '/ws/cloud-assets' },
      { label: 'SaaS exposure',  to: '/ws/saas-exposure' },
    ],
  },
  {
    key: 'certs', icon: Lock, title: 'Certificates & Trust',
    desc: 'Monitor SSL/TLS certificates, expiry, HTTPS posture, MTA-STS and TLS-RPT readiness.',
    to: '/ws/certificates', cta: 'Go to Certificates',
    secondary: { label: 'Review trust posture', to: '/ws/certificates' },
    bullets: ['Certificate expiry tracking', 'HTTPS & TLS posture', 'MTA-STS & TLS-RPT readiness'],
  },
]

function ServiceCard({ service, status }) {
  const Icon = service.icon
  return (
    <div className="card p-5 flex flex-col h-full hover:shadow-card-md transition-shadow">
      <div className="flex items-start gap-3 mb-3">
        <div className="w-11 h-11 rounded-xl bg-brand-50 flex items-center justify-center flex-shrink-0">
          <Icon className="w-5 h-5 text-brand-600" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <h3 className="font-semibold text-gray-900">{service.title}</h3>
            <StatusChip status={status} />
          </div>
          <p className="text-sm text-gray-500 leading-relaxed mt-1">{service.desc}</p>
        </div>
      </div>

      <ul className="space-y-1.5 mb-4 mt-1">
        {service.bullets.slice(0, 3).map(b => (
          <li key={b} className="flex items-start gap-2 text-xs text-gray-600">
            <CheckCircle className="w-3.5 h-3.5 text-brand-400 flex-shrink-0 mt-0.5" />
            <span>{b}</span>
          </li>
        ))}
      </ul>

      {service.links && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          {service.links.map(l => (
            <Link key={l.to} to={l.to} className="text-[11px] px-2 py-0.5 rounded-md border border-gray-200 text-gray-500 hover:bg-gray-50 hover:text-gray-700 transition-colors">
              {l.label}
            </Link>
          ))}
        </div>
      )}

      <div className="mt-auto flex items-center gap-3 pt-1">
        <Link to={service.to} className="btn-primary text-sm">
          {service.cta} <ArrowRight className="w-4 h-4" />
        </Link>
        <Link to={service.secondary.to} className="text-sm font-medium text-brand-700 hover:text-brand-800">
          {service.secondary.label}
        </Link>
      </div>
    </div>
  )
}

export default function ProductHub({ scorecard = null, summary = null, noScans = false }) {
  const statuses = deriveStatuses(scorecard, summary, noScans)
  const next = recommendedStep(statuses, noScans)

  return (
    <section className="mb-8">
      <div className="flex items-end justify-between gap-4 mb-4">
        <div>
          <span className="eyebrow">Your security platform</span>
          <h2 className="text-lg font-bold text-gray-900 mt-0.5">Where would you like to start?</h2>
        </div>
      </div>

      {/* Recommended next step */}
      {next && (
        <div className="card p-4 mb-4 flex flex-col sm:flex-row sm:items-center gap-3 border-brand-100 bg-brand-50/30">
          <div className="w-9 h-9 rounded-lg bg-white border border-brand-100 flex items-center justify-center flex-shrink-0">
            <Sparkles className="w-4 h-4 text-brand-600" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-brand-700 uppercase tracking-wide">Recommended next step</p>
            <p className="text-sm text-gray-700 mt-0.5">{next.text}</p>
          </div>
          <Link to={next.to} className="btn-primary text-sm flex-shrink-0">
            {next.cta} <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      )}

      {/* Service cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {SERVICES.map(s => (
          <ServiceCard key={s.key} service={s} status={statuses[s.key]} />
        ))}
      </div>
    </section>
  )
}
