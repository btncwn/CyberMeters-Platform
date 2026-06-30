import { Link } from 'react-router-dom'
import {
  Mail, Radar, Globe, Lock, ArrowRight, ShieldCheck, Check, Building2,
  Users, FileBarChart2, History, ClipboardList, Layers, Cloud, Activity,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'

const APP_URL = 'https://app.cybermeters.com'
const CONTACT = 'mailto:hello@cybermeters.com'

const SERVICES = [
  { icon: Mail,  title: 'Email Protection',
    copy: 'Monitor DMARC posture, authentication signals, sender behaviour, and business email compromise exposure.' },
  { icon: Radar, title: 'Brand Protection',
    copy: 'Track protected domains, suspicious lookalikes, candidate domains, and brand exposure workflows.' },
  { icon: Globe, title: 'Attack Surface',
    copy: 'Discover public-facing assets, subdomains, DNS signals, HTTP exposure, and externally visible risks.' },
  { icon: Lock,  title: 'Certificates & Trust',
    copy: 'Monitor HTTPS, TLS, certificate expiry, and transport trust indicators.' },
]

const CAPABILITIES = [
  { icon: Building2,     label: 'Multi-tenant workspaces' },
  { icon: Globe,        label: 'External attack surface scanning' },
  { icon: Mail,         label: 'DMARC and email security analysis' },
  { icon: ShieldCheck,  label: 'BEC exposure scoring' },
  { icon: Radar,        label: 'Brand monitoring workflows' },
  { icon: History,      label: 'Historical change tracking' },
  { icon: ClipboardList, label: 'Audit logging' },
  { icon: FileBarChart2, label: 'Executive reporting' },
  { icon: Cloud,        label: 'Cloud-native architecture' },
]

function TopBar() {
  return (
    <header className="border-b border-gray-100 bg-white/90 backdrop-blur sticky top-0 z-30">
      <div className="max-w-6xl mx-auto px-5 h-16 flex items-center justify-between">
        <CyberMetersLogo className="h-7" />
        <div className="flex items-center gap-3">
          <a href={CONTACT} className="hidden sm:inline text-sm font-medium text-gray-600 hover:text-gray-900">Contact</a>
          <a href={APP_URL} className="btn-primary text-sm">Open Live App <ArrowRight className="w-4 h-4" /></a>
        </div>
      </div>
    </header>
  )
}

// A calm, generic product panel — no customer data, safe example domain only.
function ProductMock() {
  return (
    <div className="card p-5 shadow-card-md">
      <div className="flex items-center gap-2 mb-4">
        <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center"><Mail className="w-4 h-4 text-brand-600" /></div>
        <div>
          <p className="text-[11px] font-bold text-brand-600 uppercase tracking-wide">Email Protection</p>
          <p className="text-sm font-semibold text-gray-900">example.com</p>
        </div>
        <span className="ml-auto inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-amber-50 text-amber-700 border-amber-200">
          Receiving reports · DNS not verified
        </span>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-4">
        {[
          { l: 'BEC exposure', v: 'High' },
          { l: 'Pass rate', v: '77%' },
          { l: 'Known senders', v: '3' },
        ].map(m => (
          <div key={m.l} className="rounded-lg border border-gray-200 px-3 py-2">
            <p className="text-xs font-semibold text-gray-700 leading-snug">{m.l}</p>
            <p className="text-[13px] font-bold text-gray-800 mt-1">{m.v}</p>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        {['DMARC record found', 'CyberMeters reporting address added', 'First report received'].map((s, i) => (
          <div key={s} className="flex items-center gap-2 text-xs text-gray-600">
            <Check className={`w-3.5 h-3.5 ${i < 2 ? 'text-brand-500' : 'text-gray-300'}`} /> {s}
          </div>
        ))}
      </div>
    </div>
  )
}

function FooterLink({ to, children }) {
  return <Link to={to} className="text-sm text-gray-500 hover:text-gray-800">{children}</Link>
}

export default function PublicLandingPage() {
  const year = new Date().getFullYear()
  return (
    <div className="min-h-screen bg-white text-gray-900">
      <TopBar />

      {/* ── Hero ── */}
      <section className="max-w-6xl mx-auto px-5 pt-16 pb-12">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          <div>
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-50 border border-brand-100 text-[11px] font-bold text-brand-700 uppercase tracking-[0.14em] mb-5">
              <span className="w-1.5 h-1.5 rounded-full bg-brand-500" /> Cloud-native security monitoring
            </span>
            <h1 className="text-[34px] sm:text-[44px] font-bold tracking-tight leading-[1.1]">
              Monitor your external security posture
            </h1>
            <p className="text-base sm:text-lg text-gray-600 mt-5 leading-relaxed max-w-xl">
              CyberMeters helps organisations monitor email security, brand exposure, attack surface risk, and certificate
              trust from one cloud-native platform.
            </p>
            <div className="flex flex-wrap items-center gap-3 mt-7">
              <a href={APP_URL} className="btn-primary">Open Live App <ArrowRight className="w-4 h-4" /></a>
              <a href={CONTACT} className="btn-secondary">Request Beta Access</a>
            </div>
            <p className="text-xs text-gray-400 mt-5 max-w-md leading-relaxed">
              CyberMeters is currently being prepared for controlled beta. The live application is available at
              <span className="text-gray-500"> app.cybermeters.com</span>. Source code is maintained in a private commercial repository.
            </p>
          </div>
          <div className="lg:pl-6"><ProductMock /></div>
        </div>
      </section>

      {/* ── Four services ── */}
      <section className="bg-gray-50/70 border-y border-gray-100">
        <div className="max-w-6xl mx-auto px-5 py-14">
          <div className="max-w-2xl mb-8">
            <span className="eyebrow">One platform, four services</span>
            <h2 className="text-2xl font-bold tracking-tight mt-1">Understand your external posture in one place</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {SERVICES.map(s => {
              const Icon = s.icon
              return (
                <div key={s.title} className="card p-6">
                  <div className="w-11 h-11 rounded-xl bg-brand-50 ring-1 ring-brand-100 flex items-center justify-center mb-4">
                    <Icon className="w-5 h-5 text-brand-600" />
                  </div>
                  <h3 className="text-lg font-bold text-gray-900">{s.title}</h3>
                  <p className="text-sm text-gray-500 mt-1.5 leading-relaxed">{s.copy}</p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ── Platform capabilities ── */}
      <section className="max-w-6xl mx-auto px-5 py-14">
        <div className="max-w-2xl mb-8">
          <span className="eyebrow">Platform capabilities</span>
          <h2 className="text-2xl font-bold tracking-tight mt-1">Built as a serious, cloud-native SaaS</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {CAPABILITIES.map(c => {
            const Icon = c.icon
            return (
              <div key={c.label} className="flex items-center gap-3 rounded-xl border border-gray-200 bg-white px-4 py-3">
                <Icon className="w-4 h-4 text-brand-600 flex-shrink-0" />
                <span className="text-sm font-medium text-gray-700">{c.label}</span>
              </div>
            )
          })}
        </div>
      </section>

      {/* ── Who it's for ── */}
      <section className="bg-gray-50/70 border-y border-gray-100">
        <div className="max-w-6xl mx-auto px-5 py-14">
          <div className="max-w-3xl">
            <span className="eyebrow">Who it is for</span>
            <h2 className="text-2xl font-bold tracking-tight mt-1">Clarity without heavy enterprise tooling</h2>
            <p className="text-base text-gray-600 mt-3 leading-relaxed">
              Small and medium businesses, consultants, MSPs, and security teams that need a clearer view of their
              external exposure — without standing up complex enterprise platforms.
            </p>
          </div>
        </div>
      </section>

      {/* ── Founder note ── */}
      <section className="max-w-6xl mx-auto px-5 py-14">
        <div className="card p-6 flex items-start gap-4 max-w-3xl">
          <div className="w-10 h-10 rounded-xl bg-brand-50 flex items-center justify-center flex-shrink-0">
            <Users className="w-5 h-5 text-brand-600" />
          </div>
          <div>
            <p className="text-sm font-semibold text-gray-900">About CyberMeters</p>
            <p className="text-sm text-gray-600 mt-1 leading-relaxed">
              Designed and developed by Turhan Acar as a cloud-native cyber security SaaS project.
            </p>
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="bg-gray-900">
        <div className="max-w-6xl mx-auto px-5 py-14 text-center">
          <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Ready to explore CyberMeters?</h2>
          <p className="text-sm text-gray-300 mt-3">See your external exposure across email, brand, attack surface and certificates.</p>
          <div className="flex flex-wrap items-center justify-center gap-3 mt-7">
            <a href={APP_URL} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm transition-colors">
              Open Live App <ArrowRight className="w-4 h-4" />
            </a>
            <a href={CONTACT} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl border border-gray-600 text-gray-200 hover:bg-gray-800 font-semibold text-sm transition-colors">
              hello@cybermeters.com
            </a>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-100 bg-white">
        <div className="max-w-6xl mx-auto px-5 py-10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
          <div>
            <CyberMetersLogo className="h-6 mb-3" />
            <p className="text-sm text-gray-500">Monitor your external security posture from one cloud-native platform.</p>
            <p className="text-sm text-gray-500 mt-1">
              <a href={CONTACT} className="hover:text-gray-800">hello@cybermeters.com</a>
              {' · '}
              <a href={APP_URL} className="hover:text-gray-800">app.cybermeters.com</a>
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            <FooterLink to="/privacy">Privacy</FooterLink>
            <FooterLink to="/terms">Terms</FooterLink>
            <FooterLink to="/dpa">DPA</FooterLink>
            <FooterLink to="/support">Support</FooterLink>
          </div>
        </div>
        <div className="border-t border-gray-100">
          <div className="max-w-6xl mx-auto px-5 py-4 text-xs text-gray-400">© {year} CyberMeters. All rights reserved.</div>
        </div>
      </footer>
    </div>
  )
}
