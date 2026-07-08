import { Link } from 'react-router-dom'
import {
  Mail, Globe, Lock, ArrowRight, ShieldCheck, Check,
  Users, FileBarChart2, History, ClipboardList, Cloud, SearchCheck,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'

const APP_URL = 'https://app.cybermeters.com'
const CONTACT = 'mailto:hello@cybermeters.com'

const BENEFITS = [
  {
    icon: Globe,
    title: 'See your business from the outside',
    copy: 'Your website, email domain and public records say a lot about your cyber posture. CyberMeters checks the visible signals that criminals, customers and suppliers can already see — domain health, email protection, TLS, DNS, website trust signals and certificate issues, in plain English.',
    outcome: 'Understand your public cyber posture before someone else questions it.',
  },
  {
    icon: ClipboardList,
    title: 'Fix the basics before they become expensive',
    copy: 'Most small businesses do not need another complex dashboard. They need to know what matters, why it matters and what to do next. CyberMeters turns technical findings into prioritised actions: weak email protection, missing website safeguards, expired certificates, risky DNS gaps and Cyber Essentials readiness issues.',
    outcome: 'Spend less time guessing and more time improving.',
  },
  {
    icon: Users,
    title: 'Built for UK small businesses and MSPs',
    copy: 'Add a domain, get a report, track changes and show progress over time. For MSPs it is a simple way to start cyber conversations with clients without a heavy enterprise platform.',
    outcome: 'Deliver clear cyber posture reporting at a price SMBs can understand.',
  },
]

const CAPABILITIES = [
  { icon: SearchCheck,  label: '2-minute Cyber MOT report' },
  { icon: Globe,        label: 'Website security signals' },
  { icon: Mail,         label: 'Email protection checks' },
  { icon: ShieldCheck,  label: 'Cyber Essentials readiness gaps' },
  { icon: Lock,         label: 'TLS and certificate posture' },
  { icon: History,      label: 'Historical change tracking' },
  { icon: ClipboardList, label: 'Prioritised fix list' },
  { icon: FileBarChart2, label: 'Executive reporting' },
  { icon: Cloud,        label: 'Cloud-native SaaS' },
]

const HOW_IT_WORKS = [
  {
    title: 'Enter your domain',
    copy: 'Add your website domain, such as example.co.uk.',
  },
  {
    title: 'Get a 2-minute Cyber MOT report',
    copy: 'External email, website, TLS, DNS and certificate posture.',
  },
  {
    title: 'Follow the fix list',
    copy: 'What needs attention first, why it matters and which actions improve your score.',
  },
]

function TopBar() {
  return (
    <header className="border-b border-gray-100 bg-white/90 backdrop-blur sticky top-0 z-30">
      <div className="max-w-6xl mx-auto px-5 h-16 flex items-center justify-between">
        <CyberMetersLogo className="h-7" />
        <div className="flex items-center gap-3">
          <a href={CONTACT} className="hidden sm:inline text-sm font-medium text-gray-600 hover:text-gray-900">Contact</a>
          <Link to="/free-scan" className="btn-primary text-sm">Run your Cyber MOT <ArrowRight className="w-4 h-4" /></Link>
        </div>
      </div>
    </header>
  )
}

// A calm, generic product panel — no customer data, safe example domain only.
function ProductMock() {
  return (
    <div id="example-report" className="card p-5 shadow-card-md scroll-mt-24">
      <div className="flex items-center gap-2 mb-4">
        <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center"><SearchCheck className="w-4 h-4 text-brand-600" /></div>
        <div>
          <p className="text-[11px] font-bold text-brand-600 uppercase tracking-wide">Cyber MOT</p>
          <p className="text-sm font-semibold text-gray-900">example.com</p>
        </div>
        <span className="ml-auto inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-amber-50 text-amber-700 border-amber-200">
          Review needed
        </span>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-4">
        {[
          { l: 'Score', v: '78/100' },
          { l: 'Email', v: 'Review' },
          { l: 'Website', v: 'Good' },
        ].map(m => (
          <div key={m.l} className="rounded-lg border border-gray-200 px-3 py-2">
            <p className="text-xs font-semibold text-gray-700 leading-snug">{m.l}</p>
            <p className="text-[13px] font-bold text-gray-800 mt-1">{m.v}</p>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        {['DMARC policy needs attention', 'TLS certificate is healthy', 'Security header missing'].map((s, i) => (
          <div key={s} className="flex items-center gap-2 text-xs text-gray-600">
            <Check className={`w-3.5 h-3.5 ${i === 1 ? 'text-brand-500' : 'text-amber-500'}`} /> {s}
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
              <span className="w-1.5 h-1.5 rounded-full bg-brand-500" /> UK cyber posture check
            </span>
            <h1 className="text-[34px] sm:text-[44px] font-bold tracking-tight leading-[1.1]">
              Your UK Cyber MOT in 2 minutes
            </h1>
            <p className="text-base sm:text-lg text-gray-600 mt-5 leading-relaxed max-w-xl">
              CyberMeters checks your business domain for the cyber basics customers, insurers and suppliers increasingly expect:
              email protection, website security, TLS, DNS and Cyber Essentials readiness gaps. No jargon. No enterprise complexity.
              Just a clear report showing what is working, what is missing and what to fix first.
            </p>
            <div className="flex flex-wrap items-center gap-3 mt-7">
              <Link to="/free-scan" className="btn-primary">Run your Cyber MOT <ArrowRight className="w-4 h-4" /></Link>
              <a href="#example-report" className="btn-secondary">See example report</a>
            </div>
            <p className="text-xs text-gray-400 mt-5 max-w-md leading-relaxed">
              Built for UK small businesses, consultants and MSPs that need clear cyber posture reporting without heavy enterprise tooling.
            </p>
          </div>
          <div className="lg:pl-6"><ProductMock /></div>
        </div>
      </section>

      {/* ── Benefits ── */}
      <section className="bg-gray-50/70 border-y border-gray-100">
        <div className="max-w-6xl mx-auto px-5 py-14">
          <div className="max-w-2xl mb-8">
            <span className="eyebrow">Why it matters</span>
            <h2 className="text-2xl font-bold tracking-tight mt-1">Clear cyber posture reporting for the basics that matter</h2>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {BENEFITS.map(s => {
              const Icon = s.icon
              return (
                <div key={s.title} className="card p-6">
                  <div className="w-11 h-11 rounded-xl bg-brand-50 ring-1 ring-brand-100 flex items-center justify-center mb-4">
                    <Icon className="w-5 h-5 text-brand-600" />
                  </div>
                  <h3 className="text-lg font-bold text-gray-900">{s.title}</h3>
                  <p className="text-sm text-gray-500 mt-1.5 leading-relaxed">{s.copy}</p>
                  <p className="text-sm font-semibold text-gray-800 mt-4 leading-relaxed">Outcome: {s.outcome}</p>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section className="max-w-6xl mx-auto px-5 py-14">
        <div className="max-w-2xl mb-8">
          <span className="eyebrow">How it works</span>
          <h2 className="text-2xl font-bold tracking-tight mt-1">From domain to fix list in three steps</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {HOW_IT_WORKS.map((step, index) => (
            <div key={step.title} className="card p-6">
              <div className="w-9 h-9 rounded-xl bg-gray-900 text-white flex items-center justify-center text-sm font-bold mb-4">
                {index + 1}
              </div>
              <h3 className="text-lg font-bold text-gray-900">{step.title}</h3>
              <p className="text-sm text-gray-500 mt-1.5 leading-relaxed">{step.copy}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Platform capabilities ── */}
      <section className="bg-gray-50/70 border-y border-gray-100">
        <div className="max-w-6xl mx-auto px-5 py-14">
          <div className="max-w-2xl mb-8">
            <span className="eyebrow">What we check</span>
            <h2 className="text-2xl font-bold tracking-tight mt-1">The visible signals your stakeholders care about</h2>
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
        </div>
      </section>

      {/* ── Who it's for ── */}
      <section className="max-w-6xl mx-auto px-5 py-14">
        <div className="card p-6 max-w-4xl">
          <span className="eyebrow">Important note</span>
          <p className="text-sm text-gray-600 mt-2 leading-relaxed">
            CyberMeters provides cyber posture checks and Cyber Essentials readiness support. It does not provide Cyber Essentials certification. Certification is handled through IASME and approved Certification Bodies.
          </p>
        </div>
      </section>

      {/* ── Who it's for ── */}
      <section className="bg-gray-50/70 border-y border-gray-100">
        <div className="max-w-6xl mx-auto px-5 py-14">
          <div className="max-w-3xl">
            <span className="eyebrow">Who it is for</span>
            <h2 className="text-2xl font-bold tracking-tight mt-1">Built for UK small businesses and MSPs</h2>
            <p className="text-base text-gray-600 mt-3 leading-relaxed">
              Add a domain, get a report, track changes and show progress over time. For MSPs it is a simple way to start cyber conversations with clients without a heavy enterprise platform.
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
          <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Ready to see your cyber posture?</h2>
          <p className="text-sm text-gray-300 mt-3 max-w-2xl mx-auto">
            Run a Cyber MOT and get a clear, plain-English report for your business domain.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 mt-7">
            <Link to="/free-scan" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm transition-colors">
              Run your Cyber MOT <ArrowRight className="w-4 h-4" />
            </Link>
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
