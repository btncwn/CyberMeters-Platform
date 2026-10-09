import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, Globe, Lock, ArrowRight, ShieldCheck, Check,
  Users, FileBarChart2, History, ClipboardList, Cloud, SearchCheck, Search,
  MonitorCheck, KeyRound, Boxes,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { SERVICE_COLORS } from '../theme/serviceColors'

const APP_URL = 'https://app.cybermeters.com'
const CONTACT = 'mailto:hello@cybermeters.com'

// The eight canonical Cyber MOT domains, each led with the question a business
// owner actually asks. Each carries a cool "glacier" identity colour from the
// shared domain palette.
const SERVICES = [
  {
    icon: Mail, name: 'Email Protection',
    q: '“Can attackers send email as me?”',
    copy: 'Review SPF, DKIM and DMARC in plain English. Connect email reports to see sending sources and plan your next policy change.',
    tags: ['DMARC setup', 'Sender inventory', 'Email reports'],
    key: 'email',
  },
  {
    icon: ShieldCheck, name: 'Brand Protection',
    q: '“Is anyone impersonating my brand?”',
    copy: 'Review lookalike domain candidates and the evidence behind them. Decide which need attention and track the next action.',
    tags: ['Lookalike domains', 'Impersonation', 'Classification'],
    key: 'brand',
  },
  {
    icon: Search, name: 'Attack Surface',
    q: '“What of mine is exposed to the internet?”',
    copy: 'See discovered subdomains and exposed services. Review the evidence, track changes and recheck after a fix.',
    tags: ['Asset inventory', 'Subdomains', 'Takeover risk'],
    key: 'surface',
  },
  {
    icon: Lock, name: 'Certificates & Trust',
    q: '“Will my site quietly break trust?”',
    copy: 'Track certificate expiry and review live TLS evidence, including hostname matching and checks against the recorded trust store.',
    tags: ['Expiry alerts', 'TLS posture', 'HTTPS trust'],
    key: 'certs',
  },
  {
    icon: ClipboardList, name: 'Cyber Essentials Readiness',
    q: '“How ready are we for Cyber Essentials?”',
    copy: 'Evidence-led readiness support that combines externally observable signals with saved questionnaire answers.',
    tags: ['Readiness gaps', 'Evidence', 'Actions'],
    key: 'cyber_essentials',
  },
  {
    icon: MonitorCheck, name: 'Website Security',
    q: '“Is my website configured safely?”',
    copy: 'HTTPS, redirects, security headers, cookie flags and visible website configuration issues in one place.',
    tags: ['HTTPS', 'Headers', 'Cookies'],
    key: 'website',
  },
  {
    icon: KeyRound, name: 'Identity Exposure',
    q: '“What is visible about our business identities?”',
    copy: 'Review identity-provider relationships and identity-facing hostnames. Owners and admins can also check a known work email address against LeakCheck breach sources after verifying its domain and confirming permission. This is not domain-wide, password or dark-web monitoring. Endpoint reachability testing is on the roadmap and is not performed today.',
    tags: ['Provider relationships', 'Identity-facing hostnames', 'Reachability: roadmap'],
    key: 'identity',
  },
  {
    icon: Boxes, name: 'Shadow IT & Unmanaged Technology',
    q: '“Which outside tools are visible?”',
    copy: 'Externally observed SaaS, vendors, third-party scripts and unmanaged technology signals for review.',
    tags: ['SaaS signals', 'Vendors', 'Scripts'],
    key: 'shadow_it',
  },
]

const STEPS = [
  { n: 'STEP 01', title: 'Preview', copy: 'Enter a domain for a bounded, non-persistent snapshot across all eight Cyber MOT domains. Verify ownership before accessing deeper checks.' },
  { n: 'STEP 02', title: 'Understand', copy: 'See what was observed, what needs attention and what could not be assessed. Share the report with your team or IT provider.' },
  { n: 'STEP 03', title: 'Take action', copy: 'Use the recommended steps to prioritise work, assign an owner and record progress. Recheck supported fixes when the work is done.' },
  { n: 'STEP 04', title: 'Monitor', copy: 'Schedule rechecks and review alerts for recorded changes. Keep the evidence and follow-up work together in your workspace.' },
]

const CHECKS = [
  { icon: SearchCheck,  label: 'Bounded eight-domain public snapshot' },
  { icon: Globe,        label: 'Website security signals' },
  { icon: Mail,         label: 'Email protection checks' },
  { icon: ShieldCheck,  label: 'Cyber Essentials readiness gaps' },
  { icon: Lock,         label: 'TLS and certificate posture' },
  { icon: History,      label: 'Historical change tracking' },
  { icon: ClipboardList, label: 'Prioritised fix list' },
  { icon: FileBarChart2, label: 'Executive reporting' },
  { icon: Cloud,        label: 'Browser-based workspace' },
]

const CAPABILITIES = ['Clear next steps', 'Scheduled rechecks', 'Shared workspaces', 'Reports for your team']

// ── Reveal-on-scroll (respects reduced motion) ──
function useReveal() {
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      document.querySelectorAll('[data-reveal]').forEach(el => el.classList.add('is-in'))
      return
    }
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-in'); io.unobserve(e.target) } })
    }, { threshold: 0.16 })
    document.querySelectorAll('[data-reveal]').forEach(el => io.observe(el))
    return () => io.disconnect()
  }, [])
}

// ── Floating pill nav ──
function Nav() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])
  return (
    <header className="sticky top-4 z-50 mx-auto mt-4 px-4" style={{ maxWidth: 'calc(72rem + 2rem)' }}>
      <div
        className={`flex items-center justify-between h-[60px] pl-5 pr-3 rounded-full border backdrop-blur-md transition-shadow ${scrolled ? 'shadow-card-md border-gray-200' : 'shadow-card border-gray-100'}`}
        style={{ background: 'rgba(255,255,255,0.78)' }}
      >
        <CyberMetersLogo className="h-6" />
        <nav className="hidden md:flex items-center gap-7 text-sm text-gray-600">
          <a href="#services" className="hover:text-gray-900 transition-colors">Domains</a>
          <a href="#how" className="hover:text-gray-900 transition-colors">How it works</a>
          <a href="#example-report" className="hover:text-gray-900 transition-colors">The Cyber MOT</a>
          <a href={CONTACT} className="hover:text-gray-900 transition-colors">Contact</a>
        </nav>
        <div className="flex items-center gap-2">
          <a href={`${APP_URL}/login`} className="hidden sm:inline text-sm font-medium text-gray-600 hover:text-gray-900 px-2">Sign in</a>
          <Link to="/free-scan" className="btn-primary text-sm !rounded-full">Run free preview <ArrowRight className="w-4 h-4" /></Link>
        </div>
      </div>
    </header>
  )
}

// ── Illustrative result card — not a live measurement or customer data ──
function MotCard() {
  const ref = useRef(null)
  const [score, setScore] = useState(0)
  const C = 326.7
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (!e.isIntersecting) return
        io.disconnect()
        if (reduce) { setScore(78); return }
        const t0 = performance.now(), dur = 1400
        const tick = (ts) => {
          const p = Math.min((ts - t0) / dur, 1)
          const eased = 1 - Math.pow(1 - p, 3)
          setScore(Math.round(78 * eased))
          if (p < 1) requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
      })
    }, { threshold: 0.4 })
    io.observe(el)
    return () => io.disconnect()
  }, [])

  const rows = [
    { icon: Mail, name: 'Email Protection', val: 'SPF ✓ · DKIM ✗', tag: 'Advisory', tone: 'adv', chip: SERVICE_COLORS.email.chip, ic: SERVICE_COLORS.email.icon },
    { icon: ShieldCheck, name: 'Brand Protection', val: '0 lookalikes', tag: 'Clear', tone: 'pass', chip: SERVICE_COLORS.brand.chip, ic: SERVICE_COLORS.brand.icon },
    { icon: Search, name: 'Attack Surface', val: '3 assets · 0 risks', tag: 'Clear', tone: 'pass', chip: SERVICE_COLORS.surface.chip, ic: SERVICE_COLORS.surface.icon },
    { icon: Lock, name: 'Certificates & Trust', val: 'valid · 74 days', tag: 'Renew soon', tone: 'adv', chip: SERVICE_COLORS.certs.chip, ic: SERVICE_COLORS.certs.icon },
    { icon: ClipboardList, name: 'Cyber Essentials Readiness', val: 'evidence-led', tag: 'Review', tone: 'adv', chip: SERVICE_COLORS.cyber_essentials.chip, ic: SERVICE_COLORS.cyber_essentials.icon },
    { icon: MonitorCheck, name: 'Website Security', val: 'HTTPS · headers', tag: 'Advisory', tone: 'adv', chip: SERVICE_COLORS.website.chip, ic: SERVICE_COLORS.website.icon },
    { icon: KeyRound, name: 'Identity Exposure', val: '2 identity-facing hostnames', tag: 'Review', tone: 'adv', chip: SERVICE_COLORS.identity.chip, ic: SERVICE_COLORS.identity.icon },
    { icon: Boxes, name: 'Shadow IT & Unmanaged Technology', val: '5 SaaS signals', tag: 'Review', tone: 'adv', chip: SERVICE_COLORS.shadow_it.chip, ic: SERVICE_COLORS.shadow_it.icon },
  ]
  const toneCls = {
    pass: 'bg-emerald-50 text-emerald-700',
    adv: 'bg-amber-50 text-amber-700',
  }

  return (
    <div ref={ref} id="example-report" data-reveal className="reveal scroll-mt-28 rounded-[20px] bg-white border border-gray-100 shadow-card-lg overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-dashed border-gray-200"
        style={{ background: 'linear-gradient(180deg, #E7F2EE 0%, transparent 120%)' }}>
        <div>
          <p className="font-semibold text-[15px] text-gray-900 leading-tight">Cyber MOT · Result</p>
          <p className="mono text-[11px] text-gray-400 tracking-wide">example.com — illustrative sample</p>
        </div>
        <span className="text-[10px] font-bold uppercase tracking-[0.1em] text-emerald-700 border-[1.5px] border-emerald-600/70 rounded-md px-2.5 py-1.5 -rotate-3 opacity-90">
          Pass · Advisories
        </span>
      </div>
      <div className="p-5">
        <div className="flex items-center gap-5 mb-5">
          <div className="relative w-[124px] h-[124px] flex-shrink-0">
            <svg viewBox="0 0 120 120" className="w-full h-full">
              <circle cx="60" cy="60" r="52" fill="none" stroke="#E1E9E6" strokeWidth="11" />
              <circle cx="60" cy="60" r="52" fill="none" stroke="#00876A" strokeWidth="11" strokeLinecap="round"
                transform="rotate(-90 60 60)" strokeDasharray={C}
                strokeDashoffset={C - (C * score / 100)}
                style={{ transition: 'stroke-dashoffset .3s linear' }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <b className="text-[2rem] font-bold tracking-tight tabular-nums leading-none text-gray-900">{score}</b>
              <span className="text-[10px] uppercase tracking-[0.12em] text-gray-400 mt-1">Posture</span>
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-[0.12em] text-gray-400">Overall verdict</div>
            <div className="text-[1.25rem] font-semibold tracking-tight mt-1 text-gray-900"><b className="text-emerald-600 font-semibold">Good</b> — two things to fix</div>
            <p className="text-sm text-gray-500 mt-2 max-w-[26ch]">Example score and findings to show the report layout. Not a live assessment.</p>
          </div>
        </div>
        <div className="flex flex-col">
          {rows.map(r => {
            const Icon = r.icon
            return (
              <div key={r.name} className="flex items-center gap-3 py-3 border-t border-gray-100">
                <div className="w-[34px] h-[34px] rounded-[10px] grid place-items-center flex-shrink-0" style={{ background: r.chip, color: r.ic }}>
                  <Icon className="w-[18px] h-[18px]" />
                </div>
                <span className="font-medium text-[15px] text-gray-800 flex-1">{r.name}</span>
                <span className="mono text-[13px] text-gray-400 tabular-nums hidden sm:inline">{r.val}</span>
                <span className={`text-[11px] font-semibold uppercase tracking-wide px-2.5 py-1 rounded-full ${toneCls[r.tone]}`}>{r.tag}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function FooterLink({ to, children }) {
  return <Link to={to} className="text-sm text-gray-500 hover:text-gray-800">{children}</Link>
}

export default function PublicLandingPage() {
  useReveal()
  const year = new Date().getFullYear()
  return (
    <div className="min-h-screen text-gray-900" style={{ background: '#F6F8F7' }}>
      {/* scoped styles for reveal + atmosphere */}
      <style>{`
        .reveal{opacity:0;transform:translateY(18px);transition:opacity .7s cubic-bezier(.2,.7,.2,1),transform .7s cubic-bezier(.2,.7,.2,1)}
        .reveal.is-in{opacity:1;transform:none}
        @media (prefers-reduced-motion: reduce){.reveal{opacity:1;transform:none;transition:none}}
        .cm-atmos{position:absolute;inset:0 0 auto 0;height:820px;z-index:0;pointer-events:none;overflow:hidden}
        .cm-atmos::before{content:"";position:absolute;inset:0;
          background:
            radial-gradient(900px 460px at 82% -6%, #D6EAE2 0%, transparent 62%),
            radial-gradient(680px 420px at 12% 4%, #E7F2EE 0%, transparent 58%),
            linear-gradient(180deg, #EDF2F0 0%, #F6F8F7 78%);}
        .cm-atmos::after{content:"";position:absolute;inset:0;opacity:.5;mix-blend-mode:multiply;
          background:repeating-linear-gradient(58deg, transparent 0 22px, rgba(0,135,106,.055) 22px 23px);
          -webkit-mask-image:radial-gradient(700px 500px at 78% 8%, #000 0%, transparent 70%);
          mask-image:radial-gradient(700px 500px at 78% 8%, #000 0%, transparent 70%);}
        .cm-pulse{animation:cmPulse 2.4s ease-in-out infinite}
        @keyframes cmPulse{0%,100%{box-shadow:0 0 0 3px rgba(0,135,106,.24)}50%{box-shadow:0 0 0 6px rgba(0,135,106,.04)}}
        @media (prefers-reduced-motion: reduce){.cm-pulse{animation:none}}
      `}</style>

      <div className="cm-atmos" aria-hidden="true" />

      <div className="relative z-10">
        <Nav />

        {/* ── Hero ── */}
        <section className="max-w-6xl mx-auto px-6 pt-16 pb-10">
          <div className="grid grid-cols-1 lg:grid-cols-[1.06fr_0.94fr] gap-14 items-center">
            <div>
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-brand-100 mono text-[11px] font-semibold uppercase tracking-[0.13em] text-brand-800"
                style={{ background: 'rgba(231,242,238,0.7)' }}>
                <span className="w-[7px] h-[7px] rounded-full bg-brand-600 cm-pulse" /> Cyber MOT · Security for small teams
              </span>
              <h1 className="text-[clamp(2.4rem,5.6vw,4.2rem)] font-bold tracking-[-0.028em] leading-[1.06] mt-5" style={{ textWrap: 'balance' }}>
                Know where your business is <span className="relative text-brand-800">exposed<span className="absolute left-0 right-0 -z-10 rounded-sm" style={{ bottom: '0.07em', height: '0.16em', background: '#D6EAE2' }} /></span> and what to do next.
              </h1>
              <p className="text-[1.18rem] text-gray-600 mt-5 leading-relaxed max-w-[34ch]">
                External security checks for small businesses, startups and digital agencies. Get a clear view across eight areas, prioritise fixes and share useful reports — from your browser.
              </p>
              <div className="flex flex-wrap items-center gap-3.5 mt-8">
                <Link to="/free-scan" className="btn-primary !rounded-full">Run free preview <ArrowRight className="w-4 h-4" /></Link>
                <a href="#how" className="btn-secondary !rounded-full">See how it works →</a>
              </div>
              <p className="text-sm text-gray-400 mt-4 flex items-center gap-2">
                <span className="w-[7px] h-[7px] rounded-full bg-emerald-500" style={{ boxShadow: '0 0 0 3px #E4F3EB' }} />
                No agent to install · free public preview · verify your domain for deeper checks
              </p>
            </div>
            <div className="lg:pl-2"><MotCard /></div>
          </div>

          {/* capability strip */}
          <div className="mt-10 pt-8 border-t border-gray-200/70">
            <p className="text-center text-[12px] uppercase tracking-[0.1em] text-gray-400">Practical security checks for your business and the clients you support</p>
            <div className="flex flex-wrap gap-x-10 gap-y-3 justify-center mt-4 opacity-70">
              {CAPABILITIES.map(c => <span key={c} className="font-semibold text-gray-600 tracking-tight">{c}</span>)}
            </div>
          </div>
        </section>

        {/* ── Eight domains ── */}
        <section id="services" className="max-w-6xl mx-auto px-6 py-20">
          <div className="max-w-[60ch]">
            <span className="eyebrow">Eight areas in one workspace</span>
            <h2 className="text-[clamp(1.8rem,3.3vw,2.6rem)] font-bold tracking-tight mt-3" style={{ textWrap: 'balance' }}>
              Understand the security signals visible outside your business.
            </h2>
            <p className="text-lg text-gray-600 mt-4">Start with a bounded, honest snapshot of all eight Cyber MOT domains. The report separates observed issues from missing evidence, so you can decide what needs attention.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-[18px] mt-11">
            {SERVICES.map(s => {
              const Icon = s.icon
              const c = SERVICE_COLORS[s.key]
              const th = { bg: c.card, ring: c.ring, chip: c.chip, icon: c.icon, q: c.text }
              return (
                <div key={s.name} data-reveal className="reveal rounded-[14px] p-7 border shadow-card hover:-translate-y-1 hover:shadow-card-md transition-all duration-200"
                  style={{ background: th.bg, borderColor: th.ring }}>
                  <div className="flex items-center gap-3.5 mb-4">
                    <div className="w-11 h-11 rounded-[10px] grid place-items-center flex-shrink-0" style={{ background: th.chip, color: th.icon }}>
                      <Icon className="w-[22px] h-[22px]" />
                    </div>
                    <h3 className="text-[1.24rem] font-semibold text-gray-900">{s.name}</h3>
                  </div>
                  <p className="mono text-[13px] font-medium mb-2.5" style={{ color: th.q }}>{s.q}</p>
                  <p className="text-gray-600">{s.copy}</p>
                  <div className="flex flex-wrap gap-2 mt-4">
                    {s.tags.map(t => (
                      <span key={t} className="text-[13px] text-gray-600 px-3 py-1 rounded-full border"
                        style={{ background: 'rgba(255,255,255,0.72)', borderColor: th.ring }}>{t}</span>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* ── How it works ── */}
        <section id="how" className="max-w-6xl mx-auto px-6 pb-20">
          <div className="max-w-[60ch]">
            <span className="eyebrow">How it works</span>
            <h2 className="text-[clamp(1.8rem,3.3vw,2.6rem)] font-bold tracking-tight mt-3">Check, understand, take action and recheck.</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 mt-11 rounded-[14px] border border-gray-100 bg-white overflow-hidden shadow-card">
            {STEPS.map((s, i) => (
              <div key={s.title} className={`relative p-7 ${i < STEPS.length - 1 ? 'lg:border-r' : ''} border-gray-100 ${i < 2 ? 'sm:border-b lg:border-b-0' : ''} ${i % 2 === 0 ? 'sm:border-r lg:border-r' : ''}`}>
                {i === 0 && <span className="absolute top-0 left-0 h-[3px] w-1/4 bg-brand-600/90" />}
                <div className="mono text-[13px] text-brand-600 font-semibold tracking-wide">{s.n}</div>
                <h3 className="text-[1.12rem] font-semibold mt-3">{s.title}</h3>
                <p className="text-sm text-gray-600 mt-2">{s.copy}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── What we check ── */}
        <section className="max-w-6xl mx-auto px-6 pb-20">
          <div className="max-w-[60ch] mb-9">
            <span className="eyebrow">What we check</span>
            <h2 className="text-[clamp(1.8rem,3.3vw,2.6rem)] font-bold tracking-tight mt-3">Useful checks for your website, email and public services.</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {CHECKS.map(c => {
              const Icon = c.icon
              return (
                <div key={c.label} data-reveal className="reveal flex items-center gap-3 rounded-[12px] border border-gray-100 bg-white px-4 py-3.5 shadow-card">
                  <Icon className="w-[18px] h-[18px] text-brand-600 flex-shrink-0" />
                  <span className="text-[15px] font-medium text-gray-700">{c.label}</span>
                </div>
              )
            })}
          </div>
        </section>

        {/* ── Legal note (Cyber Essentials) ── */}
        <section className="max-w-6xl mx-auto px-6 pb-20">
          <div className="card p-6 max-w-4xl">
            <span className="eyebrow">Important note</span>
            <p className="text-sm text-gray-600 mt-2 leading-relaxed">
              CyberMeters provides cyber posture checks and Cyber Essentials readiness support. It does not provide Cyber Essentials certification. Certification is handled through IASME and approved Certification Bodies.
            </p>
          </div>
        </section>

        <section className="max-w-6xl mx-auto px-6 pb-16">
          <div className="rounded-xl border border-brand-100 bg-brand-50 p-6 sm:p-8">
            <h2 className="text-xl font-bold text-gray-900">We use CyberMeters on our own domain.</h2>
            <p className="mt-2 text-sm text-gray-600 max-w-2xl">See our dated cybermeters.com self-check, the evidence behind it and the checks that remain incomplete.</p>
            <Link to="/trust" className="mt-4 inline-flex items-center gap-2 font-semibold text-brand-700">View our own-domain check <ArrowRight className="w-4 h-4" /></Link>
          </div>
        </section>

        {/* ── Final CTA ── */}
        <div className="max-w-6xl mx-auto px-6 pb-24">
          <div data-reveal className="reveal relative overflow-hidden rounded-[20px] px-10 sm:px-14 py-16 shadow-card-lg text-center sm:text-left"
            style={{ background: 'linear-gradient(150deg,#00352A,#00543F)' }}>
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(600px 300px at 88% 10%, rgba(140,230,205,.20), transparent 60%)' }} />
            <div className="relative">
              <h2 className="text-[clamp(1.9rem,4vw,3rem)] font-bold text-white tracking-tight max-w-[20ch] mx-auto sm:mx-0">Try the free security preview.</h2>
              <p className="text-[1.12rem] mt-4 max-w-[44ch] mx-auto sm:mx-0" style={{ color: '#bfe6d8' }}>
                See one bounded snapshot of public evidence across all eight Cyber MOT domains. Deep findings, remediation, PDF and monitoring unlock only after account and domain verification.
              </p>
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-3.5 mt-8">
                <Link to="/free-scan" className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-white text-brand-800 font-semibold hover:bg-emerald-50 transition-colors">
                  Run free preview <ArrowRight className="w-4 h-4" />
                </Link>
                <a href={CONTACT} className="inline-flex items-center gap-2 px-6 py-3 rounded-full border font-semibold transition-colors"
                  style={{ borderColor: 'rgba(234,250,244,.35)', color: '#eafaf4' }}>
                  Ask a question
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* ── Footer ── */}
        <footer className="border-t border-gray-100 bg-white">
          <div className="max-w-6xl mx-auto px-6 py-10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6">
            <div>
              <CyberMetersLogo className="h-6 mb-3" />
              <p className="text-sm text-gray-500">Practical external security for small teams.</p>
              <p className="text-sm text-gray-500 mt-1">
                <a href={CONTACT} className="hover:text-gray-800">hello@cybermeters.com</a>
                {' · '}
                <a href={APP_URL} className="hover:text-gray-800">app.cybermeters.com</a>
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
              <FooterLink to="/about">About</FooterLink>
              <FooterLink to="/trust">Trust &amp; Security</FooterLink>
              <FooterLink to="/status">Status</FooterLink>
              <FooterLink to="/privacy">Privacy</FooterLink>
              <FooterLink to="/terms">Terms</FooterLink>
              <FooterLink to="/dpa">DPA</FooterLink>
              <FooterLink to="/support">Support</FooterLink>
            </div>
          </div>
          <div className="border-t border-gray-100">
            <div className="max-w-6xl mx-auto px-6 py-4 text-xs text-gray-400">© {year} CyberMeters. All rights reserved.</div>
          </div>
        </footer>
      </div>
    </div>
  )
}
