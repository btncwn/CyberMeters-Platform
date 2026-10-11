import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, Globe, Lock, ArrowRight, ShieldCheck, Check, Search,
  MonitorCheck, KeyRound, Boxes, ClipboardList, Layers, PackageX, FileKey2, EyeOff,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import IrisGlobe from '../components/landing/IrisGlobe'
import { SERVICE_COLORS } from '../theme/serviceColors'

const APP_URL = 'https://app.cybermeters.com'
const CONTACT = 'mailto:hello@cybermeters.com'

// The eight canonical domains, each led with the question a business owner
// actually asks. Identity colours come from the shared domain palette.
const SERVICES = [
  {
    icon: KeyRound, name: 'Identity Exposure',
    q: 'What is visible about our business identities?',
    copy: 'Review identity-provider relationships, identity-facing hostnames and measured endpoints. HTTP evidence is shown where collected. This is not employee breach or dark-web monitoring.',
    tags: ['Provider relationships', 'Identity-facing hostnames', 'Measured endpoints'],
    key: 'identity',
  },
  {
    icon: Search, name: 'Attack Surface',
    q: 'What of mine is exposed to the internet?',
    copy: 'See discovered subdomains and exposed services. Review the evidence, track changes and recheck after a fix.',
    tags: ['Asset inventory', 'Subdomains', 'Takeover risk'],
    key: 'surface',
  },
  {
    icon: Mail, name: 'Email Protection',
    q: 'Can attackers send email as me?',
    copy: 'Review SPF, DKIM and DMARC in plain English. Connect email reports to see sending sources and plan your next policy change.',
    tags: ['DMARC setup', 'Sender inventory', 'Email reports'],
    key: 'email',
  },
  {
    icon: MonitorCheck, name: 'Website Security',
    q: 'Is my website configured safely?',
    copy: 'HTTPS, redirects, security headers, cookie flags and visible website configuration issues in one place.',
    tags: ['HTTPS', 'Headers', 'Cookies'],
    key: 'website',
  },
  {
    icon: Boxes, name: 'Shadow IT & Unmanaged Technology',
    q: 'Which outside tools are visible?',
    copy: 'Externally observed SaaS, vendors, third-party scripts and unmanaged technology signals for review.',
    tags: ['SaaS signals', 'Vendors', 'Scripts'],
    key: 'shadow_it',
  },
  {
    icon: Lock, name: 'Certificates & Trust',
    q: 'Will my site quietly break trust?',
    copy: 'Track certificate expiry and review live TLS evidence, including hostname matching and checks against the recorded trust store.',
    tags: ['Expiry alerts', 'TLS posture', 'HTTPS trust'],
    key: 'certs',
  },
  {
    icon: ShieldCheck, name: 'Brand Protection',
    q: 'Is anyone impersonating my brand?',
    copy: 'Review lookalike domain candidates and the evidence behind them. Decide which need attention and track the next action.',
    tags: ['Lookalike domains', 'Impersonation', 'Classification'],
    key: 'brand',
  },
  {
    icon: ClipboardList, name: 'Cyber Essentials Readiness',
    q: 'How ready are we for Cyber Essentials?',
    copy: 'Evidence-led readiness support that combines externally observable signals with saved questionnaire answers.',
    tags: ['Readiness gaps', 'Evidence', 'Actions'],
    key: 'cyber_essentials',
  },
]

const FACTS = [
  { icon: Layers, big: '8 areas', small: 'checked from the outside, in one report' },
  { icon: PackageX, big: 'No agent', small: 'nothing is installed on your systems' },
  { icon: FileKey2, big: '1 DNS record', small: 'proves that you own the domain' },
  { icon: EyeOff, big: 'Gaps named', small: 'every result says what could not be checked' },
]

const PRINCIPLES = [
  { title: 'Missing evidence is never a pass.', copy: 'If a check could not run or could not see enough, the result says so. Nothing is marked as passed on silence.' },
  { title: 'Observed and recorded stay apart.', copy: 'What CyberMeters saw from the outside and what your team recorded are shown as different things, each with a date.' },
  { title: 'Fixes are checked again.', copy: 'Where a fix can be seen from the outside, CyberMeters checks again and records what it found.' },
]

const STEPS = [
  { title: 'Check', copy: 'Enter a domain for a bounded, non-persistent snapshot across all eight areas. Verify ownership before accessing deeper checks.' },
  { title: 'Understand', copy: 'See what was observed, what needs attention and what could not be assessed. Share the report with your team or IT provider.' },
  { title: 'Act', copy: 'Use the recommended steps to prioritise work, assign an owner and record progress.' },
  { title: 'Check again', copy: 'Recheck supported fixes when the work is done, schedule rechecks and review alerts for recorded changes.' },
]

// Sample layout for the "how it reads" panel. States use the product's own
// coverage vocabulary; no scores, no live data.
const SAMPLE_ROWS = [
  { name: 'Email Protection', key: 'email', state: 'Issue detected', note: 'DMARC set to monitor only', tone: 'issue' },
  { name: 'Website Security', key: 'website', state: 'Assessed healthy', note: 'HTTPS and headers in place', tone: 'ok' },
  { name: 'Certificates & Trust', key: 'certs', state: 'Issue detected', note: 'Renews in 9 days', tone: 'issue' },
  { name: 'Identity Exposure', key: 'identity', state: 'Evidence insufficient', note: '2 identity-facing hostnames, endpoints not measured', tone: 'gap' },
  { name: 'Attack Surface', key: 'surface', state: 'Assessed healthy', note: '3 subdomains reviewed', tone: 'ok' },
  { name: 'Brand Protection', key: 'brand', state: 'Issue detected', note: '1 lookalike candidate', tone: 'issue' },
  { name: 'Shadow IT & Unmanaged Technology', key: 'shadow_it', state: 'Customer input required', note: 'Classify 4 tools', tone: 'input' },
  { name: 'Cyber Essentials Readiness', key: 'cyber_essentials', state: 'Customer input required', note: 'Questionnaire not started', tone: 'input' },
]
const TONE = {
  issue: 'bg-[#FFF1D6] text-[#8A5300]',
  ok: 'bg-[#DDF3E7] text-[#11643D]',
  gap: 'bg-[#E9ECF2] text-[#465066]',
  input: 'bg-[#E6E8FD] text-[#3D45A8]',
}

const CONTAINER = 'mx-auto w-full max-w-[1280px] px-6 sm:px-10 lg:px-16'

function useMediaQuery(query) {
  const get = () => Boolean(typeof window !== 'undefined' && window.matchMedia?.(query).matches)
  const [matches, setMatches] = useState(get)
  useEffect(() => {
    const mq = window.matchMedia?.(query)
    if (!mq) return undefined
    const on = () => setMatches(mq.matches)
    on()
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [query])
  return matches
}

function DomainForm({ id, tone = 'dark' }) {
  return (
    <form action="/free-scan" method="get" className="w-full max-w-[600px]">
      <label htmlFor={id} className="sr-only">Your domain</label>
      <div className={`flex flex-col sm:flex-row gap-2 sm:gap-0 sm:items-stretch rounded-[12px] bg-white p-1.5 ${tone === 'dark' ? 'shadow-[0_18px_50px_-20px_rgba(6,16,48,.65)]' : 'border border-[#D5DBEA] shadow-sm'}`}>
        <div className="flex items-center gap-3 flex-1 min-w-0 pl-4 h-[52px]">
          <Globe className="w-5 h-5 text-[#7A8399] flex-shrink-0" aria-hidden="true" />
          <input
            id={id}
            name="domain"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            spellCheck="false"
            placeholder="yourcompany.co.uk"
            className="w-full min-w-0 bg-transparent text-[17px] text-[#121A2E] placeholder:text-[#8A93A8] outline-none"
          />
        </div>
        <button type="submit" className="h-[52px] px-6 rounded-[8px] bg-[#FFB81C] hover:bg-[#FFC640] text-[#1B2333] text-[16px] font-semibold inline-flex items-center justify-center gap-2 transition-colors">
          Run a free check <ArrowRight className="w-4 h-4" aria-hidden="true" />
        </button>
      </div>
    </form>
  )
}

function Header() {
  const [solid, setSolid] = useState(false)
  useEffect(() => {
    const on = () => setSolid(window.scrollY > 24)
    on()
    window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [])
  return (
    <header className={`fixed inset-x-0 top-0 z-50 transition-[background-color,box-shadow] duration-300 ${solid ? 'bg-[#183A86]/95 shadow-[0_8px_30px_-12px_rgba(6,16,48,.6)] backdrop-blur' : 'bg-transparent'}`}>
      <div className={`${CONTAINER} hidden lg:flex justify-end gap-7 pt-3 text-[14px] text-white/80`}>
        <Link to="/pricing" className="hover:text-white">Pricing</Link>
        <a href={CONTACT} className="hover:text-white">Contact</a>
        <a href={`${APP_URL}/login`} className="hover:text-white">Sign in</a>
      </div>
      <div className={`${CONTAINER} flex items-center justify-between h-[68px]`}>
        <Link to="/" aria-label="CyberMeters home"><CyberMetersLogo size={30} showWordmark darkMode /></Link>
        <nav aria-label="Main" className="hidden lg:flex items-center gap-9 text-[16px] font-semibold text-white">
          <a href="#areas" className="hover:text-[#BFE6FF]">Areas</a>
          <a href="#how" className="hover:text-[#BFE6FF]">How it works</a>
          <Link to="/trust" className="hover:text-[#BFE6FF]">Trust &amp; Security</Link>
          <Link to="/about" className="hover:text-[#BFE6FF]">About</Link>
        </nav>
        <Link to="/free-scan" className="h-11 px-5 rounded-[8px] bg-white text-[#183A86] text-[15px] font-semibold inline-flex items-center hover:bg-[#EEF3FF] transition-colors">
          Run a free check
        </Link>
      </div>
    </header>
  )
}

// Desktop: the eye starts on the right of the hero and drifts to the centre as
// the page scrolls, settling above the facts band. Phones get a static layout.
function HeroStage() {
  const wide = useMediaQuery('(min-width: 1024px)')
  const still = useMediaQuery('(prefers-reduced-motion: reduce)')
  const stageRef = useRef(null)
  const eyeRef = useRef(null)
  const SIZE = 1000

  useEffect(() => {
    if (!wide) return undefined
    let raf = 0
    const apply = () => {
      raf = 0
      const stage = stageRef.current
      const eye = eyeRef.current
      if (!stage || !eye) return
      const w = stage.clientWidth
      const p = still ? 0 : Math.min(1, Math.max(0, window.scrollY / 720))
      const e = p * p * (3 - 2 * p)
      const x = w * 0.74 + (w * 0.5 - w * 0.74) * e
      const y = 470 + (1000 - 470) * e
      const s = 1 - 0.26 * e
      eye.style.transform = `translate3d(${(x - SIZE / 2).toFixed(1)}px, ${(y - SIZE / 2).toFixed(1)}px, 0) scale(${s.toFixed(3)})`
    }
    const on = () => { if (!raf) raf = requestAnimationFrame(apply) }
    apply()
    window.addEventListener('scroll', on, { passive: true })
    window.addEventListener('resize', on)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('scroll', on)
      window.removeEventListener('resize', on)
    }
  }, [wide, still])

  return (
    <div ref={stageRef} className="cm-stage relative overflow-hidden text-white">
      {wide && (
        <div ref={eyeRef} className="absolute left-0 top-0 z-0 will-change-transform" style={{ width: SIZE, height: SIZE, transformOrigin: '50% 50%' }}>
          <IrisGlobe size={SIZE} />
        </div>
      )}
      <div className="cm-legibility absolute inset-0 z-0 pointer-events-none" aria-hidden="true" />

      {/* Hero */}
      <section className={`${CONTAINER} relative z-10 pt-[148px] lg:pt-[190px] lg:min-h-[800px]`}>
        <div className="max-w-[640px]">
          <h1 className="font-cm font-normal text-[46px] sm:text-[60px] lg:text-[72px] leading-[1.04] tracking-[-0.01em] text-balance">
            Know what your business exposes to the internet.
          </h1>
          <p className="font-cm mt-7 text-[21px] lg:text-[24px] leading-[1.5] text-white/85 max-w-[34ch] text-pretty">
            CyberMeters checks your domain from the outside across eight areas, from email and website to certificates and lookalike domains, and says plainly what it could not check.
          </p>
          <div className="mt-10"><DomainForm id="hero-domain" /></div>
          <ul className="mt-6 flex flex-wrap gap-x-7 gap-y-2 text-[15px] text-white/85">
            {['Nothing to install', 'Free one-off check', 'Full results after you verify your domain'].map(t => (
              <li key={t} className="inline-flex items-center gap-2"><Check className="w-4 h-4 text-[#7FD8FF]" aria-hidden="true" />{t}</li>
            ))}
          </ul>
          <p className="mt-8 text-[13px] text-white/60">The eye and its findings are an illustration with example findings, not a live result.</p>
        </div>
        {!wide && (
          <div className="relative mx-auto mt-14 -mb-6 flex justify-center">
            <IrisGlobe size={Math.min(560, typeof window === 'undefined' ? 560 : Math.round(window.innerWidth * 1.15))} />
          </div>
        )}
      </section>

      {/* Facts band: the eye settles above it while scrolling */}
      <section aria-labelledby="facts-title" className={`${CONTAINER} relative z-10 pt-16 lg:pt-[360px] pb-20`}>
        <h2 id="facts-title" className="font-cm font-normal text-center text-[30px] lg:text-[36px] leading-[1.15]">
          What every CyberMeters check gives you
        </h2>
        <ul className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
          {FACTS.map((f, i) => {
            const Icon = f.icon
            return (
              <li key={f.big} className={`flex items-start gap-4 px-2 lg:px-6 py-5 lg:py-0 ${i > 0 ? 'lg:border-l border-white/25' : ''}`}>
                <Icon className="w-9 h-9 text-[#7FD8FF] flex-shrink-0 mt-1" strokeWidth={1.5} aria-hidden="true" />
                <div>
                  <p className="font-cm text-[30px] leading-[1.1] whitespace-nowrap">{f.big}</p>
                  <p className="mt-1.5 text-[16px] leading-[1.45] text-white/80">{f.small}</p>
                </div>
              </li>
            )
          })}
        </ul>
      </section>
    </div>
  )
}

// A smaller eye closes the page on wide screens; the globe turns without labels.
function ClosingEye() {
  const wide = useMediaQuery('(min-width: 1024px)')
  if (!wide) return null
  return (
    <div className="absolute right-[-140px] top-1/2 -translate-y-1/2 z-0">
      <IrisGlobe size={620} labels={false} />
    </div>
  )
}

function SectionHeading({ id, title, lead, center = false }) {
  return (
    <div className={center ? 'text-center mx-auto max-w-[860px]' : 'max-w-[760px]'}>
      <h2 id={id} className="font-cm font-normal text-[38px] sm:text-[46px] lg:text-[56px] leading-[1.06] tracking-[-0.005em] text-[#121A2E] text-balance">{title}</h2>
      {lead && <p className={`font-cm mt-5 text-[20px] lg:text-[22px] leading-[1.5] text-[#46506A] ${center ? 'text-balance' : 'text-pretty'}`}>{lead}</p>}
    </div>
  )
}

export default function PublicLandingPage() {
  const year = new Date().getFullYear()
  return (
    <div className="min-h-screen bg-white text-[#121A2E]">
      <style>{`
        .cm-stage{background:
          radial-gradient(900px 700px at 74% 34%, rgba(120,190,255,.30), transparent 70%),
          linear-gradient(140deg,#1B3C8C 0%,#2550B6 50%,#4B50CF 100%)}
        .cm-legibility{background:linear-gradient(90deg,rgba(20,44,108,.70) 0%,rgba(20,44,108,.35) 34%,rgba(20,44,108,0) 58%),
          linear-gradient(180deg,rgba(20,44,108,0) 70%,rgba(27,58,138,.55) 100%)}
        .cm-iris{opacity:0;transition:opacity 1.6s ease}
        .cm-iris[data-ready]{opacity:1;animation:cm-iris-spin 150s linear infinite}
        @keyframes cm-iris-spin{to{transform:rotate(360deg)}}
        .cm-finding{background:rgba(9,22,64,.78);border:1px solid rgba(150,215,255,.45);box-shadow:0 10px 30px -12px rgba(0,0,0,.6);transition:opacity .6s ease;backdrop-filter:blur(4px)}
        @media (prefers-reduced-motion: reduce){.cm-iris[data-ready]{animation:none}.cm-iris{transition:none}}
      `}</style>

      <Header />
      <HeroStage />

      {/* Principles */}
      <section aria-labelledby="principles-title" className="bg-[#F3F5FB] py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="principles-title" center title="Honest about what it can see." lead="A security check is only useful if you can trust what it did not find. These rules hold for every result." />
          <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-10 lg:gap-14">
            {PRINCIPLES.map(p => (
              <div key={p.title} className="border-t-2 border-[#2550B6] pt-7">
                <h3 className="font-cm font-normal text-[28px] lg:text-[30px] leading-[1.15] text-[#121A2E]">{p.title}</h3>
                <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">{p.copy}</p>
              </div>
            ))}
          </div>
          <div className="mt-16 flex flex-col sm:flex-row items-center justify-center gap-4 text-center">
            <p className="font-cm text-[22px] text-[#121A2E]">We use CyberMeters on our own domain.</p>
            <Link to="/trust" className="h-[50px] px-6 rounded-[8px] border-2 border-[#2550B6] text-[#1D46A8] text-[16px] font-semibold inline-flex items-center gap-2 hover:bg-[#2550B6] hover:text-white transition-colors">
              View our own-domain check <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </Link>
          </div>
        </div>
      </section>

      {/* Eight areas */}
      <section id="areas" aria-labelledby="areas-title" className="scroll-mt-24 py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="areas-title" center title="Eight areas in one workspace" lead="Start with a bounded, honest snapshot of all eight areas. The report separates observed issues from missing evidence, so you can decide what needs attention." />
          <div className="mt-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {SERVICES.map(s => {
              const Icon = s.icon
              const c = SERVICE_COLORS[s.key]
              return (
                <article key={s.name} className="flex flex-col rounded-[12px] border bg-white p-6 transition-shadow hover:shadow-[0_18px_40px_-24px_rgba(18,26,46,.45)]" style={{ borderColor: c.ring }}>
                  <div className="w-12 h-12 rounded-[10px] grid place-items-center" style={{ background: c.chip, color: c.icon }}>
                    <Icon className="w-6 h-6" aria-hidden="true" />
                  </div>
                  <h3 className="font-cm font-normal mt-5 text-[24px] leading-[1.15] text-[#121A2E]">{s.name}</h3>
                  <p className="mt-3 text-[15px] font-semibold leading-snug" style={{ color: c.text }}>{s.q}</p>
                  <p className="mt-3 text-[16px] leading-[1.55] text-[#46506A]">{s.copy}</p>
                  <ul className="mt-auto pt-5 flex flex-wrap gap-2">
                    {s.tags.map(t => (
                      <li key={t} className="text-[13px] text-[#46506A] px-2.5 py-1 rounded-full border" style={{ borderColor: c.ring, background: c.surface }}>{t}</li>
                    ))}
                  </ul>
                </article>
              )
            })}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" aria-labelledby="how-title" className="scroll-mt-24 bg-[#F3F5FB] py-24 lg:py-[120px]">
        <div className={`${CONTAINER} grid grid-cols-1 lg:grid-cols-[1fr_1.05fr] gap-14 lg:gap-20 items-start`}>
          <div>
            <SectionHeading id="how-title" title="Check, understand, act, check again." />
            <ol className="mt-12 space-y-9">
              {STEPS.map((s, i) => (
                <li key={s.title} className="flex gap-5">
                  <span className="font-cm w-11 h-11 flex-shrink-0 rounded-full bg-[#2550B6] text-white grid place-items-center text-[20px]">{i + 1}</span>
                  <div>
                    <h3 className="font-cm font-normal text-[26px] leading-[1.15]">{s.title}</h3>
                    <p className="mt-2 text-[17px] leading-[1.6] text-[#46506A]">{s.copy}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
          <figure aria-label="Sample report layout" className="rounded-[16px] bg-white border border-[#DDE2EE] shadow-[0_30px_60px_-40px_rgba(18,26,46,.5)] overflow-hidden">
            <div className="flex items-center justify-between gap-4 px-6 py-5 border-b border-[#E6EAF3]">
              <div>
                <p className="font-cm text-[22px] leading-tight">Sample report</p>
                <p className="text-[14px] text-[#6A7389] mt-1">example.co.uk</p>
              </div>
              <span className="text-[13px] font-semibold text-[#3D45A8] bg-[#E6E8FD] rounded-full px-3 py-1">Sample</span>
            </div>
            <ul>
              {SAMPLE_ROWS.map(r => {
                const c = SERVICE_COLORS[r.key]
                return (
                  <li key={r.name} className="flex items-center gap-4 px-6 py-3.5 border-b border-[#EEF1F7] last:border-b-0">
                    <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: c.icon }} aria-hidden="true" />
                    <div className="flex-1 min-w-0">
                      <p className="text-[15px] font-semibold text-[#121A2E] truncate">{r.name}</p>
                      <p className="text-[14px] text-[#6A7389] truncate">{r.note}</p>
                    </div>
                    <span className={`text-[13px] font-semibold rounded-full px-3 py-1 whitespace-nowrap ${TONE[r.tone]}`}>{r.state}</span>
                  </li>
                )
              })}
            </ul>
            <figcaption className="px-6 py-4 bg-[#F7F8FC] text-[14px] text-[#5A6378]">
              Sample layout to show how results read, not a live result. Each area says what was observed, what could not be assessed and what needs your input.
            </figcaption>
          </figure>
        </div>
      </section>

      {/* Free check and account */}
      <section aria-labelledby="start-title" className="py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="start-title" center title="Start free. Go deeper once it is yours." />
          <div className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-6 max-w-[1040px] mx-auto">
            <div className="rounded-[14px] border border-[#DDE2EE] p-8 lg:p-10">
              <h3 className="font-cm font-normal text-[30px] leading-[1.15]">Free check</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">A one-off snapshot of public evidence: nothing is stored or monitored until you create an account.</p>
              <ul className="mt-6 space-y-3 text-[16px] text-[#2B3448]">
                {['All eight areas, checked from the outside', 'Shows what could not be assessed', 'No sign-up needed'].map(t => (
                  <li key={t} className="flex gap-3"><Check className="w-5 h-5 mt-0.5 text-[#2550B6] flex-shrink-0" aria-hidden="true" />{t}</li>
                ))}
              </ul>
            </div>
            <div className="rounded-[14px] border-2 border-[#2550B6] p-8 lg:p-10 bg-[#F7F9FF]">
              <h3 className="font-cm font-normal text-[30px] leading-[1.15]">With an account</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">Full findings, fix steps, PDF reports and monitoring unlock once you verify that you own the domain.</p>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">Scheduled checks, alerts and PDF reports come with paid plans and the 14-day trial.</p>
              <Link to="/pricing" className="mt-6 inline-flex items-center gap-2 text-[16px] font-semibold text-[#1D46A8] hover:underline">See pricing <ArrowRight className="w-4 h-4" aria-hidden="true" /></Link>
            </div>
          </div>
          <p className="mt-10 max-w-[1040px] mx-auto text-[15px] leading-[1.6] text-[#5A6378] border-l-2 border-[#C9D1E4] pl-5">
            CyberMeters provides cyber posture checks and Cyber Essentials readiness support. It does not provide Cyber Essentials certification. Certification is handled through IASME and approved Certification Bodies.
          </p>
        </div>
      </section>

      {/* Final call to action */}
      <section aria-labelledby="cta-title" className="cm-stage relative overflow-hidden text-white">
        <ClosingEye />
        <div className={`${CONTAINER} relative z-10 py-24 lg:py-[120px]`}>
          <h2 id="cta-title" className="font-cm font-normal text-[40px] sm:text-[48px] lg:text-[56px] leading-[1.06] max-w-[16ch] text-balance">Run a free check on your domain.</h2>
          <p className="font-cm mt-5 text-[21px] lg:text-[22px] leading-[1.5] text-white/85 max-w-[46ch]">
            See one bounded snapshot of public evidence across all eight areas, including what could not be assessed.
          </p>
          <div className="mt-10"><DomainForm id="cta-domain" /></div>
        </div>
      </section>

      <footer className="bg-white border-t border-[#E6EAF3]">
        <div className={`${CONTAINER} py-12 flex flex-col lg:flex-row lg:items-start lg:justify-between gap-8`}>
          <div>
            <CyberMetersLogo size={28} showWordmark />
            <p className="mt-4 text-[15px] text-[#5A6378]">External security checks for small teams.</p>
            <p className="mt-1 text-[15px] text-[#5A6378]">
              <a href={CONTACT} className="hover:text-[#121A2E]">hello@cybermeters.com</a>
            </p>
          </div>
          <nav aria-label="Footer" className="grid grid-cols-2 sm:grid-cols-4 gap-x-10 gap-y-3 text-[15px] text-[#46506A]">
            <Link to="/about" className="hover:text-[#121A2E]">About</Link>
            <Link to="/trust" className="hover:text-[#121A2E]">Trust &amp; Security</Link>
            <Link to="/pricing" className="hover:text-[#121A2E]">Pricing</Link>
            <Link to="/status" className="hover:text-[#121A2E]">Status</Link>
            <Link to="/support" className="hover:text-[#121A2E]">Support</Link>
            <a href={`${APP_URL}/login`} className="hover:text-[#121A2E]">Sign in</a>
            <Link to="/privacy" className="hover:text-[#121A2E]">Privacy</Link>
            <Link to="/terms" className="hover:text-[#121A2E]">Terms</Link>
            <Link to="/dpa" className="hover:text-[#121A2E]">DPA</Link>
            <Link to="/cookies" className="hover:text-[#121A2E]">Cookies</Link>
          </nav>
        </div>
        <div className="border-t border-[#EEF1F7]">
          <div className={`${CONTAINER} py-5 text-[13px] text-[#7A8399]`}>© {year} CyberMeters. All rights reserved.</div>
        </div>
      </footer>
    </div>
  )
}
