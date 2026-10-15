import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import PublicSiteHeader from '../components/PublicSiteHeader'
import PublicSiteFooter from '../components/PublicSiteFooter'
import IrisGlobe, { GLOBE, heroGlobe } from '../components/landing/IrisGlobe'
import ProductFrame from '../components/landing/ProductFrame'
import ProductShowcase from '../components/landing/ProductShowcase'
import ProductTour from '../components/landing/ProductTour'
import { SERVICE_COLORS } from '../theme/serviceColors'

const APP_URL = 'https://app.cybermeters.com'

// The eight canonical domains, each led with the question a business owner
// actually asks. Identity colours come from the shared domain palette.
const SERVICES = [
  {
    name: 'Identity Exposure',
    q: 'What is visible about our business identities?',
    copy: 'Review identity-provider relationships, identity-facing hostnames and measured endpoints. HTTP evidence is shown where collected. This is not employee breach or dark-web monitoring.',
    tags: ['Provider relationships', 'Identity-facing hostnames', 'Measured endpoints'],
    key: 'identity',
  },
  {
    name: 'Attack Surface',
    q: 'What of mine is exposed to the internet?',
    copy: 'See discovered subdomains and exposed services. Review the evidence, track changes and recheck after a fix.',
    tags: ['Asset inventory', 'Subdomains', 'Takeover risk'],
    key: 'surface',
  },
  {
    name: 'Email Protection',
    q: 'Can attackers send email as me?',
    copy: 'Review SPF, DKIM and DMARC in plain English. Connect email reports to see sending sources and plan your next policy change.',
    tags: ['DMARC setup', 'Sender inventory', 'Email reports'],
    key: 'email',
  },
  {
    name: 'Website Security',
    q: 'Is my website configured safely?',
    copy: 'HTTPS, redirects, security headers, cookie flags and visible website configuration issues in one place.',
    tags: ['HTTPS', 'Headers', 'Cookies'],
    key: 'website',
  },
  {
    name: 'Shadow IT & Unmanaged Technology',
    q: 'Which outside tools are visible?',
    copy: 'Externally observed SaaS, vendors, third-party scripts and unmanaged technology signals for review.',
    tags: ['SaaS signals', 'Vendors', 'Scripts'],
    key: 'shadow_it',
  },
  {
    name: 'Certificates & Trust',
    q: 'Will my site quietly break trust?',
    copy: 'Track certificate expiry and review live TLS evidence, including hostname matching and checks against the recorded trust store.',
    tags: ['Expiry alerts', 'TLS posture', 'HTTPS trust'],
    key: 'certs',
  },
  {
    name: 'Brand Protection',
    q: 'Is anyone impersonating my brand?',
    copy: 'Review lookalike domain candidates and the evidence behind them. Decide which need attention and track the next action.',
    tags: ['Lookalike domains', 'Impersonation', 'Classification'],
    key: 'brand',
  },
  {
    name: 'Cyber Essentials Readiness',
    q: 'How ready are we for Cyber Essentials?',
    copy: 'Evidence-led readiness support that combines externally observable signals with saved questionnaire answers.',
    tags: ['Readiness gaps', 'Evidence', 'Actions'],
    key: 'cyber_essentials',
  },
]

const FACTS = [
  { big: 'External', small: 'checks only what is publicly visible' },
  { big: 'No agent', small: 'nothing is installed on your systems' },
  { big: '1 DNS record', small: 'proves that you own the domain' },
  { big: 'Gaps named', small: 'every result says what could not be checked' },
]

const PRINCIPLES = [
  { title: 'Missing evidence is never a pass.', copy: 'If a check could not run or could not see enough, the result says so. Nothing is marked as passed on silence.' },
  { title: 'Observed and recorded stay apart.', copy: 'What CyberMeters saw from the outside and what your team recorded are shown as different things, each with a date.' },
  { title: 'Fixes are checked again.', copy: 'Where a fix can be seen from the outside, CyberMeters checks again and records what it found.' },
]

const STEPS = [
  { title: 'Check', copy: 'Enter a domain for a bounded, non-persistent external snapshot. Verify ownership before accessing deeper checks.' },
  { title: 'Verify', copy: 'Create an account and add one DNS TXT record. CyberMeters looks for it before it shows full findings for that domain.' },
  { title: 'Understand and act', copy: 'Each area says what was observed, what needs attention and what could not be assessed. Assign the recommended steps to an owner.' },
  { title: 'Check again', copy: 'When the work is done, CyberMeters checks again where the fix can be seen from outside. Scheduled rechecks and alerts keep watching for changes.' },
]

const UNSEEN = [
  'Your internal network, devices or staff laptops',
  'Passwords or credentials leaked elsewhere, or dark-web data',
  'Settings and licences inside your SaaS accounts',
  'Activity inside your email or identity systems',
]

const FAQS = [
  { q: 'Do I need to install anything?', a: 'No. CyberMeters looks only at what is publicly visible from the internet: DNS, websites, certificates and similar public evidence. Nothing runs on your systems.' },
  { q: 'Why do I have to verify my domain?', a: 'Full findings and monitoring are shown only to someone who controls the domain. You prove that by adding one DNS TXT record; CyberMeters checks it, and you can check again while the record spreads.' },
  { q: 'Will CyberMeters change my DNS or fix things for me?', a: 'No. It explains what to change and who usually makes the change, then checks again where the fix can be seen from outside. Your DNS, email or IT provider makes the change.' },
  { q: 'What happens to the free check?', a: 'You see one snapshot in your browser. To keep results, monitor changes or get reports, create an account and verify the domain.' },
  { q: 'Is this Cyber Essentials certification?', a: 'No. CyberMeters helps you prepare and shows readiness gaps it can evidence. Certification itself comes from an approved Certification Body.' },
]


// Sample rows for the product view. States use the product's own coverage
// vocabulary; no scores, no live data.
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
      <div className={`flex flex-col sm:flex-row gap-2 sm:gap-0 sm:items-stretch rounded-[12px] bg-white p-1.5 ${tone === 'dark' ? 'shadow-[0_18px_50px_-20px_rgba(6,16,48,.65)]' : 'border border-[#D5DBEA] shadow-xs'}`}>
        <div className="flex items-center gap-3 flex-1 min-w-0 pl-4 h-[52px]">
          <input
            id={id}
            name="domain"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            spellCheck="false"
            placeholder="yourcompany.co.uk"
            className="w-full min-w-0 bg-transparent text-[17px] text-[#121A2E] placeholder:text-[#8A93A8] outline-hidden"
          />
        </div>
        <button type="submit" className="h-[52px] px-6 rounded-[8px] btn-amber text-[16px]">
          Run a free check
        </button>
      </div>
    </form>
  )
}

// Desktop: the eye starts on the right of the hero and drifts to the centre as
// the page scrolls, settling above the facts band. Phones get a static layout.
function HeroStage() {
  const wide = useMediaQuery('(min-width: 1024px)')
  const still = useMediaQuery('(prefers-reduced-motion: reduce)')
  const stageRef = useRef(null)
  const eyeRef = useRef(null)
  const textRef = useRef(null)
  const SIZE = 1000
  const [globe, setGlobe] = useState(() => heroGlobe(typeof window === 'undefined' ? 0 : window.innerWidth))

  useEffect(() => {
    if (!wide) return undefined
    let raf = 0
    // The world settles above the facts band at the same size however large it
    // is in the hero, so it never reaches the heading below it.
    const settle = 0.74 * Math.min(1, GLOBE / globe)
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
      const s = 1 - (1 - settle) * e
      eye.style.transform = `translate3d(${(x - SIZE / 2).toFixed(1)}px, ${(y - SIZE / 2).toFixed(1)}px, 0) scale(${s.toFixed(3)})`
    }
    const on = () => { if (!raf) raf = requestAnimationFrame(apply) }
    const onResize = () => { setGlobe(heroGlobe(window.innerWidth)); on() }
    apply()
    window.addEventListener('scroll', on, { passive: true })
    window.addEventListener('resize', onResize)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('scroll', on)
      window.removeEventListener('resize', onResize)
    }
  }, [wide, still, globe])

  return (
    <div ref={stageRef} className="cm-stage relative overflow-hidden text-white">
      {wide && (
        <div ref={eyeRef} className="absolute left-0 top-0 z-0 will-change-transform" style={{ width: SIZE, height: SIZE, transformOrigin: '50% 50%' }}>
          <IrisGlobe size={SIZE} globe={globe} preferRight avoidRef={textRef} />
        </div>
      )}
      <div className="cm-legibility absolute inset-0 z-0 pointer-events-none" aria-hidden="true" />

      {/* Hero */}
      <section className={`${CONTAINER} relative z-10 pt-[148px] lg:pt-[168px] lg:min-h-[800px]`}>
        <div ref={textRef} className="max-w-[700px]">
          <h1 className="font-cm font-normal text-[46px] sm:text-[60px] lg:text-[72px] leading-[1.04] tracking-[-0.01em] text-balance">
            Know where your business is exposed and what to do next.
          </h1>
          <p className="font-cm mt-7 text-[21px] lg:text-[24px] leading-normal text-white/85 max-w-[40ch] text-pretty">
            CyberMeters runs external security checks on your domain, from email and website to certificates and lookalike domains, and says plainly what it could not check.
          </p>
          <div className="mt-10"><DomainForm id="hero-domain" /></div>
          <a href="#product" className="mt-5 inline-block text-[16px] font-semibold text-white underline decoration-white/50 underline-offset-4 hover:decoration-white">
            See a sample result first
          </a>
          <ul className="mt-5 flex flex-wrap gap-x-7 gap-y-2 text-[15px] text-white/85">
            {['Nothing to install', 'Free one-off check', 'Full results after you verify your domain'].map(t => (
              <li key={t}>{t}</li>
            ))}
          </ul>
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
            return (
              <li key={f.big} className={`px-2 lg:px-6 py-5 lg:py-0 ${i > 0 ? 'lg:border-l border-white/25' : ''}`}>
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

// The eight areas as a short overview: name and question always visible,
// details on request, so the section stays scannable on every screen.
function AreasOverview() {
  const [open, setOpen] = useState(null)
  return (
    <ul className="mt-16 grid grid-cols-1 md:grid-cols-2 gap-x-10 lg:gap-x-16">
      {SERVICES.map(s => {
        const c = SERVICE_COLORS[s.key]
        const expanded = open === s.key
        const panelId = `area-${s.key}`
        return (
          <li key={s.name} className="border-t border-[#DDE2EE] py-7">
            <div className="flex items-start gap-5">
              <span className="mt-2 w-1 self-stretch rounded-full shrink-0" style={{ background: c.icon }} aria-hidden="true" />
              <div className="flex-1 min-w-0">
                <h3 className="font-cm font-normal text-[32px] leading-[1.08] text-[#121A2E]">{s.name}</h3>
                <p className="mt-3 text-[17px] font-semibold leading-snug" style={{ color: c.text }}>{s.q}</p>
                <button
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={panelId}
                  onClick={() => setOpen(expanded ? null : s.key)}
                  className="mt-3 text-[16px] font-semibold text-[#1D46A8] hover:underline"
                >
                  {expanded ? 'Hide details' : 'What it checks'}
                </button>
                <div id={panelId} hidden={!expanded}>
                  <p className="mt-3 text-[16px] leading-[1.55] text-[#46506A]">{s.copy}</p>
                  <ul className="mt-4 flex flex-wrap gap-2">
                    {s.tags.map(t => (
                      <li key={t} className="text-[14px] text-[#46506A] px-2.5 py-1 rounded-full border" style={{ borderColor: c.ring, background: c.surface }}>{t}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function SectionHeading({ id, title, lead, center = false }) {
  return (
    <div className={center ? 'text-center mx-auto max-w-[860px]' : 'max-w-[760px]'}>
      <h2 id={id} className="font-cm font-normal text-[38px] sm:text-[46px] lg:text-[56px] leading-[1.06] tracking-[-0.005em] text-[#121A2E] text-balance">{title}</h2>
      {lead && <p className={`font-cm mt-5 text-[20px] lg:text-[22px] leading-normal text-[#46506A] ${center ? 'text-balance' : 'text-pretty'}`}>{lead}</p>}
    </div>
  )
}

export default function PublicLandingPage() {
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
        .cm-tour-in{animation:cm-tour-in .22s ease-out}
        @keyframes cm-tour-in{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
        @media (prefers-reduced-motion: reduce){.cm-iris[data-ready]{animation:none}.cm-iris{transition:none}.cm-tour-in{animation:none}}
      `}</style>

      <PublicSiteHeader tone="dark" />
      <HeroStage />

      {/* Product: the first thing after the hero is the product itself */}
      <section id="product" aria-labelledby="product-title" className="scroll-mt-24 py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="product-title" title="See what a check gives you." lead="One workspace for your domain. Each area says what was observed, what needs attention and what could not be assessed." />
          <ProductShowcase rows={SAMPLE_ROWS} />
        </div>
      </section>

      {/* One finding, step by step */}
      <section id="tour" aria-labelledby="tour-title" className="scroll-mt-24 bg-[#F3F5FB] py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="tour-title" title="Follow one finding from discovery to recheck." lead="A sample email finding, in the same screens you use after signing up." />
          <ProductTour />
        </div>
      </section>

      {/* Eight areas */}
      <section id="areas" aria-labelledby="areas-title" className="scroll-mt-24 py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="areas-title" center title="Eight areas in one workspace" lead="Start with a bounded, honest external snapshot. The report separates observed issues from missing evidence, so you can decide what needs attention." />
          <AreasOverview />
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
                  <span className="font-cm w-11 h-11 shrink-0 rounded-full bg-[#2550B6] text-white grid place-items-center text-[20px]">{i + 1}</span>
                  <div>
                    <h3 className="font-cm font-normal text-[26px] leading-[1.15]">{s.title}</h3>
                    <p className="mt-2 text-[17px] leading-[1.6] text-[#46506A]">{s.copy}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
          <div className="lg:sticky lg:top-28">
            <ProductFrame label="Sample domain verification" path="/onboarding" caption="Illustrative example. Your own record is shown after you add your domain.">
              <div className="p-5 sm:p-6">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-[14px] text-[#6A7389]">Step 3 of 5</p>
                    <p className="font-cm text-[22px] leading-tight text-[#121A2E] mt-1">Verify example.co.uk</p>
                  </div>
                  <span className="text-[14px] font-semibold rounded-full px-3 py-1 bg-[#FFF1D6] text-[#8A5300]">Waiting for the record</span>
                </div>
                <p className="mt-4 text-[15px] leading-[1.55] text-[#46506A]">Add this TXT record at your DNS provider. It proves you control the domain and changes nothing else.</p>
                <dl className="mt-4 rounded-xl border border-[#E6EAF3]">
                  {[['Type', 'TXT'], ['Host', '_cybermeters.example.co.uk'], ['Value', 'cybermeters-verification=7f3c9a1e52b8']].map(([k, v]) => (
                    <div key={k} className="grid grid-cols-[72px_minmax(0,1fr)] gap-3 px-4 py-3 border-b border-[#EEF1F7] last:border-b-0">
                      <dt className="text-[14px] text-[#6A7389]">{k}</dt>
                      <dd className="mono text-[14px] text-[#121A2E] break-all">{v}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-4 text-[14px] leading-[1.55] text-[#5A6378]">DNS changes can take a while to appear. Until CyberMeters finds the record, the domain stays unverified and you can check again.</p>
              </div>
            </ProductFrame>
          </div>
        </div>
      </section>

      {/* Trust */}
      <section id="trust" aria-labelledby="principles-title" className="scroll-mt-24 py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="principles-title" title="Honest about what it can see." lead="A security check is only useful if you can trust what it did not find. These rules hold for every result." />
          <div className="mt-14 grid grid-cols-1 md:grid-cols-3 gap-10 lg:gap-14">
            {PRINCIPLES.map(p => (
              <div key={p.title} className="border-t-2 border-[#2550B6] pt-7">
                <h3 className="font-cm font-normal text-[28px] lg:text-[30px] leading-[1.15] text-[#121A2E]">{p.title}</h3>
                <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">{p.copy}</p>
              </div>
            ))}
          </div>
          <div className="mt-16 grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-8">
            <div className="rounded-[14px] border border-[#DDE2EE] p-8 lg:p-10">
              <h3 className="font-cm font-normal text-[28px] lg:text-[30px] leading-[1.15]">What CyberMeters does not see</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">It checks only what is publicly visible from the internet. It does not see:</p>
              <ul className="mt-5 space-y-2.5 text-[17px] text-[#2B3448] list-disc pl-5 marker:text-[#2550B6]">
                {UNSEEN.map(t => <li key={t}>{t}</li>)}
              </ul>
            </div>
            <div className="rounded-[14px] bg-[#F3F5FB] p-8 lg:p-10 flex flex-col">
              <h3 className="font-cm font-normal text-[28px] lg:text-[30px] leading-[1.15]">We use CyberMeters on our own domain.</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">The trust page explains how we handle your data, which providers we use and how to report a security concern.</p>
              <div className="mt-auto pt-6">
                <Link to="/trust" className="h-[50px] px-6 rounded-[8px] border-2 border-[#2550B6] text-[#1D46A8] text-[16px] font-semibold inline-flex items-center hover:bg-[#2550B6] hover:text-white transition-colors">
                  View our own-domain check
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Ways to start */}
      <section id="start" aria-labelledby="start-title" className="scroll-mt-24 bg-[#F3F5FB] py-24 lg:py-[120px]">
        <div className={CONTAINER}>
          <SectionHeading id="start-title" center title="Start free. Go deeper once it is yours." />
          <div className="mt-14 grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="rounded-[14px] bg-white border border-[#DDE2EE] p-8 flex flex-col">
              <h3 className="font-cm font-normal text-[30px] leading-[1.15]">Free check</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">A one-off snapshot of public evidence. No scan report or monitoring history is saved. Limited rate-limit records help prevent misuse.</p>
              <ul className="mt-6 space-y-3 text-[17px] text-[#2B3448] list-disc pl-5 marker:text-[#2550B6]">
                {['External checks, nothing installed', 'Shows what could not be assessed', 'No sign-up needed'].map(t => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
              <div className="mt-auto pt-8">
                <Link to="/free-scan" className="h-[50px] px-6 rounded-[8px] btn-amber text-[16px]">Check a domain now</Link>
              </div>
            </div>
            <div className="rounded-[14px] border-2 border-[#2550B6] p-8 bg-white flex flex-col">
              <h3 className="font-cm font-normal text-[30px] leading-[1.15]">With an account</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">Full findings, fix steps, PDF reports and monitoring unlock once you verify that you own the domain.</p>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">A new account starts with the 14-day trial of the full product.</p>
              <div className="mt-auto pt-8">
                <a href={`${APP_URL}/signup`} className="h-[50px] px-6 rounded-[8px] bg-[#2550B6] hover:bg-[#1D46A8] text-white text-[16px] font-semibold inline-flex items-center transition-colors">Start my 14-day trial</a>
              </div>
            </div>
            <div className="rounded-[14px] bg-white border border-[#DDE2EE] p-8 flex flex-col">
              <h3 className="font-cm font-normal text-[30px] leading-[1.15]">Plans</h3>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">Scheduled checks, alerts and PDF reports come with paid plans and the 14-day trial.</p>
              <p className="mt-4 text-[17px] leading-[1.6] text-[#46506A]">Pricing is per monitored domain. Prices shown are the live prices from our billing system.</p>
              <div className="mt-auto pt-8">
                <Link to="/pricing" className="h-[50px] px-6 rounded-[8px] border-2 border-[#2550B6] text-[#1D46A8] text-[16px] font-semibold inline-flex items-center hover:bg-[#2550B6] hover:text-white transition-colors">See pricing</Link>
              </div>
            </div>
          </div>
          <p className="mt-10 text-[15px] leading-[1.6] text-[#5A6378] border-l-2 border-[#C9D1E4] pl-5">
            CyberMeters provides cyber posture checks and Cyber Essentials readiness support. It does not provide Cyber Essentials certification. Certification is handled through IASME and approved Certification Bodies.
          </p>
        </div>
      </section>

      {/* Questions */}
      <section id="faq" aria-labelledby="faq-title" className="scroll-mt-24 py-24 lg:py-[120px]">
        <div className={`${CONTAINER} grid grid-cols-1 lg:grid-cols-[1fr_1.4fr] gap-10 lg:gap-20 items-start`}>
          <SectionHeading id="faq-title" title="Questions before you start" />
          <div className="border-t border-[#DDE2EE]">
            {FAQS.map(f => (
              <details key={f.q} className="group border-b border-[#DDE2EE]">
                <summary className="cursor-pointer list-none flex items-start justify-between gap-6 py-6 font-cm text-[26px] leading-[1.2] text-[#121A2E] [&::-webkit-details-marker]:hidden">
                  {f.q}
                  <span aria-hidden="true" className="font-cm text-[26px] leading-none text-[#2550B6] group-open:rotate-45 transition-transform">+</span>
                </summary>
                <p className="pb-6 -mt-1 text-[17px] leading-[1.6] text-[#46506A] max-w-[62ch]">{f.a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>

      {/* Final call to action */}
      <section aria-labelledby="cta-title" className="cm-stage relative overflow-hidden text-white">
        <ClosingEye />
        <div className={`${CONTAINER} relative z-10 py-24 lg:py-[120px]`}>
          <h2 id="cta-title" className="font-cm font-normal text-[40px] sm:text-[48px] lg:text-[56px] leading-[1.06] max-w-[16ch] text-balance">Run a free check on your domain.</h2>
          <p className="font-cm mt-5 text-[21px] lg:text-[22px] leading-normal text-white/85 max-w-[46ch]">
            See one bounded, external snapshot of public evidence, including what could not be assessed.
          </p>
          <div className="mt-10"><DomainForm id="cta-domain" /></div>
        </div>
      </section>

      <PublicSiteFooter sectionBase="" />
    </div>
  )
}
