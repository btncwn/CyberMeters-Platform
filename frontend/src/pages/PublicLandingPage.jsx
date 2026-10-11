import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, Lock, ShieldCheck, Search, MonitorCheck, KeyRound, Boxes, ClipboardList,
  Check, X, AlertTriangle, CircleDashed, FolderKanban, FileText, Building2, RefreshCcw,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { SERVICE_COLORS } from '../theme/serviceColors'

const APP_URL = 'https://app.cybermeters.com'
const CONTACT = 'mailto:hello@cybermeters.com'

// The eight canonical Cyber MOT domains, in canonical order, each led by the
// plain question a business owner asks. Identity colours come from the shared
// domain palette so the landing page and the app never drift apart.
export const AREAS = [
  { key: 'identity', icon: KeyRound, name: 'Identity Exposure',
    q: 'What can outsiders learn about how your staff sign in?',
    checks: 'Identity providers you use and your identity-facing hostnames. Measured endpoints appear with their responses, and HTTP evidence is shown where collected. This is not a breach or dark-web search.' },
  { key: 'surface', icon: Search, name: 'Attack Surface',
    q: 'What of yours can be reached from the internet?',
    checks: 'Subdomains, exposed services and takeover risk, tracked as they change.' },
  { key: 'email', icon: Mail, name: 'Email Protection',
    q: 'Can someone send email pretending to be you?',
    checks: 'SPF, DKIM and DMARC explained in plain English, with the services that send mail as you.' },
  { key: 'website', icon: MonitorCheck, name: 'Website Security',
    q: 'Is your website set up safely?',
    checks: 'HTTPS, redirects, security headers and cookie settings on your public sites.' },
  { key: 'shadow_it', icon: Boxes, name: 'Shadow IT & Unmanaged Technology',
    q: 'Which outside tools does your website reveal?',
    checks: 'SaaS, vendors and third-party scripts seen from outside, for you to approve or question.' },
  { key: 'certs', icon: Lock, name: 'Certificates & Trust',
    q: 'Will a certificate quietly expire on you?',
    checks: 'Certificate expiry, hostname matching and the live TLS setup of your sites.' },
  { key: 'brand', icon: ShieldCheck, name: 'Brand Protection',
    q: 'Is someone registering lookalikes of your domain?',
    checks: 'Lookalike domains from public certificate logs, with the evidence you need to decide.' },
  { key: 'cyber_essentials', icon: ClipboardList, name: 'Cyber Essentials Readiness',
    q: 'How close are you to Cyber Essentials?',
    checks: 'Readiness from what we can see, combined with your own answers.' },
]

// Sample inspection rows for the hero sheet — an illustration of the report
// layout, never a live measurement or customer data.
const SAMPLE = [
  { key: 'identity', found: 'Identity-facing hostnames reviewed', result: 'pass' },
  { key: 'surface', found: '14 hosts, 1 unexpected service', result: 'advisory' },
  { key: 'email', found: 'DMARC is not enforcing', result: 'fail' },
  { key: 'website', found: 'Security headers missing on 1 site', result: 'advisory' },
  { key: 'shadow_it', found: '6 outside tools to review', result: 'advisory' },
  { key: 'certs', found: 'Valid for 74 more days', result: 'pass' },
  { key: 'brand', found: 'No lookalike domains found', result: 'pass' },
  { key: 'cyber_essentials', found: 'Needs your questionnaire answers', result: 'unknown' },
]

const RESULT = {
  pass:     { label: 'Pass',       icon: Check,         cls: 'bg-[#E3F3EA] text-result-pass' },
  advisory: { label: 'Advisory',   icon: AlertTriangle, cls: 'bg-[#FBEFD9] text-result-advisory' },
  fail:     { label: 'Fail',       icon: X,             cls: 'bg-[#FBE4E1] text-result-fail' },
  unknown:  { label: 'Not tested', icon: CircleDashed,  cls: 'bg-[#ECEFEE] text-result-unknown' },
}

const STEPS = [
  { title: 'Check', copy: 'We read what anyone on the internet can see about your domain.' },
  { title: 'Understand', copy: 'Each result says what we saw, why it matters and what we could not see.' },
  { title: 'Assign', copy: 'Turn a finding into a case with an owner, so it does not get lost.' },
  { title: 'Fix', copy: 'Follow steps written for whoever does the work, not for a security team.' },
  { title: 'Re-check', copy: 'We test again and mark it fixed only when we can see that it is.' },
]

const PROVIDER_POINTS = [
  { icon: Building2, title: 'A workspace per client', copy: "Keep each client's domains, findings and cases apart, with their own team access." },
  { icon: FileText, title: 'Reports under your name', copy: 'Send executive and technical PDF reports with your own branding.' },
  { icon: FolderKanban, title: 'Every fix tracked', copy: 'Cases with owners and re-checks across all eight areas, so nothing is fixed only on paper.' },
]

const AREA_BY_KEY = Object.fromEntries(AREAS.map(a => [a.key, a]))

function AreaGlyph({ areaKey, size = 'md' }) {
  const area = AREA_BY_KEY[areaKey]
  const c = SERVICE_COLORS[areaKey]
  const Icon = area.icon
  const box = size === 'lg' ? 'w-11 h-11 rounded-[12px]' : 'w-8 h-8 rounded-[9px]'
  const ico = size === 'lg' ? 'w-[22px] h-[22px]' : 'w-[17px] h-[17px]'
  return (
    <span className={`${box} grid place-items-center flex-shrink-0`} style={{ background: c.chip, color: c.icon }}>
      <Icon className={ico} />
    </span>
  )
}

function ResultChip({ result, hidden = false }) {
  const r = RESULT[result]
  const Icon = r.icon
  return (
    <span
      className={`inline-flex items-center gap-1.5 pl-2 pr-2.5 py-1 rounded-full text-[13px] font-semibold whitespace-nowrap transition-[opacity,transform] duration-300 ${r.cls} ${hidden ? 'opacity-0 scale-90' : 'opacity-100 scale-100'}`}
    >
      <Icon className="w-3.5 h-3.5" strokeWidth={2.5} />
      {r.label}
    </span>
  )
}

// One orchestrated moment: on load the sheet "runs" — results land row by row.
function useStagedResults(count) {
  const [shown, setShown] = useState(0)
  useEffect(() => {
    const reduce = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (reduce) { setShown(count); return undefined }
    let i = 0
    let timer
    const tick = () => {
      i += 1
      setShown(i)
      if (i < count) timer = setTimeout(tick, 170)
    }
    timer = setTimeout(tick, 450)
    return () => clearTimeout(timer)
  }, [count])
  return shown
}

function InspectionSheet() {
  const shown = useStagedResults(SAMPLE.length)
  return (
    <figure
      className="bg-white rounded-[20px] border border-rule overflow-hidden"
      style={{ boxShadow: '0 40px 80px -40px rgba(12,61,52,.45), 0 2px 6px rgba(12,61,52,.06)' }}
      aria-label="Sample Cyber MOT report"
    >
      <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-4">
        <div>
          <p className="text-[22px] font-semibold leading-none stretch-118 tracking-[-0.02em]">Cyber MOT</p>
          <p className="text-[14px] text-graphite mt-2">example.co.uk</p>
        </div>
        <span className="mt-0.5 rotate-[-4deg] rounded-md border-2 border-graphite/40 px-2 py-0.5 text-[13px] font-semibold text-graphite stretch-112">
          Sample
        </span>
      </div>
      <div className="grid grid-cols-[1fr_auto] sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] lg:grid-cols-[1fr_auto] xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] gap-x-4 px-6 py-2 bg-bay border-y border-rule text-[12px] font-semibold text-graphite">
        <span>Area</span>
        <span className="hidden sm:block lg:hidden xl:block">What we found</span>
        <span>Result</span>
      </div>
      <ul>
        {SAMPLE.map((row, i) => (
          <li key={row.key} className={`grid grid-cols-[1fr_auto] sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] lg:grid-cols-[1fr_auto] xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] items-center gap-x-4 px-6 py-3 ${i ? 'border-t border-rule' : ''}`}>
            <span className="flex items-center gap-3 min-w-0">
              <AreaGlyph areaKey={row.key} />
              <span className="text-[15px] font-semibold leading-snug">{AREA_BY_KEY[row.key].name}</span>
            </span>
            <span className="hidden sm:block lg:hidden xl:block text-[14px] text-graphite leading-snug">{row.found}</span>
            <ResultChip result={row.result} hidden={i >= shown} />
          </li>
        ))}
      </ul>
      <figcaption className="px-6 py-4 bg-bay border-t border-rule">
        <p className="text-[14px]"><span className="font-semibold">Fix first:</span> publish a DMARC policy so spoofed email is rejected.</p>
        <p className="text-[13px] text-graphite mt-1">Sample report to show the layout, not a live result.</p>
      </figcaption>
    </figure>
  )
}

function DomainCheckForm({ id, tone = 'light' }) {
  const dark = tone === 'dark'
  return (
    <form action="/free-scan" method="get" className="flex flex-col sm:flex-row gap-3 w-full max-w-[36rem]" aria-label="Run a free check">
      <label htmlFor={id} className="sr-only">Your domain</label>
      <input
        id={id}
        name="domain"
        type="text"
        inputMode="url"
        autoComplete="url"
        autoCapitalize="none"
        spellCheck={false}
        required
        placeholder="yourcompany.co.uk"
        className={`w-full sm:w-auto sm:flex-1 min-w-0 h-14 px-5 rounded-[12px] text-[17px] text-ink bg-white border placeholder:text-gray-400 focus:outline-none focus:ring-4 ${dark ? 'border-transparent focus:ring-white/25' : 'border-rule focus:border-brand-600 focus:ring-brand-600/15'}`}
      />
      <button
        type="submit"
        className={`h-14 px-7 rounded-[12px] text-[16px] font-semibold whitespace-nowrap transition-colors ${dark ? 'bg-white text-evergreen hover:bg-evergreen-100' : 'bg-brand-600 text-white hover:bg-brand-700 shadow-btn-brand'}`}
      >
        Run a free check
      </button>
    </form>
  )
}

function Header() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])
  return (
    <header className={`sticky top-0 z-50 bg-white/90 backdrop-blur-md border-b transition-colors ${scrolled ? 'border-rule' : 'border-transparent'}`}>
      <div className="max-w-[1240px] mx-auto px-6 lg:px-8 h-[72px] flex items-center justify-between gap-6">
        <a href="/" aria-label="CyberMeters home" className="flex-shrink-0"><CyberMetersLogo size={30} showWordmark /></a>
        <nav aria-label="Main" className="hidden md:flex items-center gap-8 text-[15px] text-graphite">
          <a href="#areas" className="hover:text-ink transition-colors">What we check</a>
          <a href="#how" className="hover:text-ink transition-colors">How it works</a>
          <a href="#providers" className="hover:text-ink transition-colors">For IT providers</a>
          <a href={`${APP_URL}/pricing`} className="hover:text-ink transition-colors">Pricing</a>
        </nav>
        <div className="flex items-center gap-2 sm:gap-4">
          <a href={`${APP_URL}/login`} className="hidden sm:inline text-[15px] font-medium text-graphite hover:text-ink">Sign in</a>
          <Link to="/free-scan" className="btn-primary">Run a free check</Link>
        </div>
      </div>
    </header>
  )
}

const Container = ({ className = '', children }) => (
  <div className={`max-w-[1240px] mx-auto px-6 lg:px-8 ${className}`}>{children}</div>
)

export default function PublicLandingPage() {
  const year = new Date().getFullYear()
  return (
    <div className="min-h-screen bg-white text-ink">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-[60] btn-secondary">Skip to content</a>
      <Header />

      <main id="main">
        {/* ── Hero: the product is the hero ── */}
        <section className="relative overflow-hidden">
          <div aria-hidden="true" className="absolute inset-x-0 top-0 h-[560px] pointer-events-none"
            style={{ background: 'linear-gradient(180deg, #F2F5F3 0%, #FFFFFF 100%)' }} />
          <Container className="relative pt-16 pb-24 lg:pt-24 lg:pb-32 grid lg:grid-cols-[1.02fr_0.98fr] gap-14 lg:gap-16 items-center">
            <div>
              <h1 className="display-1 text-balance max-w-[11ch]">Put your business through a Cyber MOT.</h1>
              <p className="lead mt-7 max-w-[34rem] text-pretty">
                CyberMeters checks the eight things anyone on the internet can see about your business, explains each result in plain English and tells you what to fix first.
              </p>
              <div className="mt-10">
                <DomainCheckForm id="hero-domain" />
              </div>
              <p className="text-[14px] text-graphite mt-4 max-w-[34rem]">
                Free, in your browser, nothing to install. The free check is a one-off snapshot of public evidence: nothing is stored or monitored until you create an account.
              </p>
            </div>
            <InspectionSheet />
          </Container>
        </section>

        {/* ── The eight areas ── */}
        <section id="areas" className="scroll-mt-20 py-24 lg:py-32 border-t border-rule">
          <Container>
            <div className="max-w-[44rem]">
              <h2 className="display-2 text-balance">Eight areas, tested from the outside.</h2>
              <p className="lead mt-5 text-pretty">The same things an attacker can look at, checked on a schedule and explained in words your whole team understands.</p>
            </div>
            <div className="mt-16 grid md:grid-cols-2 gap-x-16">
              {AREAS.map(a => (
                <div key={a.key} className="flex gap-5 py-8 border-t border-rule">
                  <AreaGlyph areaKey={a.key} size="lg" />
                  <div className="min-w-0">
                    <h3 className="display-3">{a.name}</h3>
                    <p className="text-[16px] font-medium mt-2" style={{ color: SERVICE_COLORS[a.key].text }}>{a.q}</p>
                    <p className="text-[15px] text-graphite mt-2 leading-relaxed">{a.checks}</p>
                  </div>
                </div>
              ))}
            </div>
          </Container>
        </section>

        {/* ── Lifecycle: a real sequence ── */}
        <section id="how" className="scroll-mt-20 bg-evergreen text-white py-24 lg:py-32">
          <Container>
            <div className="max-w-[44rem]">
              <h2 className="display-2 text-balance">From finding to fixed.</h2>
              <p className="lead mt-5 !text-evergreen-200 text-pretty">A finding isn't done when you read it. It's done when we can see that it's fixed.</p>
            </div>
            <ol className="mt-16 grid gap-10 lg:gap-6 lg:grid-cols-5 relative">
              <span aria-hidden="true" className="hidden lg:block absolute top-[19px] left-[20px] right-[20%] h-px bg-evergreen-400" />
              {STEPS.map((s, i) => (
                <li key={s.title} className="relative flex lg:block gap-5">
                  <span className="relative z-10 w-10 h-10 flex-shrink-0 rounded-full grid place-items-center bg-evergreen border border-evergreen-200 text-[15px] font-semibold stretch-118">
                    {i + 1}
                  </span>
                  <div className="lg:mt-6">
                    <h3 className="display-3 text-white">{s.title}</h3>
                    <p className="text-[15px] text-evergreen-200 mt-2 leading-relaxed max-w-[22rem] lg:max-w-none">{s.copy}</p>
                  </div>
                </li>
              ))}
            </ol>
          </Container>
        </section>

        {/* ── Honesty: the difference ── */}
        <section className="py-24 lg:py-32 bg-bay">
          <Container className="grid lg:grid-cols-2 gap-14 lg:gap-20 items-center">
            <div>
              <h2 className="display-2 text-balance">We tell you what we could not check.</h2>
              <p className="lead mt-6 text-pretty">Many scanners turn missing evidence into a clean score. We don't. If a check could not run, your report says so, and an area is never marked as passed on silence.</p>
              <p className="text-[16px] text-graphite mt-5 leading-relaxed max-w-[34rem]">Every report shows what we observed, what needs attention and what could not be assessed, so you know exactly how far to trust it.</p>
            </div>
            <div className="bg-white rounded-[20px] border border-rule divide-y divide-rule">
              {[
                { chip: <ResultChip result="pass" />, title: 'Observed working', copy: 'CyberMeters saw it from outside on this check.' },
                { chip: <ResultChip result="unknown" />, title: 'Not enough evidence', copy: "The check could not run fully, so we don't guess. It never counts as a pass." },
                { chip: <span className="inline-flex items-center gap-1.5 pl-2 pr-2.5 py-1 rounded-full text-[13px] font-semibold bg-[#E3F3EA] text-result-pass"><RefreshCcw className="w-3.5 h-3.5" strokeWidth={2.5} />Verified</span>,
                  title: 'Fixed and re-checked', copy: 'You recorded a fix and our re-check confirmed it from outside.' },
              ].map(s => (
                <div key={s.title} className="grid sm:grid-cols-[124px_1fr] gap-3 sm:gap-5 px-6 py-6">
                  <span>{s.chip}</span>
                  <div>
                    <p className="text-[17px] font-semibold">{s.title}</p>
                    <p className="text-[15px] text-graphite mt-1">{s.copy}</p>
                  </div>
                </div>
              ))}
            </div>
          </Container>
        </section>

        {/* ── For IT providers ── */}
        <section id="providers" className="scroll-mt-20 py-24 lg:py-32">
          <Container>
            <div className="max-w-[44rem]">
              <h2 className="display-2 text-balance">Made for the people who look after other businesses' IT.</h2>
              <p className="lead mt-5 text-pretty">Run the same check for every client and keep each one's findings, fixes and reports in a workspace of its own.</p>
            </div>
            <div className="mt-16 grid md:grid-cols-3 gap-x-12 gap-y-10">
              {PROVIDER_POINTS.map(p => {
                const Icon = p.icon
                return (
                  <div key={p.title} className="pt-6 border-t-2 border-ink">
                    <Icon className="w-6 h-6 text-brand-700" />
                    <h3 className="display-3 mt-5">{p.title}</h3>
                    <p className="text-[15px] text-graphite mt-2 leading-relaxed">{p.copy}</p>
                  </div>
                )
              })}
            </div>
          </Container>
        </section>

        {/* ── Proof and fine print ── */}
        <section className="py-20 bg-bay border-t border-rule">
          <Container className="grid md:grid-cols-2 gap-12">
            <div>
              <h2 className="text-[24px] font-semibold stretch-112 tracking-[-0.015em]">We check our own domain in public.</h2>
              <p className="text-[16px] text-graphite mt-3 max-w-[30rem] leading-relaxed">See our dated cybermeters.com report, the evidence behind it and the checks that are still incomplete.</p>
              <Link to="/trust" className="inline-block mt-5 text-[16px] font-semibold text-brand-700 underline underline-offset-4 decoration-brand-600/40 hover:decoration-brand-700">See our own report</Link>
            </div>
            <div>
              <h2 className="text-[24px] font-semibold stretch-112 tracking-[-0.015em]">About Cyber Essentials</h2>
              <p className="text-[16px] text-graphite mt-3 max-w-[30rem] leading-relaxed">
                CyberMeters provides cyber posture checks and Cyber Essentials readiness support. It does not provide Cyber Essentials certification. Certification is handled through IASME and approved Certification Bodies.
              </p>
            </div>
          </Container>
        </section>

        {/* ── Final call to action ── */}
        <section className="bg-evergreen text-white py-24 lg:py-28">
          <Container className="grid lg:grid-cols-[1.1fr_0.9fr] gap-14 lg:gap-20 items-center">
            <div>
              <h2 className="display-2 max-w-[18ch] text-balance">Run your free check.</h2>
              <p className="lead mt-5 !text-evergreen-200 max-w-[38rem] text-pretty">
                Enter your domain and see all eight areas in one report. Full findings, fix steps, PDF reports and monitoring unlock once you verify that you own the domain.
              </p>
              <div className="mt-10"><DomainCheckForm id="final-domain" tone="dark" /></div>
              <p className="text-[14px] text-evergreen-200 mt-4">Questions first? <a href={CONTACT} className="text-white underline underline-offset-4">Email hello@cybermeters.com</a></p>
            </div>
            <div>
            <div className="grid sm:grid-cols-2 gap-px rounded-[20px] overflow-hidden bg-evergreen-400/60">
              {[
                { title: 'Free check', items: ['All eight areas, once', 'What we saw and could not see', 'No account, nothing stored'] },
                { title: 'After you verify', items: ['Full findings and fix steps', 'Cases, owners and re-checks', 'Scheduled checks and alerts', 'PDF reports for your team'] },
              ].map(col => (
                <div key={col.title} className="bg-evergreen-600 p-7">
                  <h3 className="text-[18px] font-semibold stretch-112">{col.title}</h3>
                  <ul className="mt-4 space-y-2.5">
                    {col.items.map(it => (
                      <li key={it} className="flex gap-2.5 text-[15px] text-evergreen-100">
                        <Check className="w-4 h-4 mt-[3px] flex-shrink-0 text-evergreen-200" strokeWidth={2.5} />{it}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
            <p className="text-[13px] text-evergreen-200 mt-3">Scheduled checks, alerts and PDF reports come with paid plans and the 14-day trial.</p>
            </div>
          </Container>
        </section>
      </main>

      <footer className="bg-white border-t border-rule">
        <Container className="py-12 flex flex-col md:flex-row md:items-start md:justify-between gap-8">
          <div>
            <CyberMetersLogo size={28} showWordmark />
            <p className="text-[15px] text-graphite mt-4 max-w-[22rem]">External security checks for small businesses and the people who look after their IT.</p>
          </div>
          <nav aria-label="Footer" className="grid grid-cols-2 sm:grid-cols-3 gap-x-12 gap-y-3 text-[15px]">
            <Link to="/about" className="text-graphite hover:text-ink">About</Link>
            <Link to="/trust" className="text-graphite hover:text-ink">Trust &amp; Security</Link>
            <Link to="/status" className="text-graphite hover:text-ink">Status</Link>
            <Link to="/privacy" className="text-graphite hover:text-ink">Privacy</Link>
            <Link to="/terms" className="text-graphite hover:text-ink">Terms</Link>
            <Link to="/dpa" className="text-graphite hover:text-ink">DPA</Link>
            <Link to="/support" className="text-graphite hover:text-ink">Support</Link>
            <a href={CONTACT} className="text-graphite hover:text-ink">hello@cybermeters.com</a>
          </nav>
        </Container>
        <div className="border-t border-rule">
          <Container className="py-5 text-[13px] text-graphite">© {year} CyberMeters. All rights reserved.</Container>
        </div>
      </footer>
    </div>
  )
}
