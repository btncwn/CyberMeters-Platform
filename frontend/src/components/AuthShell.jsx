import { Link } from 'react-router-dom'
import { Check } from 'lucide-react'
import CyberMetersLogo from './CyberMetersLogo'

// Split auth layout: the form on paper, a quiet evergreen panel beside it that
// tells the visitor what happens next. The panel hides below lg so phones get
// the form alone.
export default function AuthShell({ children, aside, footer }) {
  const year = new Date().getFullYear()
  return (
    <div className="min-h-screen bg-white lg:grid lg:grid-cols-[minmax(0,1fr)_minmax(0,0.92fr)]">
      <div className="flex flex-col min-h-screen px-6 sm:px-10 lg:px-16 xl:px-24">
        <header className="h-20 flex items-center">
          <a href="https://cybermeters.com" aria-label="CyberMeters home"><CyberMetersLogo size={30} showWordmark /></a>
        </header>
        <main className="flex-1 flex items-center py-10">
          <div className="w-full max-w-[26rem]">{children}</div>
        </main>
        <footer className="py-8 text-[13px] text-graphite flex flex-wrap items-center gap-x-5 gap-y-2">
          {footer}
          <span className="flex flex-wrap gap-x-4 gap-y-1">
            <Link to="/terms" className="hover:text-ink">Terms</Link>
            <Link to="/privacy" className="hover:text-ink">Privacy</Link>
            <Link to="/dpa" className="hover:text-ink">DPA</Link>
            <Link to="/cookies" className="hover:text-ink">Cookies</Link>
          </span>
          <span>© {year} CyberMeters</span>
        </footer>
      </div>
      {aside && (
        <aside className="hidden lg:flex bg-evergreen text-white px-14 xl:px-20 py-16 items-center">
          <div className="w-full max-w-[30rem]">{aside}</div>
        </aside>
      )}
    </div>
  )
}

export function AuthHeading({ title, subtitle }) {
  return (
    <div className="mb-8">
      <h1 className="text-[34px] font-semibold leading-[1.05] tracking-[-0.02em] stretch-112 text-ink">{title}</h1>
      {subtitle && <p className="text-[16px] text-graphite mt-3 leading-relaxed">{subtitle}</p>}
    </div>
  )
}

export function Field({ id, label, hint, children }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-2">
        <label htmlFor={id} className="text-[14px] font-semibold text-ink">{label}</label>
        {hint}
      </div>
      {children}
    </div>
  )
}

export function AuthAlert({ tone = 'error', children }) {
  const cls = tone === 'error'
    ? 'bg-[#FBE4E1] text-result-fail'
    : tone === 'warning' ? 'bg-[#FBEFD9] text-result-advisory' : 'bg-[#E3F3EA] text-result-pass'
  return <div role={tone === 'error' ? 'alert' : 'status'} className={`rounded-[10px] px-4 py-3 mb-6 text-[14px] ${cls}`}>{children}</div>
}

// The real onboarding sequence, shown beside sign-up so nothing comes as a surprise.
export function NextStepsAside() {
  const steps = [
    'Confirm your email address',
    'Name your workspace',
    'Add your domain',
    'Prove you own it with one DNS record',
    'Run your first Cyber MOT',
  ]
  return (
    <div>
      <p className="text-[15px] text-evergreen-200">What happens next</p>
      <h2 className="mt-3 text-[30px] font-semibold leading-[1.1] tracking-[-0.02em] stretch-112">Five short steps to your first report.</h2>
      <ol className="mt-10 space-y-5">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-4">
            <span className="w-8 h-8 flex-shrink-0 rounded-full border border-evergreen-200 grid place-items-center text-[14px] font-semibold stretch-118">{i + 1}</span>
            <span className="text-[16px]">{s}</span>
          </li>
        ))}
      </ol>
      <p className="mt-10 text-[14px] text-evergreen-200 leading-relaxed">We only ever look at what is public. Nothing is installed on your systems, and every result says what we could not see.</p>
    </div>
  )
}

export function SignInAside() {
  const items = [
    'Results for all eight areas, with what we could not check',
    'Cases with owners for every fix',
    'Re-checks that confirm a fix from outside',
  ]
  return (
    <div>
      <p className="text-[15px] text-evergreen-200">Your Cyber MOT</p>
      <h2 className="mt-3 text-[30px] font-semibold leading-[1.1] tracking-[-0.02em] stretch-112">Pick up where you left off.</h2>
      <ul className="mt-10 space-y-4">
        {items.map(it => (
          <li key={it} className="flex gap-3 text-[16px]">
            <Check className="w-5 h-5 mt-0.5 flex-shrink-0 text-evergreen-200" strokeWidth={2.5} />{it}
          </li>
        ))}
      </ul>
    </div>
  )
}
