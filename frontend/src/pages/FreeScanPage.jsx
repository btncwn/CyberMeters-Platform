/**
 * Public Free Cyber MOT preview.
 * Backend owns every verdict/count. This page only presents the bounded,
 * non-persistent eight-domain projection and the verified-domain handoff.
 */
import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Clock3,
  FileLock2,
  Globe2,
  LockKeyhole,
  Moon,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Sun,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import FreeCyberMotPreviewGrid from '../components/FreeCyberMotPreviewGrid'
import { BASE } from '../api'
import {
  deriveFreeScanPresentation,
  FREE_SCAN_STATE_LABELS,
} from '../lib/freeScanPresentation'
import './FreeScanPage.css'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const LOADING_STEPS = [
  'Checking public DNS evidence',
  'Reviewing TLS and certificate signals',
  'Reading passive website headers',
  'Checking email-authentication evidence',
  'Reading Certificate Transparency records',
  'Observing public technology signals',
]

const MODULE_LABELS = {
  dns: 'DNS',
  ssl: 'TLS',
  headers: 'Headers',
  email_security: 'Email',
  subdomains: 'Certificate Transparency',
  technology_detection: 'Technology',
}

function signupPath(domain) {
  return `/signup${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`
}

function initialTheme() {
  if (typeof window === 'undefined') return 'light'
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function SeverityBar({ counts = {} }) {
  const total = SEVERITIES.reduce((sum, key) => sum + (Number(counts[key]) || 0), 0)
  return (
    <div className="fm-severity" aria-label="Finding severity breakdown">
      <div className="fm-severity__track" aria-hidden="true">
        {SEVERITIES.map((severity) => {
          const count = Number(counts[severity]) || 0
          return count > 0 ? (
            <span
              className={`fm-severity__segment fm-severity__segment--${severity}`}
              key={severity}
              style={{ width: `${(count / total) * 100}%` }}
            />
          ) : null
        })}
        {total === 0 && <span className="fm-severity__segment fm-severity__segment--empty" />}
      </div>
      <div className="fm-severity__legend">
        {SEVERITIES.map((severity) => (
          <span key={severity}>
            <i className={`fm-severity-dot fm-severity-dot--${severity}`} />
            {severity} <strong>{Number(counts[severity]) || 0}</strong>
          </span>
        ))}
      </div>
    </div>
  )
}

function Finding({ finding }) {
  return (
    <article className="fm-finding" data-severity={finding.severity || 'info'}>
      <div>
        <span className="fm-finding__severity">{finding.severity || 'info'}</span>
        <h3>{finding.title || 'Observed security signal'}</h3>
      </div>
      {finding.description && <p>{finding.description}</p>}
      {finding.academy_slug && (
        <Link to={`/academy/${finding.academy_slug}`}>Plain-English guidance <ArrowRight /></Link>
      )}
    </article>
  )
}

function LoadingState({ domain, step }) {
  return (
    <main className="fm-shell fm-loading-wrap">
      <section className="fm-loading" aria-live="polite">
        <div className="fm-loading__radar"><ScanSearch /></div>
        <span className="fm-kicker">Bounded public snapshot</span>
        <h1>Building the Cyber MOT for {domain}</h1>
        <p>One rate-limited snapshot. No report, scan history or monitoring record is stored.</p>
        <div className="fm-loading__steps">
          {LOADING_STEPS.map((label, index) => (
            <div className={index <= step ? 'is-active' : ''} key={label}>
              <span>{index < step ? <Check /> : index + 1}</span>
              {label}
            </div>
          ))}
        </div>
      </section>
    </main>
  )
}

export default function FreeScanPage() {
  const [domain, setDomain] = useState('')
  const [scanning, setScanning] = useState(false)
  const [step, setStep] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [theme, setTheme] = useState(initialTheme)
  const timerRef = useRef(null)
  const resultsRef = useRef(null)

  function normaliseDomain(value) {
    return value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
  }

  function stopCycle() {
    if (timerRef.current) clearInterval(timerRef.current)
    timerRef.current = null
  }

  async function handleScan(event) {
    event?.preventDefault()
    const target = normaliseDomain(domain)
    if (!target) return
    setDomain(target)
    setError(null)
    setResult(null)
    setScanning(true)
    setStep(0)
    let nextStep = 0
    timerRef.current = setInterval(() => {
      nextStep = Math.min(nextStep + 1, LOADING_STEPS.length - 1)
      setStep(nextStep)
    }, 1600)

    try {
      const response = await fetch(`${BASE || ''}/free-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: target }),
      })
      const data = await response.json()
      if (!response.ok) {
        setError(data.error || 'The snapshot could not be completed. Please try again.')
        return
      }
      setResult(data)
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80)
    } catch {
      setError('Connection error. Please check your network and try again.')
    } finally {
      stopCycle()
      setScanning(false)
    }
  }

  function reset() {
    setResult(null)
    setError(null)
  }

  const presentation = deriveFreeScanPresentation(result)
  const shownFindings = result?.shown_findings || result?.preview_findings || []
  const exposedFindingCount = Number(result?.exposed_finding_count) || shownFindings.length
  const lockedCount = Number(result?.locked_count ?? result?.hidden_count) || 0

  return (
    <div className="free-mot-page" data-theme={theme}>
      <header className="fm-header">
        <div className="fm-shell fm-header__inner">
          <Link to="/" aria-label="CyberMeters home"><CyberMetersLogo className="fm-logo" /></Link>
          <div className="fm-header__actions">
            <button
              className="fm-theme-toggle"
              type="button"
              onClick={() => setTheme((value) => value === 'dark' ? 'light' : 'dark')}
              aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`}
            >
              {theme === 'dark' ? <Sun /> : <Moon />}
            </button>
            <Link to="/login" className="fm-text-link">Sign in</Link>
            <Link to={signupPath(result?.domain)} className="fm-button fm-button--small">Start free trial</Link>
          </div>
        </div>
      </header>

      {!result && !scanning && (
        <main>
          <section className="fm-hero">
            <div className="fm-shell fm-hero__grid">
              <div>
                <span className="fm-kicker"><Sparkles /> Free Cyber MOT</span>
                <h1>See your whole external attack surface — before an attacker does.</h1>
                <p className="fm-hero__lede">
                  One bounded snapshot maps honest public signals across all eight Cyber MOT domains.
                  Deep takeover, CVE/KEV and asset checks unlock only after account and domain verification.
                </p>
                <form className="fm-scan-form" onSubmit={handleScan}>
                  <label htmlFor="free-scan-domain">Business domain</label>
                  <div>
                    <span aria-hidden="true"><Globe2 /></span>
                    <input
                      id="free-scan-domain"
                      value={domain}
                      onChange={(event) => setDomain(event.target.value)}
                      placeholder="yourbusiness.co.uk"
                      autoComplete="off"
                      spellCheck={false}
                      autoFocus
                    />
                    <button type="submit" disabled={!domain.trim()}>
                      Run my free Cyber MOT <ArrowRight />
                    </button>
                  </div>
                </form>
                {error && (
                  <div className="fm-error" role="alert"><AlertTriangle />{error}</div>
                )}
                <div className="fm-trust-row">
                  <span><ShieldCheck /> Passive external evidence</span>
                  <span><Clock3 /> Rate-limited single snapshot</span>
                  <span><FileLock2 /> Nothing stored</span>
                </div>
              </div>

              <aside className="fm-hero-panel" aria-label="Eight Cyber MOT domains">
                <div className="fm-hero-panel__header">
                  <span>Free Cyber MOT</span>
                  <strong>8 domains · one honest view</strong>
                </div>
                <div className="fm-mini-grid">
                  {[
                    'Email Protection', 'Brand Protection', 'Attack Surface', 'Certificates & Trust',
                    'Cyber Essentials', 'Website Security', 'Identity Exposure', 'Shadow IT',
                  ].map((label, index) => (
                    <div key={label}><span>{String(index + 1).padStart(2, '0')}</span>{label}</div>
                  ))}
                </div>
                <p><LockKeyhole /> Full findings, remediation, PDF and monitoring require a verified domain.</p>
              </aside>
            </div>
          </section>
        </main>
      )}

      {scanning && <LoadingState domain={domain} step={step} />}

      {result && !scanning && (
        <main ref={resultsRef} className="fm-shell fm-results">
          <div className="fm-result-title">
            <div>
              <span className="fm-kicker">Free Cyber MOT snapshot</span>
              <h1>{result.domain}</h1>
              <p>{result.scanned_at ? `Completed ${new Date(result.scanned_at).toLocaleString('en-GB')}` : 'Snapshot completed'}</p>
            </div>
            <button className="fm-button fm-button--secondary" onClick={reset} type="button">
              <RefreshCw /> Check another domain
            </button>
          </div>

          <section className="fm-summary" aria-labelledby="preview-summary-title">
            <div className="fm-summary__verdict">
              <span className="fm-summary__score">—</span>
              <div>
                <span className="fm-state-chip">Evidence incomplete</span>
                <h2 id="preview-summary-title">{presentation.headline}</h2>
                <p>{presentation.summary}</p>
              </div>
            </div>
            <div className="fm-summary__stats">
              <div><span>Observed findings</span><strong>{result.total_findings ?? 0}</strong></div>
              <div><span>Shown now</span><strong>{exposedFindingCount}</strong></div>
              <div><span>Sealed</span><strong>{lockedCount}</strong></div>
            </div>
            <SeverityBar counts={result.severity_counts} />
          </section>

          <div className="fm-module-row" aria-label="Preview module outcomes">
            {presentation.moduleEvidence.map((module) => (
              <span data-state={module.state} key={module.module}>
                {module.label || MODULE_LABELS[module.module]} · {FREE_SCAN_STATE_LABELS[module.state]}
              </span>
            ))}
          </div>

          <FreeCyberMotPreviewGrid domains={presentation.domains} />

          <aside className="fm-guardrail">
            <ShieldCheck />
            <div>
              <h2>Built to resist misuse</h2>
              <p>
                The public path is bounded by IP, domain and global throttles, rejects private/rebinding targets,
                stores no scan or report, and never runs deep asset fan-out anonymously.
              </p>
            </div>
          </aside>

          <section className="fm-findings" aria-labelledby="preview-findings-title">
            <div className="fm-section-heading">
              <div>
                <span className="fm-kicker">Evidence-backed preview</span>
                <h2 id="preview-findings-title">A bounded finding preview. Remaining detail stays sealed.</h2>
              </div>
              <p>No hidden finding detail is sent to the anonymous browser.</p>
            </div>
            <div className="fm-findings__grid">
              {shownFindings.length > 0
                ? shownFindings.map((finding) => <Finding finding={finding} key={finding.id} />)
                : (
                  <div className="fm-findings__empty">
                    No finding was exposed by the completed public checks. Evidence remains incomplete, so this is not a healthy verdict.
                  </div>
                )}
              <div className="fm-sealed">
                <LockKeyhole />
                <strong>{lockedCount > 0 ? `${lockedCount} more sealed` : 'Deep assessment sealed'}</strong>
                <span>Unlock only after account creation and canonical domain-ownership verification.</span>
              </div>
            </div>
          </section>

          <section className="fm-cta">
            <span className="fm-kicker">Turn the snapshot into a managed Cyber MOT</span>
            <h2>Start my 14-day trial</h2>
            <p>
              Verify the domain first, then unlock the full finding list, remediation, Executive PDF,
              re-scans and ongoing monitoring across all eight domains.
            </p>
            <Link to={signupPath(result.domain)} className="fm-button">
              Start my 14-day trial <ArrowRight />
            </Link>
            <small>No card · then from £9.99/mo · cancel anytime</small>
          </section>

          <p className="fm-honesty-note">
            DKIM uses common selectors. Certificate analysis is CT/TLS-only. Brand is watchlist-only.
            Cyber Essentials is indicative. Website checks are passive and external.
          </p>
        </main>
      )}

      <footer className="fm-footer">
        <div className="fm-shell">
          <span>© 2026 CyberMeters · UK cyber-security SaaS</span>
          <nav aria-label="Legal"><Link to="/privacy">Privacy</Link><Link to="/terms">Terms</Link><Link to="/support">Support</Link></nav>
        </div>
      </footer>
    </div>
  )
}
