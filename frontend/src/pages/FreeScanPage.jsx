/**
 * Public Free Cyber MOT preview.
 * Backend owns every verdict/count. This page only presents the bounded,
 * non-persistent eight-domain projection and the verified-domain handoff.
 */
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Moon, Sun } from 'lucide-react'
import { formatDate } from '../utils/dates'
import CyberMetersLogo from '../components/CyberMetersLogo'
import FreeCyberMotPreviewGrid from '../components/FreeCyberMotPreviewGrid'
import SomethingWrong from '../components/SomethingWrong'
import { BASE, api } from '../api'
import { useAuth } from '../context/AuthContext'
import { findOwnWorkspaceForDomain } from '../lib/freeScanWorkspaceMatch'
import { SERVICE_COLORS } from '../theme/serviceColors'
import { marketingHomeHref } from '../utils/siteLinks'
import {
  deriveFreeScanPresentation,
  FREE_SCAN_STATE_LABELS,
  moreInTrialCopy,
} from '../lib/freeScanPresentation'
import './FreeScanPage.css'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

// The areas the full check covers, in the product's presentation order.
const AREAS = [
  { key: 'identity', label: 'Identity Exposure' },
  { key: 'surface', label: 'Attack Surface' },
  { key: 'email', label: 'Email Protection' },
  { key: 'website', label: 'Website Security' },
  { key: 'shadow_it', label: 'Shadow IT' },
  { key: 'certs', label: 'Certificates & Trust' },
  { key: 'brand', label: 'Brand Protection' },
  { key: 'cyber_essentials', label: 'Cyber Essentials' },
]

// Backend-ranked severities, most urgent first. Presentation order only.
function bySeverity(findings) {
  const rank = severity => {
    const i = SEVERITIES.indexOf(severity)
    return i === -1 ? SEVERITIES.length : i
  }
  return [...findings].sort((a, b) => rank(a.severity) - rank(b.severity))
}

const LOADING_STEPS = [
  'Checking public DNS evidence',
  'Reviewing HTTPS reachability',
  'Reading passive website headers',
  'Checking email-authentication evidence',
  'Observing public technology signals',
]

const MODULE_LABELS = {
  dns: 'DNS',
  ssl: 'HTTPS',
  headers: 'Headers',
  email_security: 'Email',
  technology_detection: 'Technology',
}

function signupPath(domain) {
  return `/signup${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`
}

// A domain handed over by the landing page form (/free-scan?domain=…).
// Only a syntactically valid hostname is accepted; anything else is ignored.
export function domainFromQuery(search) {
  const raw = new URLSearchParams(search || '').get('domain') || ''
  const d = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '').replace(/\.$/, '')
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d) ? apexOf(d) : ''
}

// The check runs on the business domain the account would verify, so
// www.example.co.uk becomes example.co.uk. The API applies the same rule.
export function apexOf(domain) {
  return domain.replace(/^www\.(?=[^.]+\.)/, '')
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
        <Link to={`/guide/${finding.academy_slug}`}>Plain-English guidance</Link>
      )}
    </article>
  )
}

function LoadingState({ domain, step }) {
  return (
    <main className="fm-shell fm-loading-wrap">
      <section className="fm-loading" aria-live="polite">
        <span className="fm-kicker">Bounded public snapshot</span>
        <h1>Building the Cyber MOT for {domain}</h1>
        <p>One rate-limited snapshot. No report, scan history or monitoring record is stored.</p>
        <div className="fm-loading__steps">
          {LOADING_STEPS.map((label, index) => (
            <div className={index <= step ? 'is-active' : ''} key={label}>
              <span>{index + 1}</span>
              {label}
            </div>
          ))}
        </div>
      </section>
    </main>
  )
}

export default function FreeScanPage() {
  const [domain, setDomain] = useState(() => (typeof window === 'undefined' ? '' : domainFromQuery(window.location.search)))
  const [scanning, setScanning] = useState(false)
  const [step, setStep] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [errorCode, setErrorCode] = useState(null)
  const [theme, setTheme] = useState(initialTheme)
  const { isAuthenticated } = useAuth()
  // Signed-in visitors only: is this domain already in one of their own
  // workspaces? Anonymous visitors make no extra request and see the same page.
  const [ownWorkspace, setOwnWorkspace] = useState(null)
  const resultDomain = result?.domain || null
  useEffect(() => {
    setOwnWorkspace(null)
    if (!isAuthenticated || !resultDomain) return undefined
    let alive = true
    findOwnWorkspaceForDomain(api, resultDomain).then((match) => { if (alive) setOwnWorkspace(match) })
    return () => { alive = false }
  }, [isAuthenticated, resultDomain])
  const timerRef = useRef(null)
  const resultsRef = useRef(null)

  function normaliseDomain(value) {
    return apexOf(value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
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
    setErrorCode(null)
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
        setErrorCode(data.code || `http_${response.status}`)
        return
      }
      setResult(data)
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80)
    } catch {
      setError('Connection error. Please check your network and try again.')
      setErrorCode('network_error')
    } finally {
      stopCycle()
      setScanning(false)
    }
  }

  // The visitor already pressed "Run a free check" on the landing page: run it
  // once, then drop the parameter so a refresh does not start another snapshot.
  const handedOver = useRef(false)
  useEffect(() => {
    if (handedOver.current || !domainFromQuery(window.location.search)) return
    handedOver.current = true
    window.history.replaceState(window.history.state, '', window.location.pathname)
    handleScan()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function reset() {
    setResult(null)
    setError(null)
  }

  const presentation = deriveFreeScanPresentation(result)
  const shownFindings = result?.shown_findings || result?.preview_findings || []
  const exposedFindingCount = Number(result?.exposed_finding_count) || shownFindings.length
  const lockedCount = Number(result?.locked_count ?? result?.hidden_count) || 0
  // Where the rest of the detail lives: the trial, or the visitor's own workspace.
  const moreWhere = ownWorkspace ? 'in your workspace' : 'in the trial'

  return (
    <div className="free-mot-page" data-theme={theme}>
      <header className="fm-header">
        <div className="fm-shell fm-header__inner">
          <a href={marketingHomeHref()} aria-label="CyberMeters home"><CyberMetersLogo size={28} showWordmark darkMode={theme === 'dark'} /></a>
          <div className="fm-header__actions">
            <button
              className="fm-theme-toggle"
              type="button"
              onClick={() => setTheme((value) => value === 'dark' ? 'light' : 'dark')}
              aria-label={`Use ${theme === 'dark' ? 'light' : 'dark'} theme`}
            >
              {theme === 'dark' ? <Sun /> : <Moon />}
            </button>
            {isAuthenticated ? (
              <Link to="/dashboard" className="fm-button fm-button--small">Go to dashboard</Link>
            ) : (
              <>
                <Link to="/login" className="fm-text-link">Sign in</Link>
                <Link to={signupPath(result?.domain)} className="fm-button fm-button--small">Start 14-day trial</Link>
              </>
            )}
          </div>
        </div>
      </header>

      {!result && !scanning && (
        <main>
          <section className="fm-hero">
            <div className="fm-shell fm-hero__grid">
              <div>
                <span className="fm-kicker">Free Cyber MOT</span>
                <h1>See what your domain shows the internet — before an attacker does.</h1>
                <p className="fm-hero__lede">
                  Five bounded public checks, summarised across your external posture.
                  Deep takeover and asset checks unlock only after account and domain verification.
                </p>
                <form className="fm-scan-form" onSubmit={handleScan}>
                  <label htmlFor="free-scan-domain">Business domain</label>
                  <div>
                    {/* Empty first grid cell keeps the input's left inset. */}
                    <span aria-hidden="true" />
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
                      Run my free Cyber MOT
                    </button>
                  </div>
                </form>
                {error && (
                  <>
                    <div className="fm-error" role="alert">{error}</div>
                    <SomethingWrong surface="free_scan" errorCode={errorCode} className="mt-3" />
                  </>
                )}
                <div className="fm-trust-row">
                  <span>Passive external evidence</span>
                  <span>Rate-limited single snapshot</span>
                  <span>No scan report saved</span>
                </div>
              </div>

              <aside className="fm-hero-panel" aria-label="What the free check covers">
                <div className="fm-hero-panel__header">
                  <span>Free Cyber MOT</span>
                  <strong>One honest view</strong>
                </div>
                <ul className="fm-area-list">
                  {AREAS.map(area => (
                    <li key={area.key}>
                      <i style={{ background: SERVICE_COLORS[area.key]?.icon }} aria-hidden="true" />
                      {area.label}
                    </li>
                  ))}
                </ul>
                <p>These five checks may leave some areas unassessed. Full findings, remediation, PDF and monitoring require a verified domain. Limited rate-limit records are kept to prevent misuse.</p>
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
              <p>{result.scanned_at ? `Completed ${formatDate(result.scanned_at)}` : 'Snapshot completed'}</p>
            </div>
            <button className="fm-button fm-button--secondary" onClick={reset} type="button">
              Check another domain
            </button>
          </div>

          <section className="fm-summary" aria-labelledby="preview-summary-title">
            <div className="fm-summary__verdict">
              <span className="fm-summary__score">—</span>
              <div>
                <span className="fm-state-chip" data-state={presentation.badgeState} data-tone={presentation.informationalOnly ? 'info' : undefined} data-testid="preview-badge">{presentation.badge}</span>
                <h2 id="preview-summary-title">{presentation.headline}</h2>
                <p>{presentation.summary}</p>
              </div>
            </div>
            <div className="fm-summary__stats">
              <div><span>Observed findings</span><strong>{result.total_findings ?? 0}</strong></div>
              <div><span>Shown now</span><strong>{exposedFindingCount}</strong></div>
              <div><span>{`More findings ${moreWhere}`}</span><strong>{lockedCount}</strong></div>
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
          {presentation.moduleEvidence.some((module) => module.checks) && (
            <details className="fm-module-scope">
              <summary>What these checks covered</summary>
              <dl>
                {presentation.moduleEvidence.filter((module) => module.checks).map((module) => (
                  <div key={module.module} style={{ display: 'contents' }}>
                    <dt>{module.label || MODULE_LABELS[module.module]}</dt>
                    <dd>{module.checks}</dd>
                  </div>
                ))}
              </dl>
            </details>
          )}

          <section className="fm-findings" aria-labelledby="preview-findings-title">
            <div className="fm-section-heading">
              <div>
                <span className="fm-kicker">Evidence-backed preview</span>
                <h2 id="preview-findings-title">{ownWorkspace ? 'A bounded finding preview. The full list is in your workspace.' : 'A bounded finding preview. The full list comes with the trial.'}</h2>
              </div>
              <p>No hidden finding detail is sent to the anonymous browser.</p>
            </div>
            <div className="fm-findings__grid">
              {shownFindings.length > 0
                ? bySeverity(shownFindings).map((finding) => <Finding finding={finding} key={finding.id} />)
                : (
                  <div className="fm-findings__empty">
                    No finding was exposed by the completed public checks. Evidence remains incomplete, so this is not a healthy verdict.
                  </div>
                )}
              <div className="fm-sealed">
                {ownWorkspace ? (
                  <>
                    <strong>{lockedCount > 0 ? moreInTrialCopy(lockedCount, 'finding', moreWhere) : 'Deeper checks are in your workspace'}</strong>
                    <span>{ownWorkspace.verified ? 'Open the workspace to see every finding.' : 'Shown in your workspace once you verify the domain.'}</span>
                  </>
                ) : (
                  <>
                    <strong>{lockedCount > 0 ? moreInTrialCopy(lockedCount) : 'Deeper checks come with the trial'}</strong>
                    <span>Shown in your 14-day trial, once you verify you own the domain.</span>
                  </>
                )}
              </div>
            </div>
          </section>

          {ownWorkspace ? (
            <section className="fm-cta" data-testid="free-scan-own-workspace">
              <span className="fm-kicker">Already in your workspace</span>
              <h2>{ownWorkspace.verified ? 'You already monitor this domain' : 'This domain is in your workspace'}</h2>
              <p>
                {ownWorkspace.verified
                  ? `${result.domain} is verified in ${ownWorkspace.workspace_name}. Open the workspace for every finding, its remediation and the monitoring history.`
                  : `${result.domain} is in ${ownWorkspace.workspace_name} but not verified yet. Finish verification there to see every finding and start monitoring.`}
              </p>
              <Link to={`/workspaces/${encodeURIComponent(ownWorkspace.workspace_id)}`} className="fm-button">
                Open workspace
              </Link>
            </section>
          ) : (
            <section className="fm-cta">
              <span className="fm-kicker">Turn the snapshot into a managed Cyber MOT</span>
              <h2>Start my 14-day trial</h2>
              <p>
                Verify the domain first, then unlock the full finding list, remediation, Executive PDF,
                re-scans and ongoing monitoring.
              </p>
              <ol className="fm-cta__steps">
                <li>Create your account</li>
                <li>Add one DNS TXT record to verify {result.domain}</li>
                <li>See each finding with the steps to fix it</li>
              </ol>
              <Link to={signupPath(result.domain)} className="fm-button">
                Start my 14-day trial
              </Link>
              <small>No card · then from £9.99/mo · cancel anytime</small>
            </section>
          )}


          <FreeCyberMotPreviewGrid domains={presentation.domains} moreWhere={moreWhere} />

          <aside className="fm-guardrail">
            <div>
              <h2>Built to resist misuse</h2>
              <p>
                The public path is bounded by IP, domain and global throttles, rejects private/rebinding targets,
                stores no scan or report, and never runs deep asset fan-out anonymously.
              </p>
            </div>
          </aside>

          <p className="fm-honesty-note">
            DKIM uses common selectors. The served certificate is inspected in the full scan, not in this preview. Brand is watchlist-only.
            Cyber Essentials is indicative. Website checks are passive and external.
          </p>

          <SomethingWrong surface="free_scan" className="fm-feedback" />
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
