import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { TOKEN_KEY } from '../../context/authKeys'
import PublicSiteFooter from '../PublicSiteFooter'
import PublicSiteHeader from '../PublicSiteHeader'
import ToolResult from './ToolResult'
import SomethingWrong from '../SomethingWrong'
import TurnstileWidget from './TurnstileWidget'

const CALLS = {
  dmarc: { run: api.runDmarcTool, defer: api.deferDmarcTool },
  spf: { run: api.runSpfTool, defer: api.deferSpfTool },
  headers: { run: api.runHeadersTool, defer: api.deferHeadersTool },
  lookalike: { run: api.runLookalikeTool, defer: api.deferLookalikeTool },
  ssl: { run: api.runSslTool, defer: api.deferSslTool },
}

// How each tool looks at a domain, said under the form. The lookalike count
// is the engine's own maximum, published by the API config.
function methodNote(tool, config) {
  if (tool === 'headers') return 'One request to your home page over HTTPS; only the response headers are read.'
  if (tool === 'ssl') return 'One secure connection to port 443 on one address; only the certificate is read.'
  if (tool === 'lookalike') {
    const max = config?.limits?.lookalike_max_candidates
    return Number.isInteger(max) ? `Passive DNS lookups only, for up to ${max} close variants of your name.` : 'Passive DNS lookups only, for close variants of your name.'
  }
  return 'Passive DNS lookups only.'
}

// What CyberMeters keeps watching after this one check, per tool.
const KEEP_WATCHING = {
  dmarc: 'This is one check, once. CyberMeters Email Protection re-checks your DMARC, SPF and DKIM on a schedule, tells you when a record changes, and tracks each fix until it is verified.',
  spf: 'This is one check, once. CyberMeters Email Protection re-checks your DMARC, SPF and DKIM on a schedule, tells you when a record changes, and tracks each fix until it is verified.',
  headers: 'This is one check, once. CyberMeters Website Security re-checks your HTTPS and security headers on a schedule, tells you when one changes, and tracks each fix until it is verified.',
  lookalike: 'This is one check, once. CyberMeters Brand Protection keeps watching for new lookalike domains, shows what each one points at, and tracks what you decide to do about it.',
  ssl: 'This is one check, once. CyberMeters Certificates & Trust watches your certificates, alerts you before one expires, and tracks each renewal until it is verified.',
}

// The tool name a "Something wrong?" report carries.
const TOOL_SLUGS = { dmarc: 'dmarc-checker', spf: 'spf-checker', headers: 'security-headers-checker', lookalike: 'lookalike-domain-checker', ssl: 'ssl-checker' }

const TRIAL_URL = 'https://app.cybermeters.com/signup'
// C-46 rank 8: the trial keeps the checked domain, as the main free check does.
export function trialUrlFor(domain) {
  const d = String(domain || '').trim().toLowerCase()
  return d ? `${TRIAL_URL}?domain=${encodeURIComponent(d)}` : TRIAL_URL
}

function hasSession() {
  try { return Boolean(localStorage.getItem(TOKEN_KEY)) } catch { return false }
}

function resetTime(iso) {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return null
  const sameDay = date.toDateString() === new Date().toDateString()
  return date.toLocaleString(undefined, sameDay ? { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' } : { weekday: 'short', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
}

function shareTokenFromHash() {
  if (typeof window === 'undefined') return null
  const match = window.location.hash.match(/^#share=([A-Za-z0-9._-]+)$/)
  return match ? match[1] : null
}

function LimitNotice({ outcome, toolName, domain = '' }) {
  const at = resetTime(outcome.reset_at)
  const what = outcome.scope === 'domain'
    ? `This domain has been checked many times in the last hour${at ? `; you can check it again after ${at}` : ''}.`
    : outcome.scope === 'user'
      ? `You have reached today's ${toolName} limit for your account${at ? `; it resets at ${at}` : ''}.`
      : `You have used today's free ${toolName} checks from this connection${at ? `. You can run another after ${at}` : ''}.`
  return (
    <section className="rounded-2xl border border-sky-200 bg-sky-50 p-5 sm:p-6 space-y-3" aria-live="polite">
      <h2 className="text-lg font-bold text-sky-950">That's today's free checks</h2>
      <p className="text-sky-950">{what}</p>
      <p className="text-sm text-sky-900">A 14-day trial checks your domains on a schedule and tells you when something changes, with the full remediation steps.</p>
      <a href={outcome.trial_url || trialUrlFor(domain)} className="btn-primary inline-flex">Start a 14-day trial</a>
    </section>
  )
}

function DeferForm({ tool, toolName, domain, siteKey, onQueued }) {
  const [email, setEmail] = useState('')
  const [consent, setConsent] = useState(false)
  const [token, setToken] = useState(null)
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(false)
  const widget = useRef(null)
  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setMessage(null)
    try {
      const outcome = await CALLS[tool].defer({ domain, email, consent, turnstile_token: token })
      if (outcome.body?.status === 'queued') onQueued(outcome.body.message)
      else setMessage(outcome.body?.message || 'That did not work. Please try again.')
    } catch {
      setMessage('That did not work. Please check your connection and try again.')
    } finally {
      setBusy(false)
      widget.current?.reset()
    }
  }
  return (
    <section className="rounded-2xl border border-sky-200 bg-sky-50 p-5 sm:p-6 space-y-4" aria-live="polite">
      <h2 className="text-lg font-bold text-sky-950">Free checks are very busy today</h2>
      <p className="text-sky-950">Leave your email and we will run the {toolName} check for {domain} and send you the result as soon as capacity returns, usually within a day.</p>
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-sm font-semibold text-sky-950" htmlFor="defer-email">Email</label>
        <input id="defer-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-lg border border-gray-300 px-3 py-2" autoComplete="email" />
        <label className="flex gap-2 items-start text-sm text-sky-950">
          <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-1" />
          <span>Email me this one result. CyberMeters uses this address for nothing else and deletes it once the result is sent.</span>
        </label>
        <TurnstileWidget ref={widget} siteKey={siteKey} action={`tool_${tool}_defer`} onToken={setToken} />
        {message && <p className="text-sm text-sky-950">{message}</p>}
        <button type="submit" className="btn-primary" disabled={busy || !consent || !email || (!token && !hasSession())}>Email me the result</button>
      </form>
    </section>
  )
}

/**
 * One free tool: the form, the human check, and every answer the gate can
 * give (result, used-up allowance, busy day, unavailable). A shared link
 * (#share=…) is checked by the API before it is shown.
 */
export default function FreeToolPage({ tool, toolName, title, intro, placeholder = 'example.com', Details, about }) {
  const [config, setConfig] = useState(null)
  const [domain, setDomain] = useState('')
  const [token, setToken] = useState(null)
  const [phase, setPhase] = useState('idle')
  const [outcome, setOutcome] = useState(null)
  const [shared, setShared] = useState(null)
  const [queuedMessage, setQueuedMessage] = useState(null)
  const widget = useRef(null)

  useEffect(() => {
    let cancelled = false
    api.freeToolConfig()
      .then((res) => { if (!cancelled) setConfig(res.ok ? res.body : { available: false }) })
      .catch(() => { if (!cancelled) setConfig({ available: false }) })
    const shareToken = shareTokenFromHash()
    if (shareToken) {
      api.verifyToolShare(shareToken)
        .then((res) => {
          if (cancelled) return
          setShared(res.ok && res.body?.result?.tool === tool
            ? { result: res.body.result, expires_at: res.body.expires_at }
            : { error: res.body?.status === 'expired_link' ? 'This shared link has expired. Run a new check below.' : 'This shared link could not be checked. Run a new check below.' })
        })
        .catch(() => { if (!cancelled) setShared({ error: 'This shared link could not be checked right now.' }) })
    }
    return () => { cancelled = true }
  }, [tool])

  const submit = async (event) => {
    event.preventDefault()
    setPhase('running')
    setOutcome(null)
    setQueuedMessage(null)
    try {
      const res = await CALLS[tool].run({ domain, turnstile_token: token })
      setOutcome(res.body || {})
      const status = res.body?.status
      setPhase(status === 'ok' ? 'result'
        : status === 'limit_reached' ? 'limit'
          : status === 'capacity_paused' ? 'capacity'
            : 'message')
    } catch {
      setOutcome({ message: 'The check could not reach CyberMeters. Please check your connection and try again.' })
      setPhase('message')
    } finally {
      widget.current?.reset()
    }
  }

  // The API lists the tools it serves; a tool it does not list yet (a page
  // published before its Worker) is unavailable rather than silently empty.
  const served = !Array.isArray(config?.tools) || config.tools.some((t) => t.id === tool)
  const available = config?.available === true && served
  const submittedDomain = outcome?.result?.domain || domain.trim()
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <PublicSiteHeader />
      <main className="max-w-3xl mx-auto px-4 sm:px-6 py-10 sm:py-12 space-y-8">
        <header className="space-y-3">
          <nav aria-label="Breadcrumb" className="text-sm text-gray-500"><Link to="/tools" className="hover:text-gray-900">Free tools</Link> / {toolName}</nav>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">{title}</h1>
          <p className="text-gray-600 leading-relaxed">{intro}</p>
        </header>

        {shared?.result && (
          <section className="space-y-4">
            <p className="text-sm text-gray-600">A shared result. It shows the check as it was then; run your own below for a current answer.</p>
            <ToolResult result={shared.result} sharedUntil={shared.expires_at}><Details result={shared.result} /></ToolResult>
          </section>
        )}
        {shared?.error && <p className="rounded-xl border border-gray-200 bg-white p-4 text-sm text-gray-700">{shared.error}</p>}

        <section className="rounded-2xl border border-gray-100 bg-white shadow-xs p-5 sm:p-6 space-y-4">
          {config && !available ? (
            <p className="text-gray-700">Free checks are not available right now. Please try again later.</p>
          ) : (
            <form onSubmit={submit} className="space-y-4">
              <label htmlFor="tool-domain" className="block text-sm font-semibold">Domain</label>
              <div className="flex flex-col sm:flex-row gap-3">
                <input id="tool-domain" name="domain" inputMode="url" autoCapitalize="none" spellCheck="false" required placeholder={placeholder}
                  value={domain} onChange={(e) => setDomain(e.target.value)} className="flex-1 rounded-lg border border-gray-300 px-3 py-2.5 text-base" />
                <button type="submit" className="btn-primary justify-center" disabled={!available || phase === 'running' || !domain.trim() || (!token && !hasSession())}>
                  {phase === 'running' ? 'Checking…' : `Check ${toolName}`}
                </button>
              </div>
              {available && <TurnstileWidget ref={widget} siteKey={config.turnstile_site_key} action={`tool_${tool}`} onToken={setToken} />}
              <p className="text-xs text-gray-500">{methodNote(tool, config)} Two free checks per tool every 24 hours; signed-in workspace users are not limited by this. The domain you check is not saved: a result is reused for up to 10 minutes, then dropped.</p>
            </form>
          )}
        </section>

        {phase === 'result' && outcome?.result && (
          <ToolResult result={outcome.result} cached={outcome.cached} share={outcome.share}><Details result={outcome.result} /></ToolResult>
        )}
        {phase === 'limit' && <LimitNotice outcome={outcome} toolName={toolName} domain={domain} />}
        {phase === 'capacity' && !queuedMessage && (
          <DeferForm tool={tool} toolName={toolName} domain={submittedDomain} siteKey={config?.turnstile_site_key} onQueued={setQueuedMessage} />
        )}
        {queuedMessage && <p className="rounded-2xl border border-emerald-200 bg-emerald-50 p-5 text-emerald-950" aria-live="polite">{queuedMessage}</p>}
        {phase === 'message' && outcome?.message && <p className="rounded-xl border border-gray-200 bg-white p-4 text-gray-700" aria-live="polite">{outcome.message}</p>}
        {(phase === 'result' || phase === 'message' || shared) && (
          <SomethingWrong surface="free_tool" tool={TOOL_SLUGS[tool]} errorCode={phase === 'message' ? (outcome?.code || outcome?.status || null) : null} className="text-gray-600" />
        )}

        {about}

        <section className="rounded-2xl border border-gray-100 bg-white p-5 sm:p-6 space-y-3">
          <h2 className="text-lg font-bold">Keep watching it</h2>
          <p className="text-sm text-gray-600">{KEEP_WATCHING[tool]}</p>
          <div className="flex flex-wrap gap-3"><a href={trialUrlFor(phase === 'result' ? (outcome?.domain || domain) : domain)} className="btn-primary">Start a 14-day trial</a><Link to="/tools" className="btn-secondary">More free tools</Link></div>
        </section>
      </main>
      <PublicSiteFooter />
    </div>
  )
}
