import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  ScanLine, Globe, ArrowLeft, CheckCircle,
  Shield, Mail, FileText, Info, ShieldCheck,
} from 'lucide-react'
import { api } from '../api'
import ErrorAlert from '../components/ErrorAlert'
import Spinner from '../components/Spinner'
import DomainVerificationPanel from '../components/DomainVerificationPanel'
import { useWorkspace } from '../hooks/useWorkspace'
import {
  canStartScan, isValidDomainSyntax, domainHintFor, safeErrorMessage,
  isVerificationRequired, dnsInstructionFrom, checkFailureMessage,
  requiresVerificationCta, verifyFailureNote,
} from '../lib/newScanVerification'

// Framed as Intelligence Engines (business capabilities), not internal detectors.
const CHECKS = [
  { icon: Globe,    label: 'Attack Surface Intelligence',  desc: 'Exposed assets, DNS, certificates and website security'   },
  { icon: Mail,     label: 'Business Email Intelligence',  desc: 'Protection against email spoofing and phishing'           },
  { icon: Shield,   label: 'Brand Intelligence',           desc: 'Lookalike and typosquatting domains impersonating you'    },
  { icon: FileText, label: 'Executive Intelligence',       desc: 'A scored Executive Report with prioritized next steps'    },
]


export default function NewScan() {
  const [domain, setDomain]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [success, setSuccess] = useState(null)
  // Ownership state — the single source of truth for what the page may claim and
  // whether Start Scan is enabled. Syntax alone never unlocks it.
  const [state, setState]     = useState('idle')
  // The EXACT workspace-domain record the backend gated on. A domain can be linked
  // to several of the caller's workspaces, so we must never choose one ourselves.
  const [gated, setGated]     = useState(null)
  const [dns, setDns]         = useState(null)
  const [checkNote, setCheckNote] = useState(null)
  const { wsId } = useWorkspace()
  const navigate = useNavigate()

  // Clicking "New Scan" in the header while already on this page resets the form
  // to a clean state (Router won't remount the same route on its own).
  useEffect(() => {
    const reset = () => {
      setDomain(''); setError(null); setSuccess(null); setLoading(false)
      setState('idle'); setGated(null); setDns(null); setCheckNote(null)
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
    window.addEventListener('cybermeters:new-scan-reset', reset)
    return () => window.removeEventListener('cybermeters:new-scan-reset', reset)
  }, [])

  const valid = isValidDomainSyntax(domain)
  const hint  = domainHintFor(state, domain)

  // Typing a different domain invalidates ownership proven for the previous one —
  // otherwise a verified domain would silently authorise scanning a different,
  // unverified one.
  // Typing a different domain invalidates ownership proven for the previous one —
  // otherwise a verified domain would silently authorise scanning a different,
  // unverified one.
  function onDomainChange(next) {
    setDomain(next)
    setState(isValidDomainSyntax(next) ? 'valid_unverified' : 'idle')
    setGated(null); setDns(null); setCheckNote(null); setError(null)
  }

  // Resolve ownership for the typed domain the moment it is syntactically valid.
  //
  // This is the fix for the deadlock: the page previously learned the domain_id
  // ONLY from a failed scan, but Start Scan was disabled until verified — so the
  // request that would have revealed it could never be sent. Resolution now happens
  // before any scan action, through the existing workspace-scoped lookup.
  useEffect(() => {
    if (!wsId || !isValidDomainSyntax(domain)) return
    let cancelled = false
    const t = setTimeout(async () => {
      setState('resolving')
      try {
        const res = await api.getWorkspaceDomains(wsId)
        if (cancelled) return
        const wanted = domain.trim().toLowerCase()
        // The EXACT link in THIS workspace. Never matched on hostname alone across
        // workspaces: the same domain can exist under several ids, and the scan gate
        // honours one specific (workspace_id, domain_id) link.
        const record = (res?.domains || []).find((d) => String(d.domain || '').toLowerCase() === wanted)
        if (!record) { setGated(null); setState('valid_unverified'); return }
        setGated({ domain_id: record.domain_id, workspace_id: wsId })
        // verification_status is the authoritative workspace-scoped link status.
        setState(record.verification_status === 'verified' ? 'verified' : 'valid_unverified')
      } catch {
        if (!cancelled) setState('valid_unverified')   // fail closed: never claim verified
      }
    }, 400)
    return () => { cancelled = true; clearTimeout(t) }
  }, [wsId, domain])

  // "Verify domain ownership" — the CTA that was missing. Links the domain to this
  // workspace if it is not linked yet (the same canonical step the scan route did
  // implicitly), then initiates through the canonical route.
  async function handleStartVerification() {
    if (!wsId) return
    setState('initiating_verification'); setError(null); setCheckNote(null)
    try {
      let record = gated
      // The debounced resolve may not have landed yet (a fast click). Resolve
      // synchronously before falling back to linking — otherwise we would add a
      // domain that is already linked, purely because we raced our own lookup.
      if (!record?.domain_id) {
        const wanted = domain.trim().toLowerCase()
        const res = await api.getWorkspaceDomains(wsId).catch(() => null)
        const existing = (res?.domains || []).find((d) => String(d.domain || '').toLowerCase() === wanted)
        // setGated on EVERY resolution path, not just the add-domain branch below.
        // Assigning only the local `record` left component state null for an
        // already-linked domain, so initiation worked (it uses `record`) while the
        // later Verify click had no record to act on — an inert button.
        if (existing) { record = { domain_id: existing.domain_id, workspace_id: wsId }; setGated(record) }
      }
      if (!record?.domain_id) {
        const added = await api.addDomainToWorkspace(wsId, domain.trim().toLowerCase())
        const id = added?.domain?.id || added?.domain_id || added?.id
        if (!id) { setError(safeErrorMessage({})); setState('valid_unverified'); return }
        record = { domain_id: id, workspace_id: wsId }
        setGated(record)
      }
      const res = await api.generateDomainVerification(record.domain_id, record.workspace_id)
      if (res?.already_verified) { setState('verified'); return }
      const instruction = dnsInstructionFrom(res)
      if (!instruction) { setError(safeErrorMessage({})); setState('valid_unverified'); return }
      setDns(instruction); setState('instructions')
    } catch (e) {
      setError(safeErrorMessage(e)); setState('valid_unverified')
    }
  }

  // Resolve the authoritative workspace-domain record. Shared by the CTA and the
  // Verify click so neither can act on a record the other resolved locally.
  async function resolveGatedRecord() {
    if (gated?.domain_id) return gated
    if (!wsId) return null
    const wanted = domain.trim().toLowerCase()
    const res = await api.getWorkspaceDomains(wsId).catch(() => null)
    const existing = (res?.domains || []).find((d) => String(d.domain || '').toLowerCase() === wanted)
    if (!existing) return null
    const record = { domain_id: existing.domain_id, workspace_id: wsId }
    setGated(record)
    return record
  }

  // "I've added the DNS record — Verify domain".
  //
  // This previously opened with `if (!gated) return` — a SILENT no-op. For an
  // already-linked domain `gated` was never set (see handleStartVerification), so the
  // button did nothing at all: no request, no spinner, no error. The customer had a
  // correct TXT record published and a dead button.
  //
  // Every path below now ends in exactly one visible state. There is no early return.
  async function handleVerify() {
    setState('checking'); setCheckNote(null); setError(null)
    try {
      // Re-resolve rather than give up: a missing record is recoverable, and
      // silence is not an acceptable outcome of a click.
      const record = await resolveGatedRecord()
      if (!record?.domain_id) {
        setState('check_failed')
        setCheckNote('We could not identify this domain in your workspace. Reload the page and try again — your DNS record is unaffected.')
        return
      }
      // Uses the record's EXISTING token: this only re-checks DNS. It never mints a
      // new token, so a published TXT record stays valid across retries.
      const res = await api.verifyDomain(record.domain_id, record.workspace_id)
      if (res?.verified || res?.success === true || res?.verification_status === 'verified') {
        setState('verified'); setCheckNote(null)
        // Refresh the authoritative workspace-domain state so the rest of the page
        // (and a later revisit) reads the confirmed row.
        //
        // It deliberately CANNOT downgrade the result. The verify response is the
        // server confirming a write it just made in that same request; a refresh
        // that reads a stale replica would otherwise flip a genuine success back to
        // "failed" and tell the customer their correct DNS record did not work. A
        // disagreement here is a server-side concern, not something to surface as
        // the customer's failure.
        try {
          const fresh = await api.getWorkspaceDomains(wsId)
          const row = (fresh?.domains || []).find((d) => d.domain_id === record.domain_id)
          if (row && row.verification_status !== 'verified') {
            console.warn('[new-scan] verify succeeded but the refreshed link is not yet verified', row.verification_status)
          }
        } catch { /* a refresh failure must never undo a confirmed verification */ }
        return
      }
      // Not verified. Use the server's own per-method result so the customer is told
      // which check failed, not a generic shrug.
      setState('check_failed'); setCheckNote(verifyFailureNote(res))
    } catch (e) {
      // A rejected promise must NEVER leave the UI unchanged.
      setState('check_failed'); setCheckNote(checkFailureMessage(e))
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!valid) return
    setLoading(true)
    setError(null)
    setState((prev) => (prev === 'verified' ? 'scanning' : 'starting'))
    try {
      const data = await api.createScan(domain.trim().toLowerCase())
      setSuccess(data)
      setTimeout(() => {
        const id = data?.scan?.id || data?.id
        navigate(id ? `/scans/${id}` : '/scans')
      }, 1500)
    } catch (e) {
      // Plan-limit and rate-limit errors are handled by the global UpgradePromptModal
      // (fired via the cybermeters:plan-limit event in api.js). Suppress the inline
      // ErrorAlert so the user sees one clear message, not two conflicting ones.
      if (isVerificationRequired(e)) {
        // Defence in depth. Ownership is now resolved BEFORE the scan action, so
        // this should not normally fire — but if the gate ever refuses anyway, fall
        // back to the verification flow rather than a dead end. The server names the
        // exact record it gated on, so we never guess.
        setGated({ domain_id: e.domain_id, workspace_id: e.workspace_id })
        setState('valid_unverified'); setError(null)
      } else if (e.code !== 'plan_limit_exceeded' && e.code !== 'rate_limit_exceeded') {
        // safeErrorMessage guarantees a machine code never reaches the customer.
        setError(safeErrorMessage(e)); setState(valid ? 'valid_unverified' : 'idle')
      } else {
        setState(valid ? 'valid_unverified' : 'idle')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <Link to="/dashboard" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-brand-600 transition-colors mb-6 font-medium">
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>

      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">New Scan</h1>
        <p className="text-sm text-gray-400 mt-1">
          Assess any domain from the outside. We'll map its external exposure and turn it into a clear Executive Report — usually within a few minutes.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Form */}
        <div className="lg:col-span-2 card-md p-8">
          {success ? (
            <div className="flex flex-col items-center justify-center py-12 text-center gap-5">
              <div className="w-16 h-16 rounded-2xl bg-brand-50 border border-brand-100 flex items-center justify-center">
                <CheckCircle className="w-8 h-8 text-brand-600" />
              </div>
              <div>
                <p className="text-gray-900 font-bold text-xl">Scan Queued Successfully</p>
                <p className="text-gray-400 text-sm mt-1">Redirecting to scan details…</p>
              </div>
              <Spinner />
            </div>
          ) : (
            <>
              <h2 className="text-base font-bold text-gray-900 mb-6">Choose a domain</h2>
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Domain Name</label>
                  <div className="relative">
                    <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      value={domain}
                      onChange={e => onDomainChange(e.target.value)}
                      placeholder="example.com"
                      className="input pl-11 py-3.5 text-base"
                      autoFocus
                      disabled={loading}
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                    />
                  </div>
                  <div className="mt-2">
                    {domain === '' ? (
                      <p className="text-gray-400 text-xs flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Enter the root domain only — no https://, paths, or ports
                      </p>
                    ) : hint?.tone === 'error' ? (
                      <p className="text-amber-600 text-xs font-medium">⚠ {hint.text}</p>
                    ) : hint?.tone === 'success' ? (
                      <p className="text-brand-600 text-xs font-semibold flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3" />
                        {hint.text}
                      </p>
                    ) : (
                      /* Format only. Saying "ready to scan" here would assert
                         ownership we have not established. */
                      <p className="text-gray-500 text-xs flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        {hint?.text}
                      </p>
                    )}
                  </div>
                </div>

                {error && <ErrorAlert message={error} onRetry={() => setError(null)} />}

                {/* Ownership setup. Rendered instead of an error: an unverified
                    domain is a next step, not a fault.

                    requiresVerificationCta() guarantees this block renders for EVERY
                    state that needs verification — the deadlock was a state that
                    needed it and showed nothing. */}
                {/* `verified` is included so the panel CONFIRMS success inline, where
                    the customer was working, rather than silently vanishing. */}
                {(requiresVerificationCta(state) || state === 'verified') && (
                  // `verified` has no dns instruction to show (it may have been
                  // verified before this visit) but must still render the panel's
                  // confirmation — not the CTA card asking to verify again.
                  (dns || state === 'verified')
                    ? <DomainVerificationPanel
                        domain={domain.trim().toLowerCase()}
                        dns={dns}
                        state={state}
                        note={checkNote}
                        onVerify={handleVerify}
                      />
                    : <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 space-y-3">
                        <div className="flex items-start gap-2.5">
                          <ShieldCheck className="w-4 h-4 text-gray-500 mt-0.5 shrink-0" />
                          <div>
                            <p className="text-sm font-semibold text-gray-900">Verify ownership of {domain.trim().toLowerCase()}</p>
                            <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
                              Before scanning, prove you control this domain by adding a DNS record.
                              This is a one-time step for this workspace.
                            </p>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={handleStartVerification}
                          disabled={state === 'initiating_verification' || !wsId}
                          className="btn-secondary w-full justify-center py-2.5 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          {state === 'initiating_verification'
                            ? <><Spinner size="sm" /><span>Preparing your verification record…</span></>
                            : <><ShieldCheck className="w-4 h-4" /><span>Verify domain ownership</span></>}
                        </button>
                      </div>
                )}

                <button
                  type="submit"
                  disabled={!canStartScan(state) || loading}
                  className="btn-primary w-full justify-center py-3.5 text-base disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {loading
                    ? <><Spinner size="sm" /><span>Starting scan…</span></>
                    : <><ScanLine className="w-5 h-5" /><span>Start Scan</span></>}
                </button>
                {valid && !canStartScan(state) && state !== 'starting' && (
                  <p className="text-center text-xs text-gray-400 -mt-1">
                    Verify domain ownership to enable scanning.
                  </p>
                )}

                <p className="text-center text-xs text-gray-400 leading-relaxed">
                  Scans are non-intrusive and read-only — we only inspect publicly available data
                  (DNS, certificates, public web signals), the same information any visitor can see.
                  Only scan domains you own or are authorised to assess; you are responsible for
                  ensuring you have the right to scan a domain.
                </p>
              </form>
            </>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <div className="card p-5">
            <h3 className="text-sm font-bold text-gray-900 mb-4">What's included</h3>
            <ul className="space-y-4">
              {CHECKS.map(({ icon: Icon, label, desc }) => (
                <li key={label} className="flex items-start gap-3">
                  <div className="w-7 h-7 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon className="w-3.5 h-3.5 text-brand-600" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-900 leading-tight">{label}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className="card p-4">
            <h3 className="label mb-3">Example Domains</h3>
            <div className="space-y-1">
              {['example.com', 'mycompany.io', 'testsite.co.uk'].map(d => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDomain(d)}
                  className="w-full text-left mono text-xs text-brand-600 hover:text-brand-800 hover:bg-brand-50 px-3 py-2 rounded-lg transition-colors"
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
