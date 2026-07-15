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
import {
  canStartScan, isValidDomainSyntax, domainHintFor, safeErrorMessage,
  isVerificationRequired, dnsInstructionFrom, checkFailureMessage,
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
  function onDomainChange(next) {
    setDomain(next)
    setState(isValidDomainSyntax(next) ? 'ready' : 'idle')
    setGated(null); setDns(null); setCheckNote(null); setError(null)
  }

  // Start verification for the exact record the backend named. Token, host and
  // value all come from the server — nothing is constructed here.
  async function startVerification(record) {
    try {
      const res = await api.generateDomainVerification(record.domain_id, record.workspace_id)
      if (res?.already_verified) { setState('verified'); return }
      const instruction = dnsInstructionFrom(res)
      if (!instruction) { setError(safeErrorMessage({})); return }
      setDns(instruction); setState('instructions')
    } catch (e) {
      setError(safeErrorMessage(e))
    }
  }

  async function handleVerify() {
    if (!gated) return
    setState('checking'); setCheckNote(null); setError(null)
    try {
      const res = await api.verifyDomain(gated.domain_id, gated.workspace_id)
      if (res?.verified || res?.verification_status === 'verified') {
        setState('verified'); setCheckNote(null)
      } else {
        // Not found yet — keep the instructions on screen. Clearing them would
        // strand the customer with no route back to the token.
        setState('check_failed'); setCheckNote(checkFailureMessage(res || {}))
      }
    } catch (e) {
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
        // Not a failure the customer caused — it is the next step. Show the setup
        // flow rather than an error, and never surface the raw code.
        const record = { domain_id: e.domain_id, workspace_id: e.workspace_id }
        setGated(record); setState('needs_setup'); setError(null)
        if (record.domain_id) await startVerification(record)
      } else if (e.code !== 'plan_limit_exceeded' && e.code !== 'rate_limit_exceeded') {
        // safeErrorMessage guarantees a machine code never reaches the customer.
        setError(safeErrorMessage(e)); setState(valid ? 'ready' : 'idle')
      } else {
        setState(valid ? 'ready' : 'idle')
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
                    domain is a next step, not a fault. */}
                {(state === 'needs_setup' || dns) && (
                  <DomainVerificationPanel
                    domain={domain.trim().toLowerCase()}
                    dns={dns}
                    state={state}
                    note={checkNote}
                    onVerify={handleVerify}
                  />
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
