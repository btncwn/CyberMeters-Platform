import { useState, useEffect, useCallback } from 'react'
import { useParams, useLocation, useNavigate } from 'react-router-dom'
import {
  ShieldCheck, Copy, CheckCircle, AlertTriangle, Activity,
  Wifi, RefreshCw, Globe, ArrowLeft, ExternalLink, Clock,
} from 'lucide-react'
import { api } from '../api'
import VerificationStatusBadge from '../components/VerificationStatusBadge'

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div className="bg-gray-50 rounded-xl p-4">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1.5">{label}</p>
      <div className="flex items-center gap-2">
        <code className="flex-1 text-sm text-gray-800 break-all font-mono leading-snug">{value}</code>
        <button
          onClick={copy}
          className="flex-shrink-0 flex items-center gap-1 text-xs text-gray-400 hover:text-brand-600 transition-colors"
        >
          {copied
            ? <><CheckCircle className="w-3.5 h-3.5 text-brand-500" /> Copied</>
            : <><Copy className="w-3.5 h-3.5" /> Copy</>
          }
        </button>
      </div>
    </div>
  )
}

// ── DNS Check Result Panel ────────────────────────────────────────────────────

function DnsCheckResult({ result }) {
  if (!result) return null
  const { found, matches, value, expected, error } = result
  if (error && !found) return (
    <div className="flex items-start gap-3 p-4 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
      <div>
        <p className="font-semibold">DNS lookup error</p>
        <p className="text-xs mt-0.5 opacity-80">{error}</p>
      </div>
    </div>
  )
  if (!found) return (
    <div className="flex items-start gap-3 p-4 bg-amber-50 border border-amber-100 rounded-xl text-sm text-amber-700">
      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
      <div>
        <p className="font-semibold">TXT record not found yet</p>
        <p className="text-xs mt-1 opacity-80">DNS changes can take up to 48 hours to propagate. Try again later.</p>
      </div>
    </div>
  )
  if (found && !matches) return (
    <div className="p-4 bg-amber-50 border border-amber-100 rounded-xl text-sm text-amber-700 space-y-2">
      <div className="flex items-center gap-2 font-semibold">
        <AlertTriangle className="w-4 h-4" />
        TXT record found but value doesn't match
      </div>
      <div className="text-xs space-y-1">
        <p><span className="font-medium">Found:</span> <code className="bg-white/60 px-1 rounded break-all">{value}</code></p>
        <p><span className="font-medium">Expected:</span> <code className="bg-white/60 px-1 rounded break-all">{expected}</code></p>
      </div>
    </div>
  )
  return (
    <div className="flex items-start gap-3 p-4 bg-brand-50 border border-brand-100 rounded-xl text-sm text-brand-700">
      <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0 text-brand-500" />
      <div>
        <p className="font-semibold">DNS TXT record found and matches</p>
        <p className="text-xs mt-0.5 opacity-80">You can now click "Verify Ownership" to complete verification.</p>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DomainVerifyPage() {
  const { id: domainId } = useParams()
  const location = useLocation()
  const navigate  = useNavigate()

  // Domain data — may be passed via router state (from workspace domains list) or fetched
  const [domain,      setDomain]      = useState(location.state?.domain ?? null)
  const [loading,     setLoading]     = useState(!domain)
  const [error,       setError]       = useState(null)

  // Verification flow state
  const [instructions, setInstructions] = useState(null)
  const [generating,   setGenerating]   = useState(false)
  const [genError,     setGenError]     = useState(null)
  const [tab,          setTab]          = useState('dns')

  // DNS check state
  const [dnsResult,  setDnsResult]  = useState(null)
  const [checking,   setChecking]   = useState(false)

  // Verify state
  const [verifying,    setVerifying]    = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const data = await api.getDomain(domainId)
      setDomain(data.domain)
      // If there's already a token, pre-populate instructions shape
      if (data.domain.verification_token) {
        const d = data.domain
        setInstructions({
          domain:   d.domain,
          domain_id: d.id,
          token:    d.verification_token,
          dns: d.dns,
          html: d.html,
        })
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [domainId])

  useEffect(() => {
    if (!domain) { load(); return }
    // If domain passed via state already has a token, pre-populate
    if (domain.verification_token) {
      const d = domain
      setInstructions({
        domain:   d.domain,
        domain_id: d.domain_id ?? d.id,
        token:    d.verification_token,
        dns: {
          host:  `_cybermeters.${d.domain}`,
          value: `cybermeters-verification=${d.verification_token}`,
        },
        html: {
          url:     `https://${d.domain}/cybermeters-verification-${d.verification_token}.html`,
          content: d.verification_token,
        },
      })
    }
  }, [domain, load])

  async function handleGenerate() {
    const id = domain?.domain_id ?? domain?.id ?? domainId
    setGenerating(true); setGenError(null); setDnsResult(null)
    try {
      const res = await api.generateDomainVerification(id)
      if (res.already_verified) {
        await load()
        return
      }
      setInstructions(res)
      // Also refresh domain to get updated status
      const d = await api.getDomain(id)
      setDomain(d.domain)
    } catch (e) {
      setGenError(e.message)
    } finally {
      setGenerating(false)
    }
  }

  async function handleCheckDns() {
    const id = domain?.domain_id ?? domain?.id ?? domainId
    setChecking(true); setDnsResult(null)
    try {
      const res = await api.checkDnsVerification(id)
      setDnsResult(res)
    } catch (e) {
      setDnsResult({ found: false, error: e.message })
    } finally {
      setChecking(false)
    }
  }

  async function handleVerify() {
    const id = domain?.domain_id ?? domain?.id ?? domainId
    setVerifying(true); setVerifyResult(null)
    try {
      const res = await api.verifyDomain(id)
      setVerifyResult(res)
      if (res.success) {
        setTimeout(async () => {
          const d = await api.getDomain(id)
          setDomain(d.domain)
        }, 800)
      }
    } catch (e) {
      setVerifyResult({ success: false, message: e.message })
    } finally {
      setVerifying(false)
    }
  }

  const domainName    = domain?.domain ?? '…'
  const status        = domain?.verification_status ?? 'unverified'
  const lastAttempt   = domain?.verification_initiated_at
  const verifiedAt    = domain?.verified_at
  const isVerified    = status === 'verified'

  if (loading) return (
    <div className="max-w-2xl mx-auto px-6 py-12 text-center">
      <RefreshCw className="w-6 h-6 text-gray-300 animate-spin mx-auto mb-3" />
      <p className="text-sm text-gray-400">Loading domain…</p>
    </div>
  )

  if (error) return (
    <div className="max-w-2xl mx-auto px-6 py-12">
      <div className="card p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <p className="text-gray-700 font-medium mb-1">Failed to load domain</p>
        <p className="text-sm text-gray-400 mb-4">{error}</p>
        <button onClick={load} className="btn-secondary mx-auto">Retry</button>
      </div>
    </div>
  )

  return (
    <div className="max-w-2xl mx-auto px-6 py-8">

      {/* Back */}
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-700 transition-colors mb-6"
      >
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      {/* Header */}
      <div className="flex items-start justify-between mb-8">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand-50 flex items-center justify-center">
            <Globe className="w-5 h-5 text-brand-600" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">{domainName}</h1>
            <p className="text-sm text-gray-400 mt-0.5">Domain Ownership Verification</p>
          </div>
        </div>
        <VerificationStatusBadge status={status} size="md" />
      </div>

      {/* Already verified */}
      {isVerified && (
        <div className="card p-8 text-center mb-6">
          <CheckCircle className="w-12 h-12 text-brand-500 mx-auto mb-3" />
          <p className="text-lg font-bold text-gray-900 mb-1">Domain Verified</p>
          <p className="text-sm text-gray-400">
            Ownership confirmed
            {domain?.verification_method && ` via ${domain.verification_method.replace('_', ' ')}`}
            {verifiedAt && ` on ${fmt(verifiedAt)}`}.
          </p>
        </div>
      )}

      {/* Status card */}
      {!isVerified && (
        <div className="card p-5 mb-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-5 h-5 text-amber-400 flex-shrink-0" />
            <div>
              <p className="text-sm font-semibold text-gray-900">
                {status === 'failed' ? 'Last verification attempt failed' : 'Verification required'}
              </p>
              <p className="text-xs text-gray-400 mt-0.5">
                {lastAttempt ? `Last attempt: ${fmt(lastAttempt)}` : 'No verification attempt yet'}
              </p>
            </div>
          </div>
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="btn-secondary text-sm flex-shrink-0"
          >
            {generating
              ? <><Activity className="w-3.5 h-3.5 animate-spin" /> Generating…</>
              : instructions ? <><RefreshCw className="w-3.5 h-3.5" /> Regenerate Token</> : 'Get Instructions'
            }
          </button>
        </div>
      )}

      {genError && (
        <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {genError}
        </div>
      )}

      {/* Instructions */}
      {instructions && !isVerified && (
        <div className="card overflow-hidden mb-6">
          <div className="border-b border-gray-100 px-6 py-4">
            <h2 className="font-semibold text-gray-900">Verification Instructions</h2>
            <p className="text-xs text-gray-400 mt-0.5">Choose one method. Both are checked automatically during verification.</p>
          </div>

          {/* Method tabs */}
          <div className="flex border-b border-gray-100">
            {['dns', 'html'].map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`flex-1 py-3 text-xs font-semibold uppercase tracking-wider transition-colors ${
                  tab === t
                    ? 'bg-gray-50 text-gray-900 border-b-2 border-brand-500'
                    : 'text-gray-400 hover:text-gray-600'
                }`}
              >
                {t === 'dns' ? 'DNS TXT Record (recommended)' : 'HTML File'}
              </button>
            ))}
          </div>

          <div className="p-6 space-y-3">
            {tab === 'dns' ? (
              <>
                <p className="text-xs text-gray-500">
                  Add the following TXT record to your domain's DNS. DNS changes typically propagate within 1–48 hours.
                </p>
                <CopyField label="Host / Name" value={instructions.dns?.host ?? `_cybermeters.${domainName}`} />
                <CopyField label="Type" value="TXT" />
                <CopyField label="Value" value={instructions.dns?.value ?? `cybermeters-verification=${instructions.token}`} />
              </>
            ) : (
              <>
                <p className="text-xs text-gray-500">
                  Create a publicly accessible text file at your web server. The file must contain only the token string.
                </p>
                <CopyField label="URL" value={instructions.html?.url ?? ''} />
                <CopyField label="File Content (exact)" value={instructions.html?.content ?? instructions.token} />
                {instructions.html?.url && (
                  <a
                    href={instructions.html.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-brand-600 hover:underline"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Test URL
                  </a>
                )}
              </>
            )}
          </div>

          {/* DNS check + Verify actions */}
          <div className="px-6 pb-6 space-y-3">
            <div className="border-t border-gray-100 pt-5 flex flex-wrap items-center gap-3">

              {/* DNS check button — DNS tab only */}
              {tab === 'dns' && (
                <button
                  onClick={handleCheckDns}
                  disabled={checking}
                  className="btn-secondary"
                >
                  {checking
                    ? <><Activity className="w-4 h-4 animate-spin" /> Checking…</>
                    : <><Wifi className="w-4 h-4" /> Check DNS Record</>
                  }
                </button>
              )}

              <button
                onClick={handleVerify}
                disabled={verifying}
                className="btn-primary"
              >
                {verifying
                  ? <><Activity className="w-4 h-4 animate-spin" /> Verifying…</>
                  : <><ShieldCheck className="w-4 h-4" /> Verify Ownership</>
                }
              </button>

              <span className="text-xs text-gray-400">Checks both DNS and HTML methods</span>
            </div>

            {/* DNS check result */}
            {dnsResult && <DnsCheckResult result={dnsResult} />}

            {/* Verify result */}
            {verifyResult && (
              <div className={`flex items-start gap-3 p-4 rounded-xl text-sm border ${
                verifyResult.success
                  ? 'bg-brand-50 border-brand-100 text-brand-700'
                  : 'bg-red-50 border-red-100 text-red-600'
              }`}>
                {verifyResult.success
                  ? <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  : <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                }
                <div>
                  <p className="font-semibold">{verifyResult.success ? 'Verified!' : 'Verification failed'}</p>
                  <p className="text-xs mt-0.5 opacity-80">{verifyResult.message}</p>
                  {!verifyResult.success && verifyResult.checks && (
                    <ul className="mt-2 text-xs space-y-0.5 opacity-70">
                      <li>DNS TXT: {verifyResult.checks.dns_txt?.result ?? '—'}
                        {verifyResult.checks.dns_txt?.error && ` (${verifyResult.checks.dns_txt.error})`}</li>
                      <li>HTML file: {verifyResult.checks.html_file?.result ?? '—'}
                        {verifyResult.checks.html_file?.error && ` (${verifyResult.checks.html_file.error})`}</li>
                    </ul>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Meta */}
      {lastAttempt && (
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <Clock className="w-3.5 h-3.5" />
          Verification last attempted {fmt(lastAttempt)}
        </div>
      )}
    </div>
  )
}
