// WorkspaceDomainsPage — the workspace's domains: add or import them, verify
// ownership and see how many are verified. Extracted unchanged from the
// dissolved "Workspace administration" page (founder, 17 Oct 2026): the
// verification wizard, the one-click DNS offer and the import widget are the
// same code; the stat tiles, score and posture list that page carried are gone
// (Overview owns them) and its members and activity feed moved to their own
// homes (/ws/members, /ws/audit-log).
import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Clock, ShieldCheck, ChevronDown, ChevronUp, Activity, Globe } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import StatCard from '../../components/StatCard'
import VerificationStatusBadge from '../../components/VerificationStatusBadge'
import OneClickDnsButton from '../../components/OneClickDnsButton'
import { useDomainConnectOffer } from '../../hooks/useDomainConnectOffer'

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button
      onClick={copy}
      title="Copy to clipboard"
      className="ml-1.5 inline-flex items-center gap-1 text-xs text-gray-400 hover:text-brand-800 transition-colors"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

const WIZARD_STEPS = [
  { id: 1, label: 'Add Domain' },
  { id: 2, label: 'TXT Record'  },
  { id: 3, label: 'Check DNS'   },
  { id: 4, label: 'Verify'      },
]

function WizardStep({ n, label, active, done }) {
  return (
    <div className="flex items-center gap-1.5">
      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
        done   ? 'bg-brand-500 text-brand-900' :
        active ? 'bg-brand-200 text-brand-900' :
                 'bg-gray-100 text-gray-400'
      }`}>
        {n}
      </div>
      <span className={`text-xs font-medium hidden sm:block ${active ? 'text-gray-900' : done ? 'text-brand-700' : 'text-gray-400'}`}>
        {label}
      </span>
    </div>
  )
}

function DomainVerificationPanel({ domains, wsId, onVerified, onAddDomain }) {
  const navigate = useNavigate()
  const actionable = (domains || []).filter(d => d.verification_status !== 'verified')

  // Step for the wizard applied to a specific domain
  const [activeDomain, setActiveDomain] = useState(null)      // domain obj being worked on
  const [step,         setStep]         = useState(2)          // 2=TXT, 3=CheckDNS, 4=Verify
  const [instructions, setInstructions] = useState(null)
  const [generating,   setGenerating]   = useState(false)
  const [genError,     setGenError]     = useState(null)
  const [tab,          setTab]          = useState('dns')

  // Step 3
  const [dnsResult, setDnsResult] = useState(null)
  const [checking,  setChecking]  = useState(false)

  // Step 4
  const [verifying,    setVerifying]    = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)

  const [expanded, setExpanded] = useState(true)
  const oneClick = useDomainConnectOffer(activeDomain?.domain_id, wsId, instructions?.dns?.value)

  if (actionable.length === 0) return null

  function selectDomain(d) {
    setActiveDomain(d)
    setInstructions(null)
    setDnsResult(null)
    setVerifyResult(null)
    setGenError(null)
    setStep(2)
    // If domain already has a token, populate instructions
    if (d.verification_token) {
      setInstructions({
        token: d.verification_token,
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
  }

  async function handleGenerate() {
    if (!activeDomain) return
    setGenerating(true); setGenError(null); setDnsResult(null); setVerifyResult(null)
    try {
      const res = await api.generateDomainVerification(activeDomain.domain_id)
      if (res.already_verified) { if (onVerified) onVerified(); return }
      setInstructions(res)
      setStep(2)
    } catch (e) { setGenError(e.message) }
    finally { setGenerating(false) }
  }

  async function handleCheckDns() {
    if (!activeDomain) return
    setChecking(true); setDnsResult(null)
    try {
      const res = await api.checkDnsVerification(activeDomain.domain_id)
      setDnsResult(res)
      if (res.matches) setStep(4)
    } catch (e) {
      setDnsResult({ found: false, error: e.message })
    } finally {
      setChecking(false)
    }
  }

  async function handleVerify() {
    if (!activeDomain) return
    setVerifying(true); setVerifyResult(null)
    try {
      const res = await api.verifyDomain(activeDomain.domain_id)
      setVerifyResult(res)
      if (res.success && onVerified) setTimeout(onVerified, 1200)
    } catch (e) {
      setVerifyResult({ success: false, message: e.message })
    } finally {
      setVerifying(false)
    }
  }

  function openVerifyPage(d) {
    navigate(`/domains/${d.domain_id}/verify`, { state: { domain: d } })
  }

  const currentStep = activeDomain ? (instructions ? step : 2) : 1

  return (
    <div className="card border-[1.5px] border-brand-700 mb-6 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center justify-between px-6 py-4 border-b border-[1.5px] border-brand-700 hover:bg-brand-50 transition-colors text-left"
      >
        <div>
          <p className="font-semibold text-gray-900 text-sm">Domain Ownership Verification</p>
          <p className="text-xs text-brand-700">
            {actionable.length} domain{actionable.length !== 1 ? 's' : ''} require verification
          </p>
        </div>
        {expanded
          ? <ChevronUp className="w-4 h-4 text-gray-400" />
          : <ChevronDown className="w-4 h-4 text-gray-400" />
        }
      </button>

      {expanded && (
        <div className="px-6 py-5">

          {/* Step indicator */}
          <div className="flex items-center gap-3 mb-5 pb-5 border-b border-gray-50">
            {WIZARD_STEPS.map((s, i) => (
              <div key={s.id} className="flex items-center gap-2">
                <WizardStep n={s.id} label={s.label} active={currentStep === s.id} done={currentStep > s.id} />
                {i < WIZARD_STEPS.length - 1 && (
                  <div className={`h-px w-6 sm:w-10 ${currentStep > s.id ? 'bg-brand-400' : 'bg-gray-100'}`} />
                )}
              </div>
            ))}
          </div>

          {/* Step 1: Domain list */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-5">
            {actionable.map(d => {
              const isActive = activeDomain?.domain_id === d.domain_id
              return (
                <div
                  key={d.domain_id}
                  className={`p-3 rounded-xl border cursor-pointer transition-all ${
                    isActive
                      ? 'border-brand-300 bg-brand-50'
                      : 'border-gray-100 hover:border-gray-200 bg-white'
                  }`}
                  onClick={() => selectDomain(d)}
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-sm font-medium text-gray-800 truncate">{d.domain}</span>
                    <VerificationStatusBadge status={d.verification_status} />
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={e => { e.stopPropagation(); selectDomain(d); }}
                      className="text-xs text-brand-700 hover:underline"
                    >
                      {isActive ? 'Selected' : 'Verify here →'}
                    </button>
                    <span className="text-gray-600">·</span>
                    <button
                      onClick={e => { e.stopPropagation(); openVerifyPage(d); }}
                      className="text-xs text-gray-400 hover:text-gray-600"
                    >
                      Full page ↗
                    </button>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Steps 2–4: shown when a domain is selected */}
          {activeDomain && (
            <div className="border border-gray-100 rounded-xl overflow-hidden">
              {/* Step 2: Instructions */}
              <div className="border-b border-gray-100">
                <div className="flex border-b border-gray-50">
                  {['dns', 'html'].map(t => (
                    <button
                      key={t}
                      onClick={() => setTab(t)}
                      className={`flex-1 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors ${
                        tab === t ? 'bg-gray-50 text-gray-900 border-b-2 border-brand-500' : 'text-gray-400 hover:text-gray-700'
                      }`}
                    >
                      {t === 'dns' ? 'DNS TXT Record' : 'HTML File'}
                    </button>
                  ))}
                </div>

                <div className="p-5">
                  {!instructions ? (
                    <div className="text-center py-4">
                      <p className="text-sm text-gray-500 mb-3">
                        Generate a verification token for <strong>{activeDomain.domain}</strong>
                      </p>
                      <button
                        onClick={handleGenerate}
                        disabled={generating}
                        className="btn-primary"
                      >
                        {generating
                          ? <><Activity className="w-4 h-4 animate-spin" /> Generating…</>
                          : 'Get Verification Instructions'
                        }
                      </button>
                      {genError && <p className="mt-2 text-xs text-red-700">{genError}</p>}
                    </div>
                  ) : tab === 'dns' ? (
                    <div className="space-y-3">
                      <OneClickDnsButton offer={oneClick} />
                      <p className="text-xs text-gray-500">Add this TXT record to your DNS. Changes may take up to 48 hours.</p>
                      {[
                        { label: 'Host / Name', value: instructions.dns?.host },
                        { label: 'Type',        value: 'TXT' },
                        { label: 'Value',       value: instructions.dns?.value },
                      ].map(({ label, value }) => (
                        <div key={label} className="bg-gray-50 rounded-lg p-3">
                          <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-1">{label}</p>
                          <div className="flex items-center gap-1">
                            <code className="text-xs text-gray-800 break-all">{value}</code>
                            <CopyButton text={value} />
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <p className="text-xs text-gray-500">Upload a text file to your web server at the exact URL below.</p>
                      {[
                        { label: 'URL',               value: instructions.html?.url },
                        { label: 'File Content (exact)', value: instructions.html?.content },
                      ].map(({ label, value }) => (
                        <div key={label} className="bg-gray-50 rounded-lg p-3">
                          <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-1">{label}</p>
                          <div className="flex items-center gap-1">
                            <code className="text-xs text-gray-800 break-all">{value}</code>
                            <CopyButton text={value} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Steps 3+4: DNS check + Verify */}
              {instructions && (
                <div className="p-5 flex flex-wrap items-center gap-3">
                  {/* Step 3: DNS check */}
                  {tab === 'dns' && (
                    <button
                      onClick={handleCheckDns}
                      disabled={checking}
                      className="btn-secondary text-sm"
                    >
                      {checking
                        ? <><Activity className="w-4 h-4 animate-spin" /> Checking…</>
                        : 'Check DNS'
                      }
                    </button>
                  )}

                  {/* Step 4: Verify */}
                  <button
                    onClick={handleVerify}
                    disabled={verifying}
                    className="btn-primary text-sm"
                  >
                    {verifying
                      ? <><Activity className="w-4 h-4 animate-spin" /> Verifying…</>
                      : 'Verify Ownership'
                    }
                  </button>
                  <span className="text-xs text-gray-400">Checks both DNS and HTML</span>

                  {/* DNS check result */}
                  {dnsResult && (
                    <div className={`w-full flex items-start gap-2 p-3 rounded-xl text-sm border ${
                      dnsResult.matches
                        ? 'bg-brand-50 border-brand-100 text-brand-700'
                        : dnsResult.found
                        ? 'bg-transparent border-[1.5px] border-brand-700 text-brand-700'
                        : 'bg-gray-50 border-gray-100 text-gray-500'
                    }`}>
                      <div>
                        {dnsResult.matches
                          ? <p className="font-medium">DNS record found and matches — ready to verify!</p>
                          : dnsResult.found
                          ? <p className="font-medium">Record found but value doesn't match. Check token.</p>
                          : <p className="font-medium">
                              {dnsResult.error ? `DNS error: ${dnsResult.error}` : 'TXT record not found yet. DNS may still be propagating.'}
                            </p>
                        }
                      </div>
                    </div>
                  )}

                  {/* Verify result */}
                  {verifyResult && (
                    <div className={`w-full flex items-start gap-2 p-3 rounded-xl text-sm border ${
                      verifyResult.success
                        ? 'bg-brand-50 border-brand-100 text-brand-700'
                        : 'bg-red-50 border-red-100 text-red-700'
                    }`}>
                      <div>
                        <p className="font-medium">{verifyResult.success ? 'Verified!' : 'Verification failed'}</p>
                        <p className="text-xs opacity-80 mt-0.5">{verifyResult.message}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Onboarding Widget ────────────────────────────────────────────────────────

function OnboardingWidget({ wsId, onDone }) {
  const navigate = useNavigate()
  const [singleDomain,  setSingleDomain]  = useState('')
  const [bulkText,      setBulkText]      = useState('')
  const [showBulk,      setShowBulk]      = useState(false)
  const [importing,     setImporting]     = useState(false)
  const [importResult,  setImportResult]  = useState(null)
  const [importError,   setImportError]   = useState(null)

  async function handleStart() {
    if (importing) return
    const domains = showBulk
      ? bulkText.split(/[\n,]+/).map(d => d.trim()).filter(Boolean)
      : singleDomain.trim() ? [singleDomain.trim()] : []

    if (domains.length === 0) return
    setImporting(true); setImportError(null); setImportResult(null)
    try {
      const result = await api.importWorkspaceDomains(wsId, domains)
      setImportResult(result)
      if (result.imported > 0 && onDone) setTimeout(onDone, 1500)
    } catch (e) {
      setImportError(e.message)
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="card p-10 text-center max-w-xl mx-auto">
      <h2 className="text-xl font-bold text-gray-900 mb-2">Add your first domain</h2>
      <p className="text-sm text-gray-400 mb-8">
        Enter one domain to get started, or import a list of the domains you own.
      </p>

      {!showBulk ? (
        <div className="flex gap-2 mb-3">
          <input
            type="text"
            className="input flex-1 text-sm"
            placeholder="example.com"
            value={singleDomain}
            onChange={e => setSingleDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleStart()}
            disabled={importing}
          />
          <button
            onClick={handleStart}
            disabled={importing || !singleDomain.trim()}
            className="btn-primary"
          >
            {importing
              ? <Activity className="w-4 h-4 animate-spin" />
              : 'Start Monitoring'
            }
          </button>
        </div>
      ) : (
        <div className="mb-3 text-left">
          <label className="label mb-2 block">Paste domains (one per line or comma-separated)</label>
          <textarea
            className="input w-full text-sm font-mono"
            rows={6}
            placeholder={"example.com\nexample.org\nexample.net"}
            value={bulkText}
            onChange={e => setBulkText(e.target.value)}
            disabled={importing}
          />
          <button
            onClick={handleStart}
            disabled={importing || !bulkText.trim()}
            className="btn-primary w-full mt-3"
          >
            {importing
              ? <><Activity className="w-4 h-4 animate-spin" /> Importing…</>
              : 'Import & Start Monitoring'
            }
          </button>
        </div>
      )}

      {!importing && (
        <button
          onClick={() => { setShowBulk(v => !v); setSingleDomain(''); setBulkText('') }}
          className="text-xs text-brand-700 hover:underline mt-1"
        >
          {showBulk ? '← Single domain' : 'Import multiple domains'}
        </button>
      )}

      {importResult && (
        <div className="mt-5 p-4 bg-brand-50 rounded-xl text-sm text-brand-700">
          {importResult.imported} domain{importResult.imported !== 1 ? 's' : ''} added
          {importResult.skipped > 0 && ` · ${importResult.skipped} already existed`}
          {importResult.invalid > 0 && ` · ${importResult.invalid} invalid`}
        </div>
      )}

      {importError && (
        <div className="mt-5 p-4 bg-red-50 rounded-xl text-sm text-red-700">
          {importError}
        </div>
      )}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────


export default function WorkspaceDomainsPage() {
  const { wsId, wsName } = useWorkspace()
  if (!wsId) return <NoWorkspaceSelected />
  return <WorkspaceDomainsContent key={wsId} wsId={wsId} wsName={wsName} />
}

function WorkspaceDomainsContent({ wsId, wsName }) {
  const [domains, setDomains] = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const requestGeneration = useRef(0)

  // Every read is scoped to the workspace that asked; a late answer for a
  // previous workspace is ignored, and a switch clears what was shown.
  const load = useCallback(async () => {
    const generation = ++requestGeneration.current
    setLoading(true); setError(null); setDomains([]); setSummary(null)
    try {
      const [dm, sm] = await Promise.allSettled([api.getWorkspaceDomains(wsId), api.getWorkspaceSummary(wsId)])
      if (requestGeneration.current !== generation) return
      setDomains(dm.status === 'fulfilled' ? (dm.value?.domains || []) : [])
      setSummary(sm.status === 'fulfilled' ? sm.value : null)
      if (dm.status === 'rejected') throw new Error(dm.reason?.message || 'Failed to load domains')
    } catch (e) {
      if (requestGeneration.current === generation) setError(e.message)
    } finally {
      if (requestGeneration.current === generation) setLoading(false)
    }
  }, [wsId])

  useEffect(() => {
    load()
    return () => { requestGeneration.current += 1 }
  }, [load])

  const noDomains = domains.length === 0 && (summary == null || summary.domains === 0)
  const verifiedCount = domains.filter(d => d.verification_status === 'verified').length
  const pendingCount  = domains.filter(d => ['pending', 'pending_verification'].includes(d.verification_status)).length
  const failedCount   = domains.filter(d => ['failed', 'verification_failed'].includes(d.verification_status)).length
  const verificationRate = domains.length > 0 ? Math.round((verifiedCount / domains.length) * 100) : 0

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      {noDomains ? (
        <OnboardingWidget wsId={wsId} onDone={load} />
      ) : (
        <>
          <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Domains</h1>
              <p className="text-sm text-gray-500 mt-0.5">{wsName} · the domains CyberMeters monitors for this workspace and whether ownership is verified.</p>
            </div>
            <button onClick={() => load()} className="btn-secondary" disabled={loading}>Refresh</button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6" data-testid="domain-verification-stats">
            <StatCard icon={ShieldCheck} label="Domains verified" explanation="Ownership proven by DNS or file verification" value={`${verifiedCount} / ${domains.length}`} sub={`${verificationRate}% verification rate`} />
            <StatCard icon={Clock} label="Pending verification" explanation="Added, not yet proven" value={pendingCount} warning={pendingCount > 0} />
            <StatCard icon={AlertTriangle} label="Verification failed" explanation="The last check did not find the record" value={failedCount} danger={failedCount > 0} />
          </div>

          <DomainVerificationPanel domains={domains} wsId={wsId} onVerified={load} />

          <section className="card overflow-hidden" aria-label="Domains in this workspace">
            <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
              <h2 className="text-sm font-bold text-gray-900">All domains</h2>
              <span className="text-sm text-gray-500">{domains.length}</span>
            </div>
            <ul className="divide-y divide-gray-50">
              {domains.map((d) => (
                <li key={d.domain_id || d.id || d.domain} className="flex flex-wrap items-center gap-3 px-6 py-3">
                  <Globe className="w-4 h-4 text-gray-400 shrink-0" aria-hidden="true" />
                  <span className="text-sm font-medium text-gray-900 min-w-0 break-words flex-1">{d.domain || d.name}</span>
                  <VerificationStatusBadge status={d.verification_status} />
                </li>
              ))}
            </ul>
          </section>

          <div className="mt-6">
            <AddMoreDomains wsId={wsId} onDone={load} />
          </div>
        </>
      )}
    </WsPage>
  )
}

/* Add more domains to a workspace that already has some: the same import call. */
function AddMoreDomains({ wsId, onDone }) {
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  async function submit(e) {
    e.preventDefault()
    const domains = value.split(/[\n,\s]+/).map((d) => d.trim()).filter(Boolean)
    if (!domains.length || busy) return
    setBusy(true); setError(null); setResult(null)
    try {
      const res = await api.importWorkspaceDomains(wsId, domains)
      setResult(res); setValue('')
      onDone?.()
    } catch (err) { setError(err.message || 'The domains could not be added.') }
    finally { setBusy(false) }
  }
  return (
    <form onSubmit={submit} className="card p-6 space-y-3" aria-label="Add domains">
      <h2 className="text-sm font-bold text-gray-900">Add domains</h2>
      <p className="text-sm text-gray-600">One per line or comma-separated. Each new domain then needs ownership verification above.</p>
      <textarea className="input min-h-[80px]" value={value} onChange={(e) => setValue(e.target.value)} placeholder="example.co.uk" aria-label="Domains to add" />
      {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
      {result && <p className="text-sm text-gray-700">{result.added ?? result.imported ?? 0} added{result.skipped ? ` · ${result.skipped} skipped` : ''}.</p>}
      <button type="submit" className="btn-primary" disabled={busy || !value.trim()}>{busy ? 'Adding…' : 'Add domains'}</button>
    </form>
  )
}
