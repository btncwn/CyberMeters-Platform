import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart2, Shield, Server, AlertTriangle, ShieldAlert, ScanLine,
  Package2, Zap, Tag, Terminal, TrendingUp, TrendingDown, Minus,
  Globe, Upload, Plus, FileText, Clock, CheckCircle, Activity,
  ShieldCheck, Copy, ExternalLink, ChevronDown, ChevronUp, Wifi,
} from 'lucide-react'
import {
  AreaChart, Area, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import { useAuth } from '../../context/AuthContext'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import StatCard from '../../components/StatCard'
import WorkspaceMembersPanel from '../../components/WorkspaceMembersPanel'
import VerificationStatusBadge from '../../components/VerificationStatusBadge'
import ActivityTimeline from '../../components/ActivityTimeline'

function fmt(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

// Maps score-derived posture rating values to display labels (Security Rating system).
const SECURITY_RATING_LABEL = {
  excellent: 'Excellent',
  good:      'Good',
  moderate:  'Moderate',
  high:      'Poor',
  critical:  'Critical',
}
function securityRatingLabel(r) {
  return r ? (SECURITY_RATING_LABEL[r.toLowerCase()] ?? r) : null
}

function ScoreGauge({ score, rating }) {
  if (score == null) return <span className="text-3xl font-black text-gray-300">—</span>
  const color = score >= 80 ? 'text-brand-600' : score >= 60 ? 'text-amber-500' : 'text-red-500'
  return (
    <div className="flex items-end gap-2">
      <span className={`text-5xl font-black leading-none ${color}`}>{score}</span>
      <span className="text-sm text-gray-400 mb-1">/ 100</span>
    </div>
  )
}

function HealthBadge({ status }) {
  const cfg = {
    healthy: 'bg-brand-50 text-brand-700 border-brand-100',
    warning: 'bg-amber-50 text-amber-700 border-amber-100',
    stale:   'bg-red-50 text-red-700 border-red-100',
  }[status] ?? 'bg-gray-50 text-gray-500 border-gray-100'
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold border ${cfg}`}>
      {status === 'healthy' && <CheckCircle className="w-3 h-3" />}
      {status === 'warning' && <Clock className="w-3 h-3" />}
      {status === 'stale'   && <AlertTriangle className="w-3 h-3" />}
      {status ?? '—'}
    </span>
  )
}

// ── Verification Status Badge ────────────────────────────────────────────────
// (imported from components/VerificationStatusBadge)

// ── Domain Verification Wizard ───────────────────────────────────────────────

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
      className="ml-1.5 inline-flex items-center gap-1 text-xs text-gray-400 hover:text-brand-600 transition-colors"
    >
      {copied ? <CheckCircle className="w-3.5 h-3.5 text-brand-500" /> : <Copy className="w-3.5 h-3.5" />}
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
      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
        done   ? 'bg-brand-500 text-white' :
        active ? 'bg-brand-600 text-white' :
                 'bg-gray-100 text-gray-400'
      }`}>
        {done ? <CheckCircle className="w-3.5 h-3.5" /> : n}
      </div>
      <span className={`text-xs font-medium hidden sm:block ${active ? 'text-gray-900' : done ? 'text-brand-600' : 'text-gray-400'}`}>
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
    <div className="card border-amber-100 mb-6 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center justify-between px-6 py-4 border-b border-amber-100 hover:bg-amber-50/40 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-amber-50 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4 text-amber-500" />
          </div>
          <div>
            <p className="font-semibold text-gray-900 text-sm">Domain Ownership Verification</p>
            <p className="text-xs text-amber-600">
              {actionable.length} domain{actionable.length !== 1 ? 's' : ''} require verification
            </p>
          </div>
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
                      className="text-xs text-brand-600 hover:underline"
                    >
                      {isActive ? 'Selected' : 'Verify here →'}
                    </button>
                    <span className="text-gray-200">·</span>
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
                          : <><ShieldCheck className="w-4 h-4" /> Get Verification Instructions</>
                        }
                      </button>
                      {genError && <p className="mt-2 text-xs text-red-500">{genError}</p>}
                    </div>
                  ) : tab === 'dns' ? (
                    <div className="space-y-3">
                      <p className="text-xs text-gray-500">Add this TXT record to your DNS. Changes may take up to 48 hours.</p>
                      {[
                        { label: 'Host / Name', value: instructions.dns?.host },
                        { label: 'Type',        value: 'TXT' },
                        { label: 'Value',       value: instructions.dns?.value },
                      ].map(({ label, value }) => (
                        <div key={label} className="bg-gray-50 rounded-lg p-3">
                          <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">{label}</p>
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
                          <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">{label}</p>
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
                        : <><Wifi className="w-4 h-4" /> Check DNS</>
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
                      : <><ShieldCheck className="w-4 h-4" /> Verify Ownership</>
                    }
                  </button>
                  <span className="text-xs text-gray-400">Checks both DNS and HTML</span>

                  {/* DNS check result */}
                  {dnsResult && (
                    <div className={`w-full flex items-start gap-2 p-3 rounded-xl text-sm border ${
                      dnsResult.matches
                        ? 'bg-brand-50 border-brand-100 text-brand-700'
                        : dnsResult.found
                        ? 'bg-amber-50 border-amber-100 text-amber-700'
                        : 'bg-gray-50 border-gray-100 text-gray-500'
                    }`}>
                      {dnsResult.matches
                        ? <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0 text-brand-500" />
                        : <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      }
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
                        : 'bg-red-50 border-red-100 text-red-600'
                    }`}>
                      {verifyResult.success
                        ? <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                        : <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      }
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
      <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center mx-auto mb-5">
        <Globe className="w-7 h-7 text-brand-600" />
      </div>
      <h2 className="text-xl font-bold text-gray-900 mb-2">Add your first domain</h2>
      <p className="text-sm text-gray-400 mb-8">
        Enter one domain to get started, or import a list to monitor your entire attack surface.
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
              : <><Plus className="w-4 h-4" /> Start Monitoring</>
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
              : <><Upload className="w-4 h-4" /> Import & Start Monitoring</>
            }
          </button>
        </div>
      )}

      {!importing && (
        <button
          onClick={() => { setShowBulk(v => !v); setSingleDomain(''); setBulkText('') }}
          className="text-xs text-brand-600 hover:underline mt-1"
        >
          {showBulk ? '← Single domain' : 'Import multiple domains'}
        </button>
      )}

      {importResult && (
        <div className="mt-5 p-4 bg-brand-50 rounded-xl text-sm text-brand-700">
          <CheckCircle className="w-4 h-4 inline mr-1.5" />
          {importResult.imported} domain{importResult.imported !== 1 ? 's' : ''} added
          {importResult.skipped > 0 && ` · ${importResult.skipped} already existed`}
          {importResult.invalid > 0 && ` · ${importResult.invalid} invalid`}
        </div>
      )}

      {importError && (
        <div className="mt-5 p-4 bg-red-50 rounded-xl text-sm text-red-600">
          <AlertTriangle className="w-4 h-4 inline mr-1.5" />
          {importError}
        </div>
      )}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function WorkspaceDashboard() {
  const { wsId, wsName } = useWorkspace()
  const { user } = useAuth()
  const [scorecard, setScorecard] = useState(null)
  const [timeline,  setTimeline]  = useState([])
  const [summary,   setSummary]   = useState(null)
  const [health,    setHealth]    = useState(null)
  const [domains,   setDomains]   = useState([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const [sc, tl, sm, hl, dm] = await Promise.allSettled([
        api.getWorkspaceScorecard(wsId),
        api.getWorkspacePostureTimeline(wsId),
        api.getWorkspaceSummary(wsId),
        api.getWorkspaceHealth(wsId),
        api.getWorkspaceDomains(wsId),
      ])
      if (sc.status === 'fulfilled') setScorecard(sc.value)
      setTimeline(tl.status === 'fulfilled' ? (tl.value.timeline || []).slice(-30) : [])
      if (sm.status === 'fulfilled') setSummary(sm.value)
      if (hl.status === 'fulfilled') setHealth(hl.value)
      if (dm.status === 'fulfilled') setDomains(dm.value.domains || [])

      // If scorecard errored but not a hard failure, don't block
      if (sc.status === 'rejected' && tl.status === 'rejected' && sm.status === 'rejected') {
        throw new Error(sc.reason?.message || 'Failed to load dashboard')
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const sc = scorecard
  const noDomains = health?.workspace_status === 'no_domains' || (summary && summary.domains === 0)

  // Verification metrics — computed from the domains list already loaded
  const verifiedCount   = domains.filter(d => d.verification_status === 'verified').length
  const pendingCount    = domains.filter(d => ['pending', 'pending_verification'].includes(d.verification_status)).length
  const failedCount     = domains.filter(d => ['failed', 'verification_failed'].includes(d.verification_status)).length
  const verificationRate = domains.length > 0 ? Math.round((verifiedCount / domains.length) * 100) : 0
  const noScans   = health?.workspace_status === 'no_scans'
  const hasCharts = timeline.length > 0

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* ── Onboarding: no domains yet ── */}
      {noDomains ? (
        <OnboardingWidget wsId={wsId} onDone={load} />
      ) : (
        <>
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Executive Dashboard</h1>
              <p className="text-sm text-gray-400 mt-0.5">
                {wsName}
                {sc?.last_scan_at ? ` · Last scan ${fmt(sc.last_scan_at)}` : ''}
                {health && (
                  <span className="ml-2 inline-flex items-center">
                    <HealthBadge status={health.monitoring_health} />
                  </span>
                )}
              </p>
            </div>
            <div className="card px-6 py-4 text-center">
              <p className="label mb-1">Security Score</p>
              <ScoreGauge score={sc?.security_score ?? summary?.latest_score} rating={sc?.risk_rating} />
              <p className="text-xs font-semibold text-gray-400 mt-1">{securityRatingLabel(sc?.risk_rating) || '—'}</p>
            </div>
          </div>

          {/* Summary stat cards */}
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-6">
              <StatCard icon={Globe}       label="Domains"         value={summary.domains}         />
              <StatCard icon={Server}      label="Active Assets"   value={summary.active_assets}   />
              <StatCard icon={Package2}    label="Vendors"         value={summary.vendors}         />
              <StatCard icon={FileText}    label="Reports"         value={summary.reports_count}   />
              <StatCard icon={Shield}      label="Latest Score"    value={summary.latest_score ?? '—'} />
              <StatCard icon={AlertTriangle} label="Critical"      value={summary.critical_findings ?? 0} danger={(summary.critical_findings ?? 0) > 0} />
            </div>
          )}

          {/* Verification metrics */}
          {domains.length > 0 && (
            <div className="grid grid-cols-3 gap-3 mb-6">
              <StatCard
                icon={ShieldCheck}
                label="Domains Verified"
                value={`${verifiedCount} / ${domains.length}`}
                sub={`${verificationRate}% verification rate`}
              />
              <StatCard
                icon={Clock}
                label="Pending Verification"
                value={pendingCount}
                warning={pendingCount > 0}
              />
              <StatCard
                icon={AlertTriangle}
                label="Verification Failed"
                value={failedCount}
                danger={failedCount > 0}
              />
            </div>
          )}

          {/* Domain ownership verification wizard */}
          <DomainVerificationPanel domains={domains} wsId={wsId} onVerified={load} />

          {/* Team members */}
          <WorkspaceMembersPanel workspaceId={wsId} currentUser={user} />

          {/* Activity timeline */}
          <ActivityTimeline workspaceId={wsId} />

          {/* Empty state: no scans yet */}
          {noScans ? (
            <div className="mb-8 space-y-4">
              {/* Hero CTA */}
              <div className="card p-8 flex flex-col sm:flex-row sm:items-center gap-6">
                <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center flex-shrink-0">
                  <ScanLine className="w-7 h-7 text-brand-600" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-base font-bold text-gray-900 mb-1">Run your first Cyber MOT</p>
                  <p className="text-sm text-gray-500 leading-relaxed">
                    A CyberMeters scan analyses your domain's DNS configuration, SSL certificates, security headers,
                    email security posture, exposed assets, and subdomains — producing a scored risk report in minutes.
                  </p>
                </div>
                <a href="/scans/new" className="btn-primary flex-shrink-0 inline-flex items-center gap-2">
                  <Plus className="w-4 h-4" /> Start Scan
                </a>
              </div>
              {/* What a scan checks */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {[
                  { icon: Shield,        label: 'DNS & SSL',           desc: 'Certificate validity, DNS hygiene, resolver agreement'   },
                  { icon: ShieldAlert,   label: 'Security Headers',    desc: 'CSP, HSTS, X-Frame-Options and 6 other header controls'  },
                  { icon: AlertTriangle, label: 'Email Security',      desc: 'SPF, DKIM, DMARC — misconfiguration is phishing risk'    },
                  { icon: Server,        label: 'Subdomain Discovery', desc: 'Map your full attack surface including forgotten assets'  },
                  { icon: Activity,      label: 'Asset Exposure',      desc: 'Open admin panels, dev environments and cloud leakage'   },
                  { icon: BarChart2,     label: 'Risk Score',          desc: 'Single 0–100 Cyber Metrics Score with drill-down detail' },
                ].map(({ icon: Icon, label, desc }) => (
                  <div key={label} className="card p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="w-4 h-4 text-brand-500 flex-shrink-0" />
                      <span className="text-xs font-semibold text-gray-900">{label}</span>
                    </div>
                    <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <>
              {/* KPI Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                <StatCard icon={Server}        label="Active Assets"    value={sc?.active_assets ?? '—'} sub={`${sc?.new_assets_30d ?? 0} new in 30d`} />
                <StatCard icon={AlertTriangle} label="Critical Findings" value={sc?.critical_findings ?? '—'} danger={(sc?.critical_findings ?? 0) > 0} />
                <StatCard icon={Package2}      label="Vendors Detected" value={sc?.vendors_detected ?? '—'} warning={(sc?.vendor_risk?.high ?? 0) > 0} sub={sc?.vendor_risk?.high > 0 ? `${sc.vendor_risk.high} high-risk` : undefined} />
                <StatCard icon={Zap}           label="SaaS Exposures"   value={sc?.saas_exposures ?? '—'} warning={(sc?.saas_exposures ?? 0) > 0} />
                <StatCard icon={Tag}           label="Brand Risks"      value={sc?.brand_risks?.active ?? '—'} danger={(sc?.brand_risks?.high ?? 0) > 0} sub={sc?.brand_risks?.high > 0 ? `${sc.brand_risks.high} high-risk` : undefined} />
                <StatCard icon={Terminal}      label="Admin Surfaces"   value={sc?.admin_surfaces ?? '—'} danger={(sc?.admin_surfaces ?? 0) > 0} />
                <StatCard icon={Shield}        label="Cert Risk"        value={sc?.certificate_risks?.risk_level ?? '—'} warning={['high','critical'].includes(sc?.certificate_risks?.risk_level)} />
                <StatCard icon={BarChart2}     label="Events (30d)"     value={sc?.asset_events_30d ?? '—'} sub="surface changes" />
              </div>

              {/* Charts */}
              {hasCharts && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                  <div className="card p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h2 className="font-semibold text-gray-900">Risk Score Trend</h2>
                      {timeline.length > 1 && (() => {
                        const first = timeline[0]?.score
                        const last  = timeline[timeline.length - 1]?.score
                        const diff  = last - first
                        const Icon  = diff > 0 ? TrendingUp : diff < 0 ? TrendingDown : Minus
                        const color = diff > 0 ? 'text-brand-600' : diff < 0 ? 'text-red-500' : 'text-gray-400'
                        return (
                          <span className={`flex items-center gap-1 text-sm font-semibold ${color}`}>
                            <Icon className="w-4 h-4" />
                            {diff > 0 ? '+' : ''}{diff}
                          </span>
                        )
                      })()}
                    </div>
                    <ResponsiveContainer width="100%" height={160}>
                      <LineChart data={timeline}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                        <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickFormatter={fmt} />
                        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} width={28} />
                        <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                        <Line type="monotone" dataKey="score" stroke="#00876A" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="card p-6">
                    <h2 className="font-semibold text-gray-900 mb-4">Asset Growth</h2>
                    <ResponsiveContainer width="100%" height={160}>
                      <AreaChart data={timeline}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                        <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickFormatter={fmt} />
                        <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} width={28} />
                        <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                        <Area type="monotone" dataKey="total_assets" stroke="#00876A" fill="#e6f4f1" strokeWidth={2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* Executive Summary */}
              {sc?.executive_summary ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="card p-5">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-2 h-2 rounded-full bg-brand-500" />
                      <h3 className="font-semibold text-gray-900 text-sm">Good</h3>
                    </div>
                    {sc.executive_summary.good.length === 0
                      ? <p className="text-xs text-gray-400">No positive signals yet.</p>
                      : sc.executive_summary.good.map((s, i) => (
                          <p key={i} className="text-xs text-gray-600 mb-1.5 leading-relaxed">{s}</p>
                        ))}
                  </div>

                  <div className="card p-5">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-2 h-2 rounded-full bg-amber-400" />
                      <h3 className="font-semibold text-gray-900 text-sm">Attention Required</h3>
                    </div>
                    {sc.executive_summary.attention_required.length === 0
                      ? <p className="text-xs text-gray-400">Nothing requires attention.</p>
                      : sc.executive_summary.attention_required.map((s, i) => (
                          <p key={i} className="text-xs text-gray-600 mb-1.5 leading-relaxed">{s}</p>
                        ))}
                  </div>

                  <div className="card p-5 border-red-100">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="w-2 h-2 rounded-full bg-red-500" />
                      <h3 className="font-semibold text-gray-900 text-sm">Urgent</h3>
                    </div>
                    {sc.executive_summary.urgent.length === 0
                      ? <p className="text-xs text-gray-400">No urgent issues.</p>
                      : sc.executive_summary.urgent.map((s, i) => (
                          <p key={i} className="text-xs text-red-700 mb-1.5 leading-relaxed">{s}</p>
                        ))}
                  </div>
                </div>
              ) : (
                /* No executive summary — prompt to generate a report */
                <div className="card p-10 text-center">
                  <FileText className="w-10 h-10 text-gray-200 mx-auto mb-3" />
                  <p className="text-gray-500 font-medium mb-1">No executive summary yet.</p>
                  <p className="text-sm text-gray-400 mb-5">Generate your first executive report to see an AI-powered summary here.</p>
                  <a href="/ws/reports" className="btn-secondary mx-auto inline-flex items-center gap-2">
                    <FileText className="w-4 h-4" /> Generate Report
                  </a>
                </div>
              )}
            </>
          )}
        </>
      )}
    </WsPage>
  )
}
