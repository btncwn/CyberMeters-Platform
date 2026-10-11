import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Check, Copy } from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import { PENDING_SIGNUP_DOMAIN_KEY } from '../utils/signupDomainHandoff'
import { canonicalDomainInput } from '../lib/newScanVerification'
import OneClickDnsButton from '../components/OneClickDnsButton'
import { useDomainConnectOffer } from '../hooks/useDomainConnectOffer'

function domainIdOf(domain) {
  return domain?.domain_id || domain?.id
}

function domainNameOf(domain) {
  return domain?.domain || domain?.name || ''
}

function isVerified(domain, verifyResult) {
  return domain?.verification_status === 'verified' || verifyResult?.success === true
}

function scanIdOf(scan) {
  return scan?.id || scan?.scan_id
}

function CopyButton({ value }) {
  const [copied, setCopied] = useState(false)
  if (!value) return null
  function handleCopy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-brand-700 hover:text-brand-800"
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

export default function OnboardingPage() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [workspace, setWorkspace] = useState(null)
  const [domains, setDomains] = useState([])
  const [selectedDomain, setSelectedDomain] = useState(null)
  const [scans, setScans] = useState([])
  const [reports, setReports] = useState([])
  const [workspaceName, setWorkspaceName] = useState('')
  // Prefill from the free Cyber MOT handoff (/signup?domain=… stored by SignupPage),
  // so the domain the user just scanned is waiting for them here.
  const [domainName, setDomainName] = useState(() => {
    try { return localStorage.getItem(PENDING_SIGNUP_DOMAIN_KEY) || '' } catch { return '' }
  })
  const [verificationInstructions, setVerificationInstructions] = useState(null)
  const [verifyResult, setVerifyResult] = useState(null)
  const [firstScan, setFirstScan] = useState(null)
  const [successMessage, setSuccessMessage] = useState('')
  const [actionLoading, setActionLoading] = useState(null)
  // One-click verification for the current token (re-fetched when a new one is issued).
  const oneClick = useDomainConnectOffer(
    domainIdOf(selectedDomain), workspace?.id,
    verificationInstructions?.dns?.value || verificationInstructions?.token || selectedDomain?.verification_token,
  )

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const wsData = await api.getWorkspaces()
      const list = wsData.workspaces || []
      const storedId = localStorage.getItem('cybermeters_workspace_id')
      const ws = list.find(item => item.id === storedId) || list[0] || null
      setWorkspace(ws)

      if (!ws) {
        setDomains([])
        setSelectedDomain(null)
        setScans([])
        setReports([])
        return
      }

      localStorage.setItem('cybermeters_workspace_id', ws.id)
      localStorage.setItem('cybermeters_workspace_name', ws.name)

      const [domainData, scanData, reportData] = await Promise.all([
        api.getWorkspaceDomains(ws.id).catch(() => ({ domains: [] })),
        api.getWorkspaceScans(ws.id).catch(() => ({ scans: [] })),
        api.getWorkspaceReports(ws.id).catch(() => ({ reports: [] })),
      ])

      const domainList = domainData.domains || []
      setDomains(domainList)
      setSelectedDomain(domainList[0] || null)
      setScans(scanData.scans || [])
      setReports(reportData.reports || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const completedScan = useMemo(
    () => firstScan || scans.find(scan => ['completed', 'running', 'queued', 'processing'].includes(scan.status)) || null,
    [firstScan, scans],
  )

  const steps = {
    workspace: Boolean(workspace?.id),
    domain: Boolean(domainIdOf(selectedDomain)),
    verification: Boolean(domainIdOf(selectedDomain)) && isVerified(selectedDomain, verifyResult),
    scan: Boolean(scanIdOf(completedScan)),
    report: Boolean(scanIdOf(completedScan) || reports.length > 0),
  }
  const activeStep = !steps.workspace ? 1 : !steps.domain ? 2 : !steps.verification ? 3 : !steps.scan ? 4 : 5
  const selectedDomainName = domainNameOf(selectedDomain)

  async function createWorkspace(e) {
    e.preventDefault()
    if (!workspaceName.trim()) return
    setActionLoading('workspace')
    setError(null)
    try {
      const data = await api.createWorkspace(workspaceName.trim())
      const ws = data.workspace || data
      setWorkspace(ws)
      localStorage.setItem('cybermeters_workspace_id', ws.id)
      localStorage.setItem('cybermeters_workspace_name', ws.name)
    } catch (e) {
      setError(e.message)
    } finally {
      setActionLoading(null)
    }
  }

  async function addDomain(e) {
    e.preventDefault()
    if (!workspace?.id || !domainName.trim()) return
    setActionLoading('domain')
    setError(null)
    try {
      const data = await api.addDomainToWorkspace(workspace.id, canonicalDomainInput(domainName))
      const created = data.domain || data
      const refreshed = await api.getWorkspaceDomains(workspace.id).catch(() => ({ domains: [created] }))
      const list = refreshed.domains || [created]
      setDomains(list)
      setSelectedDomain(list.find(item => domainNameOf(item) === canonicalDomainInput(domainName)) || created || list[0])
      setDomainName('')
      try { localStorage.removeItem(PENDING_SIGNUP_DOMAIN_KEY) } catch { /* ignore */ } // handoff consumed
    } catch (e) {
      setError(e.message)
    } finally {
      setActionLoading(null)
    }
  }

  async function generateVerification() {
    const id = domainIdOf(selectedDomain)
    if (!id) return
    setActionLoading('verification')
    setError(null)
    try {
      const data = await api.generateDomainVerification(id)
      setVerificationInstructions(data)
      const refreshed = await api.getDomain(id).catch(() => null)
      if (refreshed?.domain) setSelectedDomain(refreshed.domain)
    } catch (e) {
      setError(e.message)
    } finally {
      setActionLoading(null)
    }
  }

  async function verifyDomain() {
    const id = domainIdOf(selectedDomain)
    if (!id) return
    setActionLoading('verify')
    setError(null)
    try {
      const data = await api.verifyDomain(id)
      setVerifyResult(data)
      const refreshed = await api.getDomain(id).catch(() => null)
      if (refreshed?.domain) setSelectedDomain(refreshed.domain)
    } catch (e) {
      setVerifyResult({ success: false, message: e.message })
    } finally {
      setActionLoading(null)
    }
  }

  async function runFirstScan() {
    if (!workspace?.id || !selectedDomainName) return
    setActionLoading('scan')
    setError(null)
    try {
      const data = await api.createScan(selectedDomainName, workspace.id)
      const scan = data.scan || data
      setFirstScan(scan)
      setSuccessMessage('Your first Cyber MOT has started.')
      const refreshed = await api.getWorkspaceScans(workspace.id).catch(() => ({ scans: [] }))
      setScans(refreshed.scans || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setActionLoading(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Spinner size="lg" />
      </div>
    )
  }

  const dnsHost = verificationInstructions?.dns?.host || (selectedDomainName ? `_cybermeters.${selectedDomainName}` : '')
  const dnsValue = verificationInstructions?.dns?.value
    || (verificationInstructions?.token ? `cybermeters-verification=${verificationInstructions.token}` : '')
    || (selectedDomain?.verification_token ? `cybermeters-verification=${selectedDomain.verification_token}` : '')

  const rail = [
    { title: 'Name your workspace', done: steps.workspace,
      summary: workspace && <>Active workspace: <span className="font-semibold text-ink">{workspace.name}</span></> },
    { title: 'Add your domain', done: steps.domain,
      summary: selectedDomain && <>First domain: <span className="font-semibold text-ink">{selectedDomainName}</span></> },
    { title: 'Prove you own it', done: steps.verification,
      summary: steps.verification && 'Domain ownership is verified.' },
    { title: 'Run your first Cyber MOT', done: steps.scan,
      summary: steps.scan && `Started for ${selectedDomainName}.` },
    { title: 'Open your report', done: false, summary: null },
  ]

  return (
    <div className="max-w-[1120px] mx-auto px-6 py-10 lg:py-14">
      <header className="max-w-[44rem]">
        <p className="text-[15px] font-semibold text-brand-700">Step {activeStep} of 5</p>
        <h1 className="mt-2 text-[clamp(2rem,3.4vw,2.75rem)] font-semibold leading-[1.05] tracking-[-0.025em] text-ink" style={{ fontStretch: "114%" }}>
          Set up your first Cyber MOT.
        </h1>
        <p className="text-[17px] text-graphite mt-4 leading-relaxed">
          Five short steps. Proving you own the domain takes one DNS record; your provider may need a few minutes to publish it.
        </p>
      </header>

      {error && (
        <div role="alert" className="mt-8 rounded-[12px] bg-[#FBE4E1] text-result-fail px-5 py-4 text-[15px]">{error}</div>
      )}

      <div className="mt-10 grid lg:grid-cols-[300px_minmax(0,1fr)] gap-8 lg:gap-12 items-start">
        <ol aria-label="Setup steps" className="space-y-1">
          {rail.map((r, i) => {
            const n = i + 1
            const current = n === activeStep
            return (
              <li key={r.title} aria-current={current ? 'step' : undefined}
                className={`flex gap-4 rounded-[14px] px-4 py-3.5 ${current ? 'bg-white border border-rule shadow-card' : ''}`}>
                <span className={`w-8 h-8 flex-shrink-0 rounded-full grid place-items-center text-[14px] font-semibold ${
                  r.done ? 'bg-brand-600 text-white' : current ? 'bg-ink text-white' : 'border border-rule text-graphite bg-white'}`}
                  style={{ fontStretch: '118%' }}>
                  {r.done ? <Check className="w-4 h-4" strokeWidth={3} /> : n}
                </span>
                <div className="min-w-0 pt-1">
                  <p className={`text-[15px] font-semibold ${r.done || current ? 'text-ink' : 'text-graphite'}`}>{r.title}</p>
                  {r.summary && <p className="text-[14px] text-graphite mt-0.5 break-words">{r.summary}</p>}
                </div>
              </li>
            )
          })}
        </ol>

        <section className="bg-white rounded-[20px] border border-rule p-7 sm:p-10" aria-live="polite">
          {activeStep === 1 && (
            <StepPanel title="Name your workspace"
              copy="A workspace holds one business's domains, results and fixes. Use the company name; you can add more workspaces later.">
              <form onSubmit={createWorkspace} className="flex flex-col sm:flex-row gap-3">
                <label htmlFor="onb-workspace" className="sr-only">Workspace name</label>
                <input id="onb-workspace" className="input h-12 sm:flex-1" placeholder="Company or customer name"
                  value={workspaceName} onChange={e => setWorkspaceName(e.target.value)} autoFocus />
                <button className="btn-primary btn-lg" disabled={actionLoading === 'workspace' || !workspaceName.trim()}>
                  {actionLoading === 'workspace' ? 'Creating…' : 'Create workspace'}
                </button>
              </form>
            </StepPanel>
          )}

          {activeStep === 2 && (
            <StepPanel title="Add your domain"
              copy="The main domain your business uses for its website and email. Enter it without https:// or www.">
              <form onSubmit={addDomain} className="flex flex-col sm:flex-row gap-3">
                <label htmlFor="onb-domain" className="sr-only">Domain</label>
                <input id="onb-domain" className="input h-12 sm:flex-1" placeholder="example.com" inputMode="url"
                  autoCapitalize="none" spellCheck={false}
                  value={domainName} onChange={e => setDomainName(e.target.value)} autoFocus />
                <button className="btn-primary btn-lg" disabled={actionLoading === 'domain' || !domainName.trim()}>
                  {actionLoading === 'domain' ? 'Adding…' : 'Add domain'}
                </button>
              </form>
            </StepPanel>
          )}

          {activeStep === 3 && (
            <StepPanel title={`Prove you own ${selectedDomainName}`}
              copy="Add one TXT record at your DNS provider. It changes nothing for your website or email; it only shows us the domain is yours.">
              {(verificationInstructions || selectedDomain?.verification_token) ? (
                <div className="space-y-5">
                  <OneClickDnsButton offer={oneClick} />
                  <dl className="rounded-[14px] border border-rule divide-y divide-rule overflow-hidden">
                    <div className="px-5 py-4 bg-bay">
                      <dt className="text-[13px] font-semibold text-graphite">Type</dt>
                      <dd className="text-[15px] font-semibold mt-1">TXT</dd>
                    </div>
                    <div className="px-5 py-4">
                      <dt className="text-[13px] font-semibold text-graphite">Host or name</dt>
                      <dd className="mt-1"><code className="text-[15px] break-all">{dnsHost}</code></dd>
                    </div>
                    <div className="px-5 py-4">
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-[13px] font-semibold text-graphite">Value</dt>
                        <CopyButton value={dnsValue} />
                      </div>
                      <dd className="mt-1"><code className="text-[15px] break-all">{dnsValue}</code></dd>
                    </div>
                  </dl>
                </div>
              ) : (
                <p className="text-[15px] text-graphite">Start by getting your record. It is unique to this domain.</p>
              )}
              {verifyResult && !verifyResult.success && (
                <p role="status" className="mt-5 rounded-[12px] bg-[#FBEFD9] text-result-advisory px-5 py-4 text-[15px]">
                  {verifyResult.message || "We can't see the record yet. DNS changes can take a few minutes to appear; try again shortly."}
                </p>
              )}
              <div className="mt-7 flex flex-wrap items-center gap-3">
                <button onClick={generateVerification} className="btn-secondary btn-lg" disabled={actionLoading === 'verification'}>
                  {actionLoading === 'verification' ? 'Preparing…' : 'Get DNS record'}
                </button>
                <button onClick={verifyDomain} className="btn-primary btn-lg" disabled={actionLoading === 'verify'}>
                  {actionLoading === 'verify' ? 'Checking…' : 'Verify ownership'}
                </button>
                <Link to={`/domains/${domainIdOf(selectedDomain)}/verify`} className="text-[15px] font-semibold text-brand-700 hover:underline px-2">
                  Other ways to verify
                </Link>
              </div>
            </StepPanel>
          )}

          {activeStep === 4 && (
            <StepPanel title="Run your first Cyber MOT"
              copy={`We check all eight areas of ${selectedDomainName} from the outside. It runs in the background, so you can leave this page while it finishes.`}>
              <button onClick={runFirstScan} className="btn-primary btn-lg" disabled={actionLoading === 'scan'}>
                {actionLoading === 'scan' ? 'Starting…' : 'Run first Cyber MOT'}
              </button>
            </StepPanel>
          )}

          {activeStep === 5 && (
            <StepPanel title={successMessage || 'Your first Cyber MOT has started.'}
              copy="Your report fills in as the check finishes: what we saw, what needs attention and what we could not assess. Open it now or come back later.">
              <div className="flex flex-wrap gap-3">
                {scanIdOf(completedScan) && (
                  <Link to={`/scans/${scanIdOf(completedScan)}`} className="btn-primary btn-lg">Open executive report</Link>
                )}
                <button onClick={() => navigate('/dashboard')} className="btn-secondary btn-lg">Go to dashboard</button>
              </div>
            </StepPanel>
          )}
        </section>
      </div>
    </div>
  )
}

function StepPanel({ title, copy, children }) {
  return (
    <div>
      <h2 className="text-[26px] font-semibold leading-[1.15] tracking-[-0.015em] text-ink" style={{ fontStretch: '110%' }}>{title}</h2>
      <p className="text-[16px] text-graphite mt-3 leading-relaxed max-w-[36rem]">{copy}</p>
      <div className="mt-8">{children}</div>
    </div>
  )
}
