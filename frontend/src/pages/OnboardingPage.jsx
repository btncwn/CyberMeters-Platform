import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import { PENDING_SIGNUP_DOMAIN_KEY } from '../utils/signupDomainHandoff'
import { canonicalDomainInput } from '../lib/newScanVerification'
import OneClickDnsButton from '../components/OneClickDnsButton'
import PendingInvitationBanner from '../components/PendingInvitationBanner'
import { pendingInviteToken } from '../lib/invitationFlow'
import { useDomainConnectOffer } from '../hooks/useDomainConnectOffer'
import { onboardingActionError, verifyOutcomeCopy, VERIFY_RECORD_REFRESHED } from '../lib/onboardingCopy'

function domainIdOf(domain) {
  return domain?.domain_id || domain?.id
}

function domainNameOf(domain) {
  return domain?.domain || domain?.name || ''
}

function isVerified(domain, verifyResult) {
  return domain?.verification_status === 'verified' || verifyResult?.success === true
}

// The record value only ever comes from the server-issued token for THIS
// workspace's link: the issue response, or the link row in the workspace's
// domain list. Anything else (e.g. the legacy per-user domain row) is ignored.
const TOKEN_VALUE = /^cybermeters-verification=[0-9a-f]{32,128}$/

function linkRecordValue(domain) {
  const token = domain?.verification_token
  const value = token ? `cybermeters-verification=${token}` : ''
  return TOKEN_VALUE.test(value) ? value : ''
}

function scanIdOf(scan) {
  return scan?.id || scan?.scan_id
}

// Why each step is asked for, shown while it is current or still ahead.
const STEP_WHY = {
  1: 'A workspace keeps one business’s domains, results and team together.',
  2: 'CyberMeters checks this domain from the outside. Nothing is installed on your systems.',
  3: 'Full findings are shown only to someone who controls the domain. One DNS TXT record proves it and changes nothing else.',
  4: 'The first scan checks what CyberMeters can see of your domain from outside.',
  5: 'Your report shows what was observed, what needs attention and what could not be assessed.',
}

function stepStatus(done, active) {
  if (done) return { label: 'Done', cls: 'bg-brand-50 text-brand-700' }
  if (active) return { label: 'Now', cls: 'bg-gray-900 text-white' }
  return { label: 'Next', cls: 'bg-gray-100 text-gray-600' }
}

function StepCard({ number, title, done, active, children }) {
  const status = stepStatus(done, active)
  return (
    <section
      aria-labelledby={`onboarding-step-${number}`}
      aria-current={active ? 'step' : undefined}
      className={`card p-6 ${active ? 'ring-2 ring-brand-100' : ''}`}
    >
      <div className="flex items-start gap-4">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
          done ? 'bg-brand-50 text-brand-700' : active ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-500'
        }`}>
          <span className="text-sm font-bold">{number}</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 id={`onboarding-step-${number}`} className="text-base font-bold text-gray-900">{title}</h2>
            <span className={`text-xs font-semibold rounded-full px-2.5 py-0.5 ${status.cls}`}>{status.label}</span>
          </div>
          {!done && <p className="mt-1 text-sm text-gray-600 leading-relaxed">{STEP_WHY[number]}</p>}
          <div className="mt-4">{children}</div>
        </div>
      </div>
    </section>
  )
}

function StepRail({ steps, activeStep }) {
  const items = [
    ['Workspace', steps.workspace],
    ['Domain', steps.domain],
    ['Verification', steps.verification],
    ['First check', steps.scan],
    ['Report', steps.report],
  ]
  return (
    <nav aria-label="Setup steps" className="lg:sticky lg:top-24">
      <p className="lg:hidden text-sm font-semibold text-gray-700">
        Step {activeStep} of 5 · {items[activeStep - 1][0]}
      </p>
      <ol className="hidden lg:block card p-2">
        {items.map(([label, done], i) => {
          const active = activeStep === i + 1
          const status = stepStatus(done, active && !done)
          return (
            <li key={label} aria-current={active ? 'step' : undefined}
              className={`flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg ${active ? 'bg-gray-50' : ''}`}>
              <span className={`text-sm ${active ? 'font-semibold text-gray-900' : 'text-gray-700'}`}>{i + 1}. {label}</span>
              <span className={`text-xs font-semibold rounded-full px-2 py-0.5 ${status.cls}`}>{status.label}</span>
            </li>
          )
        })}
      </ol>
    </nav>
  )
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
      aria-label={`Copy ${value}`}
      className="flex items-center gap-1 text-xs font-semibold text-brand-700 hover:text-brand-800 transition-colors"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

export default function OnboardingPage() {
  const navigate = useNavigate()
  // An invited person with a pending invitation sees the invitation first, never
  // "Get Started / Create your first workspace" (P1, 18 Oct 2026).
  const [inviteState, setInviteState] = useState(() => (pendingInviteToken() ? 'checking' : 'none'))
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [workspace, setWorkspace] = useState(null)
  // Set when the caller only belongs to other people's workspaces.
  const [memberOf, setMemberOf] = useState(null)
  const [domains, setDomains] = useState([])
  const [selectedDomain, setSelectedDomain] = useState(null)
  const [scans, setScans] = useState([])
  const [reportState, setReportState] = useState(null)
  const [reportRefresh, setReportRefresh] = useState(0)
  const [workspaceName, setWorkspaceName] = useState('')
  // Prefill from the free Cyber MOT handoff (/signup?domain=… stored by SignupPage),
  // so the domain the user just scanned is waiting for them here.
  const [domainName, setDomainName] = useState(() => {
    try { return localStorage.getItem(PENDING_SIGNUP_DOMAIN_KEY) || '' } catch { return '' }
  })
  // { domainId, value } from the issue call, until the domain list carries it.
  const [issuedRecord, setIssuedRecord] = useState(null)
  // 'idle' | 'preparing' | 'failed' — the record is prepared automatically.
  const [recordState, setRecordState] = useState('idle')
  const preparingFor = useRef(null)
  const [verifyResult, setVerifyResult] = useState(null)
  const [verifyNote, setVerifyNote] = useState(null)
  const [firstScan, setFirstScan] = useState(null)
  const [actionLoading, setActionLoading] = useState(null)
  const selectedId = domainIdOf(selectedDomain)
  const dnsValue = (selectedId && issuedRecord?.domainId === selectedId ? issuedRecord.value : '') || linkRecordValue(selectedDomain)
  // One-click verification for the current token (re-fetched when a new one is issued).
  const oneClick = useDomainConnectOffer(selectedId, workspace?.id, dnsValue || null)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const wsData = await api.getWorkspaces()
      const list = wsData.workspaces || []
      const storedId = localStorage.getItem('cybermeters_workspace_id')
      // The setup checklist belongs to a workspace owner (19 Oct 2026): a member
      // is never walked through setting up someone else's workspace. Use the
      // active workspace when the caller owns it, else their first owned one;
      // with none, show the member panel. A row without a role is the caller's
      // own (the bootstrap workspace).
      const owns = (item) => !item?.role || item.role === 'owner'
      const stored = list.find(item => item.id === storedId)
      const ws = (stored && owns(stored) ? stored : list.find(owns)) || null
      setWorkspace(ws)
      setMemberOf(ws ? null : (stored || list[0] || null))

      if (!ws) {
        setDomains([])
        setSelectedDomain(null)
        setScans([])
        return
      }

      localStorage.setItem('cybermeters_workspace_id', ws.id)
      localStorage.setItem('cybermeters_workspace_name', ws.name)

      const [domainData, scanData] = await Promise.all([
        api.getWorkspaceDomains(ws.id).catch(() => ({ domains: [] })),
        api.getWorkspaceScans(ws.id).catch(() => ({ scans: [] })),
      ])

      const domainList = domainData.domains || []
      setDomains(domainList)
      setSelectedDomain(domainList[0] || null)
      setScans(scanData.scans || [])
    } catch (e) {
      setError(onboardingActionError('load', e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Re-read the workspace's own domain list — the authoritative link rows the
  // backend verifies against — keeping the same domain selected.
  async function refreshDomains(keepId) {
    if (!workspace?.id) return null
    const refreshed = await api.getWorkspaceDomains(workspace.id).catch(() => null)
    const list = refreshed?.domains
    if (!list) return null
    setDomains(list)
    const keep = list.find(item => domainIdOf(item) === keepId) || list[0] || null
    setSelectedDomain(keep)
    return keep
  }

  const completedScan = useMemo(
    () => scans.find(scan => scanIdOf(scan) === scanIdOf(firstScan))
      || firstScan
      || scans.find(scan => ['completed', 'running', 'queued', 'processing'].includes(scan.status))
      || null,
    [firstScan, scans],
  )
  const reportScanId = scanIdOf(completedScan)
  const scanFinished = completedScan?.status === 'completed'

  // The scan detail endpoint owns report availability. A completed scan alone
  // cannot mark the report step done while rendering is pending or unavailable.
  useEffect(() => {
    if (!reportScanId || !scanFinished) {
      setReportState(null)
      return
    }
    let cancelled = false
    setReportState({ scanId: reportScanId, status: 'checking' })
    api.getScan(reportScanId)
      .then(data => {
        if (!cancelled) setReportState({ scanId: reportScanId, status: data.report_availability?.status || 'unknown' })
      })
      .catch(() => {
        if (!cancelled) setReportState({ scanId: reportScanId, status: 'unknown' })
      })
    return () => { cancelled = true }
  }, [reportScanId, scanFinished, reportRefresh])

  const reportStatus = reportState && reportState.scanId === reportScanId ? reportState.status : 'checking'
  const reportReady = scanFinished && reportStatus === 'report_ready'

  const steps = {
    workspace: Boolean(workspace?.id),
    domain: Boolean(domainIdOf(selectedDomain)),
    verification: Boolean(domainIdOf(selectedDomain)) && isVerified(selectedDomain, verifyResult),
    scan: Boolean(scanIdOf(completedScan)),
    report: reportReady,
  }
  const completion = Math.round((Object.values(steps).filter(Boolean).length / 5) * 100)
  const activeStep = !steps.workspace ? 1 : !steps.domain ? 2 : !steps.verification ? 3 : !steps.scan ? 4 : 5
  const selectedDomainName = domainNameOf(selectedDomain)
  const firstResultsPartial = scanFinished && ['partial', 'degraded'].includes(completedScan?.scan_quality)

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
      setError(onboardingActionError('workspace', e))
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
      setError(onboardingActionError('domain', e))
    } finally {
      setActionLoading(null)
    }
  }

  // Issue the DNS record for THIS workspace's link. Runs by itself when step 3
  // opens without one, so nobody has to ask for the record.
  async function prepareRecord(id) {
    if (!id || !workspace?.id) return false
    preparingFor.current = id
    setRecordState('preparing')
    try {
      const data = await api.generateDomainVerification(id, workspace.id)
      if (data?.already_verified) {
        setVerifyResult({ success: true })
        await refreshDomains(id)
        setRecordState('idle')
        return true
      }
      const value = data?.dns?.value || (data?.token ? `cybermeters-verification=${data.token}` : '')
      if (!TOKEN_VALUE.test(value)) throw new Error('unusable verification record')
      setIssuedRecord({ domainId: id, value })
      setRecordState('idle')
      await refreshDomains(id)
      return true
    } catch {
      setRecordState('failed')
      return false
    }
  }

  const needsRecord = Boolean(workspace?.id && selectedId) && !isVerified(selectedDomain, verifyResult) && !dnsValue
  useEffect(() => {
    if (needsRecord && recordState === 'idle' && preparingFor.current !== selectedId) prepareRecord(selectedId)
  }, [needsRecord, recordState, selectedId]) // eslint-disable-line react-hooks/exhaustive-deps

  async function verifyDomain() {
    const id = selectedId
    if (!id) return
    setActionLoading('verify')
    setVerifyNote(null)
    try {
      const data = await api.verifyDomain(id, workspace?.id)
      if (data?.success === true) {
        setVerifyResult(data)
        await refreshDomains(id)
      } else {
        setVerifyNote(verifyOutcomeCopy(data))
      }
    } catch (e) {
      if (e?.outcome === 'no_token') {
        // The link had no record: prepare one now and say so plainly.
        preparingFor.current = null
        const ok = await prepareRecord(id)
        setVerifyNote(ok ? VERIFY_RECORD_REFRESHED : null)
      } else {
        setVerifyNote(verifyOutcomeCopy(e))
      }
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
      const refreshed = await api.getWorkspaceScans(workspace.id).catch(() => ({ scans: [] }))
      setScans(refreshed.scans || [])
    } catch (e) {
      setError(onboardingActionError('scan', e))
    } finally {
      setActionLoading(null)
    }
  }

  if (inviteState === 'checking' || inviteState === 'offer') {
    return (
      <div className="max-w-(--breakpoint-lg) mx-auto px-6 py-8 space-y-6" data-testid="onboarding-invitation-first">
        <PendingInvitationBanner onState={setInviteState} />
        {inviteState === 'checking' && (
          <div className="flex items-center justify-center min-h-[30vh]"><Spinner size="lg" /></div>
        )}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Spinner size="lg" />
      </div>
    )
  }

  if (memberOf) {
    return (
      <div className="max-w-(--breakpoint-lg) mx-auto px-6 py-8" data-testid="onboarding-member">
        <div className="card p-8 space-y-3">
          <h1 className="text-2xl font-bold text-gray-900">Nothing to set up</h1>
          <p className="text-sm text-gray-600 leading-relaxed">
            <span className="font-semibold text-gray-900">{memberOf.name}</span> is set up and managed by its owner.
            As a member you can follow its domains, scans and reports from the overview.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            <Link to="/dashboard" className="btn-primary">Go to overview</Link>
            <Link to="/workspaces" className="btn-secondary">Your workspaces</Link>
          </div>
        </div>
      </div>
    )
  }

  const dnsHost = selectedDomainName ? `_cybermeters.${selectedDomainName}` : ''

  return (
    <div className="max-w-(--breakpoint-lg) mx-auto px-6 py-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Get Started</h1>
          <p className="text-sm text-gray-500 mt-1">
            Set up your first workspace, verify a domain, and launch your first assessment.
          </p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-bold text-brand-700">{completion}%</p>
          <p className="text-xs text-gray-500 font-medium">complete</p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[240px_minmax(0,1fr)] gap-6 lg:gap-8 items-start">
      <StepRail steps={steps} activeStep={activeStep} />
      <div className="space-y-4 min-w-0">

      <StepCard number={1} title="Create Workspace" done={steps.workspace} active={activeStep === 1}>
        {workspace ? (
          <p className="text-sm text-gray-600">
            Active workspace: <span className="font-semibold text-gray-900">{workspace.name}</span>
          </p>
        ) : (
          <form onSubmit={createWorkspace} className="flex flex-col sm:flex-row gap-3">
            <input
              className="input"
              placeholder="Company or customer name"
              value={workspaceName}
              onChange={e => setWorkspaceName(e.target.value)}
            />
            <button className="btn-primary" disabled={actionLoading === 'workspace'}>
              {actionLoading === 'workspace' ? 'Creating...' : 'Create Workspace'}
            </button>
          </form>
        )}
      </StepCard>

      <StepCard number={2} title="Add Domain" done={steps.domain} active={activeStep === 2}>
        {!workspace ? (
          <p className="text-sm text-gray-500">Create a workspace first.</p>
        ) : selectedDomain ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-gray-600">
              First domain: <span className="font-semibold text-gray-900">{selectedDomainName}</span>
            </p>
            {domains.length > 1 && (
              <span className="text-xs text-gray-500">{domains.length} domains in this workspace</span>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            <form onSubmit={addDomain} className="flex flex-col sm:flex-row gap-3">
              <input
                className="input"
                placeholder="example.com"
                value={domainName}
                onChange={e => setDomainName(e.target.value)}
              />
              <button className="btn-primary" disabled={actionLoading === 'domain'}>
                {actionLoading === 'domain' ? 'Adding...' : 'Add Domain'}
              </button>
            </form>
            <p className="text-xs text-gray-500">
              Enter the root domain you want to assess — no <span className="mono">https://</span> or <span className="mono">www</span>. You'll confirm ownership in the next step.
            </p>
          </div>
        )}
      </StepCard>

      <StepCard number={3} title="Verify Domain" done={steps.verification} active={activeStep === 3}>
        {!selectedDomain ? (
          <p className="text-sm text-gray-500">Add a domain first.</p>
        ) : steps.verification ? (
          <p className="text-sm text-brand-700 font-medium">Domain ownership is verified.</p>
        ) : (
          <div className="space-y-4" data-testid="onboarding-verify">
            <p className="text-sm text-gray-500">
              Add the CyberMeters TXT record to your DNS, then verify ownership.
            </p>
            {dnsValue ? (
              <>
                <OneClickDnsButton offer={oneClick} />
                <dl className="rounded-xl border border-gray-200 divide-y divide-gray-100" data-testid="onboarding-dns-record">
                  {[['Type', 'TXT'], ['Host', dnsHost], ['TXT Value', dnsValue]].map(([label, value]) => (
                    <div key={label} className="grid grid-cols-1 sm:grid-cols-[110px_minmax(0,1fr)_auto] gap-1 sm:gap-4 items-start sm:items-center px-4 py-3">
                      <dt className="text-xs font-semibold uppercase tracking-widest text-gray-500">{label}</dt>
                      <dd className="min-w-0"><code className="text-sm text-gray-800 break-all">{value}</code></dd>
                      <dd>{label !== 'Type' && <CopyButton value={value} />}</dd>
                    </div>
                  ))}
                </dl>
                <p className="text-sm text-gray-600">
                  Where to add it: in the DNS settings at your domain or hosting provider. If someone else manages your domain, send them the host and value above.
                </p>
              </>
            ) : recordState === 'failed' ? (
              <p role="status" className="text-sm text-gray-800 bg-gray-50 border border-gray-300 rounded-xl p-3" data-testid="onboarding-record-failed">
                {onboardingActionError('record')}
              </p>
            ) : (
              <div className="flex items-center gap-2 text-sm text-gray-600" data-testid="onboarding-record-preparing">
                <Spinner size="sm" /> Preparing your DNS record…
              </div>
            )}
            {verifyNote && (
              <p role="status" className="text-sm text-gray-800 bg-gray-50 border border-gray-300 rounded-xl p-3" data-testid="onboarding-verify-note">
                {verifyNote}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              {dnsValue ? (
                <button onClick={verifyDomain} className="btn-primary" disabled={actionLoading === 'verify'}>
                  {actionLoading === 'verify' ? 'Checking…' : 'Verify ownership'}
                </button>
              ) : recordState === 'failed' ? (
                <button onClick={() => prepareRecord(selectedId)} className="btn-primary">
                  Try again
                </button>
              ) : null}
              <Link to={`/domains/${selectedId}/verify`} className="text-sm font-medium text-brand-700 hover:text-brand-800 underline underline-offset-2">
                Advanced verification
              </Link>
            </div>
          </div>
        )}
      </StepCard>

      <StepCard number={4} title="Run First Cyber MOT" done={steps.scan} active={activeStep === 4}>
        {!steps.verification ? (
          <p className="text-sm text-gray-500">Verify the domain before starting your first passive posture check.</p>
        ) : steps.scan ? (
          <p className="text-sm text-gray-600">
            {scanFinished
              ? `Your first passive posture check finished for ${selectedDomainName}.`
              : `Your first passive posture check is running for ${selectedDomainName}.`}
          </p>
        ) : (
          <button onClick={runFirstScan} className="btn-primary" disabled={actionLoading === 'scan'}>
            {actionLoading === 'scan'
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Starting...</>
              : 'Run First Cyber MOT'
            }
          </button>
        )}
      </StepCard>

      <StepCard number={5} title="Open Executive Report" done={steps.report} active={activeStep === 5}>
        {steps.scan ? (
          <div className="space-y-4">
            {/* A finished run is not the same as checks that all completed: a
                partial first scan says so instead of reading as a clean result. */}
            <div className={`rounded-xl border p-4 ${reportReady ? 'border-brand-100 bg-brand-50' : 'border-[1.5px] border-brand-700 bg-transparent'}`}>
              <p className={`text-sm font-semibold ${reportReady ? 'text-brand-800' : 'text-brand-700'}`}>
                {!scanFinished
                  ? 'Your first check has started.'
                  : reportStatus === 'report_preparing'
                    ? 'Your assessment finished. Your report is being prepared.'
                    : reportStatus === 'report_unavailable'
                      ? 'Your assessment finished, but the report is unavailable right now.'
                      : !reportReady
                        ? 'Checking report availability.'
                  : firstResultsPartial
                    ? 'Your first results are ready, but some checks did not complete.'
                    : 'Your first results are ready.'}
              </p>
              <p className={`text-xs mt-1 ${reportReady ? 'text-brand-700' : 'text-brand-700'}`}>
                {!scanFinished
                  ? 'Results fill in as each area finishes.'
                  : !reportReady
                    ? 'Check again shortly, or open the scan to see its current status.'
                  : firstResultsPartial
                    ? 'The report says which areas could not be assessed. The next scan checks them again.'
                    : 'Your Executive Report translates the technical evidence into a clear risk summary.'}
              </p>
            </div>
            {reportReady && (
              <p className="text-sm text-gray-600">
                Start with the first action the report lists. When it is fixed, mark it done: the next scan re-checks it and says whether the fix is confirmed.
              </p>
            )}
            <div className="flex flex-wrap gap-2">
              {scanIdOf(completedScan) && (
                <Link to={`/scans/${scanIdOf(completedScan)}`} className="btn-primary">
                  {reportReady ? 'Open Executive Report' : 'View scan status'}
                </Link>
              )}
              {scanFinished && !reportReady && (
                <button type="button" onClick={() => setReportRefresh(value => value + 1)} className="btn-secondary">
                  Check report status
                </button>
              )}
              <button onClick={() => navigate('/dashboard')} className="btn-secondary">
                Go to Dashboard
              </button>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-500">Run your first Cyber MOT to generate the Executive Report.</p>
        )}
      </StepCard>
      </div>
      </div>
    </div>
  )
}
