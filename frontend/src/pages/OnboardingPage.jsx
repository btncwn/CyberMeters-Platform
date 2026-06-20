import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  AlertTriangle, ArrowRight, Briefcase, CheckCircle, FileText,
  Globe, RefreshCw, ScanLine, ShieldCheck,
} from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'

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

function StepCard({ number, title, done, active, children }) {
  return (
    <div className={`card p-6 ${active ? 'ring-2 ring-brand-100' : ''}`}>
      <div className="flex items-start gap-4">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${
          done ? 'bg-brand-50 text-brand-600' : active ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-400'
        }`}>
          {done ? <CheckCircle className="w-5 h-5" /> : <span className="text-sm font-bold">{number}</span>}
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="text-base font-bold text-gray-900">{title}</h2>
          <div className="mt-4">{children}</div>
        </div>
      </div>
    </div>
  )
}

function ProgressItem({ icon: Icon, label, done }) {
  return (
    <div className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-sm ${
      done ? 'border-brand-100 bg-brand-50 text-brand-700' : 'border-gray-100 bg-white text-gray-400'
    }`}>
      <Icon className="w-4 h-4" />
      <span className="font-medium">{label}</span>
      {done && <CheckCircle className="w-4 h-4 ml-auto" />}
    </div>
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
  const [domainName, setDomainName] = useState('')
  const [verificationInstructions, setVerificationInstructions] = useState(null)
  const [verifyResult, setVerifyResult] = useState(null)
  const [firstScan, setFirstScan] = useState(null)
  const [successMessage, setSuccessMessage] = useState('')
  const [actionLoading, setActionLoading] = useState(null)

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
  const completion = Math.round((Object.values(steps).filter(Boolean).length / 5) * 100)
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
      const data = await api.addDomainToWorkspace(workspace.id, domainName.trim())
      const created = data.domain || data
      const refreshed = await api.getWorkspaceDomains(workspace.id).catch(() => ({ domains: [created] }))
      const list = refreshed.domains || [created]
      setDomains(list)
      setSelectedDomain(list.find(item => domainNameOf(item) === domainName.trim()) || created || list[0])
      setDomainName('')
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
      setSuccessMessage('Your first cyber risk assessment is ready.')
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

  return (
    <div className="max-w-screen-lg mx-auto px-6 py-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Get Started</h1>
          <p className="text-sm text-gray-400 mt-1">
            Set up your first workspace, verify a domain, and launch your first assessment.
          </p>
        </div>
        <div className="text-right">
          <p className="text-3xl font-bold text-brand-600">{completion}%</p>
          <p className="text-xs text-gray-400 font-medium">complete</p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
        <ProgressItem icon={Briefcase} label="Workspace" done={steps.workspace} />
        <ProgressItem icon={Globe} label="Domain" done={steps.domain} />
        <ProgressItem icon={ShieldCheck} label="Verification" done={steps.verification} />
        <ProgressItem icon={ScanLine} label="Scan" done={steps.scan} />
        <ProgressItem icon={FileText} label="Report" done={steps.report} />
      </div>

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
          <p className="text-sm text-gray-400">Create a workspace first.</p>
        ) : selectedDomain ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-gray-600">
              First domain: <span className="font-semibold text-gray-900">{selectedDomainName}</span>
            </p>
            {domains.length > 1 && (
              <span className="text-xs text-gray-400">{domains.length} domains in this workspace</span>
            )}
          </div>
        ) : (
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
        )}
      </StepCard>

      <StepCard number={3} title="Verify Domain" done={steps.verification} active={activeStep === 3}>
        {!selectedDomain ? (
          <p className="text-sm text-gray-400">Add a domain first.</p>
        ) : steps.verification ? (
          <p className="text-sm text-brand-700 font-medium">Domain ownership is verified.</p>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-gray-500">
              Add the CyberMeters TXT record to your DNS, then verify ownership.
            </p>
            {(verificationInstructions || selectedDomain?.verification_token) && (
              <div className="grid gap-3">
                <div className="bg-gray-50 rounded-xl p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">Host</p>
                  <code className="text-sm text-gray-800 break-all">{dnsHost}</code>
                </div>
                <div className="bg-gray-50 rounded-xl p-4">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400 mb-1">TXT Value</p>
                  <code className="text-sm text-gray-800 break-all">{dnsValue}</code>
                </div>
              </div>
            )}
            {verifyResult && !verifyResult.success && (
              <p className="text-sm text-amber-700 bg-amber-50 border border-amber-100 rounded-xl p-3">
                {verifyResult.message || 'Verification is not complete yet. DNS changes can take time to propagate.'}
              </p>
            )}
            <div className="flex flex-wrap gap-2">
              <button onClick={generateVerification} className="btn-secondary" disabled={actionLoading === 'verification'}>
                {actionLoading === 'verification' ? 'Preparing...' : 'Get DNS Record'}
              </button>
              <button onClick={verifyDomain} className="btn-primary" disabled={actionLoading === 'verify'}>
                {actionLoading === 'verify' ? 'Verifying...' : 'Verify Ownership'}
              </button>
              <Link to={`/domains/${domainIdOf(selectedDomain)}/verify`} className="btn-ghost">
                Advanced verification
              </Link>
            </div>
          </div>
        )}
      </StepCard>

      <StepCard number={4} title="Run First Scan" done={steps.scan} active={activeStep === 4}>
        {!steps.verification ? (
          <p className="text-sm text-gray-400">Verify the domain before starting the first scan.</p>
        ) : steps.scan ? (
          <p className="text-sm text-gray-600">First scan has been created for {selectedDomainName}.</p>
        ) : (
          <button onClick={runFirstScan} className="btn-primary" disabled={actionLoading === 'scan'}>
            {actionLoading === 'scan'
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Starting...</>
              : <><ScanLine className="w-4 h-4" /> Run First Scan</>
            }
          </button>
        )}
      </StepCard>

      <StepCard number={5} title="View Results" done={steps.report} active={activeStep === 5}>
        {steps.scan ? (
          <div className="space-y-4">
            <div className="rounded-xl border border-brand-100 bg-brand-50 p-4">
              <p className="text-sm font-semibold text-brand-800">
                {successMessage || 'Your first cyber risk assessment is ready.'}
              </p>
              <p className="text-xs text-brand-700 mt-1">
                Results may continue to update while scan processing completes.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {scanIdOf(completedScan) && (
                <Link to={`/scans/${scanIdOf(completedScan)}`} className="btn-primary">
                  View Report <ArrowRight className="w-4 h-4" />
                </Link>
              )}
              <button onClick={() => navigate('/dashboard')} className="btn-secondary">
                View Dashboard
              </button>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-400">Run the first scan to unlock results.</p>
        )}
      </StepCard>
    </div>
  )
}
