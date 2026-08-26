import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, ExternalLink, Pin } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'
import StatCard from '../../components/StatCard'
import DataTable from '../../components/DataTable'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const COLUMNS = [
  {
    key: 'url',
    label: 'URL',
    render: (v, row) => (
      <div>
        <a href={v} target="_blank" rel="noopener noreferrer"
           className="font-medium text-brand-600 hover:underline text-sm flex items-center gap-1 truncate max-w-xs">
          {v} <ExternalLink className="w-3 h-3 flex-shrink-0" />
        </a>
        {row.title && <p className="text-xs text-gray-400 mt-0.5 truncate max-w-xs">{row.title}</p>}
      </div>
    ),
  },
  { key: 'product',  label: 'Product',  render: v => <span className="text-xs text-gray-700">{v || 'Observed service'}</span> },
  { key: 'category', label: 'Category', render: v => <span className="capitalize text-xs text-gray-600">{(v || 'unknown').replace(/_/g, ' ')}</span> },
  { key: 'severity', label: 'Severity', render: v => <RiskBadge level={v} /> },
  { key: 'confidence', label: 'Confidence', render: v => <span className="text-xs text-gray-500 capitalize">{v || '—'}</span> },
  { key: 'domain', label: 'Domain', render: v => <span className="text-xs text-gray-500">{v || '—'}</span> },
]

const EMPTY_COPY = Object.freeze({
  assessed_healthy: {
    title: 'No admin surfaces observed',
    detail: 'The latest completed assessment did not observe an exposed admin or sensitive service.',
  },
  unavailable: {
    title: 'Admin-surface evidence unavailable',
    detail: 'CyberMeters could not read or complete the evidence needed for this assessment. Retry after the next successful scan.',
  },
  not_assessed: {
    title: 'Admin surfaces not assessed',
    detail: 'Run a scan to assess externally observable admin and sensitive services.',
  },
})

export default function AdminSurfacesPage() {
  const { wsId, wsName } = useWorkspace()
  const [surfaces, setSurfaces] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [pinSeverity, setPinSeverity] = useState('')
  const [evidenceStatus, setEvidenceStatus] = useState('not_assessed')

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const d = await api.getWorkspaceAdminSurfaces(wsId)
      setSurfaces(Array.isArray(d.services) ? d.services : [])
      setEvidenceStatus(['issue_detected', 'assessed_healthy', 'unavailable', 'not_assessed'].includes(d.evidence_status)
        ? d.evidence_status
        : 'not_assessed')
    } catch (e) {
      setSurfaces([])
      setEvidenceStatus('unavailable')
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  // Sort: pinned severity first, then by severity order
  const displayed = [...surfaces].sort((a, b) => {
    if (pinSeverity) {
      const aPin = a.severity === pinSeverity ? -1 : 0
      const bPin = b.severity === pinSeverity ? -1 : 0
      if (aPin !== bPin) return aPin - bPin
    }
    return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  })

  const critical = surfaces.filter(s => s.severity === 'critical').length
  const high     = surfaces.filter(s => s.severity === 'high').length
  const confirmed = surfaces.filter(s => s.confidence === 'confirmed').length

  const SEVERITIES = ['critical', 'high', 'medium', 'low']

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Admin Surfaces</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard icon={ShieldAlert} label="Total Surfaces" value={surfaces.length} />
        <StatCard icon={ShieldAlert} label="Critical"       value={critical} danger={critical > 0} />
        <StatCard icon={ShieldAlert} label="High"           value={high}     danger={high > 0} />
        <StatCard icon={ShieldAlert} label="Confirmed"      value={confirmed} />
      </div>

      {/* Severity pin */}
      <div className="card p-4 mb-6 flex items-center gap-2 flex-wrap">
        <Pin className="w-4 h-4 text-gray-400 flex-shrink-0" />
        <span className="text-xs text-gray-500 font-medium mr-1">Pin severity:</span>
        <button
          onClick={() => setPinSeverity('')}
          className={pinSeverity === '' ? 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 text-white' : 'px-3 py-1.5 rounded-lg text-xs font-medium text-gray-500 hover:bg-gray-100 border border-gray-200'}
        >All</button>
        {SEVERITIES.map(sev => (
          <button
            key={sev}
            onClick={() => setPinSeverity(sev === pinSeverity ? '' : sev)}
            className={pinSeverity === sev ? 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 text-white' : 'px-3 py-1.5 rounded-lg text-xs font-medium text-gray-500 hover:bg-gray-100 border border-gray-200 capitalize'}
          >
            {sev}
          </button>
        ))}
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900">Admin &amp; Sensitive Surfaces</h2>
          <span className="text-sm text-gray-400">{displayed.length} result{displayed.length !== 1 ? 's' : ''}</span>
        </div>
        <DataTable
          columns={COLUMNS}
          rows={displayed}
          empty={
            <div className="py-12 text-center text-sm text-gray-400">
              <p className="font-medium text-gray-600">{(EMPTY_COPY[evidenceStatus] || EMPTY_COPY.not_assessed).title}</p>
              <p className="mt-1">{(EMPTY_COPY[evidenceStatus] || EMPTY_COPY.not_assessed).detail}</p>
            </div>
          }
        />
      </div>
    </WsPage>
  )
}
