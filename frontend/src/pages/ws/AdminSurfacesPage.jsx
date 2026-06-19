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
  { key: 'type',     label: 'Type',     render: v => <span className="capitalize text-xs text-gray-600">{(v || '').replace(/_/g, ' ')}</span> },
  { key: 'severity', label: 'Severity', render: v => <RiskBadge level={v} /> },
  {
    key: 'auth_required',
    label: 'Auth',
    render: v => (
      <span className={`text-xs font-medium ${v ? 'text-brand-600' : 'text-red-500'}`}>
        {v ? 'Protected' : 'Open'}
      </span>
    ),
  },
  { key: 'source', label: 'Source', render: v => <span className="text-xs text-gray-400 capitalize">{v || '—'}</span> },
]

export default function AdminSurfacesPage() {
  const { wsId, wsName } = useWorkspace()
  const [surfaces, setSurfaces] = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [pinSeverity, setPinSeverity] = useState('')

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const d = await api.getWorkspaceAdminSurfaces(wsId)
      setSurfaces(d.surfaces || [])
    } catch (e) {
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
  const open     = surfaces.filter(s => !s.auth_required).length

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
        <StatCard icon={ShieldAlert} label="Unauthenticated" value={open}    danger={open > 0} />
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
              No admin surfaces detected. Run a scan to discover exposed admin panels.
            </div>
          }
        />
      </div>
    </WsPage>
  )
}
