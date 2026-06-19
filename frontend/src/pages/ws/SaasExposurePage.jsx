import { useState, useEffect, useCallback } from 'react'
import { Zap, ExternalLink } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'
import StatCard from '../../components/StatCard'

function ExposureCard({ exp }) {
  const isHigh = exp.risk_level === 'high' || exp.risk_level === 'critical'
  return (
    <div className={`card p-5 ${isHigh ? 'border-orange-100' : ''}`}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <p className="font-semibold text-gray-900">{exp.name}</p>
          <p className="text-xs text-gray-400 capitalize mt-0.5">{(exp.exposure_type || '').replace(/_/g, ' ')}</p>
        </div>
        <RiskBadge level={exp.risk_level} />
      </div>

      <p className="text-xs text-gray-500 mb-3 leading-relaxed">{exp.attack_surface}</p>

      <div className="space-y-1">
        {exp.tenant_url && (
          <a href={exp.tenant_url} target="_blank" rel="noopener noreferrer"
             className="flex items-center gap-1.5 text-xs text-brand-600 hover:underline truncate">
            <ExternalLink className="w-3 h-3 flex-shrink-0" /> Tenant: {exp.tenant_url}
          </a>
        )}
        {exp.portal_url && (
          <a href={exp.portal_url} target="_blank" rel="noopener noreferrer"
             className="flex items-center gap-1.5 text-xs text-gray-500 hover:underline truncate">
            <ExternalLink className="w-3 h-3 flex-shrink-0" /> Portal: {exp.portal_url}
          </a>
        )}
        {exp.admin_url && (
          <a href={exp.admin_url} target="_blank" rel="noopener noreferrer"
             className="flex items-center gap-1.5 text-xs text-red-500 hover:underline truncate">
            <ExternalLink className="w-3 h-3 flex-shrink-0" /> Admin: {exp.admin_url}
          </a>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-gray-50 flex items-center gap-3">
        <span className="text-[10px] text-gray-400">Confidence: <span className="capitalize font-medium">{exp.confidence}</span></span>
        <span className="text-[10px] text-gray-400">Category: <span className="capitalize">{exp.category}</span></span>
      </div>
    </div>
  )
}

export default function SaasExposurePage() {
  const { wsId, wsName } = useWorkspace()
  const [exposures, setExposures] = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const d = await api.getWorkspaceSaasExposure(wsId)
      setExposures(d.exposures || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const highCount = exposures.filter(e => ['high', 'critical'].includes(e.risk_level)).length

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SaaS Exposure</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName}</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatCard icon={Zap} label="Total Exposures" value={exposures.length} />
        <StatCard icon={Zap} label="High Risk"       value={highCount} danger={highCount > 0} />
        <StatCard icon={Zap} label="Medium Risk"     value={exposures.filter(e => e.risk_level === 'medium').length} warning />
      </div>

      {exposures.length === 0 ? (
        <div className="card py-16 text-center">
          <Zap className="w-10 h-10 text-gray-200 mx-auto mb-3" />
          <p className="text-sm text-gray-400">No SaaS portals exposed to the internet.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {exposures.map((exp, i) => <ExposureCard key={i} exp={exp} />)}
        </div>
      )}
    </WsPage>
  )
}
