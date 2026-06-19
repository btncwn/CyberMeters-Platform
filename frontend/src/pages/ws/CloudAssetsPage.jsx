import { useState, useEffect, useCallback } from 'react'
import { Cloud, ExternalLink } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'
import StatCard from '../../components/StatCard'
import DataTable from '../../components/DataTable'

const COLUMNS = [
  { key: 'asset',    label: 'Asset / Hostname', render: (v, row) => (
    <div>
      <p className="font-medium text-gray-900 truncate max-w-xs">{row.hostname || v}</p>
      {row.url && (
        <a href={row.url} target="_blank" rel="noopener noreferrer"
           className="text-xs text-brand-600 hover:underline flex items-center gap-1 mt-0.5">
          <ExternalLink className="w-3 h-3" />{row.url}
        </a>
      )}
    </div>
  )},
  { key: 'provider', label: 'Provider',  render: v => <span className="capitalize text-gray-700">{v || '—'}</span> },
  { key: 'category', label: 'Category',  render: v => <span className="capitalize text-xs text-gray-500">{(v || '').replace(/_/g, ' ')}</span> },
  { key: 'risk',     label: 'Risk',      render: v => <RiskBadge level={v} /> },
]

export default function CloudAssetsPage() {
  const { wsId, wsName } = useWorkspace()
  const [assets, setAssets]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const d = await api.getWorkspaceCloudAssets(wsId)
      setAssets(d.assets || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  // Count by provider for chart
  const providerCounts = {}
  for (const a of assets) {
    const p = a.provider || 'Unknown'
    providerCounts[p] = (providerCounts[p] || 0) + 1
  }
  const chartData = Object.entries(providerCounts)
    .map(([provider, count]) => ({ provider, count }))
    .sort((a, b) => b.count - a.count)

  const highRisk = assets.filter(a => ['high', 'critical'].includes(a.risk)).length

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Cloud Assets</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName}</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatCard icon={Cloud} label="Total Cloud Assets" value={assets.length} />
        <StatCard icon={Cloud} label="High Risk"          value={highRisk} danger={highRisk > 0} />
        <StatCard icon={Cloud} label="Providers"          value={Object.keys(providerCounts).length} />
      </div>

      {chartData.length > 0 && (
        <div className="card p-6 mb-6">
          <h2 className="font-semibold text-gray-900 mb-4">Assets by Provider</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={chartData} layout="vertical" barCategoryGap="30%">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} />
              <YAxis dataKey="provider" type="category" width={100} tick={{ fontSize: 11, fill: '#64748b' }} />
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
              <Bar dataKey="count" fill="#00876A" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="font-semibold text-gray-900">All Cloud Assets</h2>
        </div>
        <DataTable
          columns={COLUMNS}
          rows={assets}
          empty={<div className="py-12 text-center text-sm text-gray-400">No cloud assets detected. Run a scan first.</div>}
        />
      </div>
    </WsPage>
  )
}
