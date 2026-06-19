import { useState, useEffect, useCallback } from 'react'
import { Layers, Mail, Users, Headphones, MessageSquare, Megaphone, ShoppingCart } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'

const CAT_META = {
  email:         { label: 'Email',         icon: Mail,          color: 'bg-blue-50 text-blue-700'    },
  crm:           { label: 'CRM',           icon: Users,         color: 'bg-purple-50 text-purple-700' },
  support:       { label: 'Support',       icon: Headphones,    color: 'bg-amber-50 text-amber-700'  },
  collaboration: { label: 'Collaboration', icon: MessageSquare, color: 'bg-brand-50 text-brand-700'  },
  marketing:     { label: 'Marketing',     icon: Megaphone,     color: 'bg-pink-50 text-pink-700'    },
  ecommerce:     { label: 'E-commerce',    icon: ShoppingCart,  color: 'bg-orange-50 text-orange-700' },
}

function AssetCard({ asset }) {
  const meta = CAT_META[asset.category] ?? { label: asset.category, icon: Layers, color: 'bg-gray-50 text-gray-700' }
  const Icon = meta.icon
  return (
    <div className="card p-4 flex items-start gap-3">
      <div className={`w-9 h-9 rounded-xl ${meta.color} flex items-center justify-center flex-shrink-0`}>
        <Icon className="w-[18px] h-[18px]" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="font-semibold text-sm text-gray-900">{asset.name}</p>
          <RiskBadge level={asset.risk_level} />
        </div>
        <p className="text-xs text-gray-400 mt-0.5 capitalize">{meta.label}</p>
        <p className="text-xs text-gray-500 mt-1 capitalize">{asset.confidence} confidence · via {asset.source}</p>
      </div>
    </div>
  )
}

export default function ThirdPartyPage() {
  const { wsId, wsName } = useWorkspace()
  const [assets, setAssets]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const d = await api.getWorkspaceThirdPartyAssets(wsId)
      setAssets(d.assets || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  // Group by category
  const groups = {}
  for (const a of assets) {
    const cat = a.category || 'other'
    if (!groups[cat]) groups[cat] = []
    groups[cat].push(a)
  }

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Third-Party Assets</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName} · {assets.length} service{assets.length !== 1 ? 's' : ''} detected</p>
        </div>
      </div>

      {assets.length === 0 ? (
        <div className="card py-16 text-center">
          <Layers className="w-10 h-10 text-gray-200 mx-auto mb-3" />
          <p className="text-sm text-gray-400">No third-party SaaS services detected yet.</p>
          <p className="text-xs text-gray-300 mt-1">Run a scan to discover external dependencies.</p>
        </div>
      ) : (
        <div className="space-y-8">
          {Object.entries(groups).map(([cat, items]) => {
            const meta = CAT_META[cat] ?? { label: cat }
            return (
              <div key={cat}>
                <h2 className="font-semibold text-gray-700 text-sm mb-3 capitalize">{meta.label} ({items.length})</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {items.map((a, i) => <AssetCard key={i} asset={a} />)}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </WsPage>
  )
}
