import { parseServerDate } from '../../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import {
  ShieldAlert, RefreshCw, Globe, Lock, User, Key,
  Wifi, Building2,
} from 'lucide-react'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import StatCard from '../../components/StatCard'
import IdentityExposureCard from '../../components/IdentityExposureCard'
import { confidenceDetailLabel, identityClaimMeta, toneClass } from '../../lib/identityExposureDisplay'

// ── Identity type configuration ───────────────────────────────────────────────

const IDENTITY_TYPE_CONFIG = {
  sso:           { label: 'SSO Portal',          icon: Key,        color: 'text-red-600    bg-red-50    border-red-100'    },
  vpn:           { label: 'VPN Portal',           icon: Wifi,       color: 'text-orange-600 bg-orange-50 border-orange-100' },
  idp:           { label: 'Identity Provider',    icon: Building2,  color: 'text-purple-600 bg-purple-50 border-purple-100' },
  admin_login:   { label: 'Admin Login',          icon: User,       color: 'text-amber-600  bg-amber-50  border-amber-100'  },
  login_portal:  { label: 'Login Portal',         icon: Lock,       color: 'text-blue-600   bg-blue-50   border-blue-100'   },
  oauth:         { label: 'OAuth Endpoint',       icon: Key,        color: 'text-indigo-600 bg-indigo-50 border-indigo-100' },
  saml:          { label: 'SAML Endpoint',        icon: ShieldAlert,color: 'text-rose-600   bg-rose-50   border-rose-100'   },
  remote_access: { label: 'Remote Access',        icon: Globe,      color: 'text-cyan-600   bg-cyan-50   border-cyan-100'   },
}

function getConfig(identity_type) {
  return IDENTITY_TYPE_CONFIG[identity_type] ?? {
    label: identity_type ?? 'Unknown',
    icon: ShieldAlert,
    color: 'text-gray-600 bg-gray-50 border-gray-100',
  }
}

// ── Asset card ────────────────────────────────────────────────────────────────

function IdentityAssetCard({ asset }) {
  const cfg  = getConfig(asset.identity_type)
  const Icon = cfg.icon
  const claim = asset.identity_claim
  const claimMeta = identityClaimMeta(claim)

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-9 h-9 rounded-lg border flex items-center justify-center flex-shrink-0 ${cfg.color}`}>
            <Icon className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <p className="font-semibold text-gray-900 text-sm truncate">
              {asset.provider ?? asset.hostname ?? cfg.label}
            </p>
            <p className="text-xs text-gray-400 capitalize mt-0.5">{cfg.label}</p>
          </div>
        </div>
        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border flex-shrink-0 ${toneClass(claimMeta.tone)}`}>
          {claimMeta.label}
        </span>
      </div>

      {asset.hostname && (
        <div className="mb-3 text-xs text-gray-600 truncate">
          Possible hostname: {asset.hostname}
        </div>
      )}

      <div className="flex flex-wrap gap-3 text-[11px] text-gray-400">
        <span>Reachability: <span className="font-medium text-gray-600">{claim?.reachability?.status?.replace(/_/g, ' ') || 'not evaluated'}</span></span>
        <span>{confidenceDetailLabel(asset.confidence_detail)}</span>
        {asset.name_resolution?.status && <span>Name resolution: <span className="font-medium text-gray-600">{asset.name_resolution.status.replace(/_/g, ' ')}</span></span>}
        {asset.source && <span>Source: <span className="capitalize font-medium text-gray-600">{asset.source.replace(/_/g, ' ')}</span></span>}
      </div>

      <div className="mt-3 pt-3 border-t border-gray-50 flex justify-between text-[10px] text-gray-400">
        <span>First seen: {asset.first_seen ? parseServerDate(asset.first_seen).toLocaleDateString() : '—'}</span>
        <span>Last seen: {asset.last_seen  ? parseServerDate(asset.last_seen).toLocaleDateString()  : '—'}</span>
      </div>
    </div>
  )
}

// ── Filters ───────────────────────────────────────────────────────────────────

const TYPE_FILTERS = [
  { value: '',             label: 'All types' },
  { value: 'sso',         label: 'SSO' },
  { value: 'vpn',         label: 'VPN' },
  { value: 'idp',         label: 'Identity Provider' },
  { value: 'admin_login', label: 'Admin Login' },
  { value: 'login_portal',label: 'Login Portal' },
  { value: 'oauth',       label: 'OAuth' },
  { value: 'saml',        label: 'SAML' },
]

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WorkspaceIdentityPage() {
  const { wsId, wsName } = useWorkspace()
  const [assets, setAssets]     = useState([])
  const [summary, setSummary]   = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [typeFilter, setType]   = useState('')
  const [search, setSearch]     = useState('')

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const [assetsData, summaryData] = await Promise.all([
        api.getWorkspaceIdentityAssets(wsId),
        api.getWorkspaceIdentitySummary(wsId),
      ])
      setAssets(assetsData.assets ?? [])
      setSummary(summaryData)
    } catch (e) {
      setError(e.message || 'Failed to load identity assets')
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const filtered = assets.filter(a => {
    if (typeFilter && a.identity_type !== typeFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (a.provider ?? '').toLowerCase().includes(q)
          || (a.hostname ?? '').toLowerCase().includes(q)
          || (a.identity_type ?? '').toLowerCase().includes(q)
    }
    return true
  })

  const providers = [...new Set(assets.filter(a => a.provider).map(a => a.provider))]

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Identity Assets</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Provider relationships and possible identity-facing hostnames — {wsName}
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="btn-secondary flex items-center gap-2 text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Identity Exposure — consolidated verdict (explanation first) */}
      <div className="mb-6">
        <IdentityExposureCard workspaceId={wsId} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard icon={ShieldAlert} label="Identity Evidence" value={assets.length} />
        <StatCard icon={Building2} label="Provider Relationships" value={summary?.provider_relationship_count ?? 0} />
        <StatCard icon={Globe} label="Possible Hostnames" value={summary?.surface_candidate_count ?? 0} />
        <StatCard icon={Wifi} label="Reachability Evaluated" value={summary?.reachability_evaluated_count ?? 0} />
      </div>

      {/* Provider chips */}
      {providers.length > 0 && (
        <div className="card p-4 mb-5">
          <p className="text-xs font-semibold text-gray-500 mb-3 uppercase tracking-widest">Observed or possible provider relationships</p>
          <div className="flex flex-wrap gap-2">
            {providers.map(p => (
              <button
                key={p}
                onClick={() => setSearch(p === search ? '' : p)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                  search === p
                    ? 'bg-brand-600 text-white border-brand-600'
                    : 'bg-gray-50 text-gray-700 border-gray-200 hover:bg-brand-50 hover:border-brand-300 hover:text-brand-700'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-5">
        <input
          type="text"
          placeholder="Search provider or hostname…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="input-base text-sm flex-1 min-w-[200px]"
        />
        <select
          value={typeFilter}
          onChange={e => setType(e.target.value)}
          className="input-base text-sm w-48"
        >
          {TYPE_FILTERS.map(f => (
            <option key={f.value} value={f.value}>{f.label}</option>
          ))}
        </select>
      </div>

      {/* Empty state */}
      {assets.length === 0 && !loading ? (
        <div className="card py-16 text-center">
          <ShieldAlert className="w-10 h-10 text-gray-200 mx-auto mb-3" />
          <p className="text-sm font-medium text-gray-500 mb-1">No identity assets discovered yet</p>
          <p className="text-xs text-gray-400">
            Identity assets are detected during domain scans. Run a scan to populate this inventory.
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card py-10 text-center">
          <p className="text-sm text-gray-400">No assets match the current filter.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filtered.map(a => (
            <IdentityAssetCard key={a.id} asset={a} />
          ))}
        </div>
      )}

      {/* Evidence boundary */}
      <div className="mt-6 card p-4">
        <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-widest">Evidence boundary</p>
        <p className="text-xs text-gray-500">Provider identification, hostname classification, name resolution and endpoint reachability are separate propositions. Current discovery does not perform an endpoint reachability check.</p>
      </div>
    </WsPage>
  )
}
