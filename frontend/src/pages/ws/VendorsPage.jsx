import { useState, useEffect, useCallback } from 'react'
import { Package2, RefreshCw } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import StatCard from '../../components/StatCard'
import DataTable from '../../components/DataTable'
import RiskBadge from '../../components/RiskBadge'

const CATEGORY_LABELS = {
  infrastructure: 'Infrastructure',
  cloud:          'Cloud',
  email_identity: 'Email / Identity',
  hosting:        'Hosting',
  saas:           'SaaS',
  support:        'Support',
  collaboration:  'Collaboration',
  ecommerce:      'E-commerce',
  certificate_authority: 'Certificate Authority',
}

function FilterBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={active
        ? 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 text-white'
        : 'px-3 py-1.5 rounded-lg text-xs font-medium text-gray-500 hover:bg-gray-100 border border-gray-200'}
    >
      {children}
    </button>
  )
}

const COLUMNS = [
  { key: 'name',       label: 'Vendor' },
  { key: 'category',   label: 'Category', render: v => CATEGORY_LABELS[v] ?? v ?? '—' },
  { key: 'confidence', label: 'Confidence', render: v => <span className="capitalize text-gray-600 text-xs">{v}</span> },
  { key: 'risk_level', label: 'Risk',     render: v => <RiskBadge level={v} /> },
  { key: 'status',     label: 'Status',   render: v => (
    <span className={`text-xs font-semibold capitalize ${v === 'active' ? 'text-brand-600' : 'text-gray-400'}`}>{v}</span>
  )},
  { key: 'last_seen',  label: 'Last Seen', render: v => v ? new Date(v).toLocaleDateString() : '—' },
]

export default function VendorsPage() {
  const { wsId, wsName } = useWorkspace()
  const [vendors, setVendors]   = useState([])
  const [summary, setSummary]   = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [filterRisk, setFilterRisk]       = useState('')
  const [filterStatus, setFilterStatus]   = useState('active')
  const [filterCategory, setFilterCategory] = useState('')

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const params = {}
      if (filterRisk)     params.risk_level = filterRisk
      if (filterStatus)   params.status     = filterStatus
      if (filterCategory) params.category   = filterCategory
      const [v, s] = await Promise.all([
        api.getWorkspaceVendors(wsId, params),
        api.getWorkspaceVendorsSummary(wsId),
      ])
      setVendors(v.vendors || [])
      setSummary(s)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId, filterRisk, filterStatus, filterCategory])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Vendor Risk</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName}</p>
        </div>
        <button onClick={() => load()} className="btn-ghost">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatCard icon={Package2} label="Total Active"  value={summary.active ?? 0} />
          <StatCard icon={Package2} label="High Risk"     value={summary.by_risk?.high   ?? 0} danger={(summary.by_risk?.high   ?? 0) > 0} />
          <StatCard icon={Package2} label="Medium Risk"   value={summary.by_risk?.medium ?? 0} warning={(summary.by_risk?.medium ?? 0) > 0} />
          <StatCard icon={Package2} label="Low Risk"      value={summary.by_risk?.low    ?? 0} />
        </div>
      )}

      {/* Filters */}
      <div className="card p-4 mb-6 flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-500 font-medium mr-1">Risk:</span>
        <FilterBtn active={filterRisk === ''}         onClick={() => setFilterRisk('')}>All</FilterBtn>
        <FilterBtn active={filterRisk === 'high'}     onClick={() => setFilterRisk('high')}>High</FilterBtn>
        <FilterBtn active={filterRisk === 'medium'}   onClick={() => setFilterRisk('medium')}>Medium</FilterBtn>
        <FilterBtn active={filterRisk === 'low'}      onClick={() => setFilterRisk('low')}>Low</FilterBtn>

        <span className="text-xs text-gray-500 font-medium ml-4 mr-1">Status:</span>
        <FilterBtn active={filterStatus === ''}       onClick={() => setFilterStatus('')}>All</FilterBtn>
        <FilterBtn active={filterStatus === 'active'} onClick={() => setFilterStatus('active')}>Active</FilterBtn>

        <span className="text-xs text-gray-500 font-medium ml-4 mr-1">Category:</span>
        <FilterBtn active={filterCategory === ''}     onClick={() => setFilterCategory('')}>All</FilterBtn>
        {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
          <FilterBtn key={k} active={filterCategory === k} onClick={() => setFilterCategory(k)}>{v}</FilterBtn>
        ))}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900">Vendors</h2>
          <span className="text-sm text-gray-400">{vendors.length} results</span>
        </div>
        <DataTable
          columns={COLUMNS}
          rows={vendors}
          empty={<div className="py-12 text-center text-sm text-gray-400">No vendors detected yet. Run a scan to discover third-party vendors.</div>}
        />
      </div>
    </WsPage>
  )
}
