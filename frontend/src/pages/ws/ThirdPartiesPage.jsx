// ThirdPartiesPage — ONE home for third parties in Shadow IT & Unmanaged
// Technology (founder, 17 Oct 2026): the services seen in your pages (was
// /ws/third-party), the providers behind your domain (was /ws/vendors) and
// their concentration and dependency analysis (was /ws/supply-chain). The
// three old routes redirect here. Every number is the backend's own; the
// dependency analysis keeps its completeness honesty — an unavailable
// composite is said to be unavailable, never shown as 0, "initial" or "low".
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, GitBranch, Package2, Shield, Zap } from 'lucide-react'
import { parseServerDate } from '../../utils/dates'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { useWorkspace } from '../../hooks/useWorkspace'
import StatCard from '../../components/StatCard'
import DataTable from '../../components/DataTable'
import RiskBadge from '../../components/RiskBadge'
import { PlanGate } from '../../components/PlanUsageCard'

const CAT_META = {
  email:         { label: 'Email'         },
  crm:           { label: 'CRM'           },
  support:       { label: 'Support'       },
  collaboration: { label: 'Collaboration' },
  marketing:     { label: 'Marketing'     },
  ecommerce:     { label: 'E-commerce'    },
}

function AssetCard({ asset }) {
  const meta = CAT_META[asset.category] ?? { label: asset.category }
  return (
    <div className="card p-4 flex items-start gap-3">
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

const CATEGORY_LABELS = {
  infrastructure:       'Infrastructure',
  cloud:                'Cloud',
  email_identity:       'Email / Identity',
  hosting:              'Hosting',
  saas:                 'SaaS',
  support:              'Support',
  collaboration:        'Collaboration',
  ecommerce:            'E-commerce',
  certificate_authority:'Certificate Authority',
  // vendor_relationship categories (Phase 7k)
  analytics:            'Analytics',
  payments:             'Payments',
  crm:                  'CRM',
  identity:             'Identity',
  cdn:                  'CDN',
  security:             'Security',
  // identity cross-population (Phase 8f)
  identity_provider:    'Identity Provider',
}

function FilterBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={active
        ? 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-200 text-brand-900'
        : 'px-3 py-1.5 rounded-lg text-xs font-medium text-gray-500 hover:bg-gray-100 border border-gray-200'}
    >
      {children}
    </button>
  )
}

const COLUMNS = [
  { key: 'name',       label: 'Provider' },
  { key: 'category',   label: 'Category', render: v => CATEGORY_LABELS[v] ?? v ?? '—' },
  { key: 'confidence', label: 'Confidence', render: v => <span className="capitalize text-gray-600 text-xs">{v}</span> },
  { key: 'risk_level', label: 'Risk',     render: v => <RiskBadge level={v} /> },
  { key: 'status',     label: 'Status',   render: v => (
    <span className={`text-xs font-semibold capitalize ${v === 'active' ? 'text-brand-700' : 'text-gray-400'}`}>{v}</span>
  )},
  { key: 'last_seen',  label: 'Last Seen', render: v => v ? parseServerDate(v).toLocaleDateString() : '—' },
]

// ── Helpers ──────────────────────────────────────────────────────────────────

function concentrationColor(level) {
  if (level === 'critical') return 'text-red-700 bg-red-50 border-red-200'
  if (level === 'high')     return 'text-red-700 bg-red-50 border-red-100'
  if (level === 'medium')   return 'text-brand-700 bg-transparent border-[1.5px] border-brand-700'
  return 'text-brand-700 bg-brand-50 border-brand-100'
}

function scoreColor(score) {
  if (score >= 75) return '#117362'
  if (score >= 55) return '#22C55E'
  if (score >= 35) return '#45e3c7'
  return '#EF4444'
}

function ScoreRing({ score, label, size = 80 }) {
  const r = (size - 12) / 2
  const circ = 2 * Math.PI * r
  const dash = circ * (score / 100)
  const color = scoreColor(score)
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#F3F4F6" strokeWidth={8} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth={8}
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
        <text x={size / 2} y={size / 2 + 5} textAnchor="middle" fontSize={size > 70 ? 16 : 13} fontWeight="700" fill="#111827">
          {score}
        </text>
      </svg>
      <span className="text-xs text-gray-500 text-center leading-tight">{label}</span>
    </div>
  )
}

function ConfidencePill({ level }) {
  const cls =
    level === 'high'   ? 'bg-brand-50 text-brand-700 border border-brand-100' :
    level === 'medium' ? 'bg-transparent text-brand-700 border border-[1.5px] border-brand-700' :
    'bg-gray-100 text-gray-500 border border-gray-200'
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full capitalize ${cls}`}>
      {level}
    </span>
  )
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

// ── Sub-sections ─────────────────────────────────────────────────────────────

function CriticalVendorsTable({ vendors }) {
  if (!vendors?.length) {
    return <p className="text-sm text-gray-400 py-4">No critical vendors detected.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-100 text-left text-xs text-gray-400 uppercase tracking-wide">
            <th className="pb-2 font-medium">Vendor</th>
            <th className="pb-2 font-medium">Category</th>
            <th className="pb-2 font-medium">Tier</th>
            <th className="pb-2 font-medium">Risk</th>
            <th className="pb-2 font-medium">Parent</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {vendors.map((v, i) => (
            <tr key={i}>
              <td className="py-2 font-medium text-gray-800">{v.name}</td>
              <td className="py-2 text-gray-500 capitalize">{(v.category || '').replace(/_/g, ' ')}</td>
              <td className="py-2">
                <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                  v.tier === 1 ? 'bg-red-50 text-red-700' :
                  v.tier === 2 ? 'bg-transparent text-brand-700' :
                  'bg-gray-100 text-gray-500'
                }`}>T{v.tier}</span>
              </td>
              <td className="py-2"><RiskBadge level={v.risk_level} /></td>
              <td className="py-2 text-gray-400 text-xs">{v.parent_company || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CascadingRiskList({ risks }) {
  if (!risks?.length) {
    return (
      <div className="text-sm text-brand-700 py-2">
        No cascading risk scenarios detected.
      </div>
    )
  }
  const sorted = [...risks].sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  )
  return (
    <ul className="space-y-3">
      {sorted.map((r, i) => (
        <li key={i} className="flex gap-3">
          <div>
            <p className="text-sm font-medium text-gray-800">{r.scenario}</p>
            <p className="text-xs text-gray-400 mt-0.5 capitalize">
              Severity: {r.severity} · Likelihood: {r.likelihood}
              {r.vendors?.length ? ` · Vendors: ${r.vendors.slice(0, 3).join(', ')}` : ''}
            </p>
          </div>
        </li>
      ))}
    </ul>
  )
}

function ConcentrationSection({ concentration }) {
  if (!concentration) return null
  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-700 mb-3">Top Parent Companies</h3>
      {(concentration.top_parents || []).length === 0
        ? <p className="text-sm text-gray-400">No parent company data available.</p>
        : (
          <ul className="space-y-2">
            {concentration.top_parents.map((p, i) => (
              <li key={i} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <span className={`w-5 h-5 rounded text-xs font-bold flex items-center justify-center ${
                    p.tier === 1 ? 'bg-red-50 text-red-700' :
                    p.tier === 2 ? 'bg-transparent text-brand-700' :
                    'bg-gray-100 text-gray-500'
                  }`}>T{p.tier}</span>
                  <span className="font-medium text-gray-800">{p.name}</span>
                </div>
                <span className="text-xs text-gray-400">{p.vendor_count} vendor{p.vendor_count !== 1 ? 's' : ''}</span>
              </li>
            ))}
          </ul>
        )
      }
      {(concentration.spofs || []).length > 0 && (
        <div className="mt-4 p-3 rounded-lg bg-red-50 border border-red-100">
          <p className="text-xs font-semibold text-red-700 mb-1">Single Points of Failure</p>
          <ul className="space-y-0.5">
            {concentration.spofs.map((s, i) => (
              <li key={i} className="text-xs text-red-700">• {s}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ComplianceSection({ compliance }) {
  if (!compliance) return null
  const items = [
    { label: 'GDPR Readiness',       key: 'gdpr' },
    { label: 'Security Governance',  key: 'security_governance' },
    { label: 'PCI-DSS Exposure',     key: 'pci_dss' },
  ]
  return (
    <div>
      <ul className="space-y-3">
        {items.map(({ label, key }) => (
          <li key={key} className="flex items-center justify-between">
            <span className="text-sm text-gray-700">{label}</span>
            {compliance.coverage?.[key]?.state === 'assessed' && compliance[key] ? (
              <ConfidencePill level={compliance[key]} />
            ) : (
              <span
                className="text-xs font-semibold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 border border-gray-200"
                title={compliance.state_reason || 'This readiness signal is incomplete.'}
              >
                Incomplete
              </span>
            )}
          </li>
        ))}
      </ul>
      {compliance.note && (
        <p className="text-xs text-gray-400 mt-4 leading-relaxed">{compliance.note}</p>
      )}
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────


// ── Observed services (the SaaS and services seen in your pages) ────────────

function ObservedServices({ assets }) {
  const groups = {}
  for (const a of assets) {
    const cat = a.category || 'other'
    if (!groups[cat]) groups[cat] = []
    groups[cat].push(a)
  }
  return (
    <section className="card p-6" aria-labelledby="observed-services-title" id="observed-services">
      <h2 id="observed-services-title" className="font-semibold text-gray-900">Services seen in your pages</h2>
      <p className="text-sm text-gray-600 mt-0.5 mb-4">{assets.length} service{assets.length !== 1 ? 's' : ''} observed. An observed service is a dependency, not a verdict.</p>
      {assets.length === 0 ? (
        <p className="text-sm text-gray-600">No third-party services observed yet. Run a scan to discover external dependencies.</p>
      ) : (
        <div className="space-y-6">
          {Object.entries(groups).map(([cat, items]) => {
            const meta = CAT_META[cat] ?? { label: cat }
            return (
              <div key={cat}>
                <h3 className="font-semibold text-gray-700 text-sm mb-3 capitalize">{meta.label} ({items.length})</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {items.map((a, i) => <AssetCard key={`${a.name}-${i}`} asset={a} />)}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

// ── Providers (the companies behind your domain's infrastructure) ───────────

function Providers({ wsId }) {
  const [vendors, setVendors] = useState([])
  const [summary, setSummary] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filterRisk, setFilterRisk] = useState('')
  const [filterStatus, setFilterStatus] = useState('active')
  const [filterCategory, setFilterCategory] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const params = {}
      if (filterRisk)     params.risk_level = filterRisk
      if (filterStatus)   params.status     = filterStatus
      if (filterCategory) params.category   = filterCategory
      const [v, s] = await Promise.all([api.getWorkspaceVendors(wsId, params), api.getWorkspaceVendorsSummary(wsId)])
      setVendors(v.vendors || [])
      setSummary(s)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }, [wsId, filterRisk, filterStatus, filterCategory])
  useEffect(() => { load() }, [load])

  return (
    <section className="space-y-4" aria-labelledby="providers-title" id="providers">
      <div>
        <h2 id="providers-title" className="font-semibold text-gray-900">Providers behind your domain</h2>
        <p className="text-sm text-gray-600 mt-0.5">Hosting, email, DNS, payments and other providers observed from the outside, with the risk level the backend recorded.</p>
      </div>
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard icon={Package2} label="Active providers" value={summary.active ?? 0} />
          <StatCard icon={Package2} label="High risk"   value={summary.by_risk?.high   ?? 0} danger={(summary.by_risk?.high   ?? 0) > 0} />
          <StatCard icon={Package2} label="Medium risk" value={summary.by_risk?.medium ?? 0} warning={(summary.by_risk?.medium ?? 0) > 0} />
          <StatCard icon={Package2} label="Low risk"    value={summary.by_risk?.low    ?? 0} />
        </div>
      )}
      <div className="card p-4 flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-500 font-medium mr-1">Risk:</span>
        <FilterBtn active={filterRisk === ''}       onClick={() => setFilterRisk('')}>All</FilterBtn>
        <FilterBtn active={filterRisk === 'high'}   onClick={() => setFilterRisk('high')}>High</FilterBtn>
        <FilterBtn active={filterRisk === 'medium'} onClick={() => setFilterRisk('medium')}>Medium</FilterBtn>
        <FilterBtn active={filterRisk === 'low'}    onClick={() => setFilterRisk('low')}>Low</FilterBtn>
        <span className="text-xs text-gray-500 font-medium ml-4 mr-1">Status:</span>
        <FilterBtn active={filterStatus === ''}       onClick={() => setFilterStatus('')}>All</FilterBtn>
        <FilterBtn active={filterStatus === 'active'} onClick={() => setFilterStatus('active')}>Active</FilterBtn>
        <span className="text-xs text-gray-500 font-medium ml-4 mr-1">Category:</span>
        <FilterBtn active={filterCategory === ''} onClick={() => setFilterCategory('')}>All</FilterBtn>
        {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
          <FilterBtn key={k} active={filterCategory === k} onClick={() => setFilterCategory(k)}>{v}</FilterBtn>
        ))}
      </div>
      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h3 className="font-semibold text-gray-900">Providers</h3>
          <span className="text-sm text-gray-500">{loading ? 'Loading…' : `${vendors.length} results`}</span>
        </div>
        {error
          ? <p role="alert" className="px-5 py-4 text-sm text-red-700">{error}</p>
          : <DataTable columns={COLUMNS} rows={vendors} empty={<div className="py-12 text-center text-sm text-gray-600">No providers observed yet. Run a scan to discover them.</div>} />}
      </div>
    </section>
  )
}

// ── Concentration and dependencies (plan-gated analysis) ────────────────────

function Dependencies({ wsId }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setData(await api.getWorkspaceSupplyChain(wsId)) }
    catch (err) { setError(err) }
    finally { setLoading(false) }
  }, [wsId])
  useEffect(() => { load() }, [load])

  const concentrationLevel = data?.concentration_level ?? 'unknown'
  const dependencyScoreAssessed = data?.supply_chain_score_state === 'assessed' && Number.isFinite(data?.supply_chain_score)
  const resilienceAssessed = Number.isFinite(data?.operational_resilience_score)
  const asmMaturityAssessed = data?.asm_maturity?.state === 'assessed' && Number.isFinite(data?.asm_maturity?.score)

  if (error && error?.error !== 'plan_feature_required') {
    return <section className="card p-6" id="dependencies"><h2 className="font-semibold text-gray-900">Concentration and dependencies</h2><p role="alert" className="text-sm text-red-700 mt-2">{error.message}</p><button onClick={load} className="btn-secondary mt-3">Retry</button></section>
  }

  return (
    <section className="space-y-6" aria-labelledby="dependencies-title" id="dependencies">
      <div>
        <h2 id="dependencies-title" className="font-semibold text-gray-900">Concentration and dependencies</h2>
        <p className="text-sm text-gray-600 mt-0.5">Which providers you depend on most, where one failure would cascade, and the readiness signals derived from existing CyberMeters data.</p>
      </div>
      <PlanGate error={error}>
        {loading && <p className="text-sm text-gray-600">Loading…</p>}
        {data && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard
                icon={Shield}
                label="Dependency score"
                value={dependencyScoreAssessed ? data.supply_chain_score : 'Unavailable'}
                explanation={dependencyScoreAssessed ? null : data.supply_chain_score_reason}
                tone={dependencyScoreAssessed ? null : 'neutral'}
                danger={dependencyScoreAssessed && data.supply_chain_score < 40}
                warning={dependencyScoreAssessed && data.supply_chain_score < 65 && data.supply_chain_score >= 40}
              />
              <StatCard
                icon={Zap}
                label="Resilience score"
                value={resilienceAssessed ? data.operational_resilience_score : 'Unavailable'}
                tone={resilienceAssessed ? null : 'neutral'}
                danger={resilienceAssessed && data.operational_resilience_score < 40}
                warning={resilienceAssessed && data.operational_resilience_score < 65 && data.operational_resilience_score >= 40}
              />
              <StatCard icon={AlertTriangle} label="Critical providers" value={data.critical_vendor_count ?? 0} danger={(data.critical_vendor_count ?? 0) >= 5} warning={(data.critical_vendor_count ?? 0) >= 2} />
              <StatCard icon={GitBranch} label="Single points of failure" value={data.spof_count ?? 0} danger={(data.spof_count ?? 0) >= 2} warning={(data.spof_count ?? 0) === 1} />
            </div>

            <div className={`card p-4 flex items-center justify-between border ${concentrationColor(concentrationLevel)}`}>
              <div>
                <p className="text-sm font-semibold capitalize">Provider concentration: {concentrationLevel}</p>
                <p className="text-xs mt-0.5 opacity-75">{data.tier1_count} Tier 1 · {data.tier2_count} Tier 2 · {data.tier3_count} Tier 3 providers</p>
              </div>
              <div className="flex gap-6">
                {dependencyScoreAssessed ? (
                  <ScoreRing score={data.supply_chain_score} label="Dependency" size={72} />
                ) : (
                  <div className="max-w-40 text-right">
                    <p className="text-xs font-semibold">Dependency score unavailable</p>
                    <p className="text-xs mt-1 opacity-75">Current BRS-dependent maturity evidence is incomplete.</p>
                  </div>
                )}
                {resilienceAssessed && <ScoreRing score={data.operational_resilience_score} label="Resilience" size={72} />}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="card p-6 lg:col-span-2">
                <h3 className="font-semibold text-gray-900 mb-4">Cascading risk scenarios</h3>
                <CascadingRiskList risks={data.cascading_risks} />
              </div>
              <div className="card p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Concentration analysis</h3>
                <ConcentrationSection concentration={data.concentration} />
              </div>
            </div>

            <div className="card p-6">
              <h3 className="font-semibold text-gray-900 mb-4">Critical providers</h3>
              <CriticalVendorsTable vendors={data.critical_vendors} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="card p-6">
                <h3 className="font-semibold text-gray-900 mb-1">Compliance readiness signals</h3>
                <p className="text-xs text-gray-500 mb-4">Confidence estimates only — not a formal certification assessment.</p>
                <ComplianceSection compliance={data.compliance_readiness} />
              </div>
              <div className="card p-6">
                <h3 className="font-semibold text-gray-900 mb-4">ASM programme maturity</h3>
                {asmMaturityAssessed ? (
                  <div className="flex items-center gap-6">
                    <ScoreRing score={data.asm_maturity.score} label="Maturity Score" size={88} />
                    <div>
                      <p className="text-lg font-bold text-gray-800 capitalize">{data.asm_maturity.level}</p>
                      <p className="text-xs text-gray-500 mt-1">Based on scan history, provider visibility, asset coverage, and security posture.</p>
                      {Number.isFinite(data.brs_score) && <p className="text-xs text-gray-500 mt-2">BRS input: <span className="font-semibold">{data.brs_score}</span></p>}
                    </div>
                  </div>
                ) : data.asm_maturity ? (
                  <div className="rounded-lg border border-[1.5px] border-brand-700 bg-transparent p-4">
                    <p className="text-sm font-semibold text-brand-700">ASM maturity unavailable</p>
                    <p className="text-xs text-brand-700 mt-1">{data.asm_maturity.state_reason}</p>
                    <p className="text-xs text-gray-600 mt-3">
                      Scan cadence, provider visibility and asset visibility remain observed
                      {Number.isFinite(data.asm_maturity.observed_subtotal) ? ` (${data.asm_maturity.observed_subtotal}/${data.asm_maturity.observed_max_score} observed points)` : ''}.
                    </p>
                  </div>
                ) : (
                  <p className="text-sm text-gray-500">ASM maturity has not been assessed.</p>
                )}
              </div>
            </div>

            <div className="card p-4 border border-blue-100 bg-blue-50">
              <p className="text-xs text-blue-700 leading-relaxed">
                This analysis is derived entirely from existing CyberMeters scan data — no external feeds, no questionnaires, no active probing.
                Compliance readiness signals are confidence indicators only and do not constitute legal or regulatory advice.
                Run a new scan to refresh it.
              </p>
            </div>
          </>
        )}
        {!data && !loading && !error && (
          <div className="card p-12 text-center">
            <p className="text-gray-700 font-medium">No dependency analysis yet</p>
            <p className="text-sm text-gray-600 mt-1">Run a scan to generate it.</p>
          </div>
        )}
      </PlanGate>
    </section>
  )
}

export default function ThirdPartiesPage() {
  const { wsId, wsName } = useWorkspace()
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const d = await api.getWorkspaceThirdPartyAssets(wsId)
      setAssets(d.assets || [])
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }, [wsId])
  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Third parties</h1>
          <p className="text-sm text-gray-500 mt-0.5">{wsName} · the services, providers and dependencies observed for your domain, from the outside.</p>
        </div>
        <button onClick={() => load()} className="btn-secondary">Refresh</button>
      </div>
      <div className="space-y-8">
        <ObservedServices assets={assets} />
        <Providers key={`providers-${wsId}`} wsId={wsId} />
        <Dependencies key={`deps-${wsId}`} wsId={wsId} />
      </div>
    </WsPage>
  )
}
