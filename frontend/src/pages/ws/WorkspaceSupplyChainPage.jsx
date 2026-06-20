import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle, CheckCircle2, GitBranch, RefreshCw, Shield, Zap,
} from 'lucide-react'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { useWorkspace } from '../../hooks/useWorkspace'
import StatCard from '../../components/StatCard'
import RiskBadge from '../../components/RiskBadge'
import { PlanGate } from '../../components/PlanUsageCard'

// ── Helpers ──────────────────────────────────────────────────────────────────

function concentrationColor(level) {
  if (level === 'critical') return 'text-red-700 bg-red-50 border-red-200'
  if (level === 'high')     return 'text-orange-700 bg-orange-50 border-orange-200'
  if (level === 'medium')   return 'text-amber-700 bg-amber-50 border-amber-200'
  return 'text-brand-700 bg-brand-50 border-brand-100'
}

function scoreColor(score) {
  if (score >= 75) return '#00876A'
  if (score >= 55) return '#22C55E'
  if (score >= 35) return '#F59E0B'
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
    level === 'medium' ? 'bg-amber-50 text-amber-700 border border-amber-100' :
    'bg-gray-100 text-gray-500 border border-gray-200'
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize ${cls}`}>
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
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                  v.tier === 1 ? 'bg-red-50 text-red-700' :
                  v.tier === 2 ? 'bg-amber-50 text-amber-700' :
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
      <div className="flex items-center gap-2 text-sm text-brand-600 py-2">
        <CheckCircle2 className="w-4 h-4" />
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
          <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${
            r.severity === 'critical' ? 'text-red-500' :
            r.severity === 'high'     ? 'text-orange-500' :
            'text-amber-400'
          }`} />
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
                  <span className={`w-5 h-5 rounded text-[10px] font-bold flex items-center justify-center ${
                    p.tier === 1 ? 'bg-red-50 text-red-700' :
                    p.tier === 2 ? 'bg-amber-50 text-amber-700' :
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
              <li key={i} className="text-xs text-red-600">• {s}</li>
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
            <ConfidencePill level={compliance[key] || 'low'} />
          </li>
        ))}
      </ul>
      {compliance.note && (
        <p className="text-[10px] text-gray-400 mt-4 leading-relaxed">{compliance.note}</p>
      )}
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function WorkspaceSupplyChainPage() {
  const { wsId, wsName } = useWorkspace()
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true)
    setError(null)
    try {
      setData(await api.getWorkspaceSupplyChain(wsId))
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  const concentrationLevel = data?.concentration_level ?? 'unknown'

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error?.error === 'plan_feature_required' ? null : error?.message} onRetry={load}>
      <PlanGate error={error}>

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Supply Chain Risk</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Third-party concentration, resilience, and cascading risk intelligence — powered by existing CyberMeters data.
          </p>
        </div>
        <button onClick={load} className="btn-ghost flex items-center gap-1.5">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {data && (
        <>
          {/* Score cards row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatCard
              icon={Shield}
              label="Supply Chain Score"
              value={data.supply_chain_score ?? 0}
              danger={(data.supply_chain_score ?? 0) < 40}
              warning={(data.supply_chain_score ?? 0) < 65 && (data.supply_chain_score ?? 0) >= 40}
            />
            <StatCard
              icon={Zap}
              label="Resilience Score"
              value={data.operational_resilience_score ?? 0}
              danger={(data.operational_resilience_score ?? 0) < 40}
              warning={(data.operational_resilience_score ?? 0) < 65 && (data.operational_resilience_score ?? 0) >= 40}
            />
            <StatCard
              icon={AlertTriangle}
              label="Critical Vendors"
              value={data.critical_vendor_count ?? 0}
              danger={(data.critical_vendor_count ?? 0) >= 5}
              warning={(data.critical_vendor_count ?? 0) >= 2}
            />
            <StatCard
              icon={GitBranch}
              label="Single Points of Failure"
              value={data.spof_count ?? 0}
              danger={(data.spof_count ?? 0) >= 2}
              warning={(data.spof_count ?? 0) === 1}
            />
          </div>

          {/* Concentration banner */}
          <div className={`card p-4 mb-6 flex items-center justify-between border ${concentrationColor(concentrationLevel)}`}>
            <div>
              <p className="text-sm font-semibold capitalize">
                Vendor Concentration: {concentrationLevel}
              </p>
              <p className="text-xs mt-0.5 opacity-75">
                {data.tier1_count} Tier 1 · {data.tier2_count} Tier 2 · {data.tier3_count} Tier 3 vendors
              </p>
            </div>
            <div className="flex gap-6">
              <ScoreRing score={data.supply_chain_score ?? 0}           label="Supply Chain" size={72} />
              <ScoreRing score={data.operational_resilience_score ?? 0} label="Resilience"   size={72} />
            </div>
          </div>

          {/* Three-column grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">

            {/* Cascading risks */}
            <div className="card p-6 lg:col-span-2">
              <h2 className="font-semibold text-gray-900 mb-4">Cascading Risk Scenarios</h2>
              <CascadingRiskList risks={data.cascading_risks} />
            </div>

            {/* Concentration + SPOFs */}
            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-4">Concentration Analysis</h2>
              <ConcentrationSection concentration={data.concentration} />
            </div>
          </div>

          {/* Critical vendors table */}
          <div className="card p-6 mb-6">
            <h2 className="font-semibold text-gray-900 mb-4">Critical Vendors</h2>
            <CriticalVendorsTable vendors={data.critical_vendors} />
          </div>

          {/* Bottom row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Compliance readiness */}
            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-1">Compliance Readiness Signals</h2>
              <p className="text-xs text-gray-400 mb-4">Confidence estimates only — not a formal certification assessment.</p>
              <ComplianceSection compliance={data.compliance_readiness} />
            </div>

            {/* ASM maturity */}
            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-4">ASM Programme Maturity</h2>
              {data.asm_maturity && (
                <div className="flex items-center gap-6">
                  <ScoreRing score={data.asm_maturity.score ?? 0} label="Maturity Score" size={88} />
                  <div>
                    <p className="text-lg font-bold text-gray-800 capitalize">{data.asm_maturity.level}</p>
                    <p className="text-xs text-gray-400 mt-1">Based on scan history, vendor visibility, asset coverage, and security posture.</p>
                    {data.brs_score > 0 && (
                      <p className="text-xs text-gray-500 mt-2">BRS input: <span className="font-semibold">{data.brs_score}</span></p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Disclaimer */}
          <div className="mt-6 card p-4 border border-blue-100 bg-blue-50">
            <p className="text-xs text-blue-700 leading-relaxed">
              Supply chain intelligence is derived entirely from existing CyberMeters scan data — no external feeds, no vendor questionnaires, no active probing.
              Compliance readiness signals are confidence indicators only and do not constitute legal or regulatory advice.
              Run a new scan to refresh this analysis.
            </p>
          </div>
        </>
      )}

      {!data && !loading && !error && (
        <div className="card p-12 text-center">
          <GitBranch className="w-10 h-10 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500 font-medium">No supply chain data yet</p>
          <p className="text-sm text-gray-400 mt-1">Run a scan to generate supply chain intelligence.</p>
        </div>
      )}

      </PlanGate>
    </WsPage>
  )
}
