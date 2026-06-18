import { useState } from 'react'
import { Globe, Layers, Lock, Wifi, AlertCircle, CheckCircle, Clock, XCircle } from 'lucide-react'

/**
 * AssetInventory
 *
 * Tabbed inventory across four asset categories.
 * All data props default to empty arrays — replace with API data when available.
 *
 * Expected shapes (future API):
 *
 * domains[]      { id, domain, status, risk, last_seen }
 * subdomains[]   { id, hostname, parent_domain, ip, risk, last_seen }
 * certificates[] { id, domain, issuer, valid_from, valid_to, days_remaining, status }
 * services[]     { id, host, port, service, protocol, risk, last_seen }
 *
 * API integration point:
 *   Replace prop defaults with data from GET /api/assets when available.
 */

// ── Risk badge ─────────────────────────────────────────────────────────────

function RiskBadge({ risk }) {
  if (!risk) return <span className="text-xs text-gray-300">—</span>
  const map = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
  }
  const cls = map[risk.toLowerCase()] || 'badge-low'
  return <span className={cls}>{risk}</span>
}

// ── Status indicator ───────────────────────────────────────────────────────

function StatusDot({ status }) {
  const cfg = {
    active:   { cls: 'text-brand-600', Icon: CheckCircle,  label: 'Active'   },
    expiring: { cls: 'text-amber-500', Icon: Clock,        label: 'Expiring' },
    expired:  { cls: 'text-red-500',   Icon: XCircle,      label: 'Expired'  },
    unknown:  { cls: 'text-gray-300',  Icon: AlertCircle,  label: 'Unknown'  },
  }[status?.toLowerCase()] || { cls: 'text-gray-300', Icon: AlertCircle, label: status || 'Unknown' }

  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${cfg.cls}`}>
      <cfg.Icon className="w-3.5 h-3.5" />
      {cfg.label}
    </span>
  )
}

// ── Empty tab state ────────────────────────────────────────────────────────

function TabEmpty({ icon: Icon, label }) {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <div className="w-10 h-10 rounded-2xl bg-gray-100 flex items-center justify-center">
        <Icon className="w-5 h-5 text-gray-300" />
      </div>
      <div>
        <p className="text-sm font-semibold text-gray-400">No {label} discovered</p>
        <p className="text-xs text-gray-300 mt-0.5">
          Run a scan to populate this category
        </p>
      </div>
    </div>
  )
}

// ── Table wrapper ──────────────────────────────────────────────────────────

function Table({ head, rows }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full data-table">
        <thead>
          <tr>
            {head.map((h) => <th key={h}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
  )
}

// ── Tab: Domains ───────────────────────────────────────────────────────────

function DomainsTab({ items }) {
  if (!items.length) return <TabEmpty icon={Globe} label="domains" />
  return (
    <Table
      head={['Domain', 'Status', 'Risk', 'Last Seen']}
      rows={items.map((item) => (
        <tr key={item.id || item.domain} className="hover:bg-gray-50 transition-colors">
          <td>
            <span className="font-semibold text-gray-900 mono">{item.domain}</span>
          </td>
          <td><StatusDot status={item.status} /></td>
          <td><RiskBadge risk={item.risk} /></td>
          <td className="text-gray-400">{item.last_seen ?? '—'}</td>
        </tr>
      ))}
    />
  )
}

// ── Tab: Subdomains ────────────────────────────────────────────────────────

function SubdomainsTab({ items }) {
  if (!items.length) return <TabEmpty icon={Layers} label="subdomains" />
  return (
    <Table
      head={['Hostname', 'Parent Domain', 'IP Address', 'Risk', 'Last Seen']}
      rows={items.map((item) => (
        <tr key={item.id || item.hostname} className="hover:bg-gray-50 transition-colors">
          <td>
            <span className="font-semibold text-gray-900 mono text-xs">{item.hostname}</span>
          </td>
          <td className="text-gray-500 mono text-xs">{item.parent_domain ?? '—'}</td>
          <td className="text-gray-500 mono text-xs">{item.ip ?? '—'}</td>
          <td><RiskBadge risk={item.risk} /></td>
          <td className="text-gray-400">{item.last_seen ?? '—'}</td>
        </tr>
      ))}
    />
  )
}

// ── Tab: Certificates ─────────────────────────────────────────────────────

function CertificatesTab({ items }) {
  if (!items.length) return <TabEmpty icon={Lock} label="certificates" />
  return (
    <Table
      head={['Domain', 'Issuer', 'Valid From', 'Expires', 'Days Left', 'Status']}
      rows={items.map((item) => (
        <tr key={item.id || item.domain} className="hover:bg-gray-50 transition-colors">
          <td>
            <span className="font-semibold text-gray-900 mono text-xs">{item.domain}</span>
          </td>
          <td className="text-gray-500 text-xs">{item.issuer ?? '—'}</td>
          <td className="text-gray-400 text-xs">{item.valid_from ?? '—'}</td>
          <td className="text-gray-400 text-xs">{item.valid_to ?? '—'}</td>
          <td>
            {item.days_remaining != null ? (
              <span className={`font-bold text-sm ${
                item.days_remaining <= 14  ? 'text-red-600'   :
                item.days_remaining <= 30  ? 'text-amber-600' :
                'text-brand-600'
              }`}>
                {item.days_remaining}d
              </span>
            ) : '—'}
          </td>
          <td><StatusDot status={item.status} /></td>
        </tr>
      ))}
    />
  )
}

// ── Tab: Services ─────────────────────────────────────────────────────────

function ServicesTab({ items }) {
  if (!items.length) return <TabEmpty icon={Wifi} label="exposed services" />
  return (
    <Table
      head={['Host', 'Port', 'Service', 'Protocol', 'Risk', 'Last Seen']}
      rows={items.map((item) => (
        <tr key={item.id || `${item.host}:${item.port}`} className="hover:bg-gray-50 transition-colors">
          <td>
            <span className="font-semibold text-gray-900 mono text-xs">{item.host}</span>
          </td>
          <td>
            <span className="mono text-xs bg-gray-100 px-2 py-0.5 rounded-md font-bold text-gray-700">
              {item.port}
            </span>
          </td>
          <td className="text-gray-700 font-medium text-xs">{item.service ?? '—'}</td>
          <td className="text-gray-400 text-xs uppercase">{item.protocol ?? '—'}</td>
          <td><RiskBadge risk={item.risk} /></td>
          <td className="text-gray-400">{item.last_seen ?? '—'}</td>
        </tr>
      ))}
    />
  )
}

// ── Tab definition ─────────────────────────────────────────────────────────

const TABS = [
  { key: 'domains',      label: 'Domains',      icon: Globe,   Component: DomainsTab      },
  { key: 'subdomains',   label: 'Subdomains',   icon: Layers,  Component: SubdomainsTab   },
  { key: 'certificates', label: 'Certificates', icon: Lock,    Component: CertificatesTab },
  { key: 'services',     label: 'Services',     icon: Wifi,    Component: ServicesTab     },
]

// ── Risk Indicators bar ───────────────────────────────────────────────────

function RiskIndicators({ items }) {
  // Aggregate risk counts across all asset types
  const all = [
    ...items.domains,
    ...items.subdomains,
    ...items.services,
    ...items.certificates,
  ]

  const counts = all.reduce((acc, item) => {
    const r = item.risk?.toLowerCase()
    if (r) acc[r] = (acc[r] || 0) + 1
    return acc
  }, {})

  const indicators = [
    { label: 'Critical', key: 'critical', cls: 'badge-critical' },
    { label: 'High',     key: 'high',     cls: 'badge-high'     },
    { label: 'Medium',   key: 'medium',   cls: 'badge-medium'   },
    { label: 'Low',      key: 'low',      cls: 'badge-low'      },
  ]

  const hasRisk = indicators.some(i => counts[i.key] > 0)

  return (
    <div className="card p-5">
      <div className="flex flex-col sm:flex-row sm:items-center gap-4">
        <div className="flex-1">
          <h3 className="text-sm font-bold text-gray-900">Asset Risk Indicators</h3>
          <p className="text-xs text-gray-400 mt-0.5">
            {hasRisk
              ? 'Risk distribution across all discovered assets'
              : 'Risk levels will populate once assets are discovered'}
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {indicators.map(({ label, key, cls }) => (
            <div key={key} className="flex items-center gap-2">
              <span className={cls}>{label}</span>
              <span className={`text-sm font-bold ${counts[key] ? 'text-gray-900' : 'text-gray-300'}`}>
                {counts[key] ?? 0}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────

export default function AssetInventory({
  domains      = [],
  subdomains   = [],
  certificates = [],
  services     = [],
}) {
  const [activeTab, setActiveTab] = useState('domains')

  const counts = { domains, subdomains, certificates, services }
  const items  = { domains, subdomains, certificates, services }
  const active = TABS.find(t => t.key === activeTab)

  return (
    <div className="space-y-4">

      {/* Risk indicators */}
      <RiskIndicators items={items} />

      {/* Inventory card */}
      <div className="card overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-base font-bold text-gray-900">Asset Inventory</h2>
          <span className="label">
            {Object.values(counts).reduce((a, b) => a + b.length, 0)} assets
          </span>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-1 px-4 py-2 border-b border-gray-100 bg-gray-50 overflow-x-auto">
          {TABS.map(({ key, label, icon: Icon }) => {
            const count = counts[key]?.length ?? 0
            const isActive = activeTab === key
            return (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-white text-brand-700 shadow-sm border border-gray-100 font-semibold'
                    : 'text-gray-500 hover:text-gray-900 hover:bg-white'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
                  count > 0
                    ? 'bg-brand-100 text-brand-700'
                    : 'bg-gray-200 text-gray-400'
                }`}>
                  {count}
                </span>
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        <div className="min-h-[200px]">
          {active && (
            <active.Component items={counts[active.key]} />
          )}
        </div>
      </div>
    </div>
  )
}
