import { Globe, Layers, Lock, Wifi, Eye, TrendingUp, TrendingDown, Minus } from 'lucide-react'

/**
 * AssetSummary
 *
 * Props (all optional, default 0 / null):
 *   domains          {number}
 *   subdomains       {number}
 *   certificates     {number}
 *   exposedServices  {number}
 *   hiddenAssets     {number}
 *
 * Each card accepts an optional `trend` string: 'up' | 'down' | 'stable'
 * and `trendValue` string (e.g. '+3 this week') for future API enrichment.
 *
 * API integration point:
 *   Replace prop defaults with data from GET /api/assets/summary when available.
 */

const CARD_CONFIG = [
  {
    key:   'domains',
    label: 'Domains',
    icon:  Globe,
    bg:    'bg-blue-50',
    icon_color: 'text-blue-600',
    val_color:  'text-blue-700',
    desc:  'Root domains tracked',
  },
  {
    key:   'subdomains',
    label: 'Subdomains',
    icon:  Layers,
    bg:    'bg-purple-50',
    icon_color: 'text-purple-600',
    val_color:  'text-purple-700',
    desc:  'Discovered subdomains',
  },
  {
    key:   'certificates',
    label: 'Certificates',
    icon:  Lock,
    bg:    'bg-brand-50',
    icon_color: 'text-brand-600',
    val_color:  'text-brand-700',
    desc:  'TLS certificates tracked',
  },
  {
    key:   'exposedServices',
    label: 'Exposed Services',
    icon:  Wifi,
    bg:    'bg-amber-50',
    icon_color: 'text-amber-600',
    val_color:  'text-amber-700',
    desc:  'Internet-facing services',
  },
  {
    key:   'hiddenAssets',
    label: 'Hidden Assets',
    icon:  Eye,
    bg:    'bg-orange-50',
    icon_color: 'text-orange-600',
    val_color:  'text-orange-700',
    desc:  'Unregistered / shadow IT',
  },
]

function TrendIcon({ trend }) {
  if (trend === 'up')     return <TrendingUp   className="w-3.5 h-3.5 text-red-400"       />
  if (trend === 'down')   return <TrendingDown  className="w-3.5 h-3.5 text-brand-500"     />
  if (trend === 'stable') return <Minus         className="w-3.5 h-3.5 text-gray-300"      />
  return null
}

function SummaryCard({ config, value, trend, trendValue }) {
  const { label, icon: Icon, bg, icon_color, val_color, desc } = config
  const isEmpty = value === 0 || value == null

  return (
    <div className={`card p-5 flex flex-col gap-3 ${isEmpty ? 'opacity-60' : ''}`}>
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center`}>
          <Icon className={`w-5 h-5 ${icon_color}`} />
        </div>
        {trend && (
          <div className="flex items-center gap-1">
            <TrendIcon trend={trend} />
            {trendValue && (
              <span className="text-[10px] font-semibold text-gray-400">{trendValue}</span>
            )}
          </div>
        )}
      </div>

      {/* Value */}
      <div>
        <p className={`text-3xl font-bold ${isEmpty ? 'text-gray-300' : val_color}`}>
          {value ?? 0}
        </p>
        <p className="text-sm font-semibold text-gray-700 mt-0.5">{label}</p>
        <p className="text-xs text-gray-400 mt-0.5">{desc}</p>
      </div>
    </div>
  )
}

export default function AssetSummary({
  domains         = 0,
  subdomains      = 0,
  certificates    = 0,
  exposedServices = 0,
  hiddenAssets    = 0,
  trends          = {},  // { domains: 'up', subdomains: 'stable', ... }
  trendValues     = {},  // { domains: '+2 this week', ... }
}) {
  const values = { domains, subdomains, certificates, exposedServices, hiddenAssets }
  const total  = Object.values(values).reduce((a, b) => a + (b ?? 0), 0)

  return (
    <div className="space-y-4">
      {/* Section header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-gray-900">Asset Summary</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            {total > 0
              ? `${total} total asset${total !== 1 ? 's' : ''} discovered across all categories`
              : 'No assets discovered — run a scan to populate this view'}
          </p>
        </div>
        {total > 0 && (
          <span className="label">
            {total} total
          </span>
        )}
      </div>

      {/* Cards grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {CARD_CONFIG.map((cfg) => (
          <SummaryCard
            key={cfg.key}
            config={cfg}
            value={values[cfg.key]}
            trend={trends[cfg.key]}
            trendValue={trendValues[cfg.key]}
          />
        ))}
      </div>
    </div>
  )
}
