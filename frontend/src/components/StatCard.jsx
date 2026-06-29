/**
 * StatCard — reusable KPI card used across workspace pages.
 *
 * Design intent: the LABEL leads, the value supports. Numbers are restrained
 * (text-xl) so product meaning reads first. Risk cards are distinguished with a
 * quiet left accent + semantic value colour — never a loud filled block.
 *
 * Props (backward-compatible):
 *   icon       Lucide icon component
 *   label      Short label (leads the card)
 *   value      Primary value (string | number | ReactNode)
 *   sub        Optional supporting context line
 *   danger     Boolean — critical semantic (red)
 *   warning    Boolean — needs-review semantic (amber)
 *   tone       Optional 'info' for neutral informational categories (blue)
 *   iconColor  Optional explicit icon colour override
 */
export default function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  danger  = false,
  warning = false,
  tone,
  iconColor,
}) {
  const t = danger ? 'danger' : warning ? 'warning' : (tone || 'default')
  const T = {
    default: { icon: 'text-brand-600', value: 'text-gray-900',  accent: '' },
    danger:  { icon: 'text-red-600',   value: 'text-red-700',   accent: 'accent-danger' },
    warning: { icon: 'text-amber-600', value: 'text-amber-700', accent: 'accent-warning' },
    info:    { icon: 'text-blue-600',  value: 'text-gray-900',  accent: 'accent-info' },
  }[t] || { icon: 'text-brand-600', value: 'text-gray-900', accent: '' }

  return (
    <div className={`card p-5 ${T.accent}`}>
      <div className="flex items-center gap-2 mb-2">
        {Icon && (
          <Icon className={`w-4 h-4 flex-shrink-0 ${iconColor || T.icon}`} />
        )}
        <p className="metric-label truncate">{label}</p>
      </div>
      <p className={`text-xl font-bold leading-tight tabular-nums ${T.value}`}>{value ?? '—'}</p>
      {sub && <p className="metric-sub mt-1 truncate">{sub}</p>}
    </div>
  )
}
