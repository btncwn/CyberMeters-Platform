/**
 * StatCard — reusable KPI card used across workspace pages.
 *
 * Props:
 *   icon        Lucide icon component
 *   label       Short uppercase label
 *   value       Primary value (string | number | ReactNode)
 *   sub         Optional subtitle
 *   iconColor   Tailwind text colour class (default: text-brand-600)
 *   iconBg      Tailwind bg colour class   (default: bg-brand-50)
 *   danger      Boolean — override colours with red
 *   warning     Boolean — override colours with amber
 */
export default function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  iconColor = 'text-brand-600',
  iconBg    = 'bg-brand-50',
  danger    = false,
  warning   = false,
}) {
  if (danger)  { iconColor = 'text-red-600';    iconBg = 'bg-red-50'    }
  if (warning) { iconColor = 'text-amber-600';  iconBg = 'bg-amber-50'  }

  return (
    <div className="card p-5">
      <div className="flex items-start gap-3">
        <div className={`w-9 h-9 rounded-xl ${iconBg} flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-[18px] h-[18px] ${iconColor}`} />
        </div>
        <div className="min-w-0">
          <p className="label">{label}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1 leading-none">{value ?? '—'}</p>
          {sub && <p className="text-xs text-gray-400 mt-1 truncate">{sub}</p>}
        </div>
      </div>
    </div>
  )
}
