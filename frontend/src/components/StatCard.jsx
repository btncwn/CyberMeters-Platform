/**
 * StatCard — the canonical CyberMeters metric card.
 *
 * GLOBAL HIERARCHY RULE: meaning leads, number supports.
 *   1. The label/title is the visual lead — dark, semibold, on top, wraps freely.
 *   2. An optional explanation carries the meaning and reads before the number.
 *   3. The numeric value is secondary — calm, ≤ text-lg, tone-coloured.
 * Risk cards are distinguished by a quiet left accent + semantic value colour,
 * never a loud filled block. Green = healthy/primary, amber = warning, red =
 * critical only, blue = informational.
 *
 * Props (backward-compatible):
 *   icon         Lucide icon component
 *   label        Title — leads the card (wraps, never harshly truncated)
 *   value        Supporting numeric/string value
 *   explanation  Optional short context line (carries meaning; reads before value)
 *   sub          Optional small footnote under the value
 *   danger       Boolean — critical (red)
 *   warning      Boolean — needs review (amber)
 *   tone         Optional 'info' (blue) | 'neutral' (gray) for categories
 *   iconColor    Optional explicit icon colour override
 */
export default function StatCard({
  icon: Icon,
  label,
  value,
  explanation,
  sub,
  danger  = false,
  warning = false,
  tone,
  iconColor,
}) {
  const t = danger ? 'danger' : warning ? 'warning' : (tone || 'default')
  const T = {
    default: { icon: 'text-brand-600', value: 'text-gray-800',  accent: '' },
    danger:  { icon: 'text-red-600',   value: 'text-red-700',   accent: 'accent-danger' },
    warning: { icon: 'text-amber-600', value: 'text-amber-700', accent: 'accent-warning' },
    info:    { icon: 'text-blue-600',  value: 'text-gray-800',  accent: 'accent-info' },
    neutral: { icon: 'text-gray-400',  value: 'text-gray-700',  accent: '' },
  }[t] || { icon: 'text-brand-600', value: 'text-gray-800', accent: '' }

  return (
    <div className={`card p-5 ${T.accent}`}>
      {/* TEXT ON TOP — the label leads (larger than the number), dark + semibold,
         with a subtle icon. Wraps freely. */}
      <div className="flex items-start gap-2">
        {Icon && <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${iconColor || T.icon}`} />}
        <p className="text-[15px] font-semibold text-gray-900 leading-snug">{label}</p>
      </div>
      {explanation && <p className="text-xs text-gray-500 mt-1 leading-snug">{explanation}</p>}
      {sub && <p className="text-xs text-gray-500 mt-0.5 leading-snug">{sub}</p>}
      {/* NUMBER AT THE BOTTOM, and deliberately SMALLER than the label — it
         supports the meaning, it does not dominate it. */}
      <p className={`text-[13px] font-bold mt-2 leading-none tabular-nums ${T.value}`}>{value ?? '—'}</p>
    </div>
  )
}
