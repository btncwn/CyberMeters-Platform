/** Risk level badge — maps level → design-system badge class. */
export default function RiskBadge({ level }) {
  if (!level) return <span className="text-gray-300 text-xs">—</span>
  const cls = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
  }[level.toLowerCase()] ?? 'badge-low'
  return <span className={cls}>{level}</span>
}
