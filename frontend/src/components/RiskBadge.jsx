/**
 * Risk level badge — maps level → design-system badge class.
 *
 * The fallback used to be `?? 'badge-low'`, so every level this map did not recognise
 * rendered in low-risk blue — including the backend's own honest 'unknown', which
 * `portfolio-risk.js` emits for a workspace that has no assessment at all. A customer
 * we knew nothing about was painted the same colour as a customer verified to be fine.
 *
 * Unrecognised now means unknown, and unknown looks unknown. This is the safe
 * direction: 'critical' / 'high' / 'medium' / 'low' are unaffected, and everything
 * else stops claiming to be benign.
 */
const BADGE_CLASS = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  unknown:  'badge-unknown',
}

export default function RiskBadge({ level }) {
  if (!level) return <span className="text-gray-300 text-xs">—</span>
  const cls = BADGE_CLASS[String(level).toLowerCase()] ?? 'badge-unknown'
  return <span className={cls}>{level}</span>
}
