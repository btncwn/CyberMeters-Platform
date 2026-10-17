/**
 * VerificationStatusBadge
 *
 * Normalises backend verification_status values to a consistent display label.
 *
 * Backend values → display:
 *   verified           → Verified      (green)
 *   pending            → Pending       (amber)
 *   pending_verification → Pending     (amber)
 *   failed             → Failed        (red)
 *   verification_failed  → Failed      (red)
 *   unverified (default) → Unverified  (gray)
 *
 * Props:
 *   status  {string}  — verification_status from the API
 *   size    {string}  — 'sm' (default) | 'md'
 */
export default function VerificationStatusBadge({ status, size = 'sm' }) {
  const s = (status || 'unverified').toLowerCase()

  const cfg = (() => {
    if (s === 'verified') return {
      label: 'Verified',
      cls:   'bg-brand-50 text-brand-700 border-brand-100',
    }
    if (s === 'pending' || s === 'pending_verification') return {
      label: 'Pending',
      cls:   'bg-transparent text-brand-700 border-[1.5px] border-brand-700',
    }
    if (s === 'failed' || s === 'verification_failed') return {
      label: 'Failed',
      cls:   'bg-red-50 text-red-700 border-red-100',
    }
    return {
      label: 'Unverified',
      cls:   'bg-gray-50 text-gray-500 border-gray-100',
    }
  })()

  const textSize = size === 'md' ? 'text-xs' : 'text-xs'
  const px       = size === 'md' ? 'px-2.5 py-1' : 'px-2 py-0.5'

  return (
    <span className={`inline-flex items-center gap-1 ${px} rounded-full font-semibold border ${textSize} ${cfg.cls}`}>
      {cfg.label}
    </span>
  )
}
