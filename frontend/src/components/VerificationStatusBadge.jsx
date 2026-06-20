import { CheckCircle, Clock, XCircle, AlertCircle } from 'lucide-react'

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
      Icon:  CheckCircle,
    }
    if (s === 'pending' || s === 'pending_verification') return {
      label: 'Pending',
      cls:   'bg-amber-50 text-amber-700 border-amber-100',
      Icon:  Clock,
    }
    if (s === 'failed' || s === 'verification_failed') return {
      label: 'Failed',
      cls:   'bg-red-50 text-red-600 border-red-100',
      Icon:  XCircle,
    }
    return {
      label: 'Unverified',
      cls:   'bg-gray-50 text-gray-500 border-gray-100',
      Icon:  AlertCircle,
    }
  })()

  const textSize = size === 'md' ? 'text-xs' : 'text-[11px]'
  const iconSize = size === 'md' ? 'w-3.5 h-3.5' : 'w-3 h-3'
  const px       = size === 'md' ? 'px-2.5 py-1' : 'px-2 py-0.5'

  return (
    <span className={`inline-flex items-center gap-1 ${px} rounded-full font-semibold border ${textSize} ${cfg.cls}`}>
      <cfg.Icon className={iconSize} />
      {cfg.label}
    </span>
  )
}
