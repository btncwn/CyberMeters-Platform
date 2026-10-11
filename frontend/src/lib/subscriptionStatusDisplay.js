// Presentation for the account subscription status the backend resolves
// (engines/entitlements.js describeAccountSubscription). The backend owns the
// decision; this file only maps each canonical value to words and a tone.
//
// Unknown or missing values never fall back to a positive state: they read
// "Unknown" in a neutral tone, so a new or unexpected backend value can never
// be shown to a customer as an active subscription.

const TONES = {
  positive: { dot: 'bg-green-500', text: 'text-green-700', pill: 'bg-green-50 text-green-700 border-green-100' },
  info:     { dot: 'bg-blue-400',  text: 'text-blue-700',  pill: 'bg-blue-50 text-blue-700 border-blue-100' },
  warning:  { dot: 'bg-amber-400', text: 'text-amber-700', pill: 'bg-amber-50 text-amber-700 border-amber-100' },
  negative: { dot: 'bg-red-400',   text: 'text-red-700',   pill: 'bg-red-50 text-red-700 border-red-100' },
  neutral:  { dot: 'bg-gray-300',  text: 'text-gray-600',  pill: 'bg-gray-50 text-gray-600 border-gray-100' },
}

export const SUBSCRIPTION_STATUS_DISPLAY = Object.freeze({
  active:          { label: 'Active',              tone: 'positive', note: null },
  trialing:        { label: 'Trial',               tone: 'info',     note: 'Your free trial is running.' },
  past_due:        { label: 'Payment overdue',     tone: 'warning',  note: 'Payment failed. Access continues during the grace period — update your payment method.' },
  past_due_lapsed: { label: 'Payment overdue',     tone: 'negative', note: 'Payment failed and the grace period has ended. Paid features are paused.' },
  trial_expired:   { label: 'Trial ended',         tone: 'negative', note: 'Your trial has ended. Choose a plan to keep using paid features.' },
  canceled:        { label: 'Cancelled',           tone: 'neutral',  note: 'This subscription was cancelled.' },
  cancelled:       { label: 'Cancelled',           tone: 'neutral',  note: 'This subscription was cancelled.' },
  expired:         { label: 'Expired',             tone: 'negative', note: 'The paid period ended without renewal.' },
  inactive:        { label: 'Inactive',            tone: 'neutral',  note: 'This subscription does not currently grant paid features.' },
  none:            { label: 'No subscription',     tone: 'neutral',  note: 'Your account is on the free plan.' },
  unavailable:     { label: 'Unavailable',         tone: 'neutral',  note: 'Subscription status could not be loaded. Please try again later.' },
})

const UNKNOWN = { label: 'Unknown', tone: 'neutral', note: null }

export function subscriptionStatusDisplay(status) {
  const key = typeof status === 'string' ? status.trim().toLowerCase() : ''
  const base = Object.prototype.hasOwnProperty.call(SUBSCRIPTION_STATUS_DISPLAY, key)
    ? SUBSCRIPTION_STATUS_DISPLAY[key]
    : UNKNOWN
  return { ...base, ...TONES[base.tone] }
}
