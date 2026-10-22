// The trial is never called a plan (founder, 22 Oct 2026: a 14-day trial read
// "Professional plan"). Seat 2's session fields: `is_trial` is true only inside a
// live trial, `trial_end` is its UTC end. One wording for the account menu and
// the billing tab: "Professional trial · ends 4 Nov" (the end as a local date).
const PLAN_NAMES = { starter: 'Starter', professional: 'Professional', business: 'Business', enterprise: 'MSP' }

export function trialEndDay(trialEnd) {
  const date = trialEnd ? new Date(trialEnd) : null
  if (!date || !Number.isFinite(date.getTime())) return null
  return new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' }).format(date)
}

/** "Professional trial · ends 4 Nov", or null when the user is not in a live trial. */
export function trialPlanLabel(user) {
  if (user?.is_trial !== true) return null
  const name = PLAN_NAMES[String(user.plan || '').toLowerCase()]
  if (!name) return null
  const day = trialEndDay(user.trial_end)
  return day ? `${name} trial · ends ${day}` : `${name} trial`
}
