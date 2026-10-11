import { describe, it, expect } from 'vitest'
import { SUBSCRIPTION_STATUS_DISPLAY, subscriptionStatusDisplay } from '../subscriptionStatusDisplay'

// Mirrors ACCOUNT_SUBSCRIPTION_STATUSES in workers/scan-api/src/engines/entitlements.js
const BACKEND_STATUSES = [
  'active', 'trialing', 'past_due', 'trial_expired', 'past_due_lapsed',
  'canceled', 'expired', 'inactive', 'none', 'unavailable',
]

describe('subscriptionStatusDisplay', () => {
  it('maps every canonical backend status explicitly', () => {
    for (const s of BACKEND_STATUSES) {
      expect(Object.prototype.hasOwnProperty.call(SUBSCRIPTION_STATUS_DISPLAY, s)).toBe(true)
      expect(subscriptionStatusDisplay(s).label).not.toBe('Unknown')
    }
  })

  it('only an active subscription is shown in the positive tone', () => {
    for (const s of BACKEND_STATUSES) {
      const d = subscriptionStatusDisplay(s)
      expect(d.tone === 'positive').toBe(s === 'active')
    }
  })

  it('a trial is never labelled Active', () => {
    expect(subscriptionStatusDisplay('trialing').label).toBe('Trial')
    expect(subscriptionStatusDisplay('trial_expired').label).toBe('Trial ended')
  })

  it('unknown, missing or malformed values read Unknown in a neutral tone', () => {
    for (const v of [undefined, null, '', 'incomplete_expired', 'ACTIVE ', 42, {}, 'toString', '__proto__']) {
      const d = subscriptionStatusDisplay(v)
      if (v === 'ACTIVE ') { expect(d.label).toBe('Active'); continue }
      expect(d.label).toBe('Unknown')
      expect(d.tone).toBe('neutral')
      expect(d.dot).not.toMatch(/green/)
    }
  })

  it('no subscription and unreadable state are distinct and never positive', () => {
    expect(subscriptionStatusDisplay('none').label).toBe('No subscription')
    expect(subscriptionStatusDisplay('unavailable').label).toBe('Unavailable')
    expect(subscriptionStatusDisplay('none').tone).toBe('neutral')
    expect(subscriptionStatusDisplay('unavailable').tone).toBe('neutral')
  })
})
