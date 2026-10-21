import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// Founder, 21 Oct 2026: public and customer copy names only what the code does.
//  - README / AGENTS: no Certificate Transparency signals (nothing reads CT
//    logs), no legacy-authentication indicators (no producer exists; see the
//    identity.legacy_auth registry entry), no vulnerability intelligence (the
//    check pack uses no outside vulnerability database; check-pack.js).
//  - The trial description does not promise "all 8 categories".
//  - Business domains above the included 10 cannot be bought (entitlement stops
//    at 10, overage billing is off), so no price or cap is quoted for them.
//  - DNS copy beside the DNS-apply feature says changes need explicit confirmation.

const root = resolve(__dirname, '../../..')
const read = (p) => readFileSync(resolve(root, p), 'utf8')

describe('claims the code does not back', () => {
  it('README and AGENTS name no unbacked capability', () => {
    for (const file of ['README.md', 'AGENTS.md']) {
      const text = read(file)
      expect(text).not.toMatch(/Certificate Transparency signals/i)
      expect(text).not.toMatch(/legacy-authentication indicators/i)
      expect(text).not.toMatch(/vulnerability intelligence/i)
    }
  })

  it('the trial description does not promise every category, and the MSP price says how it is sold', () => {
    const registry = read('workers/scan-api/src/engines/pricing-registry.js')
    expect(registry).not.toMatch(/all 8 categories/i)
    // There is no MSP checkout (checkout_enabled: false): the per-domain price is invoiced manually.
    expect(registry).toMatch(/per monitored domain \(minimum 10 domains\), invoiced manually\./)
  })

  it('the Business domain-limit message quotes no price or cap for domains that cannot be bought', () => {
    const src = read('workers/scan-api/src/engines/plan-usage.js')
    const message = src.slice(src.indexOf('code: "additional_domain_billing_unavailable"'))
    const line = message.slice(0, message.indexOf('\n', message.indexOf('upgrade_message')))
    expect(line).toMatch(/More domains are not available on Business yet/)
    expect(line).not.toMatch(/£|domain_hard_cap|additional_domain_monthly_pence|contact support to add/)
  })

  it('no copy says CyberMeters never changes DNS', () => {
    for (const file of ['frontend/src/pages/ws/WorkspaceEmailProtectionPage.jsx', 'frontend/src/components/landing/ProductTour.jsx', 'workers/scan-api/src/engines/remediation-registry.js']) {
      const text = read(file)
      expect(text).not.toMatch(/never edits your DNS|will not apply the DNS change|we never touch it/)
    }
  })
})
