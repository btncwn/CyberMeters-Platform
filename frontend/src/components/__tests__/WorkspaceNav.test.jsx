import { SERVICES, detectServiceKey, subpagesForDomainKey, MODULE_SUBPAGES } from '../WorkspaceNav'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import { MODULES } from '../../lib/moduleRegistry'

// The canonical area list (data only since the shell v2, 17 Oct 2026): eight
// areas in founder order, each route mapped to its palette entry, each area's
// sub-pages as absolute tiles. The rail that rendered it is gone; the workspace
// popover tests live in WorkspaceMenu.test.jsx and the sheet in AreaMenu.test.jsx.

describe('WorkspaceNav (area list)', () => {
  it('lists the eight canonical domains in founder order, agreeing with the module registry', () => {
    expect(SERVICES.map(s => s.title)).toEqual([
      'Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure',
      'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness',
    ])
    expect(SERVICES.map(s => [s.title, s.to])).toEqual(MODULES.map(m => [m.title, m.to]))
  })

  it('maps every canonical domain route to its palette entry; non-domain routes stay neutral', () => {
    for (const svc of SERVICES) expect(SERVICE_COLORS[detectServiceKey(svc.to)]).toBeTruthy()
    expect(detectServiceKey('/scans')).toBe('surface')
    expect(detectServiceKey('/ws/saas-exposure')).toBe('shadow_it')
    expect(detectServiceKey('/dashboard')).toBeNull()
    expect(detectServiceKey('/ws/cases')).toBeNull()
  })

  it('exposes each area’s sub-pages as absolute tiles (anchors resolve against the area page)', () => {
    expect(subpagesForDomainKey('email_protection').map(t => t.to)).toEqual([
      '/ws/email-protection#dmarc-setup', '/ws/email-protection#sender-inventory', '/ws/email-protection#auth-detail',
      '/ws/email-protection#connect-reporting', '/ws/email-protection#lifecycle-history',
    ])
    expect(subpagesForDomainKey('attack_surface')[0]).toEqual({ label: 'Timeline', desc: 'What appeared, changed or disappeared', to: '/exposure', anchor: false })
    // The scan intelligence page is reachable from the Attack Surface area (16 Oct 2026).
    expect(subpagesForDomainKey('attack_surface').at(-1)).toEqual({ label: 'Intelligence', desc: 'Score history, changes between scans and the remediation plan', to: '/intelligence', anchor: false })
    // The network/port evidence is reachable from the area menu as a Findings anchor.
    expect(subpagesForDomainKey('attack_surface').find((t) => t.label === 'Network assets'))
      .toEqual({ label: 'Network assets', desc: 'Open ports and services on addresses you are authorised to test', to: '/assets#network-assets', anchor: true })
    expect(detectServiceKey('/intelligence')).toBe('surface')
    expect(detectServiceKey('/ws/identity-assets')).toBe('identity')
    expect(subpagesForDomainKey('identity_exposure').map(t => t.to)).toEqual([
      '/ws/identity-assets', '/ws/identity-assets#workforce-response', '/ws/identity-assets#public-sources',
    ])
    // Third parties is one home (17 Oct 2026); the retired routes still resolve to the area for redirects.
    expect(detectServiceKey('/ws/third-parties')).toBe('shadow_it')
    expect(detectServiceKey('/ws/vendors')).toBe('shadow_it')
    expect(detectServiceKey('/ws/supply-chain')).toBe('shadow_it')
    expect(subpagesForDomainKey('shadow_it_unmanaged_technology').map(t => t.to)).toEqual(['/ws/saas-exposure', '/ws/third-parties'])
    // A summary block that lives on Overview is reached with the tab stated.
    expect(subpagesForDomainKey('brand_protection').find((t) => t.label === 'Brand Findings').to).toBe('/ws/brand-monitoring?tab=overview#brand-summary')
    expect(subpagesForDomainKey('certificates_trust').find((t) => t.label === 'Expiry Risk').to).toBe('/ws/certificates?tab=overview#cert-expiry')
    expect(subpagesForDomainKey('certificates_trust').find((t) => t.label === 'Inventory').to).toBe('/ws/certificates#cert-inventory')
    expect(subpagesForDomainKey('website_security').map(t => t.to)).toEqual([
      '/ws/website-security?tab=overview#website-observations',
      '/ws/website-security?tab=overview#exposure-checks',
      '/ws/website-security#pages-checked',
      '/ws/website-security#sign-in-settings',
    ])
    expect(subpagesForDomainKey('nope')).toEqual([])
    expect(Object.keys(MODULE_SUBPAGES)).toEqual(MODULES.map(m => m.domainKey))
  })

  it('every palette entry ships a surface wash lighter than its card tint', () => {
    const lum = (hex) => { const n = parseInt(hex.slice(1), 16); return ((n >> 16) & 255) + ((n >> 8) & 255) + (n & 255) }
    for (const c of Object.values(SERVICE_COLORS)) expect(lum(c.surface)).toBeGreaterThan(lum(c.card))
  })
})
