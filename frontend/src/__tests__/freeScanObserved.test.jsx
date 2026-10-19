import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, within } from '@testing-library/react'
import { buildFreeScanEvidence, FREE_SCAN_MODULE_DEFINITIONS } from '../../../workers/scan-api/src/engines/free-scan-evidence.js'
import { buildFreeScanPreview } from '../../../workers/scan-api/src/engines/free-scan-preview.js'
import FreeCyberMotPreviewGrid from '../components/FreeCyberMotPreviewGrid'
import { deriveFreeScanPresentation } from '../lib/freeScanPresentation'

// F0 (founder, 19 Oct 2026, "never send them away empty-handed"): the free scan
// showed only problems, so a well-configured domain got "0 findings" and an
// empty card everywhere. The API now states what the completed public checks
// did observe, per card, as evidence and never as a verdict. Fixtures are
// anonymised shapes of two live captures: a well-configured domain and the
// CyberMeters public site.

const fixtures = resolve(__dirname, '../../../scripts/fixtures')
const load = (name) => JSON.parse(readFileSync(resolve(fixtures, `free-scan-${name}.json`), 'utf8'))

function settle(fixture) {
  return Object.fromEntries(Object.entries(fixture.module_outcomes).map(([module, outcome]) => [
    module,
    outcome.kind === 'rejected' ? { status: 'rejected', reason: new Error(outcome.reason) } : { status: 'fulfilled', value: structuredClone(outcome.value) },
  ]))
}

function preview(fixture) {
  return buildFreeScanPreview({
    domain: fixture.domain,
    scannedAt: '2026-10-19T12:00:00.000Z',
    freeScanEvidence: buildFreeScanEvidence(settle(fixture)),
  })
}

const observedOf = (result, key) => result.cyber_mot_domains.find((d) => d.domain_key === key).observed.map((o) => o.text)

describe('positive evidence the API states for each card', () => {
  it('a well-configured domain: every completed check says what it saw', () => {
    const result = preview(load('well-configured'))
    expect(observedOf(result, 'email_protection')).toEqual([
      'DMARC policy p=reject observed, with sp=reject for subdomains',
      'DMARC aggregate reports requested (rua)',
      'SPF record observed, ending in ~all (unlisted senders soft-fail)',
      'DKIM keys observed at selectors "selector1", "selector2"',
    ])
    expect(observedOf(result, 'website_security')).toEqual([
      'Site answered over HTTPS',
      'Plain HTTP redirects to HTTPS',
      'HSTS set: max-age=63072000 (730 days), includeSubDomains, preload',
      'Framing restricted (X-Frame-Options: DENY)',
      'MIME sniffing disabled (X-Content-Type-Options: nosniff)',
      'Referrer-Policy set (origin)',
    ])
    expect(observedOf(result, 'attack_surface')).toEqual([
      'Domain resolves in public DNS',
      'Mail servers (MX) published',
      'DNSSEC signing observed (DS and DNSKEY records)',
    ])
    expect(observedOf(result, 'certificates_trust')).toEqual(['TLS handshake completed: the site answered over HTTPS'])
    // A CSP with an unsafe script source is the card's finding, not a positive line.
    const website = result.cyber_mot_domains.find((d) => d.domain_key === 'website_security')
    expect(website.samples.map((s) => s.title)).toContain('Weak Content Security Policy')
    expect(website.observed.some((o) => /Content-Security-Policy/.test(o.text))).toBe(false)
  })

  it('a site like CyberMeters: the inline-style caveat stays, and missing DKIM is not stated as present', () => {
    const result = preview(load('own-site-like'))
    expect(observedOf(result, 'email_protection')).toEqual([
      'DMARC policy p=reject observed',
      'DMARC aggregate reports requested (rua)',
      'SPF record observed, ending in -all (unlisted senders fail)',
    ])
    expect(observedOf(result, 'website_security')).toContain('Content-Security-Policy set with no unsafe script source (inline styles allowed)')
    expect(observedOf(result, 'attack_surface')).not.toContain('DNSSEC signing observed (DS and DNSKEY records)')
  })

  it('never states a verdict: no secure, safe, protected, healthy, verified or passed', () => {
    for (const name of ['well-configured', 'own-site-like', 'partial']) {
      for (const domain of preview(load(name)).cyber_mot_domains) {
        for (const item of domain.observed) {
          expect(item.text).not.toMatch(/\b(secure|safe|protected|healthy|verified|passed|compliant)\b/i)
        }
      }
    }
  })

  it('a check that did not complete states nothing', () => {
    const failed = preview(load('failed'))
    const usable = new Set(failed.module_evidence.filter((m) => ['completed', 'partial'].includes(m.state)).map((m) => m.module))
    for (const domain of failed.cyber_mot_domains) {
      for (const item of domain.observed) expect(usable.has(item.module)).toBe(true)
    }
    const allFailed = preview(load('all-probes-failed'))
    expect(allFailed.cyber_mot_domains.every((d) => d.observed.length === 0)).toBe(true)
  })

  it.each([
    ['email_security', 'email_protection'],
    ['ssl', 'certificates_trust'],
    ['dns', 'attack_surface'],
  ])('a failed %s module removes its statements from %s', (module, domainKey) => {
    const fixture = load('well-configured')
    fixture.module_outcomes[module] = { kind: 'rejected', reason: 'probe failed' }
    expect(observedOf(preview(fixture), domainKey)).toEqual([])
  })

  it('a module that came back incomplete states nothing, even though it carries partial data', () => {
    // HTTPS answered but the plain-HTTP redirect was not observed: the module is
    // incomplete, so neither fact becomes a positive statement.
    const fixture = load('well-configured')
    Object.assign(fixture.module_outcomes.ssl.value, { incomplete: true, incomplete_reason: 'http_redirect_not_observed' })
    const result = preview(fixture)
    expect(result.module_evidence.find((m) => m.module === 'ssl').state).toBe('incomplete')
    expect(observedOf(result, 'certificates_trust')).toEqual([])
    expect(observedOf(result, 'website_security').some((t) => /HTTPS/.test(t))).toBe(false)
    // The headers module did complete, so its own statements remain.
    expect(observedOf(result, 'website_security')).toContain('MIME sniffing disabled (X-Content-Type-Options: nosniff)')
  })

  it('a signal whose own lookup was not observed states nothing about it', () => {
    const fixture = load('well-configured')
    fixture.module_outcomes.email_security.value.dmarc_state.evidence_status = 'failed'
    fixture.module_outcomes.email_security.value.dkim_evidence_status = 'failed'
    const email = observedOf(preview(fixture), 'email_protection')
    expect(email.some((t) => /DMARC/.test(t))).toBe(false)
    expect(email.some((t) => /DKIM/.test(t))).toBe(false)
    expect(email).toEqual(['SPF record observed, ending in ~all (unlisted senders soft-fail)'])
  })

  it('a monitor-only DMARC policy is not stated as positive evidence', () => {
    const fixture = load('well-configured')
    const e = fixture.module_outcomes.email_security.value
    e.dmarc_state.policy = 'none'
    e.dmarc_detail.policy = 'none'
    expect(observedOf(preview(fixture), 'email_protection').some((t) => /DMARC policy/.test(t))).toBe(false)
  })
})

describe('the HTTPS step says what it checked', () => {
  it('is labelled HTTPS and says the certificate is not inspected, matching Certificates & Trust', () => {
    const ssl = FREE_SCAN_MODULE_DEFINITIONS.find((d) => d.module === 'ssl')
    expect(ssl.label).toBe('HTTPS')
    expect(ssl.checks).toMatch(/answers over HTTPS/)
    expect(ssl.checks).toMatch(/certificate itself is not inspected/)
    const result = preview(load('well-configured'))
    expect(result.module_evidence.find((m) => m.module === 'ssl')).toMatchObject({ label: 'HTTPS', checks: ssl.checks })
    const certs = result.cyber_mot_domains.find((d) => d.domain_key === 'certificates_trust')
    expect(certs.limitation).toMatch(/does not inspect it/)
    for (const def of FREE_SCAN_MODULE_DEFINITIONS) expect(def.checks.length).toBeGreaterThan(10)
  })
})

describe('the card shows what was observed', () => {
  it('lists the observed evidence instead of an empty card, and keeps the empty line where nothing was seen', () => {
    // The page's own path: API response → presentation adapter → grid.
    const result = deriveFreeScanPresentation(JSON.parse(JSON.stringify(preview(load('own-site-like')))))
    render(<FreeCyberMotPreviewGrid domains={result.domains} />)
    const email = screen.getByRole('heading', { name: 'Email Protection' }).closest('article')
    expect(within(email).getByText('Observed in the completed checks')).toBeInTheDocument()
    expect(within(email).getByText('DMARC policy p=reject observed')).toBeInTheDocument()
    expect(within(email).queryByText(/No result is exposed/)).toBeNull()
    const brand = screen.getByRole('heading', { name: 'Brand Protection' }).closest('article')
    expect(within(brand).getByText(/No result is exposed/)).toBeInTheDocument()
    expect(within(brand).queryByText('Observed in the completed checks')).toBeNull()
    const surface = screen.getByRole('heading', { name: 'Attack Surface' }).closest('article')
    expect(within(surface).getByText('Domain resolves in public DNS')).toBeInTheDocument()
  })

  it('the presentation adapter keeps only well-formed statements', () => {
    const raw = JSON.parse(JSON.stringify(preview(load('well-configured'))))
    const email = raw.cyber_mot_domains.find((d) => d.domain_key === 'email_protection')
    email.observed.push({ id: 'x', text: '' }, { text: 'no id' }, { id: 'y', text: 42 }, null)
    const adapted = deriveFreeScanPresentation(raw)
    const list = adapted.domains.find((d) => d.domain_key === 'email_protection').observed
    expect(list.map((o) => o.id)).toEqual(['dmarc_enforcing_policy', 'dmarc_aggregate_reporting', 'spf_single_record', 'dkim_key_observed'])
  })
})
