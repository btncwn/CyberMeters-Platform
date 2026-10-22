import { describe, expect, it } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { OWN_DOMAIN_SUMMARY, OWN_DOMAIN_MAX_AGE_DAYS } from '../data/ownDomainSummary'

// Founder, 21 Oct 2026. (1) The /trust own-domain summary must show the latest
// COMPLETE own-domain assessment and never go stale: this fails once it is more
// than 7 days old, prompting a refresh from the live workspace summary.
// (2) Public pages name the hosting provider, never the blueprint.

describe('/trust own-domain summary is current', () => {
  it('is a complete assessment with a score, measured within the last 7 days', () => {
    expect(OWN_DOMAIN_SUMMARY.coverage).toBe('complete')
    expect(Number.isFinite(OWN_DOMAIN_SUMMARY.score)).toBe(true)
    const ageDays = (Date.now() - Date.parse(OWN_DOMAIN_SUMMARY.measuredAt)) / 86_400_000
    expect(ageDays, `own-domain summary is ${ageDays.toFixed(1)} days old — refresh frontend/src/data/ownDomainSummary.js from the latest complete own-domain assessment`).toBeLessThanOrEqual(OWN_DOMAIN_MAX_AGE_DAYS)
  })
})

describe('public copy names the provider, never the component architecture', () => {
  const root = path.resolve(__dirname, '..')
  const PUBLIC = [
    'pages/TrustPage.jsx', 'pages/AboutPage.jsx', 'pages/PrivacyPage.jsx', 'pages/DpaPage.jsx', 'pages/TermsPage.jsx',
    'pages/CookiePolicyPage.jsx', 'pages/SupportPage.jsx', 'pages/StatusPage.jsx', 'pages/PublicLandingPage.jsx',
    'pages/SecurityPage.jsx', 'pages/CyberEssentialsReadinessPage.jsx', 'pages/FreeScanPage.jsx', 'pages/PricingPage.jsx',
    'data/fieldGuide.js', 'data/academy.js', 'publicPages.js',
  ]
  const ARCHITECTURE = /\b(D1|R2|Workers|Containers|Cloudflare Pages|Durable Objects|KV namespace|edge endpoints?)\b|\b\d[\d,]* (?:of [\d,]+ )?planned check outcomes\b/
  it.each(PUBLIC)('%s', (file) => {
    const text = fs.readFileSync(path.join(root, file), 'utf8')
    const hit = text.split('\n').find((line) => ARCHITECTURE.test(line) && !line.trim().startsWith('//'))
    expect(hit, `architecture detail in public copy: ${hit?.trim().slice(0, 160)}`).toBeUndefined()
  })
})
