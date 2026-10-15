import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { GUIDE_AREAS, ARTICLE_AREAS, COMMON_STATES, getGuideArea, getGuideAreaArticles, guideSlugForColourKey, getGuideAreaForArticle } from '../../data/fieldGuide'
import { ARTICLES } from '../../data/academy'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import GuideAreaPage from '../GuideAreaPage'
import GuideEntryPage from '../GuideEntryPage'
import AcademyPage from '../AcademyPage'

// The sidebar order the founder fixed on 14 Oct 2026. The Field Guide must
// present the areas in exactly this order, with exactly these titles.
const FOUNDER_ORDER = [
  ['email-protection',  'email',            'Email Protection'],
  ['attack-surface',    'surface',          'Attack Surface'],
  ['website-security',  'website',          'Website Security'],
  ['identity-exposure', 'identity',         'Identity Exposure'],
  ['shadow-it',         'shadow_it',        'Shadow IT & Unmanaged Technology'],
  ['certificates-trust','certs',            'Certificates & Trust'],
  ['brand-protection',  'brand',            'Brand Protection'],
  ['cyber-essentials',  'cyber_essentials', 'Cyber Essentials Readiness'],
]

const allText = JSON.stringify(GUIDE_AREAS)

describe('Field Guide data', () => {
  it('has the eight areas in founder order with their service colours', () => {
    expect(GUIDE_AREAS.map(a => [a.key, a.colourKey, a.title])).toEqual(FOUNDER_ORDER)
    for (const area of GUIDE_AREAS) expect(SERVICE_COLORS[area.colourKey]).toBeDefined()
    for (const [, colourKey, , ] of FOUNDER_ORDER) expect(guideSlugForColourKey(colourKey)).not.toBe('')
  })

  it('gives every area the same four complete sections', () => {
    for (const area of GUIDE_AREAS) {
      expect(area.route, area.key).toMatch(/^\//)
      expect(area.intro.length, area.key).toBeGreaterThan(40)
      expect(area.summary.length, area.key).toBeGreaterThan(40)
      expect(area.covers.length, area.key).toBeGreaterThan(0)
      expect(area.checks.why.length, area.key).toBeGreaterThan(0)
      expect(area.checks.observed.length, area.key).toBeGreaterThan(0)
      expect(area.checks.notObserved.length, area.key).toBeGreaterThan(0)
      expect(area.reading.intro.length, area.key).toBeGreaterThan(0)
      expect(area.reading.states.length, area.key).toBeGreaterThanOrEqual(COMMON_STATES.length)
      expect(area.next.intro.length, area.key).toBeGreaterThan(0)
      expect(area.next.owners.length, area.key).toBeGreaterThan(0)
      expect(area.next.verification.length, area.key).toBeGreaterThan(0)
      // Each state word appears once per area.
      const states = area.reading.states.map(([s]) => s)
      expect(new Set(states).size, area.key).toBe(states.length)
    }
  })

  it('reserves "verified" for CyberMeters’ own observation in every area', () => {
    for (const area of GUIDE_AREAS) {
      const text = area.next.verification.join(' ')
      expect(text, area.key).toMatch(/attested by you|recorded as attested/i)
      expect(text, area.key).toMatch(/reserved for CyberMeters/i)
    }
  })

  it('never claims visibility the product does not have', () => {
    expect(allText).not.toMatch(/fully compliant|RFC compliant|guarantee/i)
    expect(allText).not.toMatch(/certificate transparency|\bCT\b/)
    expect(allText).not.toMatch(/small business|small compan|UK SMB/i)
    // Identity wording stays at relationship level (see validate-identity-truth-projection).
    expect(allText).not.toMatch(/internet-facing login|publicly reachable admin|login or admin surface|none exposed|credentials are attacked/i)
    // Nobody is told CyberMeters performs the registrar or takedown action.
    expect(getGuideArea('brand-protection').covers.join(' ')).toMatch(/does not file them/i)
  })

  it('maps every in-depth article to exactly one existing area', () => {
    const slugs = new Set(ARTICLES.map(a => a.slug))
    for (const [slug, areaKey] of Object.entries(ARTICLE_AREAS)) {
      expect(slugs.has(slug), slug).toBe(true)
      expect(getGuideArea(areaKey), `${slug} → ${areaKey}`).not.toBeNull()
    }
    const unmapped = ARTICLES.filter(a => !ARTICLE_AREAS[a.slug]).map(a => a.slug)
    expect(unmapped).toEqual([])
    expect(getGuideAreaArticles('email-protection').map(a => a.slug)).toContain('dmarc-explained')
    expect(getGuideAreaForArticle('hsts-explained')?.key).toBe('website-security')
    expect(getGuideArea('')).toBeNull()
    expect(getGuideArea('nope')).toBeNull()
  })
})

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/guide" element={<AcademyPage />} />
        <Route path="/guide/:slug" element={<GuideEntryPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('Field Guide pages', () => {
  it('lists the eight areas on the guide home in order', () => {
    renderAt('/guide')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('CyberMeters Field Guide')
    const headings = screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent).filter(t => t !== 'The eight areas')
    expect(headings).toEqual(FOUNDER_ORDER.map(([, , title]) => title))
    expect(screen.getByRole('link', { name: /Email Protection/ })).toHaveAttribute('href', '/guide/email-protection')
  })

  it('renders an area with the four numbered sections and both scope lists', () => {
    renderAt('/guide/certificates-trust')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Certificates & Trust')
    expect(screen.getByText('Area 6 of 8')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '1. What this area covers' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '2. What CyberMeters checks, and why' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '3. Reading your results' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '4. What to do next' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'What CyberMeters observes from outside' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'What CyberMeters cannot see' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Open Certificates in your workspace/ })).toHaveAttribute('href', '/ws/certificates')
    // Previous / next follow founder order.
    expect(screen.getByRole('link', { name: /← Shadow IT & Unmanaged Technology/ })).toHaveAttribute('href', '/guide/shadow-it')
    expect(screen.getByRole('link', { name: /Brand Protection →/ })).toHaveAttribute('href', '/guide/brand-protection')
  })

  it('shows deeper reading only when an area has articles', () => {
    renderAt('/guide/email-protection')
    expect(screen.getByRole('heading', { name: 'Deeper reading' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /DMARC: stop criminals sending email as your business/ })).toHaveAttribute('href', '/guide/dmarc-stop-email-impersonation')
  })

  it('opens an article at /guide/:slug when the slug is not an area', () => {
    renderAt('/guide/hsts-explained')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/HSTS/i)
  })

  it('redirects an unknown area slug to the guide home', () => {
    render(
      <MemoryRouter initialEntries={['/guide/not-an-area']}>
        <Routes>
          <Route path="/guide" element={<AcademyPage />} />
          <Route path="/guide/:slug" element={<GuideAreaPage />} />
        </Routes>
      </MemoryRouter>,
    )
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('CyberMeters Field Guide')
  })
})
