import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import PublicPageMeta, { applyPageMeta, PUBLIC_PAGE_META, resetPageMetaDefaultsForTests } from '../PublicPageMeta'

// Every route is served the same index.html, so search results showed the
// homepage title for /cyber-essentials-readiness (seen live 19 Oct 2026).

const HOME_TITLE = 'CyberMeters — Know where your business is exposed'
const HOME_DESCRIPTION = 'Know where your business is exposed and what to do next.'

beforeEach(() => {
  resetPageMetaDefaultsForTests()
  document.head.innerHTML = `
    <meta name="description" content="${HOME_DESCRIPTION}">
    <meta property="og:title" content="${HOME_TITLE}">
    <meta property="og:description" content="${HOME_DESCRIPTION}">
    <meta name="twitter:title" content="${HOME_TITLE}">
    <meta name="twitter:description" content="${HOME_DESCRIPTION}">`
  document.title = HOME_TITLE
})

const content = (selector) => document.head.querySelector(selector).getAttribute('content')

describe('public page meta', () => {
  it('gives /cyber-essentials-readiness its own title and description', () => {
    render(<MemoryRouter initialEntries={['/cyber-essentials-readiness']}><Routes><Route path="*" element={<PublicPageMeta />} /></Routes></MemoryRouter>)
    expect(document.title).toBe('Cyber Essentials Readiness Preview | CyberMeters')
    expect(content('meta[name="description"]')).toMatch(/^See how prepared your business looks against the five Cyber Essentials control areas/)
    expect(content('meta[property="og:title"]')).toBe(document.title)
    expect(content('meta[name="twitter:description"]')).toBe(content('meta[name="description"]'))
  })

  it('restores the index.html defaults on the homepage and app routes', () => {
    applyPageMeta('/free-scan')
    expect(document.title).toBe('Free Cyber MOT — check your domain | CyberMeters')
    applyPageMeta('/')
    expect(document.title).toBe(HOME_TITLE)
    expect(content('meta[name="description"]')).toBe(HOME_DESCRIPTION)
    applyPageMeta('/pricing/')
    expect(document.title).toBe('Pricing | CyberMeters')
    applyPageMeta('/dashboard')
    expect(document.title).toBe(HOME_TITLE)
    expect(content('meta[property="og:description"]')).toBe(HOME_DESCRIPTION)
  })

  it('keeps the homepage description for a page without its own', () => {
    applyPageMeta('/terms')
    expect(document.title).toBe('Terms of Service | CyberMeters')
    expect(content('meta[name="description"]')).toBe(HOME_DESCRIPTION)
  })

  it('makes no claim the product does not support', () => {
    const all = Object.values(PUBLIC_PAGE_META).map((m) => `${m.title} ${m.description || ''}`).join(' ')
    expect(all).not.toMatch(/DMARC & BEC|certified|guarantee|fully compliant|dark.?web/i)
  })
})
