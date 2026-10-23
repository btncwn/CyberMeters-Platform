// Founder, 23 Oct 2026: the six free tools were footer-only and /free-tools fell
// into the catch-all. /free-tools (and anything under it) opens /tools — at the
// edge (public/_redirects 301) and in the app (react-router) — and the public
// header lists "Free tools" after "How it works", before "Pricing".
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { freeToolsAliasRoutes } from '../App'
import PublicSiteHeader, { siteNav } from '../components/PublicSiteHeader'

describe('/free-tools → /tools', () => {
  it('public/_redirects 301s /free-tools and /free-tools/* to /tools, before the SPA catch-all', () => {
    const lines = readFileSync(resolve(__dirname, '../../public/_redirects'), 'utf8').split('\n').map((l) => l.trim().split(/\s+/)).filter((l) => l[0] && !l[0].startsWith('#'))
    const at = (src) => lines.findIndex((l) => l[0] === src)
    expect(lines[at('/free-tools')]).toEqual(['/free-tools', '/tools', '301'])
    expect(lines[at('/free-tools/*')]).toEqual(['/free-tools/*', '/tools', '301'])
    expect(at('/free-tools')).toBeLessThan(at('/*'))
    expect(at('/free-tools/*')).toBeLessThan(at('/*'))
  })
  for (const path of ['/free-tools', '/free-tools/', '/free-tools/dmarc-checker', '/tools', '/tools/']) {
    it(`${path} opens the tools index`, () => {
      render(
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/tools" element={<p>Tools index</p>} />
            {freeToolsAliasRoutes()}
            <Route path="*" element={<p>Home</p>} />
          </Routes>
        </MemoryRouter>,
      )
      expect(screen.getByText('Tools index')).toBeInTheDocument()
    })
  }
})

describe('public header: "Free tools"', () => {
  it('sits after "How it works" and before "Pricing"; nothing else moves', () => {
    expect(siteNav('/').map((i) => i.label)).toEqual(['Product', 'Areas', 'How it works', 'Free tools', 'Pricing', 'Trust & Security', 'About'])
    expect(siteNav('/').find((i) => i.label === 'Free tools')).toEqual({ label: 'Free tools', to: '/tools' })
  })
  it('the desktop header and the mobile menu both link it to /tools', () => {
    render(<MemoryRouter><PublicSiteHeader /></MemoryRouter>)
    expect(screen.getAllByRole('link', { name: 'Free tools' })[0]).toHaveAttribute('href', '/tools')
    fireEvent.click(screen.getByRole('button', { name: /Menu/ }))
    const links = screen.getAllByRole('link', { name: 'Free tools' })
    expect(links.length).toBe(2)
    for (const l of links) expect(l).toHaveAttribute('href', '/tools')
  })
})
