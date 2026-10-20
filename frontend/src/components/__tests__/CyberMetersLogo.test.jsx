import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { render, screen } from '@testing-library/react'
import { expect, it } from 'vitest'
import CyberMetersLogo from '../CyberMetersLogo'

const here = path.dirname(fileURLToPath(import.meta.url))

function definedIds(container) {
  return [...container.querySelectorAll('defs [id]')].map((el) => el.id)
}

it('gives every logo on a page its own gradient, filter and clip IDs', () => {
  const { container } = render(
    <>
      <CyberMetersLogo size={30} showWordmark />
      <CyberMetersLogo size={34} darkMode />
    </>,
  )
  const ids = definedIds(container)
  expect(ids.length).toBe(16)
  expect(new Set(ids).size).toBe(ids.length)
  // Every url(#…) reference resolves inside its own svg.
  for (const svg of container.querySelectorAll('svg')) {
    const own = new Set([...svg.querySelectorAll('defs [id]')].map((el) => el.id))
    const refs = [...svg.querySelectorAll('*')]
      .flatMap((el) => ['fill', 'filter', 'clip-path'].map((a) => el.getAttribute(a)))
      .filter((v) => v?.startsWith('url(#'))
      .map((v) => v.slice(5, -1))
    expect(refs.length).toBeGreaterThan(0)
    for (const ref of refs) expect(own.has(ref)).toBe(true)
  }
})

it('hides the mark from assistive technology beside the wordmark, and names it when alone', () => {
  const { container, rerender } = render(<CyberMetersLogo showWordmark />)
  const withWord = container.querySelector('svg')
  expect(withWord.getAttribute('aria-hidden')).toBe('true')
  expect(withWord.getAttribute('role')).toBeNull()
  expect(screen.getByText('CyberMeters')).toBeInTheDocument()

  rerender(<CyberMetersLogo />)
  expect(screen.getByRole('img', { name: 'CyberMeters' })).toBeInTheDocument()
})

it('keeps the 45 x 32 proportions at any size', () => {
  const { container } = render(<CyberMetersLogo size={64} />)
  const svg = container.querySelector('svg')
  expect(svg.getAttribute('viewBox')).toBe('0 0 45 32')
  expect(svg.getAttribute('height')).toBe('64')
  expect(svg.getAttribute('width')).toBe('90')
})

it('draws the same polygons as the favicon, so the two cannot drift apart', () => {
  const favicon = fs.readFileSync(path.resolve(here, '../../../public/favicon.svg'), 'utf8')
  const { container } = render(<CyberMetersLogo />)
  const points = [...container.querySelectorAll('polygon')].map((p) => p.getAttribute('points'))
  // The favicon carries the flat shapes (no shadows or highlights); each of
  // those must be one of the component's polygons.
  const faviconPoints = [...favicon.matchAll(/<polygon points="([^"]+)"/g)].map((m) => m[1])
  expect(faviconPoints.length).toBeGreaterThan(0)
  for (const p of faviconPoints) expect(points).toContain(p)
})

it('uses the dark C on light backgrounds and the light C on dark ones', () => {
  const stops = (el) => [...el.querySelectorAll('linearGradient')].flatMap((g) =>
    [...g.querySelectorAll('stop')].map((s) => s.getAttribute('stop-color')))
  const light = render(<CyberMetersLogo />).container
  expect(stops(light)).toContain('#26303B')
  expect(stops(light)).not.toContain('#FFFFFF')
  const dark = render(<CyberMetersLogo darkMode />).container
  expect(stops(dark)).toContain('#FFFFFF')
  expect(stops(dark)).not.toContain('#26303B')
})
