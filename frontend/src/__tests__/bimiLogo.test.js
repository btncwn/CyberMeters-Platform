import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// public/bimi.svg is the logo referenced by the default._bimi.cybermeters.com
// TXT record. Mailbox providers only render it if it is SVG Tiny Portable/Secure
// (BIMI Group profile); anything outside that profile makes the logo silently
// disappear from inboxes, so the constraints are pinned here.
const here = path.dirname(fileURLToPath(import.meta.url))
const file = path.resolve(here, '../../public/bimi.svg')
const src = fs.readFileSync(file, 'utf8')
const doc = new DOMParser().parseFromString(src, 'image/svg+xml')
const root = doc.documentElement

describe('BIMI logo (SVG Tiny PS)', () => {
  it('is well-formed SVG', () => {
    expect(doc.getElementsByTagName('parsererror')).toHaveLength(0)
    expect(root.nodeName).toBe('svg')
    expect(root.getAttribute('xmlns')).toBe('http://www.w3.org/2000/svg')
  })

  it('declares the Tiny PS profile', () => {
    expect(root.getAttribute('version')).toBe('1.2')
    expect(root.getAttribute('baseProfile')).toBe('tiny-ps')
  })

  it('is square and carries no root position or size', () => {
    const [, , w, h] = (root.getAttribute('viewBox') || '').split(/\s+/).map(Number)
    expect(w).toBeGreaterThan(0)
    expect(w).toBe(h)
    for (const attr of ['x', 'y', 'width', 'height']) expect(root.hasAttribute(attr)).toBe(false)
  })

  it('has a non-empty title', () => {
    const title = root.getElementsByTagName('title')[0]
    expect(title?.textContent.trim()).toBeTruthy()
  })

  it('uses nothing the profile forbids', () => {
    for (const tag of ['script', 'style', 'image', 'foreignObject', 'animate', 'animateTransform', 'animateMotion', 'set', 'a'])
      expect(root.getElementsByTagName(tag)).toHaveLength(0)
    for (const el of root.getElementsByTagName('*')) {
      expect(el.hasAttribute('style')).toBe(false)
      expect(el.hasAttribute('class')).toBe(false)
      const href = el.getAttribute('href') || el.getAttribute('xlink:href') || ''
      expect(href === '' || href.startsWith('#')).toBe(true)
    }
  })

  it('has an opaque background so the circular crop never shows transparency', () => {
    const first = [...root.children].find((el) => el.nodeName !== 'title' && el.nodeName !== 'defs')
    expect(first?.nodeName).toBe('rect')
    expect(first.getAttribute('width')).toBe(root.getAttribute('viewBox').split(/\s+/)[2])
    expect(first.getAttribute('fill')).toMatch(/^#[0-9A-Fa-f]{6}$/)
  })

  it('stays under the 32 KB limit', () => {
    expect(Buffer.byteLength(src)).toBeLessThan(32 * 1024)
  })
})
