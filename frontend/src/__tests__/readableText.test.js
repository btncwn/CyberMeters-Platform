import fs from 'node:fs'
import path from 'node:path'

// Readable text — static guard (founder, 17 Oct 2026). The axe-core gate in
// e2e/contrast.spec.js measures rendered pages; this guard catches the two
// patterns at the source so they cannot come back on a route the gate does
// not visit:
//   1. light text on the aqua / brand-50..300 grounds (white, gray-50..300,
//      brand-50..500 text) — including the invitation header band;
//   2. light grey text tokens (gray-50..300) used as text colour anywhere.
// It also reads the Worker email templates, which no browser test renders:
// no white text on the aqua button ground, no old green.

const FRONTEND = path.resolve(__dirname, '..')
const REPO = path.resolve(FRONTEND, '..', '..')

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) { if (!/__tests__|node_modules/.test(entry.name)) walk(full, out) }
    else if (/\.(jsx|js)$/.test(entry.name) && !/\.test\.(jsx|js)$/.test(entry.name)) out.push(full)
  }
  return out
}

const sources = walk(FRONTEND).map((file) => ({ file: path.relative(FRONTEND, file), text: fs.readFileSync(file, 'utf8') }))
const classStrings = (text) => [...text.matchAll(/(['"`])((?:(?!\1).)*?(?:bg-|text-)(?:(?!\1).)*)\1/g)].map((m) => m[2])

const LIGHT_GROUND = /\b(?:hover:|group-hover:|focus:)?bg-brand-(?:50|100|200|300)\b|bg-\[#a9f2e5\]/
const LIGHT_TEXT = /\btext-(?:white|gray-(?:50|100|200|300)|brand-(?:50|100|200|300|400|500))\b/
const LIGHT_GREY_TEXT = /\btext-gray-(?:50|100|200|300)\b/
const DARK_GROUND = /\bbg-(?:gray-(?:700|800|900|950)|black|brand-(?:800|900)|slate-(?:800|900)|red-(?:600|700|800)|\[#0[0-9a-f]{5}\])\b/

describe('readable text — static guard', () => {
  it('never puts light text on the aqua or brand-50..300 grounds (including the invitation header)', () => {
    const offenders = []
    for (const { file, text } of sources) {
      for (const cls of classStrings(text)) {
        if (LIGHT_GROUND.test(cls) && LIGHT_TEXT.test(cls)) offenders.push(`${file}: "${cls}"`)
      }
    }
    expect(offenders).toEqual([])
    const invitation = sources.find((s) => s.file.endsWith('pages/InvitationLandingPage.jsx'))
    const band = invitation.text.slice(invitation.text.indexOf('Header band'), invitation.text.indexOf('Details */'))
    expect(band).toMatch(/bg-brand-200/)
    expect(band).not.toMatch(/text-white|text-brand-(?:50|100|200|300)/)
  })

  it('uses no light grey text token (gray-50..300) as a text colour outside a dark ground', () => {
    const offenders = []
    for (const { file, text } of sources) {
      for (const cls of classStrings(text)) {
        if (LIGHT_GREY_TEXT.test(cls) && !DARK_GROUND.test(cls)) offenders.push(`${file}: "${cls}"`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('email templates: aqua buttons carry dark ink, no old green anywhere', () => {
    const templates = [
      'workers/scan-api/src/routes/workspace-members.js', 'workers/scan-api/src/routes/auth.js',
      'workers/scan-api/src/lib/lifecycle-email.js', 'workers/scan-api/src/engines/alerts.js', 'workers/scan-api/src/engines/asset-alerts.js',
    ]
    for (const rel of templates) {
      const text = fs.readFileSync(path.join(REPO, rel), 'utf8')
      expect(text, rel).not.toMatch(/#0a7c5c|#00876a/i)
      expect(text, rel).not.toMatch(/#a9f2e5[^"'`]{0,80}color:\s*(?:#fff\b|#ffffff|white)/i)
    }
  })
})
