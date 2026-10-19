// @vitest-environment-options {"url":"https://cybermeters.com/"}
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PublicLandingPage from '../pages/PublicLandingPage'
import { appHostHref } from '../utils/siteLinks'

// P1 (19 Oct 2026): the homepage "Run a free check" form did nothing on
// cybermeters.com. It submits to the app host, and the CSP form-action allowed
// only 'self' and checkout, so the browser silently blocked it. Every place a
// form can send the visitor must be allowed by form-action.

const src = resolve(__dirname, '..')
const headers = readFileSync(resolve(src, '../public/_headers'), 'utf8')
const csp = headers.match(/^\s+Content-Security-Policy: (.+)$/m)[1]
const formAction = csp.match(/(?:^|;)\s*form-action ([^;]+)/)[1].trim().split(/\s+/)

const HOSTS = ['cybermeters.com', 'www.cybermeters.com', 'app.cybermeters.com']

/** Would the browser let a page on `pageOrigin` submit a form to `target`? */
function allowed(pageOrigin, target) {
  const origin = new URL(target, pageOrigin).origin
  return (origin === pageOrigin && formAction.includes("'self'")) || formAction.includes(origin)
}

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sourceFiles(path)
    return /\.(jsx?|tsx?)$/.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

describe('CSP form-action allows every form the app renders', () => {
  it('the homepage form on the marketing host submits to an allowed origin', () => {
    const { container } = render(<MemoryRouter><PublicLandingPage /></MemoryRouter>)
    const forms = [...container.querySelectorAll('form')]
    expect(forms.length).toBeGreaterThan(0)
    for (const form of forms) {
      const target = form.getAttribute('action')
      expect(target).toBe('https://app.cybermeters.com/free-scan')
      expect(allowed('https://cybermeters.com', target)).toBe(true)
    }
  })

  it('every <form action=…> in the source resolves, on every host, to an allowed origin', () => {
    const found = []
    for (const file of sourceFiles(src)) {
      const text = readFileSync(file, 'utf8')
      for (const m of text.matchAll(/<form\b[^>]*?\baction=(\{[^}]*\}\)?\}?|"[^"]*"|'[^']*')/g)) {
        found.push({ file: relative(src, file), expr: m[1] })
      }
    }
    expect(found.length).toBeGreaterThan(0)
    for (const { file, expr } of found) {
      const literal = expr.match(/^["'](.*)["']$/)
      const viaHelper = expr.match(/^\{appHostHref\((['"])([^'"]+)\1\)\}$/)
      // A form target this test cannot resolve must be added here deliberately.
      expect(Boolean(literal || viaHelper), `${file}: unrecognised form action ${expr}`).toBe(true)
      for (const host of HOSTS) {
        const target = literal ? literal[1] : appHostHref(viaHelper[2], host)
        expect(allowed(`https://${host}`, target), `${file} on ${host}: ${target} is not allowed by form-action`).toBe(true)
      }
    }
  })

  it('keeps everything else form-action already allowed', () => {
    expect(formAction).toEqual(["'self'", 'https://app.cybermeters.com', 'https://checkout.stripe.com'])
  })
})
