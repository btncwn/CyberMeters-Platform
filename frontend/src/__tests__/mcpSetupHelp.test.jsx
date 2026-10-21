import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import SupportPage from '../pages/SupportPage'

const repo = resolve(__dirname, '../../..')
describe('MCP setup instructions match the customer server', () => {
  it('documents every current customer tool exactly once', () => {
    const source = readFileSync(resolve(repo, 'workers/mcp-server/src/customer-mcp.js'), 'utf8')
    const catalogue = source.slice(source.indexOf('const tools = Object.freeze(['), source.indexOf('async function callBackend'))
    const names = [...catalogue.matchAll(/\['(cybermeters_[a-z_]+)'/g)].map(m => m[1])
    const doc = readFileSync(resolve(repo, 'docs/MCP-SETUP.md'), 'utf8')
    const documented = [...doc.matchAll(/^\| `(cybermeters_[a-z_]+)`/gm)].map(m => m[1])
    expect(documented).toEqual(names)
    expect(new Set(documented).size).toBe(documented.length)
  })

  it('offers client setup, explicit compatibility limits and account revocation', () => {
    render(<MemoryRouter><SupportPage /></MemoryRouter>)
    const help = within(screen.getByRole('region', { name: 'Connect your AI assistant' }))
    expect(help.getByText('https://mcp.cybermeters.com/mcp')).toBeInTheDocument()
    for (const name of ['Claude', 'ChatGPT', 'Gemini CLI']) {
      expect(help.getByRole('heading', { name })).toBeInTheDocument()
    }
    expect(help.getByRole('link', { name: 'MCP connections in your account' }))
      .toHaveAttribute('href', 'https://app.cybermeters.com/account/mcp')
    expect(help.getByText(/hosted sign-in callback is not currently enabled/)).toBeInTheDocument()
    expect(help.getByText(/not yet been confirmed by a complete live read and reconnect test/)).toBeInTheDocument()
    expect(help.getByText(/cannot erase those copies/)).toBeInTheDocument()
    expect(help.getByText(/cannot start scans, change settings or fix issues/)).toBeInTheDocument()
    expect(help.getByText(/Never paste passwords or access tokens/)).toBeInTheDocument()
  })
})
