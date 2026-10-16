import { describe, it, expect } from 'vitest'
import {
  safeLoginDestination, mcpLoginDestination,
  saveMicrosoftMcpContinuation, takeMicrosoftMcpContinuation,
} from '../mcpLoginContinuation'

const INTENT = 'i'.repeat(43)
const BINDING = 'b'.repeat(43)
const DESTINATION = `/mcp/connect?intent=${INTENT}`

function storage() {
  const data = new Map()
  return {
    getItem: key => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
    removeItem: key => data.delete(key),
    data,
  }
}

describe('MCP post-login destination', () => {
  it('accepts only one valid MCP intent and canonicalises the local path', () => {
    const from = { pathname: '/mcp/connect', search: `?intent=${INTENT}` }
    expect(safeLoginDestination(from)).toBe(DESTINATION)
    expect(mcpLoginDestination(from)).toBe(DESTINATION)
    expect(safeLoginDestination({ ...from, search: `?intent=${INTENT}&next=//evil.example` }))
      .toBe('/services')
    expect(safeLoginDestination({ ...from, search: '?intent=short' })).toBe('/services')
    expect(safeLoginDestination({ ...from, search: `?intent=${INTENT}&intent=${INTENT}` }))
      .toBe('/services')
  })

  it('rejects foreign URLs and never attaches an intent or bearer to another route', () => {
    expect(safeLoginDestination({ pathname: '//evil.example', search: `?intent=${INTENT}` }))
      .toBe('/services')
    expect(safeLoginDestination({ pathname: '/services', search: `?intent=${INTENT}` }))
      .toBe('/services')
    expect(safeLoginDestination({ pathname: '/dashboard', search: '?access_token=secret' }))
      .toBe('/services')
    expect(safeLoginDestination({ pathname: '/ws/cases', search: '?page=2' }))
      .toBe('/ws/cases?page=2')
  })

  it('consumes only the matching, fresh browser binding once', () => {
    const box = storage()
    saveMicrosoftMcpContinuation(BINDING, DESTINATION, { storage: box, now: 1_000 })
    expect(JSON.stringify([...box.data.values()])).not.toContain('Bearer')
    expect(takeMicrosoftMcpContinuation('x'.repeat(43), { storage: box, now: 2_000 })).toBeNull()
    expect(takeMicrosoftMcpContinuation(BINDING, { storage: box, now: 2_000 })).toBeNull()
    saveMicrosoftMcpContinuation(BINDING, DESTINATION, { storage: box, now: 1_000 })
    expect(takeMicrosoftMcpContinuation(BINDING, { storage: box, now: 2_000 })).toBe(DESTINATION)
    expect(takeMicrosoftMcpContinuation(BINDING, { storage: box, now: 2_000 })).toBeNull()
    saveMicrosoftMcpContinuation(BINDING, DESTINATION, { storage: box, now: 1_000 })
    expect(takeMicrosoftMcpContinuation(BINDING, { storage: box, now: 16 * 60 * 1000 })).toBeNull()
  })

  it('rejects tampered storage and destinations outside the MCP consent page', () => {
    const box = storage()
    expect(() => saveMicrosoftMcpContinuation(BINDING, '/services', { storage: box }))
      .toThrow()
    expect(() => saveMicrosoftMcpContinuation(BINDING, `${DESTINATION}&bearer=secret`, { storage: box }))
      .toThrow()
    box.setItem('cm_ms_mcp_continuation', JSON.stringify({
      binding: BINDING, destination: '//evil.example', at: 1_000,
    }))
    expect(takeMicrosoftMcpContinuation(BINDING, { storage: box, now: 2_000 })).toBeNull()
  })
})
