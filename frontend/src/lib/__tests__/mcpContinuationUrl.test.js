import { describe, expect, it } from 'vitest'
import { validMcpContinuationUrl } from '../mcpContinuationUrl'

const base = 'https://api.cybermeters.com/api'
const intent = 'A'.repeat(43)

describe('MCP browser consent continuation', () => {
  it('accepts only the API origin and the original one-time intent', () => {
    expect(validMcpContinuationUrl(base, intent,
      `https://api.cybermeters.com/authorize?intent=${intent}`))
      .toBe(`https://api.cybermeters.com/authorize?intent=${intent}`)
    for (const candidate of [
      `https://evil.example/authorize?intent=${intent}`,
      `https://api.cybermeters.com.evil.example/authorize?intent=${intent}`,
      `https://evil@api.cybermeters.com/authorize?intent=${intent}`,
      `https://api.cybermeters.com/authorize?intent=${intent}#leak`,
      `https://api.cybermeters.com/authorize?intent=${intent}&next=https://evil.example`,
      `https://api.cybermeters.com/authorize?intent=${'B'.repeat(43)}`,
      `https://api.cybermeters.com/oauth/token?intent=${intent}`,
    ]) expect(validMcpContinuationUrl(base, intent, candidate)).toBeNull()
  })
})
