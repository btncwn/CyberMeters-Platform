import { describe, it, expect } from 'vitest'
import { APP_URL, MARKETING_URL, appHostHref, isMarketingHost, isPreviewHost, marketingHomeHref } from '../siteLinks'

describe('siteLinks', () => {
  it('recognises the public site hosts', () => {
    expect(isMarketingHost('cybermeters.com')).toBe(true)
    expect(isMarketingHost('www.cybermeters.com')).toBe(true)
    expect(isMarketingHost('app.cybermeters.com')).toBe(false)
  })

  it('recognises previews and local runs', () => {
    expect(isPreviewHost('localhost')).toBe(true)
    expect(isPreviewHost('127.0.0.1')).toBe(true)
    expect(isPreviewHost('abc123.cybermeters-platform.pages.dev')).toBe(true)
    expect(isPreviewHost('app.cybermeters.com')).toBe(false)
  })

  it('sends the brand mark home on every host', () => {
    expect(marketingHomeHref('cybermeters.com')).toBe('/')
    expect(marketingHomeHref('app.cybermeters.com')).toBe(MARKETING_URL)
    expect(marketingHomeHref('abc123.cybermeters-platform.pages.dev')).toBe('/landing')
  })

  it('sends a form on the public site straight to the app host, so the page loads once', () => {
    expect(appHostHref('/free-scan', 'cybermeters.com')).toBe(`${APP_URL}/free-scan`)
    expect(appHostHref('/free-scan', 'www.cybermeters.com')).toBe('https://app.cybermeters.com/free-scan')
    expect(appHostHref('/free-scan', 'app.cybermeters.com')).toBe('/free-scan')
    expect(appHostHref('/free-scan', 'abc123.cybermeters-platform.pages.dev')).toBe('/free-scan')
  })

  it('reads the current host by default', () => {
    // The test environment runs on localhost.
    expect(isPreviewHost()).toBe(true)
    expect(isMarketingHost()).toBe(false)
    expect(marketingHomeHref()).toBe('/landing')
  })
})
