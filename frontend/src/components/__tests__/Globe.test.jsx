import { render, screen } from '@testing-library/react'
import Globe, { worldDots, buildWorldDots, LAND_POLYGONS, drawGlobe, ROTATION_PERIOD_MS } from '../shell/Globe'

// The decorative globe: land dots from the continent outlines, a graticule, one
// turn every 24 seconds, still under reduced motion, invisible to assistive
// technology and never a pointer target.

function fakeContext() {
  const calls = { arc: 0, lineTo: 0, clearRect: 0 }
  return {
    calls,
    setTransform() {}, clearRect() { calls.clearRect += 1 }, beginPath() {}, stroke() {}, fill() {},
    moveTo() {}, lineTo() { calls.lineTo += 1 }, arc() { calls.arc += 1 },
    lineWidth: 0, strokeStyle: '', fillStyle: '', globalAlpha: 1,
  }
}

const hasDot = (lon, lat) => worldDots.some(([x, y]) => Math.abs(x - lon) < 3 && Math.abs(y - lat) < 3)

describe('world dots', () => {
  it('sample land, not ocean', () => {
    expect(worldDots.length).toBeGreaterThan(400)
    expect(hasDot(10, 50)).toBe(true)      // central Europe
    expect(hasDot(-100, 40)).toBe(true)    // North America
    expect(hasDot(20, 0)).toBe(true)       // central Africa
    expect(hasDot(135, -25)).toBe(true)    // Australia
    expect(hasDot(-30, 0)).toBe(false)     // Atlantic
    expect(hasDot(-150, 0)).toBe(false)    // Pacific
    expect(LAND_POLYGONS.length).toBeGreaterThanOrEqual(8)
    expect(buildWorldDots(8).length).toBeLessThan(worldDots.length)
  })

  it('drawGlobe paints the outline, the graticule and only the front-facing dots', () => {
    const ctx = fakeContext()
    drawGlobe(ctx, 110, 0)
    expect(ctx.calls.clearRect).toBe(1)
    expect(ctx.calls.lineTo).toBeGreaterThan(100)
    expect(ctx.calls.arc).toBeGreaterThan(50)
    expect(ctx.calls.arc).toBeLessThan(worldDots.length + 1)
    expect(ROTATION_PERIOD_MS).toBe(24000)
  })
})

describe('<Globe>', () => {
  let raf, caf, matchMedia
  beforeEach(() => {
    raf = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 1)
    caf = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})
    matchMedia = window.matchMedia
  })
  afterEach(() => { raf.mockRestore(); caf.mockRestore(); window.matchMedia = matchMedia })

  function mockMotion(reduce) {
    window.matchMedia = vi.fn().mockReturnValue({ matches: reduce, addEventListener: vi.fn(), removeEventListener: vi.fn() })
  }

  it('is hidden from assistive technology and inert to the pointer', () => {
    mockMotion(false)
    render(<Globe />)
    const el = screen.getByTestId('shell-globe')
    expect(el).toHaveAttribute('aria-hidden', 'true')
    expect(el.className).toContain('cm-globe')
    expect(el.querySelector('canvas')).toBeTruthy()
  })

  it('animates when motion is allowed and stays still when the viewer prefers reduced motion', () => {
    const ctx = fakeContext()
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(ctx)
    try {
      mockMotion(false)
      const { unmount } = render(<Globe />)
      expect(raf).toHaveBeenCalled()
      unmount()
      expect(caf).toHaveBeenCalled()

      raf.mockClear()
      mockMotion(true)
      render(<Globe />)
      expect(raf).not.toHaveBeenCalled()
      expect(ctx.calls.clearRect).toBeGreaterThan(0)
    } finally {
      getContext.mockRestore()
    }
  })

  it('renders without a 2D context (no canvas support) and without crashing', () => {
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
    try {
      mockMotion(false)
      render(<Globe />)
      expect(raf).not.toHaveBeenCalled()
    } finally {
      getContext.mockRestore()
    }
  })
})
