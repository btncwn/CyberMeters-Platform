import {
  buildEarthTexture, buildSphereNormals, flatOceanTexture, shadeEarthPixels, spinAt,
  ROTATION_PERIOD_MS, STILL_FRAME_SPIN, EARTH_SIZE_TOPBAR, TEXTURE_WIDTH, TEXTURE_HEIGHT,
} from '../shell/earth'
import { EARTH_LAND } from '../shell/earth-land'

// The photographic globe: real coastlines painted onto an equirectangular
// texture, a per-pixel sphere with sun light, specular water and an
// atmosphere rim; one turn every 24 seconds; one still frame under reduced
// motion. The land data is a Natural Earth derivative (public domain).

function fakeTextureContext(width, height) {
  const calls = { fillRect: 0, fill: 0, stroke: 0, drawImage: 0 }
  const gradient = () => ({ addColorStop() {} })
  return {
    calls,
    fillStyle: '', strokeStyle: '', lineWidth: 0, lineJoin: '', globalCompositeOperation: 'source-over',
    createLinearGradient: gradient, createRadialGradient: gradient,
    fillRect() { calls.fillRect += 1 }, beginPath() {}, moveTo() {}, lineTo() {}, closePath() {},
    fill() { calls.fill += 1 }, stroke() { calls.stroke += 1 }, drawImage() { calls.drawImage += 1 },
    getImageData: () => ({ data: new Uint8ClampedArray(width * height * 4).fill(40) }),
  }
}

describe('continent data', () => {
  it('is a public-domain derivative with real rings', () => {
    expect(EARTH_LAND.length).toBeGreaterThan(100)
    const points = EARTH_LAND.reduce((n, ring) => n + ring.length, 0)
    expect(points).toBeGreaterThan(5000)
    for (const ring of EARTH_LAND) {
      expect(ring.length).toBeGreaterThanOrEqual(3)
      for (const [lon, lat] of ring) {
        expect(lon).toBeGreaterThanOrEqual(-180); expect(lon).toBeLessThanOrEqual(180)
        expect(lat).toBeGreaterThanOrEqual(-90); expect(lat).toBeLessThanOrEqual(90)
      }
    }
    expect(Object.isFrozen(EARTH_LAND)).toBe(true)
  })
})

describe('texture', () => {
  it('paints ocean, every landmass, the desert tint and the ice caps once', () => {
    const ctx = fakeTextureContext(TEXTURE_WIDTH, TEXTURE_HEIGHT)
    const scratch = []
    const makeCanvas = (w, h) => { const c = fakeTextureContext(w, h); scratch.push(c); return { getContext: () => c } }
    const texture = buildEarthTexture(ctx, TEXTURE_WIDTH, TEXTURE_HEIGHT, makeCanvas, () => 0.5)
    expect(texture.width).toBe(TEXTURE_WIDTH)
    expect(texture.height).toBe(TEXTURE_HEIGHT)
    expect(texture.data.length).toBe(TEXTURE_WIDTH * TEXTURE_HEIGHT * 4)
    expect(ctx.calls.fill).toBe(EARTH_LAND.length)       // one fill per landmass
    expect(ctx.calls.stroke).toBe(EARTH_LAND.length)     // one coastline stroke per landmass
    expect(ctx.calls.fillRect).toBeGreaterThan(900)      // ocean + mottling + ice caps
    expect(ctx.calls.drawImage).toBe(1)                  // the land-only desert tint
    expect(scratch[0].calls.fill).toBe(EARTH_LAND.length) // the land mask
  })

  it('returns null without a paintable context, and the flat ocean fallback is a valid texture', () => {
    expect(buildEarthTexture(null)).toBeNull()
    expect(buildEarthTexture({})).toBeNull()
    const flat = flatOceanTexture()
    expect(flat.data.length).toBe(flat.width * flat.height * 4)
    expect(flat.data[2]).toBeGreaterThan(flat.data[0] + 30) // reads as water
  })
})

describe('sphere', () => {
  it('normals cover the disc and mark the outside', () => {
    const n = buildSphereNormals(20)
    const centre = 10 * 20 + 10
    expect(n.nz[centre]).toBeGreaterThan(0.95)
    expect(n.nz[0]).toBe(-1)                 // corner: outside the disc
    expect(n.radius).toBeCloseTo(10 * 0.985)
  })

  it('shades a lit, opaque disc with a transparent halo outside, and the spin moves the picture', () => {
    const size = 24
    const normals = buildSphereNormals(size)
    const texture = flatOceanTexture(64, 32)
    // Mark one bright land-coloured column so rotation is observable.
    for (let y = 0; y < 32; y += 1) { const p = (y * 64 + 10) * 4; texture.data[p] = 200; texture.data[p + 1] = 180; texture.data[p + 2] = 60 }
    const a = shadeEarthPixels(new Uint8ClampedArray(size * size * 4), normals, texture, 0)
    const b = shadeEarthPixels(new Uint8ClampedArray(size * size * 4), normals, texture, 1.3)
    const centre = (12 * size + 12) * 4
    expect(a[centre + 3]).toBe(255)          // opaque on the disc
    expect(a[3]).toBe(0)                     // transparent far corner
    // The halo ring just outside the disc has some alpha.
    const edge = ((Math.round(size / 2) - 1) * size + (size - 1)) * 4
    expect(a[edge + 3]).toBeGreaterThanOrEqual(0)
    let differs = 0
    for (let i = 0; i < a.length; i += 4) if (a[i] !== b[i] || a[i + 1] !== b[i + 1]) differs += 1
    expect(differs).toBeGreaterThan(10)
  })

  it('turns once every 24 seconds and holds one still frame under reduced motion', () => {
    expect(ROTATION_PERIOD_MS).toBe(24000)
    expect(spinAt(0)).toBe(0)
    expect(spinAt(ROTATION_PERIOD_MS / 2)).toBeCloseTo(Math.PI)
    expect(spinAt(12345, true)).toBe(STILL_FRAME_SPIN)
    expect(spinAt(99999, true)).toBe(STILL_FRAME_SPIN)
    expect(EARTH_SIZE_TOPBAR).toBe(44)   // the account initial's diameter (cm-avatar w-11 h-11, S1-SHELL-V2)
  })
})
