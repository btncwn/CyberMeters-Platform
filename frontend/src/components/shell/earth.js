// Photographic-style globe renderer for the app shell (founder prototype v2,
// 17 Oct 2026). Pure functions over a 2D canvas context so the component and
// the tests share one implementation:
//
//   1. buildEarthTexture(ctx2d, width, height) paints an equirectangular
//      texture once — ocean gradient with depth mottling, the coastline
//      polygons (earth-land.js), warm desert belts tinted onto land only, and
//      the polar ice caps — and returns its RGBA bytes.
//   2. buildSphereNormals(size) precomputes the unit normal of every pixel on
//      the disc once per canvas size.
//   3. renderEarthFrame(...) samples the texture per pixel for the current spin
//      (undo the axial tilt, undo the spin, read lon/lat), lights it with a
//      fixed sun (diffuse, soft terminator, specular on water) and adds the
//      atmosphere at the limb and a thin halo outside the disc.
//
// One full turn every 24 seconds. Under prefers-reduced-motion the component
// draws one still frame. Decorative: no product fact is read from the globe.
import { EARTH_LAND } from './earth-land'

export const ROTATION_PERIOD_MS = 24000
export const EARTH_TILT = 0.41
export const STILL_FRAME_SPIN = 2.2
export const TEXTURE_WIDTH = 1440
export const TEXTURE_HEIGHT = 720
// 108px: the founder prototype's 135px less 20% (review of #662). Its only job
// is the notification control, so it stays well above the 44×44 hit minimum.
// The globe sits in the top bar at the account initial's diameter (cm-avatar: 40px).
export const EARTH_SIZE_TOPBAR = 40

const SUN = (() => {
  const l = [-0.55, 0.5, 0.67]
  const n = Math.hypot(...l)
  return l.map((v) => v / n)
})()

function tracePolygons(ctx, X, Y) {
  for (const ring of EARTH_LAND) {
    ctx.beginPath()
    ring.forEach(([lon, lat], i) => {
      const x = X(lon); const y = Y(lat)
      if (i) ctx.lineTo(x, y); else ctx.moveTo(x, y)
    })
    ctx.closePath()
    ctx.fill()
    if (typeof ctx.stroke === 'function' && ctx.strokeStyle) ctx.stroke()
  }
}

/**
 * Paint the equirectangular texture. `makeCanvas` creates the scratch
 * canvases used for the land mask and the desert tint (document.createElement
 * in the browser; a factory of fake contexts in tests). Returns
 * { data, width, height } or null when the context cannot paint.
 */
export function buildEarthTexture(ctx, width = TEXTURE_WIDTH, height = TEXTURE_HEIGHT, makeCanvas = null, random = Math.random) {
  if (!ctx || typeof ctx.fillRect !== 'function' || typeof ctx.getImageData !== 'function') return null
  const X = (lon) => ((lon + 180) / 360) * width
  const Y = (lat) => ((90 - lat) / 180) * height

  // Ocean, with depth mottling.
  const ocean = ctx.createLinearGradient(0, 0, 0, height)
  ocean.addColorStop(0, '#1d4e89'); ocean.addColorStop(0.5, '#0f3f7a'); ocean.addColorStop(1, '#1d4e89')
  ctx.fillStyle = ocean
  ctx.fillRect(0, 0, width, height)
  for (let i = 0; i < 900; i += 1) {
    const x = random() * width; const y = random() * height; const r = 20 + random() * 90
    const g = ctx.createRadialGradient(x, y, 0, x, y, r)
    g.addColorStop(0, 'rgba(60,130,200,.10)'); g.addColorStop(1, 'rgba(60,130,200,0)')
    ctx.fillStyle = g
    ctx.fillRect(x - r, y - r, 2 * r, 2 * r)
  }

  // Land: a latitude gradient from polar white through temperate green to
  // the sub-tropics, with a coastline stroke.
  const land = ctx.createLinearGradient(0, 0, 0, height)
  land.addColorStop(0, '#e9eef2'); land.addColorStop(0.12, '#6f8f55'); land.addColorStop(0.32, '#7a8f4e')
  land.addColorStop(0.5, '#8a8a52'); land.addColorStop(0.7, '#6f8f55'); land.addColorStop(0.86, '#a9b7a0'); land.addColorStop(1, '#f4f7f9')
  ctx.fillStyle = land
  ctx.strokeStyle = 'rgba(40,70,50,.45)'
  ctx.lineWidth = 1.2
  ctx.lineJoin = 'round'
  tracePolygons(ctx, X, Y)

  // Desert belts, tinted onto land only (mask → tint → draw).
  if (typeof makeCanvas === 'function') {
    const mask = makeCanvas(width, height)
    const mc = mask && typeof mask.getContext === 'function' ? mask.getContext('2d') : null
    const tint = makeCanvas(width, height)
    const tc = tint && typeof tint.getContext === 'function' ? tint.getContext('2d') : null
    if (mc && tc && typeof tc.drawImage === 'function' && typeof ctx.drawImage === 'function') {
      mc.fillStyle = '#000'
      mc.strokeStyle = ''
      tracePolygons(mc, X, Y)
      for (const [a, b, alpha] of [[15, 35, 0.55], [-35, -18, 0.35]]) {
        const g = tc.createLinearGradient(0, Y(b), 0, Y(a))
        g.addColorStop(0, 'rgba(201,166,98,0)'); g.addColorStop(0.5, `rgba(201,166,98,${alpha})`); g.addColorStop(1, 'rgba(201,166,98,0)')
        tc.fillStyle = g
        tc.fillRect(0, Y(b), width, Y(a) - Y(b))
      }
      tc.globalCompositeOperation = 'destination-in'
      tc.drawImage(mask, 0, 0)
      ctx.drawImage(tint, 0, 0)
    }
  }

  // Polar ice.
  const iceN = ctx.createLinearGradient(0, Y(76), 0, Y(88))
  iceN.addColorStop(0, 'rgba(240,246,250,0)'); iceN.addColorStop(1, 'rgba(240,246,250,.9)')
  ctx.fillStyle = iceN; ctx.fillRect(0, 0, width, Y(76))
  const iceS = ctx.createLinearGradient(0, Y(-60), 0, Y(-72))
  iceS.addColorStop(0, 'rgba(240,246,250,0)'); iceS.addColorStop(1, 'rgba(240,246,250,.95)')
  ctx.fillStyle = iceS; ctx.fillRect(0, Y(-60), width, height - Y(-60))

  const image = ctx.getImageData(0, 0, width, height)
  if (!image || !image.data) return null
  return { data: image.data, width, height }
}

/** Unit normals for every pixel of a `size`×`size` disc; nz < 0 marks "outside". */
export function buildSphereNormals(size) {
  const n = size * size
  const nx = new Float32Array(n); const ny = new Float32Array(n); const nz = new Float32Array(n)
  const radius = (size / 2) * 0.985; const c = size / 2
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const i = y * size + x
      const u = (x + 0.5 - c) / radius; const v = (c - (y + 0.5)) / radius
      const d = u * u + v * v
      if (d > 1) { nz[i] = -1; continue }
      nx[i] = u; ny[i] = v; nz[i] = Math.sqrt(1 - d)
    }
  }
  return { nx, ny, nz, size, radius }
}

/** Spin angle (radians) for a wall-clock time; one turn per ROTATION_PERIOD_MS. */
export function spinAt(nowMs, reduceMotion = false) {
  if (reduceMotion) return STILL_FRAME_SPIN
  return ((nowMs % ROTATION_PERIOD_MS) / ROTATION_PERIOD_MS) * Math.PI * 2
}

/**
 * Fill `out` (an RGBA byte array of size×size pixels) with one lit frame.
 * Exported separately from the canvas put so a test can inspect pixels.
 */
export function shadeEarthPixels(out, normals, texture, spin) {
  const { nx, ny, nz, size, radius } = normals
  const { data: td, width: TW, height: TH } = texture
  const c = size / 2
  const cs = Math.cos(spin); const sn = Math.sin(spin)
  const ct = Math.cos(EARTH_TILT); const st = Math.sin(EARTH_TILT)
  const h0 = SUN[0]; const h1 = SUN[1]; const h2 = SUN[2] + 1; const hl = Math.hypot(h0, h1, h2)
  for (let i = 0, p = 0; i < size * size; i += 1, p += 4) {
    const z = nz[i]
    if (z < 0) {
      // Outside the disc: a thin atmospheric halo, then transparent.
      const x = (i % size) + 0.5 - c; const y = Math.floor(i / size) + 0.5 - c
      const r = Math.hypot(x, y) / radius
      if (r < 1.09) {
        const a = Math.max(0, 1 - (r - 1) / 0.09)
        out[p] = 150; out[p + 1] = 190; out[p + 2] = 255; out[p + 3] = Math.round(90 * a * a)
      } else out[p + 3] = 0
      continue
    }
    const x = nx[i]; const y = ny[i]
    const y1 = y * ct + z * st; const z1 = -y * st + z * ct
    const x2 = x * cs - z1 * sn; const z2 = x * sn + z1 * cs
    const lon = Math.atan2(x2, z2); const lat = Math.asin(Math.max(-1, Math.min(1, y1)))
    const tx = ((lon / (2 * Math.PI) + 0.5) * TW) | 0
    const ty = ((0.5 - lat / Math.PI) * TH) | 0
    const ti = ((ty < 0 ? 0 : ty >= TH ? TH - 1 : ty) * TW + (((tx % TW) + TW) % TW)) * 4
    let r = td[ti]; let g = td[ti + 1]; let b = td[ti + 2]
    const ndl = x * SUN[0] + y * SUN[1] + z * SUN[2]
    const diffuse = 0.22 + 0.85 * Math.max(0, ndl)
    let spec = 0
    if (b > r + 30) { // water
      const ndh = (x * h0 + y * h1 + z * h2) / hl
      spec = Math.pow(Math.max(0, ndh), 60) * 0.55
    }
    r = r * diffuse + 255 * spec; g = g * diffuse + 255 * spec; b = b * diffuse + 255 * spec
    const rim = Math.pow(1 - z, 2.6)
    r = r * (1 - rim) + 160 * rim; g = g * (1 - rim) + 200 * rim; b = b * (1 - rim) + 255 * rim
    out[p] = r > 255 ? 255 : r; out[p + 1] = g > 255 ? 255 : g; out[p + 2] = b > 255 ? 255 : b; out[p + 3] = 255
  }
  return out
}

/** Shade one frame into `image` (an ImageData) and put it on `ctx`. */
export function renderEarthFrame(ctx, image, normals, texture, spin) {
  shadeEarthPixels(image.data, normals, texture, spin)
  ctx.putImageData(image, 0, 0)
}

/**
 * Fallback when the texture could not be built (no 2D painting available):
 * a flat ocean texture, so the sphere still lights and rotates honestly as a
 * plain blue globe rather than failing.
 */
export function flatOceanTexture(width = 64, height = 32) {
  const data = new Uint8ClampedArray(width * height * 4)
  for (let p = 0; p < data.length; p += 4) { data[p] = 0x14; data[p + 1] = 0x45; data[p + 2] = 0x80; data[p + 3] = 255 }
  return { data, width, height }
}
