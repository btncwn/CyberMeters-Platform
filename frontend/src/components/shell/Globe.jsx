// Globe — the small decorative world in the bottom-right corner of the app
// shell (the counterpart of the workspace button bottom-left). Land is drawn
// as dots sampled from a coarse outline of the continents, with thin
// latitude/longitude lines, on a canvas. One full turn every 24 seconds;
// still when the viewer prefers reduced motion or the tab is hidden; never
// takes pointer events and is hidden from assistive technology.
import { useEffect, useRef } from 'react'

// Coarse continent outlines as [longitude, latitude] rings. Decorative only.
export const LAND_POLYGONS = Object.freeze([
  [[-168, 66], [-140, 70], [-95, 72], [-75, 62], [-55, 50], [-66, 44], [-75, 35], [-81, 25], [-97, 26], [-106, 22], [-117, 32], [-125, 40], [-124, 49], [-140, 60], [-165, 60]],
  [[-55, 60], [-20, 70], [-20, 82], [-60, 83], [-70, 76]],
  [[-80, 10], [-60, 10], [-50, 0], [-35, -8], [-40, -23], [-50, -33], [-62, -40], [-68, -52], [-75, -45], [-72, -18], [-80, -5]],
  [[-10, 36], [-9, 43], [-5, 48], [5, 52], [10, 58], [20, 70], [30, 70], [40, 66], [30, 60], [28, 55], [24, 48], [30, 45], [20, 40], [12, 38], [2, 37]],
  [[-6, 50], [2, 52], [-2, 58], [-7, 57]],
  [[-17, 15], [-17, 10], [-5, 5], [8, 4], [10, -5], [14, -20], [20, -34], [30, -30], [40, -15], [50, 10], [43, 12], [33, 32], [10, 37], [-5, 35], [-12, 27]],
  [[28, 70], [60, 72], [100, 76], [140, 72], [180, 68], [160, 60], [135, 55], [140, 42], [122, 30], [110, 20], [105, 10], [100, 5], [80, 8], [72, 20], [60, 25], [50, 30], [40, 40], [30, 45], [35, 55], [40, 66]],
  [[130, 31], [141, 36], [145, 44], [140, 45], [134, 35]],
  [[114, -22], [122, -18], [136, -12], [146, -19], [153, -28], [150, -38], [140, -38], [130, -32], [116, -35]],
  [[-180, -70], [180, -70], [180, -85], [-180, -85]],
])

function pointInPolygon(lon, lat, ring) {
  let inside = false
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i]
    const [xj, yj] = ring[j]
    const crosses = (yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi
    if (crosses) inside = !inside
  }
  return inside
}

// Land dots: a grid of [longitude, latitude] points inside the outlines, with
// the longitude step widened towards the poles so density stays even.
export function buildWorldDots(step = 4) {
  const dots = []
  for (let lat = -84; lat <= 84; lat += step) {
    const lonStep = step / Math.max(0.25, Math.cos((lat * Math.PI) / 180))
    for (let lon = -180; lon < 180; lon += lonStep) {
      if (LAND_POLYGONS.some((ring) => pointInPolygon(lon, lat, ring))) dots.push([lon, lat])
    }
  }
  return dots
}

export const worldDots = buildWorldDots()

const TILT = (22 * Math.PI) / 180
export const ROTATION_PERIOD_MS = 24000

// Orthographic projection of a lon/lat point for a globe rotated by `spin`.
function project(lonDeg, latDeg, spin) {
  const lon = (lonDeg * Math.PI) / 180 + spin
  const lat = (latDeg * Math.PI) / 180
  const x = Math.cos(lat) * Math.sin(lon)
  const y = Math.sin(lat)
  const z = Math.cos(lat) * Math.cos(lon)
  // Tilt the axis towards the viewer.
  const y2 = y * Math.cos(TILT) - z * Math.sin(TILT)
  const z2 = y * Math.sin(TILT) + z * Math.cos(TILT)
  return { x, y: y2, z: z2 }
}

export function drawGlobe(ctx, size, spin, { ink = '#0d2a62' } = {}) {
  const r = size / 2 - 2
  const cx = size / 2
  const cy = size / 2
  ctx.clearRect(0, 0, size, size)
  ctx.lineWidth = 0.6
  ctx.strokeStyle = ink
  ctx.fillStyle = ink

  // Outline
  ctx.globalAlpha = 0.45
  ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke()

  // Graticule — latitude rings every 30°, meridians every 30°, front half only.
  ctx.globalAlpha = 0.3
  for (let lat = -60; lat <= 60; lat += 30) {
    ctx.beginPath(); let pen = false
    for (let lon = -180; lon <= 180; lon += 3) {
      const p = project(lon, lat, spin)
      if (p.z < 0) { pen = false; continue }
      const px = cx + p.x * r; const py = cy - p.y * r
      if (pen) ctx.lineTo(px, py); else { ctx.moveTo(px, py); pen = true }
    }
    ctx.stroke()
  }
  for (let lon = -180; lon < 180; lon += 30) {
    ctx.beginPath(); let pen = false
    for (let lat = -90; lat <= 90; lat += 3) {
      const p = project(lon, lat, spin)
      if (p.z < 0) { pen = false; continue }
      const px = cx + p.x * r; const py = cy - p.y * r
      if (pen) ctx.lineTo(px, py); else { ctx.moveTo(px, py); pen = true }
    }
    ctx.stroke()
  }

  // Land dots — the front hemisphere, faded towards the limb.
  for (const [lon, lat] of worldDots) {
    const p = project(lon, lat, spin)
    if (p.z <= 0.02) continue
    ctx.globalAlpha = 0.35 + 0.65 * p.z
    ctx.beginPath()
    ctx.arc(cx + p.x * r, cy - p.y * r, 0.95, 0, Math.PI * 2)
    ctx.fill()
  }
  ctx.globalAlpha = 1
}

export default function Globe({ size = 110, className = '' }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas && typeof canvas.getContext === 'function' ? canvas.getContext('2d') : null
    if (!ctx) return undefined
    const dpr = Math.min(2, (typeof window !== 'undefined' && window.devicePixelRatio) || 1)
    canvas.width = size * dpr
    canvas.height = size * dpr
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    const media = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)')
      : null
    let frame = 0
    let running = false
    const start = typeof performance !== 'undefined' ? performance.now() : Date.now()

    const tick = (now) => {
      const t = ((now - start) % ROTATION_PERIOD_MS) / ROTATION_PERIOD_MS
      drawGlobe(ctx, size, t * Math.PI * 2)
      frame = window.requestAnimationFrame(tick)
    }
    const stop = () => { if (running) { window.cancelAnimationFrame(frame); running = false } }
    const sync = () => {
      const still = (media && media.matches) || document.hidden
      if (still) { stop(); drawGlobe(ctx, size, 0); return }
      if (!running && typeof window.requestAnimationFrame === 'function') { running = true; frame = window.requestAnimationFrame(tick) }
      else if (!running) drawGlobe(ctx, size, 0)
    }
    sync()
    media?.addEventListener?.('change', sync)
    document.addEventListener('visibilitychange', sync)
    return () => {
      stop()
      media?.removeEventListener?.('change', sync)
      document.removeEventListener('visibilitychange', sync)
    }
  }, [size])

  return (
    <div className={`cm-globe ${className}`} aria-hidden="true" data-testid="shell-globe" style={{ width: size, height: size }}>
      <canvas ref={canvasRef} style={{ width: size, height: size, display: 'block' }} />
    </div>
  )
}
