import { useEffect, useRef } from 'react'
import { landVectors } from './worldDots'

// Hero illustration for the public website: an eye whose pupil is a turning
// globe — continents, major cities and the routes between them — with example
// findings surfacing as it turns. With a mouse, the eye darts towards the
// pointer, flinches and glitches when a finding appears, and shudders while the
// page scrolls. On phones and tablets it stays calm instead: it keeps looking
// at the viewer as the device tilts, and looks at wherever the screen is
// touched. Everything is drawn in code and every motion stops under reduced
// motion. Only the illustration moves; page text and forms never do.
//
// The findings are illustrative copy, never live data. The page captions the
// illustration as an example.

const TAU = Math.PI * 2

export const EXAMPLE_FINDINGS = [
  { area: 'Certificates & Trust', text: 'Certificate renews in 9 days', lat: 47, lon: 8 },
  { area: 'Email Protection', text: 'DMARC is set to monitor only', lat: 38, lon: -96 },
  { area: 'Brand Protection', text: 'Lookalike domain observed', lat: 22, lon: 79 },
  { area: 'Attack Surface', text: 'New subdomain found', lat: 34, lon: 106 },
  { area: 'Website Security', text: 'Security headers missing', lat: -11, lon: -55 },
  { area: 'Shadow IT & Unmanaged Technology', text: 'New third-party script', lat: 8, lon: 20 },
]

export const CITIES = [
  ['London', 51.51, -0.13], ['Paris', 48.86, 2.35], ['Berlin', 52.52, 13.41],
  ['Istanbul', 41.01, 28.98], ['Moscow', 55.76, 37.62], ['Cairo', 30.04, 31.24],
  ['Lagos', 6.52, 3.38], ['Nairobi', -1.29, 36.82], ['Johannesburg', -26.2, 28.05],
  ['Dubai', 25.2, 55.27], ['Mumbai', 19.08, 72.88], ['Singapore', 1.35, 103.82],
  ['Jakarta', -6.21, 106.85], ['Shanghai', 31.23, 121.47], ['Seoul', 37.57, 126.98],
  ['Tokyo', 35.68, 139.65], ['Sydney', -33.87, 151.21], ['San Francisco', 37.77, -122.42],
  ['Los Angeles', 34.05, -118.24], ['Mexico City', 19.43, -99.13], ['Toronto', 43.65, -79.38],
  ['New York', 40.71, -74.01], ['São Paulo', -23.55, -46.63], ['Buenos Aires', -34.6, -58.38],
]

const ROUTES = [
  ['London', 'New York'], ['New York', 'São Paulo'], ['London', 'Istanbul'], ['Istanbul', 'Dubai'],
  ['Dubai', 'Mumbai'], ['Mumbai', 'Singapore'], ['Singapore', 'Tokyo'], ['Tokyo', 'San Francisco'],
  ['San Francisco', 'New York'], ['London', 'Lagos'], ['Lagos', 'Johannesburg'], ['Paris', 'Cairo'],
  ['Moscow', 'Shanghai'], ['Singapore', 'Sydney'], ['Berlin', 'Moscow'], ['Toronto', 'London'],
  ['Mexico City', 'Los Angeles'], ['Nairobi', 'Dubai'], ['Seoul', 'Shanghai'], ['São Paulo', 'Lagos'],
]

// Small deterministic generator so the iris looks the same on every load.
function mulberry32(seed) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6D2B79F5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const reducedMotion = () => Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches)
// Phones and tablets: a touch screen is the main input and nothing hovers.
const touchScreen = () => Boolean(window.matchMedia?.('(hover: none) and (pointer: coarse)').matches)
const clamp1 = v => Math.max(-1, Math.min(1, v))

function context(canvas, cssSize, maxDpr) {
  const ctx = canvas?.getContext?.('2d')
  if (!ctx) return null
  const dpr = Math.min(window.devicePixelRatio || 1, maxDpr)
  canvas.width = Math.round(cssSize * dpr)
  canvas.height = Math.round(cssSize * dpr)
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  return ctx
}

const polar = (c, r, a) => [c + Math.cos(a) * r, c + Math.sin(a) * r]

// Iris fibres radiate from the pupil edge, sweep a little, and fade outwards.
// Additive blending makes overlapping fibres glow.
export function paintIris(canvas, size) {
  const ctx = context(canvas, size, 1.5)
  if (!ctx) return false
  const c = size / 2
  const R = size / 2
  const rnd = mulberry32(20261011)

  // A deeper iris disc under the fibres so they read as light on a lighter page.
  const disc = ctx.createRadialGradient(c, c, R * 0.33, c, c, R * 0.97)
  disc.addColorStop(0, 'rgba(6,22,78,0.62)')
  disc.addColorStop(0.45, 'rgba(10,34,104,0.38)')
  disc.addColorStop(0.8, 'rgba(14,44,124,0.14)')
  disc.addColorStop(1, 'rgba(14,44,124,0)')
  ctx.fillStyle = disc
  ctx.beginPath(); ctx.arc(c, c, R, 0, TAU); ctx.fill()

  ctx.globalCompositeOperation = 'lighter'
  ctx.lineCap = 'round'
  const fibres = size > 700 ? 3600 : 2200
  for (let i = 0; i < fibres; i++) {
    const a = rnd() * TAU
    const r0 = R * (0.355 + rnd() * 0.05)
    const reach = Math.pow(rnd(), 0.6)
    const r1 = R * (0.47 + reach * 0.5)
    const sweep = (rnd() - 0.5) * 0.55
    const mid = 0.45 + rnd() * 0.15
    const [x0, y0] = polar(c, r0, a)
    const [xm, ym] = polar(c, r0 + (r1 - r0) * mid, a + sweep * 0.45 + (rnd() - 0.5) * 0.04)
    const [x1, y1] = polar(c, r1, a + sweep)
    const pick = rnd()
    const hue = pick < 0.62 ? 190 + rnd() * 12 : pick < 0.94 ? 208 + rnd() * 14 : 250 + rnd() * 16
    const light = 48 + rnd() * 24
    const alpha = (0.07 + rnd() * 0.17) * (1 - reach * 0.55)
    ctx.strokeStyle = `hsla(${hue.toFixed(0)},100%,${light.toFixed(0)}%,${alpha.toFixed(3)})`
    ctx.lineWidth = 0.5 + rnd() * 1.2
    ctx.beginPath(); ctx.moveTo(x0, y0); ctx.quadraticCurveTo(xm, ym, x1, y1); ctx.stroke()
  }

  // Bright collarette just outside the pupil.
  for (let i = 0; i < fibres * 0.4; i++) {
    const a = rnd() * TAU
    const r0 = R * (0.36 + rnd() * 0.01)
    const r1 = r0 + R * (0.03 + rnd() * 0.1)
    const [x0, y0] = polar(c, r0, a)
    const [x1, y1] = polar(c, r1, a + (rnd() - 0.5) * 0.06)
    ctx.strokeStyle = `hsla(${(190 + rnd() * 20).toFixed(0)},100%,${(72 + rnd() * 20).toFixed(0)}%,${(0.08 + rnd() * 0.2).toFixed(3)})`
    ctx.lineWidth = 0.6 + rnd() * 0.9
    ctx.beginPath(); ctx.moveTo(x0, y0); ctx.lineTo(x1, y1); ctx.stroke()
  }

  // Fine tick ring on the pupil edge.
  ctx.strokeStyle = 'rgba(150,225,255,0.45)'
  ctx.lineWidth = 1
  for (let i = 0; i < 180; i++) {
    const a = (i / 180) * TAU
    const [x0, y0] = polar(c, R * 0.338, a)
    const [x1, y1] = polar(c, R * (i % 5 === 0 ? 0.354 : 0.347), a)
    ctx.beginPath(); ctx.moveTo(x0, y0); ctx.lineTo(x1, y1); ctx.stroke()
  }

  ctx.globalCompositeOperation = 'source-over'
  const pupil = ctx.createRadialGradient(c, c, 0, c, c, R * 0.34)
  pupil.addColorStop(0, '#0C1E4C')
  pupil.addColorStop(0.85, '#091840')
  pupil.addColorStop(1, '#0A1B46')
  ctx.fillStyle = pupil
  ctx.beginPath(); ctx.arc(c, c, R * 0.334, 0, TAU); ctx.fill()
  return true
}

// Unit vector for a latitude/longitude, on the globe's axes.
function vec(lat, lon, k = 1) {
  const la = (lat * Math.PI) / 180
  const lo = (lon * Math.PI) / 180
  return [Math.cos(la) * Math.sin(lo) * k, Math.sin(la) * k, Math.cos(la) * Math.cos(lo) * k]
}

// Great-circle route lifted off the surface so it reads as a link above the map.
function route(a, b, steps = 28) {
  const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))
  const omega = Math.acos(dot)
  const s = Math.sin(omega) || 1
  const lift = 0.05 + 0.16 * (omega / Math.PI)
  const pts = []
  for (let i = 0; i <= steps; i++) {
    const t = i / steps
    const w1 = Math.sin((1 - t) * omega) / s
    const w2 = Math.sin(t * omega) / s
    const k = 1 + lift * Math.sin(Math.PI * t)
    pts.push([(a[0] * w1 + b[0] * w2) * k, (a[1] * w1 + b[1] * w2) * k, (a[2] * w1 + b[2] * w2) * k])
  }
  return pts
}

const GRATICULE = (() => {
  const lines = []
  for (let lon = 0; lon < 360; lon += 30) {
    const pts = []
    for (let lat = -90; lat <= 90; lat += 6) pts.push(vec(lat, lon))
    lines.push(pts)
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const pts = []
    for (let lon = 0; lon <= 360; lon += 6) pts.push(vec(lat, lon))
    lines.push(pts)
  }
  return lines
})()

function buildScene() {
  const byName = Object.fromEntries(CITIES.map(([name, lat, lon]) => [name, vec(lat, lon)]))
  return {
    land: landVectors(),
    cities: CITIES.map(([name, lat, lon]) => ({ name, v: vec(lat, lon) })),
    routes: ROUTES.map(([a, b], i) => ({ pts: route(byName[a], byName[b]), dur: 2600 + (i % 5) * 700, phase: (i * 0.137) % 1 })),
    findings: EXAMPLE_FINDINGS.map(f => vec(f.lat, f.lon)),
    labelWidths: new Map(),
  }
}

// Rotation for one frame: spin about the polar axis, then tilt towards the viewer.
function rotator(spin, tilt, c, R) {
  const cs = Math.cos(spin), sn = Math.sin(spin), ct = Math.cos(tilt), st = Math.sin(tilt)
  return (v) => {
    const xr = v[0] * cs + v[2] * sn
    const zr = v[2] * cs - v[0] * sn
    const yt = v[1] * ct - zr * st
    const zt = v[1] * st + zr * ct
    // Visible when facing the viewer, or lifted clear of the globe's silhouette.
    return { x: c + xr * R, y: c - yt * R, z: zt, vis: zt >= 0 || xr * xr + yt * yt > 1 }
  }
}

function drawGlobe(ctx, canvas, box, R, spin, tilt, active, now, fx, scene) {
  const c = box / 2
  const rot = rotator(spin, tilt, c, R)
  ctx.clearRect(0, 0, box, box)

  const body = ctx.createRadialGradient(c - R * 0.35, c - R * 0.4, R * 0.1, c, c, R)
  body.addColorStop(0, 'rgba(120,200,255,0.20)')
  body.addColorStop(0.7, 'rgba(50,110,220,0.09)')
  body.addColorStop(1, 'rgba(30,70,170,0.05)')
  ctx.fillStyle = body
  ctx.beginPath(); ctx.arc(c, c, R, 0, TAU); ctx.fill()

  for (const front of [false, true]) {
    ctx.beginPath()
    for (const line of GRATICULE) {
      let prev = null
      for (const v of line) {
        const p = rot(v)
        if (prev && (prev.z >= 0) === front && (p.z >= 0) === front) { ctx.moveTo(prev.x, prev.y); ctx.lineTo(p.x, p.y) }
        prev = p
      }
    }
    ctx.strokeStyle = front ? 'rgba(170,228,255,0.22)' : 'rgba(140,200,255,0.06)'
    ctx.lineWidth = 0.8
    ctx.stroke()
  }

  // Continents as a dot matrix, brighter towards the centre of the globe.
  const cs = Math.cos(spin), sn = Math.sin(spin), ct = Math.cos(tilt), st = Math.sin(tilt)
  const land = scene.land
  const step = 3 * fx.stride
  const d = Math.max(1.3, R / 95)
  const paths = typeof Path2D === 'function' ? [new Path2D(), new Path2D(), new Path2D(), new Path2D()] : null
  if (paths) {
    for (let i = 0; i < land.length; i += step) {
      const x = land[i], y = land[i + 1], z = land[i + 2]
      const xr = x * cs + z * sn
      const zr = z * cs - x * sn
      const zt = y * st + zr * ct
      if (zt <= 0.03) continue
      const yt = y * ct - zr * st
      const b = zt > 0.72 ? 3 : zt > 0.48 ? 2 : zt > 0.24 ? 1 : 0
      paths[b].rect(c + xr * R - d / 2, c - yt * R - d / 2, d, d)
    }
    const alphas = [0.2, 0.38, 0.58, 0.8]
    ctx.fillStyle = '#B4E8FF'
    paths.forEach((p, b) => { ctx.globalAlpha = alphas[b]; ctx.fill(p) })
    if (fx.glitch > 0) {
      // Chromatic split while the eye flinches.
      ctx.globalCompositeOperation = 'lighter'
      const off = 8 * fx.glitch
      for (const [dx, colour] of [[off, '#FF2E6E'], [-off, '#00F0FF']]) {
        ctx.save(); ctx.translate(dx, 0); ctx.fillStyle = colour
        paths.forEach((p, b) => { ctx.globalAlpha = alphas[b] * 0.6 * fx.glitch; ctx.fill(p) })
        ctx.restore()
      }
      ctx.globalCompositeOperation = 'source-over'
    }
    ctx.globalAlpha = 1
  }

  ctx.strokeStyle = 'rgba(170,230,255,0.7)'
  ctx.lineWidth = 1.2
  ctx.beginPath(); ctx.arc(c, c, R, 0, TAU); ctx.stroke()

  // Routes between cities, with a packet travelling along each.
  ctx.strokeStyle = 'rgba(150,225,255,0.32)'
  ctx.lineWidth = 1
  ctx.beginPath()
  const projected = scene.routes.map(r => r.pts.map(rot))
  for (const pts of projected) {
    for (let i = 1; i < pts.length; i++) {
      if (pts[i - 1].vis && pts[i].vis) { ctx.moveTo(pts[i - 1].x, pts[i - 1].y); ctx.lineTo(pts[i].x, pts[i].y) }
    }
  }
  ctx.stroke()
  if (fx.packets) {
    scene.routes.forEach((r, i) => {
      const pts = projected[i]
      const t = (now / r.dur + r.phase) % 1
      const p = pts[Math.min(pts.length - 1, Math.floor(t * (pts.length - 1)))]
      if (!p.vis) return
      ctx.fillStyle = 'rgba(190,240,255,0.25)'
      ctx.beginPath(); ctx.arc(p.x, p.y, 4.2, 0, TAU); ctx.fill()
      ctx.fillStyle = '#EFFCFF'
      ctx.beginPath(); ctx.arc(p.x, p.y, 1.7, 0, TAU); ctx.fill()
    })
  }

  // Major cities. Names closest to the viewer are labelled first and a name
  // that would overlap one already drawn is left out, so labels never collide.
  ctx.font = "600 12px 'Computer Modern Text', Georgia, serif"
  const shown = scene.cities.map(city => ({ city, p: rot(city.v) })).filter(({ p }) => p.z > 0.04)
  for (const { p } of shown) {
    ctx.fillStyle = `rgba(255,236,190,${(0.45 + p.z * 0.55).toFixed(2)})`
    ctx.beginPath(); ctx.arc(p.x, p.y, 2.1, 0, TAU); ctx.fill()
    ctx.strokeStyle = `rgba(255,226,160,${(p.z * 0.35).toFixed(2)})`
    ctx.beginPath(); ctx.arc(p.x, p.y, 4.6, 0, TAU); ctx.stroke()
  }
  if (fx.cityLabels) {
    const taken = []
    const widths = scene.labelWidths
    for (const { city, p } of shown.filter(({ p }) => p.z > 0.5).sort((a, b) => b.p.z - a.p.z)) {
      if (!widths.has(city.name)) widths.set(city.name, ctx.measureText(city.name).width)
      const box = { x: p.x + 4, y: p.y - 17, w: widths.get(city.name) + 4, h: 15 }
      if (taken.some(t => box.x < t.x + t.w && t.x < box.x + box.w && box.y < t.y + t.h && t.y < box.y + box.h)) continue
      taken.push(box)
      ctx.fillStyle = `rgba(232,246,255,${Math.min(0.92, (p.z - 0.5) * 2.4).toFixed(2)})`
      ctx.fillText(city.name, p.x + 6, p.y - 5)
    }
  }

  const placed = []
  scene.findings.forEach((v, i) => {
    const p = rot(v)
    if (p.z <= 0) return
    const on = active.includes(i)
    if (!on && !fx.showFindingDots) return
    ctx.fillStyle = on ? '#FFC94D' : 'rgba(255,215,120,0.7)'
    ctx.beginPath(); ctx.arc(p.x, p.y, on ? 3.8 : 2.4, 0, TAU); ctx.fill()
    if (!on) return
    const phase = (now / 1100) % 1
    ctx.strokeStyle = `rgba(255,201,77,${((1 - phase) * 0.85).toFixed(2)})`
    ctx.lineWidth = 1.6
    ctx.beginPath(); ctx.arc(p.x, p.y, 4 + phase * 18, 0, TAU); ctx.stroke()
    // Leader line from the point out past the rim.
    const dx = p.x - c, dy = p.y - c
    const len = Math.hypot(dx, dy) || 1
    const reach = R * 1.12 + 26
    const ex = c + (dx / len) * reach
    const ey = c + (dy / len) * reach
    ctx.strokeStyle = 'rgba(255,214,120,0.8)'
    ctx.lineWidth = 1
    ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(ex, ey); ctx.stroke()
    placed.push({ i, x: ex, y: ey, left: dx < 0, z: p.z })
  })

  // Shock ring through the iris when a finding lands.
  if (fx.shock >= 0) {
    const r = R * 1.05 + (c * 0.97 - R * 1.05) * Math.sqrt(fx.shock)
    ctx.strokeStyle = `rgba(255,205,96,${((1 - fx.shock) * 0.6).toFixed(2)})`
    ctx.lineWidth = 0.6 + 2.4 * (1 - fx.shock)
    ctx.beginPath(); ctx.arc(c, c, r, 0, TAU); ctx.stroke()
  }

  // Torn scan lines while glitching.
  if (fx.glitch > 0 && canvas) {
    const dpr = canvas.width / box
    for (let k = 0; k < 4; k++) {
      const y = Math.random() * box
      const h = 2 + Math.random() * 14
      const dx = (Math.random() * 2 - 1) * 26 * fx.glitch
      ctx.drawImage(canvas, 0, Math.round(y * dpr), canvas.width, Math.max(1, Math.round(h * dpr)), dx, y, box, h)
    }
  }
  return placed
}

export default function IrisGlobe({ size, labels = true, preferRight = false, avoidRef = null, className = '', style }) {
  const rootRef = useRef(null)
  const shakeRef = useRef(null)
  const irisRef = useRef(null)
  const irisWrapRef = useRef(null)
  const globeRef = useRef(null)
  const pupilRef = useRef(null)
  const labelRefs = useRef([])

  const globeBox = Math.round(size * 0.9)
  const globeR = size * 0.5 * 0.29

  useEffect(() => {
    const iris = irisRef.current
    let cancelled = false
    const paint = () => {
      if (cancelled || !iris) return
      if (paintIris(iris, size)) iris.dataset.ready = 'true'
    }
    // Let the first paint of the page happen before the fibres are drawn.
    const id = window.requestIdleCallback ? window.requestIdleCallback(paint, { timeout: 400 }) : window.setTimeout(paint, 60)
    return () => {
      cancelled = true
      if (window.cancelIdleCallback) window.cancelIdleCallback(id)
      window.clearTimeout(id)
    }
  }, [size])

  useEffect(() => {
    const canvas = globeRef.current
    const ctx = context(canvas, globeBox, 2)
    if (!ctx) return undefined
    const scene = buildScene()
    const still = reducedMotion()
    // Phones and tablets get a calm eye: no shaking, glitching or twitching.
    const calm = touchScreen()
    const baseTilt = 0.42
    let tilt = baseTilt
    const maxActive = size < 700 ? 1 : 2
    const maxGaze = size * 0.05
    const baseFx = { stride: globeR < 100 ? 2 : 1, cityLabels: globeR >= 110, showFindingDots: labels }
    let spin = 0.35
    // The world turns towards the pointer: horizontal movement spins it,
    // vertical movement tilts it, and a quick flick adds momentum.
    let spinOff = 0, tiltOff = 0, spinOffTarget = 0, tiltOffTarget = 0, flick = 0
    let lastPointerX = null
    let last = performance.now()
    let active = []
    const activatedAt = {}
    let cursor = 0
    let nextSwitch = 0
    let raf = 0
    let visible = true

    // Gaze: quick saccades with a little overshoot, towards the pointer when it moves.
    const gaze = { x: 0, y: 0, vx: 0, vy: 0, tx: 0, ty: 0 }
    let nextSaccade = 0
    let pointerAt = -1e9
    let pointerDir = { x: 0, y: 0 }
    let flinchAt = -1e9
    let twitchAt = -1e9
    let twitchDir = 1
    let nextTwitch = last + 4000
    let scrollEnergy = 0
    let extraRot = 0
    let lastScroll = window.scrollY
    let lastScrollAt = last
    // Calm mode: where the screen was last touched, and how the device is tilted.
    let touchDir = { x: 0, y: 0 }
    let touchAt = -1e9
    let tiltDir = null
    let tiltAt = -1e9
    let tiltBase = null

    // With page text to the left of the eye, findings on the right half of the
    // globe are preferred so their labels open away from the text.
    const pickNext = (now) => {
      const rot = rotator(spin + spinOff, tilt, 0, 1)
      const order = EXAMPLE_FINDINGS.map((_, step) => (cursor + step) % EXAMPLE_FINDINGS.length)
      const ready = order.filter(i => rot(scene.findings[i]).z > 0.35 && !active.includes(i))
      const right = preferRight ? ready.find(i => rot(scene.findings[i]).x > 0.05) : undefined
      const i = right ?? ready[0]
      if (i === undefined) return
      cursor = i + 1
      active = [...active, i].slice(-maxActive)
      activatedAt[i] = now
      flinchAt = now
    }

    // Labels sit at the end of their leader line; one that would leave the
    // screen is pulled back inside it (the eye can be partly off-screen).
    const place = (placed, now) => {
      const root = rootRef.current
      const scale = root ? root.getBoundingClientRect().width / size || 1 : 1
      const avoid = avoidRef?.current?.getBoundingClientRect()
      const taken = []
      labelRefs.current.forEach((el, i) => {
        if (!el) return
        const spot = placed.find(p => p.i === i)
        if (!spot) { el.style.opacity = '0'; return }
        const age = calm ? 1e9 : now - (activatedAt[i] ?? -1e9)
        const flicker = age < 260 ? [1, 0.1, 0.9, 0.2, 1, 0.5][Math.floor(age / 45)] ?? 1 : 1
        // The fade is switched off while a new label flickers in.
        el.style.transition = age < 260 ? 'none' : ''
        el.style.opacity = String(Math.min(1, 0.2 + spot.z * 1.6) * flicker)
        const jitter = age < 260 ? (Math.random() * 2 - 1) * 6 : 0
        const base = `translate(${(spot.x + jitter).toFixed(1)}px, ${spot.y.toFixed(1)}px) translate(${spot.left ? '-100%' : '0'}, -50%)`
        el.style.transform = base
        const r = el.getBoundingClientRect()
        const vw = document.documentElement.clientWidth
        let shift = r.right > vw - 12 ? vw - 12 - r.right : r.left < 12 ? 12 - r.left : 0
        // Never cover the page text: move clear of it, or hide when there is no room.
        if (avoid && r.left + shift < avoid.right + 12 && r.bottom > avoid.top && r.top < avoid.bottom) {
          shift = avoid.right + 16 - r.left
          if (r.right + shift > vw - 12) el.style.opacity = '0'
        }
        // Two labels never stack on top of each other: the later one moves below.
        const box = { left: r.left + shift, right: r.right + shift, top: r.top, bottom: r.bottom }
        const clash = taken.find(t => box.left < t.right && t.left < box.right && box.top < t.bottom + 6 && t.top < box.bottom + 6)
        const drop = clash ? clash.bottom + 8 - box.top : 0
        taken.push({ ...box, top: box.top + drop, bottom: box.bottom + drop })
        if (shift || drop) el.style.transform = `translate(${(shift / scale).toFixed(1)}px, ${(drop / scale).toFixed(1)}px) ${base}`
      })
    }

    const draw = (now, fx) => place(drawGlobe(ctx, canvas, globeBox, globeR, spin + spinOff, tilt, labels ? active : [], now, { ...baseFx, ...fx }, scene), now)

    if (still) {
      pickNext(-1e9); pickNext(-1e9)
      // One still frame; placed again once the parent has positioned the eye
      // and the fonts have loaded, so labels are measured where they will stay.
      const drawStill = () => draw(0, { glitch: 0, shock: -1, packets: false })
      drawStill()
      const id = requestAnimationFrame(drawStill)
      document.fonts?.ready?.then(drawStill)
      window.addEventListener('resize', drawStill)
      return () => {
        cancelAnimationFrame(id)
        window.removeEventListener('resize', drawStill)
      }
    }

    // Calm frame for touch screens. The pupil looks where the screen was just
    // touched; otherwise it keeps looking at the viewer as the device tilts,
    // like an eye holding someone's gaze while its head moves.
    const calmFrame = (now) => {
      const dt = Math.min(64, now - last)
      last = now
      const touching = now - touchAt < 1800
      const tilting = tiltDir && now - tiltAt < 1200
      const target = touching ? touchDir : tilting ? tiltDir : { x: 0, y: 0 }
      // Turn the world towards where the eye is looking; settle back when idle.
      spinOffTarget = target.x * 0.9
      tiltOffTarget = Math.max(-0.4, Math.min(0.4, target.y * 0.4))
      spinOff += (spinOffTarget - spinOff) * Math.min(1, dt * 0.004)
      tiltOff += (tiltOffTarget - tiltOff) * Math.min(1, dt * 0.004)
      spin += dt * 0.00011
      tilt = baseTilt + tiltOff
      if (now >= nextSwitch) { pickNext(now); nextSwitch = now + 2600 }
      // Smooth pursuit, no darting.
      const follow = Math.min(1, dt * (touching ? 0.012 : 0.006))
      gaze.x += (target.x * maxGaze - gaze.x) * follow
      gaze.y += (target.y * maxGaze - gaze.y) * follow
      // The iris travels most of the way with the pupil, so the globe always
      // stays inside the pupil.
      if (irisWrapRef.current) irisWrapRef.current.style.transform = `translate3d(${(gaze.x * 0.7).toFixed(2)}px, ${(gaze.y * 0.7).toFixed(2)}px, 0)`
      if (pupilRef.current) pupilRef.current.style.transform = `translate3d(${gaze.x.toFixed(2)}px, ${gaze.y.toFixed(2)}px, 0)`
      const sp = (now - flinchAt) / 820
      draw(now, { glitch: 0, shock: sp < 1 ? sp : -1, packets: true })
      raf = visible && !document.hidden ? requestAnimationFrame(calmFrame) : 0
    }

    const frame = (now) => {
      const dt = Math.min(64, now - last)
      last = now
      scrollEnergy *= Math.pow(0.9, dt / 16)
      spinOff += (spinOffTarget - spinOff) * Math.min(1, dt * 0.006)
      tiltOff += (tiltOffTarget - tiltOff) * Math.min(1, dt * 0.006)
      flick *= Math.pow(0.93, dt / 16)
      spin += dt * (0.00011 + scrollEnergy * 0.0014) + flick * dt
      tilt = baseTilt + tiltOff
      extraRot += dt * scrollEnergy * 0.06

      if (now >= nextSwitch) { pickNext(now); nextSwitch = now + 2600 }

      // Saccades: hold, then snap to a new point — at the visitor when they move.
      const watching = now - pointerAt < 1600
      if (now >= nextSaccade) {
        if (watching) {
          gaze.tx = (pointerDir.x + (Math.random() - 0.5) * 0.25) * maxGaze
          gaze.ty = (pointerDir.y + (Math.random() - 0.5) * 0.25) * maxGaze
        } else {
          const a = Math.random() * TAU
          const m = Math.sqrt(Math.random()) * maxGaze
          gaze.tx = Math.cos(a) * m
          gaze.ty = Math.sin(a) * m
        }
        nextSaccade = now + (watching ? 380 + Math.random() * 700 : 650 + Math.random() * 2100)
      }
      gaze.vx = gaze.vx * 0.48 + (gaze.tx - gaze.x) * 0.38
      gaze.vy = gaze.vy * 0.48 + (gaze.ty - gaze.y) * 0.38
      gaze.x += gaze.vx
      gaze.y += gaze.vy

      // Flinch when a finding lands: shake, pupil constriction, glitch, shock ring.
      const fp = (now - flinchAt) / 620
      let shakeX = 0, shakeY = 0, constrict = 1
      if (fp < 1) {
        // A hard jolt, then a smaller aftershock as it settles.
        const amp = 22 * (1 - fp) * (1 - fp) + (fp > 0.38 && fp < 0.5 ? 9 : 0)
        shakeX = (Math.random() * 2 - 1) * amp
        shakeY = (Math.random() * 2 - 1) * amp * 0.65
        constrict = 1 - 0.22 * Math.sin(Math.PI * Math.min(1, fp * 1.4))
      }
      const gp = (now - flinchAt) / 270
      const glitch = gp < 1 ? 1 - gp : 0
      const sp = (now - flinchAt) / 820
      const shock = sp < 1 ? sp : -1

      // Scrolling makes the eye shudder and the world spin faster.
      if (scrollEnergy > 0.02) {
        shakeX += (Math.random() * 2 - 1) * 26 * scrollEnergy
        shakeY += (Math.random() * 2 - 1) * 16 * scrollEnergy
      }

      // An occasional twitch of the iris.
      if (now >= nextTwitch) { twitchAt = now; twitchDir = Math.random() < 0.5 ? -1 : 1; nextTwitch = now + 4500 + Math.random() * 4500 }
      const tp = (now - twitchAt) / 900
      const twitch = tp < 1 ? twitchDir * 9 * (tp < 0.06 ? tp / 0.06 : (1 - tp) / 0.94) : 0

      const gj = glitch > 0 ? (Math.random() * 2 - 1) * 16 * glitch : 0
      const gs = glitch > 0 ? (Math.random() * 2 - 1) * 10 * glitch : 0
      if (shakeRef.current) shakeRef.current.style.transform = `translate3d(${shakeX.toFixed(2)}px, ${shakeY.toFixed(2)}px, 0)`
      if (irisWrapRef.current) irisWrapRef.current.style.transform = `translate3d(${(gaze.x * 0.55 + gj).toFixed(2)}px, ${(gaze.y * 0.55).toFixed(2)}px, 0) rotate(${(twitch + extraRot).toFixed(2)}deg) skewX(${gs.toFixed(2)}deg)`
      if (pupilRef.current) pupilRef.current.style.transform = `translate3d(${gaze.x.toFixed(2)}px, ${gaze.y.toFixed(2)}px, 0) scale(${constrict.toFixed(3)})`

      draw(now, { glitch, shock, packets: true })
      raf = visible && !document.hidden ? requestAnimationFrame(frame) : 0
    }

    const start = () => { if (!raf && visible && !document.hidden) { last = performance.now(); raf = requestAnimationFrame(calm ? calmFrame : frame) } }
    // Touch: look at the point that was touched (and follow a dragging finger).
    const onTouch = (e) => {
      if (e.pointerType === 'mouse') return
      const r = rootRef.current?.getBoundingClientRect()
      if (!r) return
      const dx = e.clientX - (r.left + r.width / 2)
      const dy = e.clientY - (r.top + r.height / 2)
      const dist = Math.hypot(dx, dy) || 1
      const reach = Math.min(1, dist / 160)
      touchDir = { x: (dx / dist) * reach, y: (dy / dist) * reach }
      touchAt = performance.now()
    }
    // Tilt: the angle the device is held at slowly becomes the neutral point,
    // so the eye responds to turning the phone, not to how it is held.
    const onTilt = (e) => {
      if (e.beta == null || e.gamma == null) return
      const angle = window.screen?.orientation?.angle ?? window.orientation ?? 0
      let x = e.gamma
      let y = e.beta
      if (angle === 90) { x = e.beta; y = -e.gamma } else if (angle === -90 || angle === 270) { x = -e.beta; y = e.gamma } else if (angle === 180) { x = -e.gamma; y = -e.beta }
      if (!tiltBase || Math.abs(x - tiltBase.x) > 60 || Math.abs(y - tiltBase.y) > 60) tiltBase = { x, y }
      tiltBase.x += (x - tiltBase.x) * 0.006
      tiltBase.y += (y - tiltBase.y) * 0.006
      // Turning the phone one way moves the pupil the other way, so it keeps
      // facing the viewer.
      tiltDir = { x: clamp1(-(x - tiltBase.x) / 18), y: clamp1((y - tiltBase.y) / 18) }
      tiltAt = performance.now()
    }
    // iPhone and iPad only share motion data after the visitor allows it, and
    // only in answer to a tap, so the eye asks when it is tapped — never unasked.
    let motionAsked = false
    const askForMotion = () => {
      const D = window.DeviceOrientationEvent
      if (motionAsked || typeof D?.requestPermission !== 'function') return
      motionAsked = true
      D.requestPermission().then(state => { if (state === 'granted') window.addEventListener('deviceorientation', onTilt) }).catch(() => {})
    }
    const onPointer = (e) => {
      const r = rootRef.current?.getBoundingClientRect()
      if (!r) return
      const dx = e.clientX - (r.left + r.width / 2)
      const dy = e.clientY - (r.top + r.height / 2)
      const dist = Math.hypot(dx, dy) || 1
      const reach = Math.min(1, dist / 420)
      pointerDir = { x: (dx / dist) * reach, y: (dy / dist) * reach }
      spinOffTarget = pointerDir.x * 1.1
      tiltOffTarget = Math.max(-0.5, Math.min(0.5, pointerDir.y * 0.5))
      if (lastPointerX !== null) flick = Math.max(-0.0025, Math.min(0.0025, flick + (e.clientX - lastPointerX) * 0.00003))
      lastPointerX = e.clientX
      const now = performance.now()
      if (now - pointerAt > 260) nextSaccade = Math.min(nextSaccade, now + 70)
      pointerAt = now
    }
    const onScroll = () => {
      const now = performance.now()
      const y = window.scrollY
      const v = Math.abs(y - lastScroll) / Math.max(8, now - lastScrollAt)
      lastScroll = y
      lastScrollAt = now
      scrollEnergy = Math.min(1, scrollEnergy + v * 0.18)
    }
    const io = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; start() })
    const root = rootRef.current
    if (root) io.observe(root)
    document.addEventListener('visibilitychange', start)
    if (calm) {
      window.addEventListener('pointerdown', onTouch, { passive: true })
      window.addEventListener('pointermove', onTouch, { passive: true })
      if (typeof window.DeviceOrientationEvent?.requestPermission === 'function') root?.addEventListener('click', askForMotion)
      else window.addEventListener('deviceorientation', onTilt)
    } else {
      window.addEventListener('pointermove', onPointer, { passive: true })
      window.addEventListener('scroll', onScroll, { passive: true })
    }
    start()
    return () => {
      cancelAnimationFrame(raf)
      io.disconnect()
      document.removeEventListener('visibilitychange', start)
      window.removeEventListener('pointermove', onPointer)
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('pointerdown', onTouch)
      window.removeEventListener('pointermove', onTouch)
      window.removeEventListener('deviceorientation', onTilt)
      root?.removeEventListener('click', askForMotion)
    }
  }, [globeBox, globeR, size, labels, preferRight, avoidRef])

  const offset = (size - globeBox) / 2
  return (
    <div ref={rootRef} className={`cm-eye relative ${className}`} style={{ width: size, height: size, flexShrink: 0, ...style }} aria-hidden="true">
      <div ref={shakeRef} className="absolute inset-0">
        <div ref={irisWrapRef} className="absolute inset-0">
          <canvas ref={irisRef} className="cm-iris absolute inset-0" style={{ width: size, height: size }} />
        </div>
        <div ref={pupilRef} className="absolute inset-0">
          <canvas ref={globeRef} className="absolute" style={{ width: globeBox, height: globeBox, left: offset, top: offset }} />
          <div className="absolute" style={{ width: globeBox, height: globeBox, left: offset, top: offset }}>
            {labels && EXAMPLE_FINDINGS.map((f, i) => (
              <div
                key={f.text}
                ref={el => { labelRefs.current[i] = el }}
                className="cm-finding absolute left-0 top-0 whitespace-nowrap rounded-lg px-3 py-2"
                style={{ opacity: 0 }}
              >
                <span className="block text-[13px] leading-4 text-[#BFE6FF]">{f.area}</span>
                <span className="block text-[14px] leading-5 font-semibold text-white">{f.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
