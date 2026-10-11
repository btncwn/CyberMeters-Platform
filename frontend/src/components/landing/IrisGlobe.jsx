import { useEffect, useRef } from 'react'

// Hero illustration for the public website: an eye whose pupil is a turning
// globe, with example findings surfacing as the globe turns. Everything is drawn
// in code — no image assets — and every motion stops under reduced motion.
//
// The findings are illustrative copy, never live data. The page captions the
// illustration as an example.

const TAU = Math.PI * 2

export const EXAMPLE_FINDINGS = [
  { area: 'Certificates & Trust', text: 'Certificate renews in 9 days', lat: 18, lon: 20 },
  { area: 'Email Protection', text: 'DMARC is set to monitor only', lat: -22, lon: 82 },
  { area: 'Brand Protection', text: 'Lookalike domain observed', lat: 34, lon: 150 },
  { area: 'Attack Surface', text: 'New subdomain found', lat: -8, lon: -150 },
  { area: 'Website Security', text: 'Security headers missing', lat: 42, lon: -84 },
  { area: 'Shadow IT & Unmanaged Technology', text: 'New third-party script', lat: -38, lon: -24 },
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

// Orthographic projection of a point on a sphere turned by `spin` around a
// tilted axis. Returns screen x/y and depth (z > 0 faces the viewer).
function project(lat, lon, spin, tilt, c, r) {
  const la = (lat * Math.PI) / 180
  const lo = (lon * Math.PI) / 180 + spin
  const x = Math.cos(la) * Math.sin(lo)
  const y = Math.sin(la)
  const z = Math.cos(la) * Math.cos(lo)
  const yt = y * Math.cos(tilt) - z * Math.sin(tilt)
  const zt = y * Math.sin(tilt) + z * Math.cos(tilt)
  return { x: c + x * r, y: c - yt * r, z: zt }
}

const GRATICULE = (() => {
  const lines = []
  for (let lon = 0; lon < 360; lon += 20) {
    const pts = []
    for (let lat = -90; lat <= 90; lat += 5) pts.push([lat, lon])
    lines.push(pts)
  }
  for (let lat = -60; lat <= 60; lat += 20) {
    const pts = []
    for (let lon = 0; lon <= 360; lon += 5) pts.push([lat, lon])
    lines.push(pts)
  }
  return lines
})()

const NODES = (() => {
  const rnd = mulberry32(8)
  return Array.from({ length: 46 }, () => [Math.asin(rnd() * 2 - 1) * (180 / Math.PI), rnd() * 360 - 180])
})()

function drawGlobe(ctx, size, globeR, spin, tilt, active, now) {
  const c = size / 2
  ctx.clearRect(0, 0, size, size)

  const body = ctx.createRadialGradient(c - globeR * 0.35, c - globeR * 0.4, globeR * 0.1, c, c, globeR)
  body.addColorStop(0, 'rgba(120,200,255,0.22)')
  body.addColorStop(0.7, 'rgba(50,110,220,0.10)')
  body.addColorStop(1, 'rgba(30,70,170,0.06)')
  ctx.fillStyle = body
  ctx.beginPath(); ctx.arc(c, c, globeR, 0, TAU); ctx.fill()

  for (const front of [false, true]) {
    ctx.beginPath()
    for (const line of GRATICULE) {
      let prev = null
      for (const [lat, lon] of line) {
        const p = project(lat, lon, spin, tilt, c, globeR)
        if (prev && (prev.z >= 0) === front && (p.z >= 0) === front) {
          ctx.moveTo(prev.x, prev.y); ctx.lineTo(p.x, p.y)
        }
        prev = p
      }
    }
    ctx.strokeStyle = front ? 'rgba(170,228,255,0.5)' : 'rgba(140,200,255,0.12)'
    ctx.lineWidth = front ? 1 : 0.8
    ctx.stroke()
  }

  ctx.strokeStyle = 'rgba(170,230,255,0.75)'
  ctx.lineWidth = 1.3
  ctx.beginPath(); ctx.arc(c, c, globeR, 0, TAU); ctx.stroke()

  ctx.fillStyle = 'rgba(200,240,255,0.85)'
  for (const [lat, lon] of NODES) {
    const p = project(lat, lon, spin, tilt, c, globeR)
    if (p.z <= 0) continue
    ctx.globalAlpha = 0.25 + p.z * 0.6
    ctx.beginPath(); ctx.arc(p.x, p.y, 1.6, 0, TAU); ctx.fill()
  }
  ctx.globalAlpha = 1

  const placed = []
  EXAMPLE_FINDINGS.forEach((f, i) => {
    const p = project(f.lat, f.lon, spin, tilt, c, globeR)
    if (p.z <= 0) return
    const on = active.includes(i)
    ctx.fillStyle = on ? '#FFC94D' : 'rgba(255,215,120,0.7)'
    ctx.beginPath(); ctx.arc(p.x, p.y, on ? 3.6 : 2.4, 0, TAU); ctx.fill()
    if (!on) return
    const phase = (now / 1400) % 1
    ctx.strokeStyle = `rgba(255,201,77,${(1 - phase) * 0.8})`
    ctx.lineWidth = 1.5
    ctx.beginPath(); ctx.arc(p.x, p.y, 4 + phase * 16, 0, TAU); ctx.stroke()
    // Leader line from the point out past the rim.
    const dx = p.x - c, dy = p.y - c
    const len = Math.hypot(dx, dy) || 1
    const reach = globeR * 1.12 + 26
    const ex = c + (dx / len) * reach
    const ey = c + (dy / len) * reach
    ctx.strokeStyle = 'rgba(255,214,120,0.75)'
    ctx.lineWidth = 1
    ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(ex, ey); ctx.stroke()
    placed.push({ i, x: ex, y: ey, left: dx < 0, z: p.z })
  })
  return placed
}

export default function IrisGlobe({ size, labels = true, className = '', style }) {
  const rootRef = useRef(null)
  const irisRef = useRef(null)
  const globeRef = useRef(null)
  const pupilRef = useRef(null)
  const irisWrapRef = useRef(null)
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
    const ctx = context(globeRef.current, globeBox, 2)
    if (!ctx) return undefined
    const still = reducedMotion()
    // Small eyes show one finding at a time so labels never crowd the globe.
    const maxActive = size < 700 ? 1 : 2
    const tilt = -0.32
    let spin = 0.6
    let last = performance.now()
    let active = []
    let nextSwitch = 0
    let cursor = 0
    let pointer = { x: 0, y: 0 }
    let eased = { x: 0, y: 0 }
    let raf = 0
    let visible = true

    const pickNext = () => {
      for (let step = 0; step < EXAMPLE_FINDINGS.length; step++) {
        const i = (cursor + step) % EXAMPLE_FINDINGS.length
        const f = EXAMPLE_FINDINGS[i]
        if (project(f.lat, f.lon, spin, tilt, 0, 1).z > 0.35 && !active.includes(i)) {
          cursor = i + 1
          active = [...active, i].slice(-maxActive)
          return
        }
      }
    }

    // Labels sit at the end of their leader line; one that would leave the
    // screen is pulled back inside it (the eye can be partly off-screen).
    const place = (placed) => {
      const root = rootRef.current
      const scale = root ? root.getBoundingClientRect().width / size || 1 : 1
      labelRefs.current.forEach((el, i) => {
        if (!el) return
        const spot = placed.find(p => p.i === i)
        if (!spot) { el.style.opacity = '0'; return }
        el.style.opacity = String(Math.min(1, 0.2 + spot.z * 1.6))
        const base = `translate(${spot.x.toFixed(1)}px, ${spot.y.toFixed(1)}px) translate(${spot.left ? '-100%' : '0'}, -50%)`
        el.style.transform = base
        const r = el.getBoundingClientRect()
        const vw = document.documentElement.clientWidth
        const shift = r.right > vw - 12 ? vw - 12 - r.right : r.left < 12 ? 12 - r.left : 0
        if (shift) el.style.transform = `translateX(${(shift / scale).toFixed(1)}px) ${base}`
      })
    }

    const frame = (now) => {
      const dt = Math.min(64, now - last)
      last = now
      spin += dt * 0.00011
      if (now >= nextSwitch) { pickNext(); nextSwitch = now + 2600 }
      eased = { x: eased.x + (pointer.x - eased.x) * 0.06, y: eased.y + (pointer.y - eased.y) * 0.06 }
      if (pupilRef.current) pupilRef.current.style.transform = `translate3d(${(eased.x * 14).toFixed(2)}px, ${(eased.y * 14).toFixed(2)}px, 0)`
      if (irisWrapRef.current) irisWrapRef.current.style.transform = `translate3d(${(eased.x * 5).toFixed(2)}px, ${(eased.y * 5).toFixed(2)}px, 0)`
      place(drawGlobe(ctx, globeBox, globeR, spin, tilt, labels ? active : [], now))
      raf = visible && !document.hidden ? requestAnimationFrame(frame) : 0
    }

    if (still) {
      pickNext(); pickNext()
      // One still frame; placed again once the parent has positioned the eye
      // and the fonts have loaded, so labels are measured where they will stay.
      const drawStill = () => place(drawGlobe(ctx, globeBox, globeR, spin, tilt, labels ? active : [], 0))
      drawStill()
      const id = requestAnimationFrame(drawStill)
      document.fonts?.ready?.then(drawStill)
      window.addEventListener('resize', drawStill)
      return () => {
        cancelAnimationFrame(id)
        window.removeEventListener('resize', drawStill)
      }
    }

    const start = () => { if (!raf && visible && !document.hidden) { last = performance.now(); raf = requestAnimationFrame(frame) } }
    const onPointer = (e) => {
      pointer = { x: (e.clientX / window.innerWidth - 0.5) * 2, y: (e.clientY / window.innerHeight - 0.5) * 2 }
    }
    const io = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; start() })
    if (rootRef.current) io.observe(rootRef.current)
    document.addEventListener('visibilitychange', start)
    window.addEventListener('pointermove', onPointer, { passive: true })
    start()
    return () => {
      cancelAnimationFrame(raf)
      io.disconnect()
      document.removeEventListener('visibilitychange', start)
      window.removeEventListener('pointermove', onPointer)
    }
  }, [globeBox, globeR, size, labels])

  return (
    <div ref={rootRef} className={`cm-eye relative ${className}`} style={{ width: size, height: size, ...style }} aria-hidden="true">
      <div ref={irisWrapRef} className="absolute inset-0">
        <canvas ref={irisRef} className="cm-iris absolute inset-0" style={{ width: size, height: size }} />
      </div>
      <div ref={pupilRef} className="absolute inset-0">
        <canvas
          ref={globeRef}
          className="absolute"
          style={{ width: globeBox, height: globeBox, left: (size - globeBox) / 2, top: (size - globeBox) / 2 }}
        />
        <div className="absolute" style={{ width: globeBox, height: globeBox, left: (size - globeBox) / 2, top: (size - globeBox) / 2 }}>
          {labels && EXAMPLE_FINDINGS.map((f, i) => (
            <div
              key={f.text}
              ref={el => { labelRefs.current[i] = el }}
              className="cm-finding absolute left-0 top-0 whitespace-nowrap rounded-lg px-3 py-2"
              style={{ opacity: 0 }}
            >
              <span className="block text-[12px] leading-4 text-[#BFE6FF]">{f.area}</span>
              <span className="block text-[14px] leading-5 font-semibold text-white">{f.text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
