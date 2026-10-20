/**
 * CyberMetersLogo
 *
 * The approved CyberMeters brand mark (October 2026): a graphite "<" folded
 * strip (the C) beside an M drawn as a green → red risk gradient, turned 21° so
 * the C and the green side come towards the viewer and the orange/red recede.
 * Stroke 2.8 in a 45 × 32 canvas, with a subtle 3D treatment: the front strokes
 * are lit with a fine highlight and a soft cast shadow, the back strokes darken
 * toward the fold.
 *
 * Props:
 *   size        {number}  Height of the mark in px (default 32). Width is derived (45:32).
 *   showWordmark{bool}    Render "CyberMeters" wordmark beside the mark (default false).
 *                         With the wordmark the mark is aria-hidden; alone it is
 *                         role="img" with aria-label="CyberMeters".
 *   animated    {bool}    Accepted for call-site compatibility; the mark is static.
 *   spacing     {string}  Accepted for call-site compatibility; the geometry is fixed.
 *   darkMode    {bool}    Light C for dark backgrounds (default false).
 *   wordmarkColor{string}  Explicit wordmark colour (e.g. the brand amber on the app bar).
 *   wordmarkSize {number}  Explicit wordmark font size in px (default: half the mark size).
 *   subtitle    {bool}    Show the small "Platform" line under the wordmark (default true).
 *   className   {string}  Extra class on the root element.
 *
 * The polygons are the output of the approved geometry (mark(dark, size, th=-21))
 * and match public/favicon.svg. Gradient, filter and clip IDs come from useId so
 * several logos can share a page.
 *
 * Usage:
 *   <CyberMetersLogo size={30} showWordmark />            // site header
 *   <CyberMetersLogo size={48} showWordmark />            // auth pages
 *   <CyberMetersLogo size={34} />                         // app menu
 */
import { useId } from 'react'

const CANVAS_W = 45
const CANVAS_H = 32

// Band the strokes are trimmed to (the top and bottom lines, in perspective).
const CLIP = '-12.07,0.22 46.03,4.89 46.03,27.11 -12.07,31.78'
// The C: lower and upper arms of the folded strip.
const C_LOWER = '12.26,33.15 1.84,16.00 5.60,16.00 14.78,31.43'
const C_UPPER = '12.26,-1.15 1.84,16.00 5.60,16.00 14.78,0.57'
// The M: two back (down) strokes and two front (up) strokes with their highlights.
const M_BACK = [
  { key: 'k1', points: '20.90,1.84 27.46,30.25 29.81,29.38 23.45,1.39', fold: [22.50, 3.00, 28.35, 28.53] },
  { key: 'k3', points: '32.40,2.84 38.09,29.28 40.13,28.49 34.61,2.40', fold: [33.79, 3.91, 38.86, 27.68] },
]
const M_FRONT = [
  { points: '17.22,31.18 24.07,2.12 21.54,1.22 14.47,30.72', highlight: '15.53,29.88 22.00,2.78 21.54,2.62 15.03,29.79' },
  { points: '29.23,30.09 35.15,3.08 32.96,2.25 26.86,29.64', highlight: '27.78,28.87 33.36,3.70 32.96,3.56 27.35,28.79' },
]

const RISK_STOPS = [
  [0, '#00C389'], [0.45, '#59D98E'], [0.58, '#EBC547'], [0.72, '#FBA94A'], [1, '#FF5A5F'],
]

// The C's two faces and the drop-shadow strength, per background.
const TONES = {
  light: { upper: ['#6A7787', '#4E5A69'], lower: ['#26303B', '#141A21'], shadow: 0.28 },
  dark:  { upper: ['#FFFFFF', '#DCE2EA'], lower: ['#A3ADB9', '#7B8592'], shadow: 0.5 },
}

function Gradient({ id, coords: [x1, y1, x2, y2], stops }) {
  return (
    <linearGradient id={id} gradientUnits="userSpaceOnUse" x1={x1} y1={y1} x2={x2} y2={y2}>
      {stops.map(([offset, color, opacity]) => (
        <stop key={offset} offset={offset} stopColor={color} stopOpacity={opacity} />
      ))}
    </linearGradient>
  )
}

export default function CyberMetersLogo({
  size = 32,
  showWordmark = false,
  darkMode = false,
  wordmarkColor = null,
  wordmarkSize: wordmarkSizeProp = null,
  subtitle = true,
  className = '',
}) {
  // Unique IDs — prevents conflicts when multiple instances are on the page.
  const uid = useId().replace(/:/g, '')
  const id = (name) => `cm-${uid}-${name}`
  const url = (name) => `url(#${id(name)})`
  const tone = darkMode ? TONES.dark : TONES.light
  const clip = url('clip')

  const mark = (
    <svg
      viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`}
      width={Math.round((size * CANVAS_W) / CANVAS_H)}
      height={size}
      fill="none"
      aria-hidden={showWordmark ? true : undefined}
      aria-label={showWordmark ? undefined : 'CyberMeters'}
      role={showWordmark ? undefined : 'img'}
      style={{ flexShrink: 0, display: 'block' }}
      data-testid="cm-logo-mark"
    >
      <defs>
        <clipPath id={id('clip')}><polygon points={CLIP} /></clipPath>
        <filter id={id('drop')} x="-10%" y="-20%" width="120%" height="150%">
          <feDropShadow dx="0" dy="1" stdDeviation=".7" floodColor="#000" floodOpacity={tone.shadow} />
        </filter>
        <filter id={id('soft')} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation=".38" />
        </filter>
        <Gradient id={id('risk')} coords={[14.77, 16, 39.91, 16]} stops={RISK_STOPS} />
        <Gradient id={id('upper')} coords={[12.06, 2.16, 3.74, 16]} stops={[[0, tone.upper[0]], [1, tone.upper[1]]]} />
        <Gradient id={id('lower')} coords={[12.06, 29.84, 3.74, 16]} stops={[[0, tone.lower[0]], [1, tone.lower[1]]]} />
        {M_BACK.map(({ key, fold }) => (
          <Gradient key={key} id={id(key)} coords={fold} stops={[[0, '#000', 0.34], [1, '#000', 0.14]]} />
        ))}
      </defs>
      <g filter={url('drop')}>
        <polygon points={C_LOWER} fill={url('lower')} clipPath={clip} />
        <polygon points={C_UPPER} fill="#000" fillOpacity=".28" filter={url('soft')} transform="translate(.35,.55)" clipPath={clip} />
        <polygon points={C_UPPER} fill={url('upper')} clipPath={clip} />
        {M_BACK.map(({ key, points }) => (
          <g key={key}>
            <polygon points={points} fill={url('risk')} clipPath={clip} />
            <polygon points={points} fill={url(key)} clipPath={clip} />
          </g>
        ))}
        {M_FRONT.map(({ points, highlight }) => (
          <g key={points}>
            <polygon points={points} fill="#000" fillOpacity=".26" filter={url('soft')} transform="translate(.4,.6)" clipPath={clip} />
            <polygon points={points} fill={url('risk')} clipPath={clip} />
            <polygon points={highlight} fill="#fff" fillOpacity=".4" clipPath={clip} />
          </g>
        ))}
      </g>
    </svg>
  )

  if (!showWordmark) {
    return className ? <span className={className}>{mark}</span> : mark
  }

  // Font size tracks with mark size so the wordmark stays proportional.
  const wordmarkSize = wordmarkSizeProp || Math.round(size * 0.50)
  const subSize      = Math.round(size * 0.28)

  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      {mark}
      <span className="leading-none select-none">
        <span
          className={`font-semibold tracking-tight block ${darkMode ? 'text-white' : 'text-gray-900'}`}
          style={{ fontSize: wordmarkSize, color: wordmarkColor || undefined }}
        >
          CyberMeters
        </span>
        {subtitle && size >= 36 && (
          <span
            className="font-semibold text-brand-700 tracking-widest uppercase block"
            style={{ fontSize: subSize, marginTop: 2 }}
          >
            Platform
          </span>
        )}
      </span>
    </span>
  )
}
