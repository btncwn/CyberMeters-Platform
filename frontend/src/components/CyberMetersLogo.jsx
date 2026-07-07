/**
 * CyberMetersLogo
 *
 * The approved CyberMeters brand mark: static metallic brackets framing a
 * gradient risk-indicator needle.
 *
 * Props:
 *   size        {number}  Height of the mark in px (default 32). Width is derived.
 *   showWordmark{bool}    Render "CyberMeters" wordmark beside the mark (default false).
 *   animated    {bool}    Animate the needle. Uses CSS class cm-needle-animated defined
 *                         in index.css (default false). Static on PDF/email/exports.
 *   spacing     {string}  Bracket spacing variant (default 'wide' — approved for production):
 *                           'wide'     — Variant B, increased separation '<  /  >'.
 *                           'balanced' — Variant A, moderate spacing.
 *                         Geometry is derived from SPACING_PRESETS (see below), so the
 *                         spacing can be re-tuned later by editing numbers — no markup
 *                         changes. Stroke, 45° bracket angle, needle tilt, colors and the
 *                         32px canvas are unchanged — this is a spacing/geometry refinement.
 *   darkMode    {bool}    Lighten the brackets for dark backgrounds (default false).
 *   className   {string}  Extra class on the root element.
 *
 * Animation note:
 *   The animated <g> uses className="cm-needle-animated" — NOT inline transformOrigin.
 *   Inline px-based transformOrigin is broken for non-32 sizes because it operates in
 *   CSS pixel space, not SVG viewBox units. The CSS class uses transform-box:fill-box
 *   so transform-origin:center always resolves to the needle's own bounding-box center
 *   (SVG point 20,16) regardless of the rendered CSS size.
 *
 * Usage:
 *   <CyberMetersLogo size={36} showWordmark animated />  // navbar
 *   <CyberMetersLogo size={48} showWordmark animated />  // auth pages
 *   <CyberMetersLogo size={64} showWordmark animated />  // hero
 */
import { useId } from 'react'

// ── Bracket geometry ─────────────────────────────────────────────────────────
//
// Geometry is derived from three tunable numbers, NOT hard-coded point strings,
// so the spacing can be nudged later (e.g. a midpoint between A and B) by editing
// one value — without touching the SVG markup.
//
//   armOffset  — horizontal distance from canvas centre (16) to the open arm-ends.
//                Larger = more separation between the brackets and the needle.
//   depth      — horizontal distance from the arm-ends to the bracket tip.
//   halfHeight — vertical distance from centre to each arm-end.
//
// Keeping depth === halfHeight preserves the original 45° bracket angle. The
// 3.5 stroke and −9° needle are fixed by spec. The canvas is wider than it is
// tall (40 × 32) so the brackets sit well apart from the needle: with armOffset
// 9.5 the 'wide' tips land at x 2.5 / 37.5 (miter tip ≈ 0.03 / 39.97), the same
// edge treatment the original had on its 32-wide canvas — just twice the gap.
const SPACING_PRESETS = {
  balanced: { armOffset: 7.5, depth: 8, halfHeight: 8 }, // moderate separation
  wide:     { armOffset: 9.5, depth: 8, halfHeight: 8 }, // production — '<' and '>' well apart
  // Raise armOffset to push the brackets further apart (tips stay on-canvas up to ~10.5).
}

// Canvas: 40 wide × 32 tall. Centre is (20, 16); the extra width is what lets the
// two brackets separate from the needle without the tips overflowing.
const CENTER_X = 20
const CENTER_Y = 16
const CANVAS_W = 40
const CANVAS_H = 32

function buildBracketPoints({ armOffset, depth, halfHeight }) {
  const round = (n) => Number(n.toFixed(2))
  const top = round(CENTER_Y - halfHeight)
  const bot = round(CENTER_Y + halfHeight)
  const lArm = round(CENTER_X - armOffset)
  const lTip = round(CENTER_X - armOffset - depth)
  const rArm = round(CENTER_X + armOffset)
  const rTip = round(CENTER_X + armOffset + depth)
  return {
    // "<" opens right toward the needle; "armTop  tip  armBottom"
    left:  `${lArm},${top} ${lTip},${CENTER_Y} ${lArm},${bot}`,
    right: `${rArm},${top} ${rTip},${CENTER_Y} ${rArm},${bot}`,
  }
}

export default function CyberMetersLogo({
  size = 32,
  showWordmark = false,
  animated = false,
  spacing = 'wide',
  darkMode = false,
  className = '',
}) {
  // Unique gradient ID — prevents conflicts when multiple instances are on the page.
  const uid = useId().replace(/:/g, '')
  const gradId = `cmg-${uid}`

  // Bracket color. Lightens on dark backgrounds so the graphite brackets stay legible.
  const bracketColor = darkMode ? '#E5E9F0' : '#2B3440'

  const bracket = buildBracketPoints(SPACING_PRESETS[spacing] || SPACING_PRESETS.wide)

  const mark = (
    <svg
      viewBox="0 0 40 32"
      width={Math.round((size * CANVAS_W) / CANVAS_H)}
      height={size}
      fill="none"
      aria-hidden={showWordmark ? true : undefined}
      aria-label={showWordmark ? undefined : 'CyberMeters'}
      role={showWordmark ? undefined : 'img'}
      style={{ flexShrink: 0, display: 'block' }}
    >
      <defs>
        {/* Gradient: green (bottom / low risk) → red (top / critical risk).
            Distribution per brand spec: 0–51% greenish, 51–64% yellowish,
            64–100% orange/red. y1=1→y2=0 maps offset 0% to the bottom. */}
        <linearGradient id={gradId} x1="0.5" y1="1" x2="0.5" y2="0">
          <stop offset="0%"   stopColor="#00C389" />
          <stop offset="51%"  stopColor="#59D98E" />
          <stop offset="58%"  stopColor="#EBC547" />
          <stop offset="64%"  stopColor="#FBA94A" />
          <stop offset="82%"  stopColor="#FF9F43" />
          <stop offset="100%" stopColor="#FF5A5F" />
        </linearGradient>
      </defs>

      {/* Left bracket — static, square ends, metallic graphite */}
      <polyline
        points={bracket.left}
        stroke={bracketColor}
        strokeWidth="3.5"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />

      {/* Right bracket — static */}
      <polyline
        points={bracket.right}
        stroke={bracketColor}
        strokeWidth="3.5"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />

      {/*
        Needle — the only colored/animated element.
        Static:  SVG transform attribute (reliable, no CSS dependency).
        Animated: className="cm-needle-animated" — see index.css.
                  Must NOT use inline transformOrigin in CSS px: that value is in
                  rendered CSS pixels, which differs from SVG viewBox units at every
                  size except 32. transform-box:fill-box in the CSS class fixes this.
      */}
      <g
        transform={!animated ? 'rotate(-9, 20, 16)' : undefined}
        className={animated ? 'cm-needle-animated' : undefined}
      >
        <rect
          x="18.5"
          y="1"
          width="3"
          height="30"
          rx="0"
          fill={`url(#${gradId})`}
        />
      </g>
    </svg>
  )

  if (!showWordmark) {
    return className ? <span className={className}>{mark}</span> : mark
  }

  // Font size tracks with mark size so the wordmark stays proportional.
  const wordmarkSize = Math.round(size * 0.50)
  const subSize      = Math.round(size * 0.28)

  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      {mark}
      <span className="leading-none select-none">
        <span
          className="font-semibold text-gray-900 tracking-tight block"
          style={{ fontSize: wordmarkSize }}
        >
          CyberMeters
        </span>
        {size >= 36 && (
          <span
            className="font-semibold text-brand-600 tracking-widest uppercase block"
            style={{ fontSize: subSize, marginTop: 2 }}
          >
            Platform
          </span>
        )}
      </span>
    </span>
  )
}
