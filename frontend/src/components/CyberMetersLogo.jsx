/**
 * CyberMetersLogo
 *
 * The approved CyberMeters brand mark: static metallic brackets framing a
 * gradient risk-indicator needle.
 *
 * Props:
 *   size        {number}  Height of the mark in px (default 32). Width is derived.
 *   showWordmark{bool}    Render "CyberMeters" wordmark beside the mark (default false).
 *   animated    {bool}    Animate the needle — MARKETING SURFACES ONLY (default false).
 *                         Requires the @keyframes cmNeedleSwing rule in index.css.
 *   className   {string}  Extra class on the root element.
 *
 * Usage:
 *   <CyberMetersLogo size={32} />                        // icon only, navbar
 *   <CyberMetersLogo size={40} showWordmark />           // full logo, auth pages
 *   <CyberMetersLogo size={64} showWordmark animated />  // homepage hero
 */
import { useId } from 'react'

export default function CyberMetersLogo({
  size = 32,
  showWordmark = false,
  animated = false,
  className = '',
}) {
  // Unique gradient ID — prevents conflicts when multiple instances are on the page.
  const uid = useId().replace(/:/g, '')
  const gradId = `cmg-${uid}`

  // Bracket color. The mark is always rendered on a light background per spec.
  // Dark mode callers should pass darkMode and the brackets lighten to remain visible.
  const bracketColor = '#2B3440'

  const mark = (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      fill="none"
      aria-hidden={showWordmark ? true : undefined}
      aria-label={showWordmark ? undefined : 'CyberMeters'}
      role={showWordmark ? undefined : 'img'}
      style={{ flexShrink: 0, display: 'block' }}
    >
      <defs>
        {/* Gradient: green (bottom / low risk) → red (top / critical risk) */}
        <linearGradient id={gradId} x1="0.5" y1="1" x2="0.5" y2="0">
          <stop offset="0%"   stopColor="#00C389" />
          <stop offset="33%"  stopColor="#59D98E" />
          <stop offset="55%"  stopColor="#EBC547" />
          <stop offset="78%"  stopColor="#FF9F43" />
          <stop offset="100%" stopColor="#FF5A5F" />
        </linearGradient>
      </defs>

      {/* Left bracket — static, square ends, metallic graphite */}
      <polyline
        points="20,4 8,16 20,28"
        stroke={bracketColor}
        strokeWidth="3.5"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />

      {/* Right bracket — static */}
      <polyline
        points="12,4 24,16 12,28"
        stroke={bracketColor}
        strokeWidth="3.5"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />

      {/*
        Needle — the only colored/animated element.
        Static: SVG transform attribute (reliable, no CSS dependency).
        Animated: CSS animation (marketing hero only).
        Slightly taller than brackets (y=1..31 vs brackets y=4..28).
      */}
      <g
        transform={!animated ? 'rotate(-9, 16, 16)' : undefined}
        style={animated ? {
          transformOrigin: '16px 16px',
          animation: 'cmNeedleSwing 13s ease-in-out infinite',
        } : undefined}
      >
        <rect
          x="14.5"
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
