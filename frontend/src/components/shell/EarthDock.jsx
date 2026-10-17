// EarthDock — the photographic globe in the bottom-right corner of the app
// shell (founder prototype v2, 17 Oct 2026). The globe IS the notifications
// button: it carries the unread counter, and the notification panel grows out
// of its centre. Pointer events are limited to the globe itself so the dock
// never sits on top of content. 108px on the wide layout (the only place it
// is rendered); the 88px size is kept for a phone caller.
//
// Rendering lives in shell/earth.js. One turn every 24 seconds; a single still
// frame under prefers-reduced-motion; paused while the tab is hidden.
import { useEffect, useRef } from 'react'
import NotificationBell from '../NotificationBell'
import {
  buildEarthTexture, buildSphereNormals, flatOceanTexture, renderEarthFrame, spinAt,
  EARTH_SIZE_DESKTOP, EARTH_SIZE_PHONE, TEXTURE_WIDTH, TEXTURE_HEIGHT,
} from './earth'

export const EARTH_PHONE_QUERY = '(max-width: 639.98px)'
const FRAME_MIN_MS = 1000 / 30 // the texture lookup is per pixel; 30 fps is plenty for a 24 s turn

let textureCache = null
function earthTexture() {
  if (textureCache) return textureCache
  if (typeof document === 'undefined') return (textureCache = flatOceanTexture())
  const canvas = document.createElement('canvas')
  canvas.width = TEXTURE_WIDTH; canvas.height = TEXTURE_HEIGHT
  const ctx = typeof canvas.getContext === 'function' ? canvas.getContext('2d') : null
  const makeCanvas = (w, h) => { const c = document.createElement('canvas'); c.width = w; c.height = h; return c }
  let texture = null
  try { texture = buildEarthTexture(ctx, TEXTURE_WIDTH, TEXTURE_HEIGHT, makeCanvas) } catch { texture = null }
  textureCache = texture || flatOceanTexture()
  return textureCache
}

export function useEarthCanvas(canvasRef, size) {
  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas && typeof canvas.getContext === 'function' ? canvas.getContext('2d') : null
    if (!ctx || typeof ctx.putImageData !== 'function' || typeof ctx.createImageData !== 'function') return undefined
    const dpr = Math.min(2, (typeof window !== 'undefined' && window.devicePixelRatio) || 1)
    const px = Math.round(size * dpr)
    canvas.width = px; canvas.height = px
    const normals = buildSphereNormals(px)
    const image = ctx.createImageData(px, px)
    if (!image || !image.data) return undefined
    const texture = earthTexture()

    const media = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)')
      : null
    let frame = 0
    let running = false
    let last = 0
    const draw = (now) => renderEarthFrame(ctx, image, normals, texture, spinAt(now, false))
    const tick = (now) => {
      if (now - last >= FRAME_MIN_MS) { last = now; draw(now) }
      frame = window.requestAnimationFrame(tick)
    }
    const stop = () => { if (running) { window.cancelAnimationFrame(frame); running = false } }
    const sync = () => {
      const still = (media && media.matches) || document.hidden
      if (still) { stop(); renderEarthFrame(ctx, image, normals, texture, spinAt(0, true)); return }
      if (!running && typeof window.requestAnimationFrame === 'function') { running = true; frame = window.requestAnimationFrame(tick) }
      else if (!running) draw(0)
    }
    sync()
    media?.addEventListener?.('change', sync)
    document.addEventListener('visibilitychange', sync)
    return () => {
      stop()
      media?.removeEventListener?.('change', sync)
      document.removeEventListener('visibilitychange', sync)
    }
  }, [canvasRef, size])
}

export function EarthCanvas({ size, label, expanded, controls, onToggle }) {
  const canvasRef = useRef(null)
  useEarthCanvas(canvasRef, size)
  return (
    <canvas
      ref={canvasRef}
      role="button"
      tabIndex={0}
      aria-label={label}
      aria-haspopup="dialog"
      aria-expanded={expanded}
      aria-controls={controls}
      onClick={onToggle}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle(e) } }}
      className="cm-earth"
      data-testid="shell-earth"
      style={{ width: size, height: size }}
    />
  )
}

export default function EarthDock({ phone = false }) {
  const size = phone ? EARTH_SIZE_PHONE : EARTH_SIZE_DESKTOP
  return (
    <div className="cm-earthdock" data-testid="earth-dock" style={{ width: size, height: size }}>
      <NotificationBell
        variant="earth"
        trigger={({ open, toggle, unreadCount, hasUnread, panelId }) => (
          <>
            <EarthCanvas
              size={size}
              label={hasUnread ? `Notifications (${unreadCount} unread)` : 'Notifications'}
              expanded={open}
              controls={panelId}
              onToggle={toggle}
            />
            {hasUnread && (
              <span className="cm-earth-count" aria-hidden="true" data-testid="earth-unread">{unreadCount > 99 ? '99+' : unreadCount}</span>
            )}
          </>
        )}
      />
    </div>
  )
}
