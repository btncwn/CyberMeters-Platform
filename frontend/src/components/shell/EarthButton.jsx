// EarthButton — the photographic globe in the top bar, the ONE notifications
// control (founder, 17 Oct 2026): it sits immediately left of the account
// initial, the same 40px diameter, with the unread counter as a small aqua
// label at its top-right and the notification panel opening beneath it,
// right-aligned. No corner dock and no bell at any width.
//
// Rendering lives in shell/earth.js. One turn every 24 seconds; a single still
// frame under prefers-reduced-motion; paused while the tab is hidden.
import { useEffect, useRef } from 'react'
import NotificationBell from '../NotificationBell'
import {
  buildEarthTexture, buildSphereNormals, flatOceanTexture, renderEarthFrame, spinAt,
  EARTH_SIZE_TOPBAR, TEXTURE_WIDTH, TEXTURE_HEIGHT,
} from './earth'

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

/** "Notifications, 12 unread" / "Notifications" — the control's accessible name. */
export function notificationsLabel(unreadCount) {
  const n = Number(unreadCount) || 0
  return n > 0 ? `Notifications, ${n} unread` : 'Notifications'
}

export default function EarthButton({ size = EARTH_SIZE_TOPBAR }) {
  const canvasRef = useRef(null)
  useEarthCanvas(canvasRef, size)
  return (
    <NotificationBell
      variant="earth"
      trigger={({ open, toggle, unreadCount, hasUnread, panelId }) => (
        <button
          type="button"
          onClick={toggle}
          className="cm-earthbtn"
          style={{ width: size, height: size }}
          aria-label={notificationsLabel(unreadCount)}
          aria-haspopup="dialog"
          aria-expanded={open}
          aria-controls={panelId}
          data-testid="shell-earth"
        >
          <canvas ref={canvasRef} className="cm-earth" aria-hidden="true" style={{ width: size, height: size }} />
          {hasUnread && (
            <span className="cm-earth-count" aria-hidden="true" data-testid="earth-unread">{unreadCount > 99 ? '99+' : unreadCount}</span>
          )}
        </button>
      )}
    />
  )
}
