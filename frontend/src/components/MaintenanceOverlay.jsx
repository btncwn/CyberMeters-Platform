import { useEffect, useState, useCallback } from 'react'
import { BASE } from '../api'
import { Wrench } from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// Full-screen planned-maintenance overlay. Shows when any API call returns the
// 503 `maintenance` contract (api.js dispatches `cybermeters:maintenance`), so
// the user sees a calm "back shortly" screen instead of scattered error toasts.
// While shown, it polls /health (which stays reachable during maintenance and
// reports a `maintenance` flag) and auto-reloads the moment the window lifts.
// ─────────────────────────────────────────────────────────────────────────────

export default function MaintenanceOverlay() {
  const [visible, setVisible] = useState(false)
  const [checking, setChecking] = useState(false)

  const checkLifted = useCallback(async () => {
    if (!BASE) return
    setChecking(true)
    try {
      const res = await fetch(`${BASE.replace(/\/api$/, '')}/health`, { cache: 'no-store' })
      const body = await res.json().catch(() => ({}))
      // maintenance === false → back up. Reload to a clean app state.
      if (res.ok && body.maintenance === false) {
        window.location.reload()
        return
      }
    } catch {
      // Still unreachable — stay on the overlay and try again on the next tick.
    } finally {
      setChecking(false)
    }
  }, [])

  useEffect(() => {
    const onMaintenance = () => setVisible(true)
    window.addEventListener('cybermeters:maintenance', onMaintenance)
    return () => window.removeEventListener('cybermeters:maintenance', onMaintenance)
  }, [])

  useEffect(() => {
    if (!visible) return
    const id = setInterval(checkLifted, 20000)
    return () => clearInterval(id)
  }, [visible, checkLifted])

  if (!visible) return null

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-gray-50 px-6" role="alertdialog" aria-modal="true" aria-label="Scheduled maintenance">
      <div className="max-w-md w-full text-center">
        <div className="mx-auto mb-6 flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50">
          <Wrench className="h-7 w-7 text-brand-600" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Scheduled maintenance</h1>
        <p className="mt-3 text-gray-600 leading-relaxed">
          CyberMeters is undergoing brief scheduled maintenance and will be back
          shortly. Your data is safe — no action is needed. This page will refresh
          automatically once we&rsquo;re back.
        </p>
        <button
          onClick={checkLifted}
          disabled={checking}
          className="mt-6 inline-flex items-center gap-2 rounded-full bg-brand-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-700 disabled:opacity-60"
        >
          {checking ? 'Checking…' : 'Check again'}
        </button>
      </div>
    </div>
  )
}
