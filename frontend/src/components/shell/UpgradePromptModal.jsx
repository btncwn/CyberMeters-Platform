// UpgradePromptModal — the plan-limit notice the API triggers through the
// `cybermeters:plan-limit` event (moved out of Layout with the app shell
// rewrite; behaviour unchanged).
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X } from 'lucide-react'
import { parseServerDate, formatDay } from '../../utils/dates'

const RESOURCE_LABELS = {
  scans_per_month:     'monthly scans',
  reports_per_month:   'monthly reports',
  scheduled_scans:     'scheduled scans',
  scans_per_hour:      'scans this hour',
  domains:             'domains',
  workspaces:          'workspaces',
  users:               'team members',
}

export default function UpgradePromptModal() {
  const navigate = useNavigate()
  const [limit, setLimit] = useState(null)
  // Draggable: offset from the centred position. Re-centres each time it opens.
  const [pos, setPos] = useState({ x: 0, y: 0 })
  const dragRef = useRef(null)
  useEffect(() => { if (limit) setPos({ x: 0, y: 0 }) }, [limit])
  const onDragStart = (e) => {
    dragRef.current = { sx: e.clientX, sy: e.clientY, bx: pos.x, by: pos.y }
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }
  const onDragMove = (e) => {
    if (!dragRef.current) return
    setPos({ x: dragRef.current.bx + (e.clientX - dragRef.current.sx), y: dragRef.current.by + (e.clientY - dragRef.current.sy) })
  }
  const onDragEnd = (e) => {
    dragRef.current = null
    e.currentTarget.releasePointerCapture?.(e.pointerId)
  }

  useEffect(() => {
    function handlePlanLimit(e) {
      setLimit(e.detail || {})
    }
    window.addEventListener('cybermeters:plan-limit', handlePlanLimit)
    return () => window.removeEventListener('cybermeters:plan-limit', handlePlanLimit)
  }, [])

  if (!limit) return null

  // Prefer the upgrade_message already composed by the API; fall back to a
  // generic message built from resource/limit fields.
  const resourceKey   = limit.resource || ''
  const resourceLabel = RESOURCE_LABELS[resourceKey] ?? resourceKey.replace(/_/g, ' ')
  const limitVal      = limit.limit >= 999999 ? 'unlimited' : limit.limit
  const body = limit.upgrade_message
    ?? (limitVal != null
      ? `You have used all ${limitVal} ${resourceLabel} included in your current plan.`
      : `You have reached the ${resourceLabel} limit on your current plan.`)

  let resetNote = null
  if (limit.reset_at) {
    try {
      const d = parseServerDate(limit.reset_at)
      resetNote = limit.reason === 'trial_daily_allowance'
        ? `Renews ${formatDay(d, '—', { timeZone: 'UTC' })}, 00:00 UTC.`
        : `Your quota resets on ${formatDay(d)}.`
    } catch { /* ignore */ }
  }

  return (
    <div className="fixed inset-0 z-100 flex items-center justify-center bg-gray-900/30 px-4">
      <div
        className="w-full max-w-md rounded-xl bg-white border border-gray-100 shadow-xl p-5"
        style={{ transform: `translate(${pos.x}px, ${pos.y}px)` }}
      >
        <div
          className="flex items-start gap-3 cursor-grab active:cursor-grabbing select-none touch-none"
          onPointerDown={onDragStart}
          onPointerMove={onDragMove}
          onPointerUp={onDragEnd}
          onPointerCancel={onDragEnd}
          title="Drag to move"
        >
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-bold text-gray-900">{limit.title || "You've reached your plan limit"}</h2>
            <p className="text-sm text-gray-500 mt-1">{body}</p>
            {resetNote && <p className="text-xs text-gray-400 mt-1">{resetNote}</p>}
          </div>
          <button
            type="button"
            onClick={() => setLimit(null)}
            onPointerDown={(e) => e.stopPropagation()}
            className="w-7 h-7 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-50 flex items-center justify-center cursor-pointer"
            aria-label="Close plan limit notice"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={() => setLimit(null)} className="btn-secondary">Not now</button>
          <button type="button" onClick={() => { setLimit(null); navigate('/billing') }} className="btn-primary">Upgrade plan</button>
        </div>
      </div>
    </div>
  )
}
