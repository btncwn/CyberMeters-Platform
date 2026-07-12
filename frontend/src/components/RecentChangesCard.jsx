import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Clock, ArrowRight, Globe, Network, Mail, Lock, AlertTriangle, Activity } from 'lucide-react'
import { api } from '../api'

// Compact "what changed recently" widget for the dashboard — the habit-forming
// hook that pulls people back into the product. Shows the latest few Exposure
// Timeline events and links to the full feed. Renders nothing until it knows
// there is (or isn't) history, so it never flashes an empty box.

const CATEGORY_ICON = {
  asset: Globe, dns: Network, email: Mail, certificate: Lock, exposure: AlertTriangle,
}
const SEVERITY_DOT = {
  info: 'bg-gray-300', low: 'bg-blue-400', medium: 'bg-amber-400', high: 'bg-red-400', critical: 'bg-red-600',
}
function relTime(str) {
  if (!str) return ''
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  const d = new Date(s)
  const min = Math.floor((Date.now() - d.getTime()) / 60000)
  if (min < 1) return 'just now'
  if (min < 60) return `${min}m ago`
  const h = Math.floor(min / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function RecentChangesCard({ workspaceId }) {
  const [events, setEvents] = useState(null) // null = loading, [] = loaded-empty

  useEffect(() => {
    let cancelled = false
    if (!workspaceId) { setEvents([]); return }
    api.getExposureFeed(workspaceId, { limit: 5 })
      .then(data => { if (!cancelled) setEvents(data.events || []) })
      .catch(() => { if (!cancelled) setEvents([]) })
    return () => { cancelled = true }
  }, [workspaceId])

  // Loading or genuinely empty → render nothing (keeps the dashboard clean until
  // there's real change history to show).
  if (events === null || events.length === 0) return null

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-brand-600" />
          <h2 className="text-sm font-semibold text-gray-900">Recent changes</h2>
        </div>
        <Link to="/exposure" className="inline-flex items-center gap-1 text-xs font-semibold text-brand-600 hover:text-brand-700">
          View timeline <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
      <ul className="space-y-2">
        {events.map(e => {
          const Icon = CATEGORY_ICON[e.category] ?? Activity
          return (
            <li key={e.id} className="flex items-center gap-3">
              <Icon className="w-4 h-4 text-gray-400 flex-shrink-0" />
              <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEVERITY_DOT[e.severity] ?? SEVERITY_DOT.info}`} />
              <span className="text-sm text-gray-700 truncate flex-1 min-w-0">{e.title}</span>
              <time className="text-xs text-gray-400 flex-shrink-0">{relTime(e.created_at)}</time>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
