import { Clock } from 'lucide-react'
import ExposureTimeline from '../components/ExposureTimeline'

// Exposure Timeline — the workspace-wide "what changed" feed. Part of the Attack
// Surface service; the feature that turns a one-time scan into a subscription
// customers keep paying for month after month.
export default function ExposureTimelinePage() {
  const workspaceId = localStorage.getItem('cybermeters_workspace_id')

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Clock className="w-5 h-5 text-brand-600" />
          <h1 className="text-xl font-bold text-gray-900">Exposure Timeline</h1>
        </div>
        <p className="text-sm text-gray-500 mt-1">
          Every externally visible change to your domains — new assets, DNS and email-auth
          changes, exposed services, and certificates — newest first.
        </p>
      </div>

      {workspaceId
        ? <ExposureTimeline workspaceId={workspaceId} />
        : <div className="card p-8 text-center text-sm text-gray-400">Select a workspace to view its timeline.</div>}
    </div>
  )
}
