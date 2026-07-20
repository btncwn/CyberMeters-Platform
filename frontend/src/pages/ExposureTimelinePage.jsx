import { Clock } from 'lucide-react'
import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import ExposureTimeline from '../components/ExposureTimeline'
import { useWorkspace } from '../hooks/useWorkspace'

// Exposure Timeline — the workspace-wide "what changed" feed. Part of the Attack
// Surface service; the feature that turns a one-time scan into a subscription
// customers keep paying for month after month.
//
// Workspace resolution (digest-truth episode, July 2026): the weekly digest CTA
// links here with ?ws=<workspace_id> so the email always opens ITS OWN
// workspace. The requested id is honoured only after the server-authoritative
// workspace list confirms the user can access it — never straight from the URL,
// and never by trusting stale localStorage first. An inaccessible or absent id
// falls back to the validated active workspace.
export default function ExposureTimelinePage() {
  const { wsId: activeWsId, workspaces, loading, setWorkspace } = useWorkspace()
  const [searchParams] = useSearchParams()
  const requested = searchParams.get('ws')
  const requestedRow = requested ? workspaces.find((w) => w.id === requested) : null

  // A validated deep link switches the active selection to the digest's
  // workspace, so the rest of the app follows the context the customer opened.
  useEffect(() => {
    if (requestedRow && requestedRow.id !== activeWsId) {
      setWorkspace(requestedRow.id, requestedRow.name)
    }
  }, [requestedRow, activeWsId, setWorkspace])

  // While the server list is loading and a specific workspace was requested,
  // wait rather than rendering whichever workspace was last selected.
  const pendingRequested = Boolean(requested) && loading
  const workspaceId = requestedRow ? requestedRow.id : (pendingRequested ? null : activeWsId)

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
        {requested && !loading && !requestedRow && (
          <p className="text-sm text-amber-600 mt-2">
            The workspace this link refers to isn't available on your account — showing your current workspace instead.
          </p>
        )}
      </div>

      {pendingRequested
        ? <div className="card p-8 text-center text-sm text-gray-400">Loading…</div>
        : workspaceId
          ? <ExposureTimeline workspaceId={workspaceId} />
          : <div className="card p-8 text-center text-sm text-gray-400">Select a workspace to view its timeline.</div>}
    </div>
  )
}
