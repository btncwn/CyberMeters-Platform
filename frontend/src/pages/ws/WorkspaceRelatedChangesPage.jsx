// Related Changes — the workspace-scoped home for deterministic change
// clusters (M6 Phase B1). Additive: it gives the RelatedChangesList a proper
// route; each row links to the canonical Related Change detail surface.
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import RelatedChangesList from '../../components/RelatedChangesList'

export default function WorkspaceRelatedChangesPage() {
  const { wsId, loading } = useWorkspace()

  if (!loading && !wsId) return <NoWorkspaceSelected />

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">
      <div className="mb-5">
        <h1 className="text-xl font-semibold text-slate-900">Related changes</h1>
        {/* One line of purpose; the caveats are stated once, in the note below. */}
        <p className="text-sm text-slate-500 mt-1">
          Changes CyberMeters saw on the same domain at the same time, grouped so you can confirm whether each was planned.
        </p>
      </div>
      {wsId && <RelatedChangesList workspaceId={wsId} />}
    </div>
  )
}
