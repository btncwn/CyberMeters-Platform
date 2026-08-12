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
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-5">
        <h1 className="text-xl font-semibold text-slate-900">Related changes</h1>
        <p className="text-sm text-slate-500 mt-1">
          When two or more independent signal families change together on the same domain in the same period, CyberMeters
          groups them into a change cluster. This view is workspace-level — a cluster may affect any domain in this
          workspace, and each entry names the domain it affects. These are correlated observations that may be
          connected — review each and confirm whether it was planned.
        </p>
      </div>
      {wsId && <RelatedChangesList workspaceId={wsId} />}
    </div>
  )
}
