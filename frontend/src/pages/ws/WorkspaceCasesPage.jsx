// Operations — the canonical home for one workspace's managed cases, in the
// four working lanes (Triage · In progress / waiting · Ready to verify ·
// Closed). Workspace-scoped: the MSP picks the customer first. Every row links
// to the canonical Case Detail surface, where the backend's
// available_transitions drive every change through the universal validator.
import { useSearchParams } from 'react-router-dom'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import OperationsBoard from '../../components/operations/OperationsBoard'

export default function WorkspaceCasesPage() {
  const { wsId, wsName, loading } = useWorkspace()
  const [params, setParams] = useSearchParams()
  const setParam = (key, value) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    setParams(next, { replace: true })
  }

  if (!loading && !wsId) return <NoWorkspaceSelected />

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">
      <div className="mb-5">
        <h1 className="text-xl font-semibold text-slate-900">Operations</h1>
        <p className="text-sm text-slate-500 mt-1">
          Evidence, fixes and verification across all eight services{wsName ? ` for ${wsName}` : ''}.
        </p>
      </div>
      {wsId && (
        <OperationsBoard
          key={wsId}
          workspaceId={wsId}
          domainKey={params.get('domain_key') || ''}
          onDomainChange={(domain) => setParam('domain_key', domain)}
          view={params.get('view') || ''}
          onViewChange={(view) => setParam('view', view)}
        />
      )}
    </div>
  )
}
