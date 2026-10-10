// Managed Cases — the canonical home for the cross-domain case queue. Additive:
// it gives the universal CasesQueue a proper route (no longer only a temporary
// embed) and every row links to the canonical Case Detail surface. Bespoke
// domain panels are unchanged and reachable from each case's detail view.
import { useSearchParams } from 'react-router-dom'
import { useWorkspace } from '../../hooks/useWorkspace'
import { NoWorkspaceSelected } from '../../components/WsPage'
import CasesQueue from '../../components/CasesQueue'

export default function WorkspaceCasesPage() {
  const { wsId, loading } = useWorkspace()
  const [params, setParams] = useSearchParams()
  const changeDomain = (domain) => {
    const next = new URLSearchParams(params)
    if (domain) next.set('domain_key', domain); else next.delete('domain_key')
    setParams(next, { replace: true })
  }

  if (!loading && !wsId) return <NoWorkspaceSelected />

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-5">
        <h1 className="text-xl font-semibold text-slate-900">Managed cases</h1>
        <p className="text-sm text-slate-500 mt-1">
          Evidence, fixes and verification across all eight services.
        </p>
      </div>
      {wsId && <CasesQueue key={wsId} workspaceId={wsId} domainKey={params.get('domain_key') || ''} onDomainChange={changeDomain} />}
    </div>
  )
}
