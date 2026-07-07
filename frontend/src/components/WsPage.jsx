/**
 * WsPage — layout shell for workspace-scoped pages.
 *
 * Renders sidebar + content column. Shows a "select workspace" prompt when
 * no workspace is active in localStorage.
 */
import { useNavigate } from 'react-router-dom'
import { Briefcase } from 'lucide-react'
import Spinner from './Spinner'
import ErrorAlert from './ErrorAlert'

export function NoWorkspaceSelected() {
  const navigate = useNavigate()
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="text-center max-w-sm">
        <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center mx-auto mb-4">
          <Briefcase className="w-7 h-7 text-brand-600" />
        </div>
        <h2 className="text-lg font-bold text-gray-900 mb-1">No workspace selected</h2>
        <p className="text-sm text-gray-500 mb-5">
          Select a workspace from the top-right dropdown to see intelligence data.
        </p>
        <button className="btn-secondary" onClick={() => navigate('/workspaces')}>
          Go to Workspaces
        </button>
      </div>
    </div>
  )
}

export default function WsPage({ wsId, wsName, loading, error, onRetry, children }) {
  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      {loading ? (
        <div className="flex items-center justify-center py-32">
          <Spinner />
        </div>
      ) : error ? (
        <ErrorAlert message={error} onRetry={onRetry} />
      ) : (
        children
      )}
    </div>
  )
}
