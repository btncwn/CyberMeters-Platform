import { useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { FileBarChart2, ArrowRight } from 'lucide-react'

export default function ReportsPage() {
  const navigate = useNavigate()
  const activeWorkspaceId = localStorage.getItem('cybermeters_workspace_id')
  const activeWorkspaceName = localStorage.getItem('cybermeters_workspace_name')

  // If a workspace is already active, send the user straight to workspace reports.
  useEffect(() => {
    if (activeWorkspaceId) {
      navigate('/ws/reports', { replace: true })
    }
  }, [activeWorkspaceId, navigate])

  // Render the no-workspace state only while the redirect hasn't fired
  // (or for users with no active workspace).
  if (activeWorkspaceId) return null

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-sm text-gray-400 mt-0.5">Security posture reports for stakeholders</p>
      </div>
      <div className="card flex flex-col items-center justify-center py-24 text-center gap-5">
        <div className="w-16 h-16 rounded-2xl bg-brand-50 flex items-center justify-center">
          <FileBarChart2 className="w-7 h-7 text-brand-600" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-gray-900">Select a workspace to view reports</h2>
          <p className="text-sm text-gray-400 mt-2 max-w-sm">
            Reports are organised by workspace. Select a workspace from the top navigation,
            or complete the guided setup to run your first assessment.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-3">
          <Link to="/workspaces" className="btn-primary">
            <ArrowRight className="w-4 h-4" />
            Go to Workspaces
          </Link>
          <Link to="/onboarding" className="btn-secondary">
            Get Started Guide
          </Link>
        </div>
      </div>
    </div>
  )
}
