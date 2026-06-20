import { Link } from 'react-router-dom'
import { FileBarChart2 } from 'lucide-react'

export default function ReportsPage() {
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
          <h2 className="text-lg font-bold text-gray-900">No reports yet</h2>
          <p className="text-sm text-gray-400 mt-2 max-w-sm">
            Complete the guided setup to run your first assessment and generate an executive report.
          </p>
        </div>
        <Link to="/onboarding" className="btn-primary">
          Get Started
        </Link>
      </div>
    </div>
  )
}
