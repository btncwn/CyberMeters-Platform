import { Link } from 'react-router-dom'

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <main className="max-w-3xl mx-auto px-6 py-12">
        <Link to="/pricing" className="text-sm font-medium text-brand-600 hover:text-brand-700">CyberMeters</Link>
        <article className="mt-6 bg-white border border-gray-100 rounded-2xl shadow-card p-8">
          <h1 className="text-3xl font-bold text-gray-900">Terms of Service</h1>
          <p className="text-sm text-gray-400 mt-2">Placeholder v1 for commercial launch readiness.</p>
          <div className="prose prose-sm max-w-none mt-6 text-gray-600">
            <p>CyberMeters provides external attack surface monitoring, reporting, and related security intelligence tools.</p>
            <p>Customers are responsible for scanning only domains and workspaces they own or are authorized to assess.</p>
            <p>These terms should be reviewed by legal counsel before broad public launch.</p>
          </div>
        </article>
      </main>
    </div>
  )
}
