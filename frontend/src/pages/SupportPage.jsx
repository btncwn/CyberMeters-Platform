import { Link } from 'react-router-dom'

export default function SupportPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <main className="max-w-3xl mx-auto px-6 py-12">
        <Link to="/pricing" className="text-sm font-medium text-brand-600 hover:text-brand-700">CyberMeters</Link>
        <section className="mt-6 bg-white border border-gray-100 rounded-2xl shadow-card p-8">
          <h1 className="text-3xl font-bold text-gray-900">Support</h1>
          <p className="text-gray-600 mt-3 leading-relaxed">
            Need help getting started or understanding a report? Email us about setup, account access or billing for your business or agency workspace.
          </p>
          <a href="mailto:hello@cybermeters.com" className="mt-6 inline-flex items-center gap-2 btn-primary">
            hello@cybermeters.com
          </a>
          <p className="text-sm text-gray-600 mt-5 leading-relaxed">
            Support is by email. Tell us what you were trying to do and what happened so we can help with the next step.
          </p>
        </section>
      </main>
    </div>
  )
}
