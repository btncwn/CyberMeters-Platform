import { Link } from 'react-router-dom'
import { Server, ScanLine } from 'lucide-react'

export default function AssetsPage() {
  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Assets</h1>
        <p className="text-sm text-gray-400 mt-0.5">Discovered domains, subdomains and services</p>
      </div>
      <div className="card flex flex-col items-center justify-center py-24 text-center gap-5">
        <div className="w-16 h-16 rounded-2xl bg-brand-50 flex items-center justify-center">
          <Server className="w-7 h-7 text-brand-600" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-gray-900">Asset discovery coming soon</h2>
          <p className="text-sm text-gray-400 mt-2 max-w-sm">
            Run scans to automatically discover subdomains, services and infrastructure assets.
          </p>
        </div>
        <Link to="/scans/new" className="btn-primary">
          <ScanLine className="w-4 h-4" />
          Run a scan
        </Link>
      </div>
    </div>
  )
}
