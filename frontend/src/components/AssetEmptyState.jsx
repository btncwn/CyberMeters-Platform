import { Link } from 'react-router-dom'
import { ScanLine, Globe, Server, Lock, Wifi, Eye } from 'lucide-react'

/**
 * AssetEmptyState
 * Shown when no asset data has been collected yet.
 * Replace with API-driven content once /api/assets is implemented.
 */
export default function AssetEmptyState() {
  const features = [
    {
      icon:  Globe,
      color: 'bg-blue-50 text-blue-600',
      title: 'Domains & Subdomains',
      desc:  'Automatically enumerate every subdomain exposed on your attack surface.',
    },
    {
      icon:  Lock,
      color: 'bg-brand-50 text-brand-600',
      title: 'TLS Certificates',
      desc:  'Track certificate expiry, issuers, and mis-issuance across all assets.',
    },
    {
      icon:  Wifi,
      color: 'bg-amber-50 text-amber-600',
      title: 'Exposed Services',
      desc:  'Identify open ports and internet-facing services that expand your risk.',
    },
    {
      icon:  Eye,
      color: 'bg-orange-50 text-orange-600',
      title: 'Hidden Assets',
      desc:  'Surface forgotten infrastructure and shadow IT you may not know exists.',
    },
    {
      icon:  Server,
      color: 'bg-purple-50 text-purple-600',
      title: 'Infrastructure Map',
      desc:  'Visualise your full external infrastructure across cloud and on-prem.',
    },
  ]

  return (
    <div className="space-y-8">

      {/* Hero empty state */}
      <div className="card-md flex flex-col items-center text-center gap-6 px-8 py-16">
        {/* Icon cluster */}
        <div className="relative w-24 h-24 flex-shrink-0">
          <div className="absolute inset-0 rounded-3xl bg-brand-50 flex items-center justify-center">
            <Server className="w-10 h-10 text-brand-600" />
          </div>
          {/* Orbiting mini icons */}
          <div className="absolute -top-2 -right-2 w-8 h-8 rounded-xl bg-blue-50 border-2 border-white flex items-center justify-center shadow-sm">
            <Globe className="w-4 h-4 text-blue-500" />
          </div>
          <div className="absolute -bottom-2 -left-2 w-8 h-8 rounded-xl bg-amber-50 border-2 border-white flex items-center justify-center shadow-sm">
            <Wifi className="w-4 h-4 text-amber-500" />
          </div>
          <div className="absolute -bottom-2 -right-2 w-8 h-8 rounded-xl bg-brand-50 border-2 border-white flex items-center justify-center shadow-sm">
            <Lock className="w-4 h-4 text-brand-600" />
          </div>
        </div>

        <div className="max-w-md">
          <h2 className="text-xl font-bold text-gray-900">No assets discovered yet</h2>
          <p className="text-sm text-gray-400 mt-2 leading-relaxed">
            Run a security scan on your domain to automatically discover and map your
            external attack surface — subdomains, services, certificates and more.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link to="/scans/new" className="btn-primary">
            <ScanLine className="w-4 h-4" />
            Run your first scan
          </Link>
          <Link to="/scans" className="btn-secondary">
            View scan history
          </Link>
        </div>
      </div>

      {/* Feature preview grid */}
      <div>
        <p className="label text-center mb-5">What Asset Intelligence will show</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map(({ icon: Icon, color, title, desc }) => (
            <div key={title} className="card p-5 flex items-start gap-4">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${color}`}>
                <Icon className="w-5 h-5" />
              </div>
              <div>
                <p className="text-sm font-bold text-gray-900">{title}</p>
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">{desc}</p>
              </div>
            </div>
          ))}
          {/* Coming soon card */}
          <div className="card p-5 flex items-start gap-4 opacity-50">
            <div className="w-10 h-10 rounded-xl bg-gray-100 flex items-center justify-center flex-shrink-0">
              <Eye className="w-5 h-5 text-gray-400" />
            </div>
            <div>
              <p className="text-sm font-bold text-gray-500">More coming soon</p>
              <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                IP ranges, cloud buckets, leaked credentials, and vulnerability correlation.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
