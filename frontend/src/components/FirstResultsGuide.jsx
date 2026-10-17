/**
 * FirstResultsGuide — shown after a user's first completed scan.
 *
 * Explains the five core CyberMeters concepts:
 *   Cyber Score · Findings · Assets · Historical Tracking · Shadow IT
 *
 * Dismissible (localStorage: cybermeters_results_guide_dismissed).
 * Pass `compact` prop to render a condensed inline version.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'

const DISMISS_KEY = 'cybermeters_results_guide_dismissed'

const FEATURES = [
  {
    title: 'Cyber Score',
    desc:  'Your 0–100 risk rating. Higher is better. Driven by DNS, SSL, email security, headers, and exposed assets.',
    href:  '/dashboard',
    cta:   'View score',
  },
  {
    title: 'Findings',
    desc:  'Specific security issues detected across your domains — categorised by severity: Critical, High, Medium, Low.',
    href:  '/scans',
    cta:   'Review findings',
  },
  {
    title: 'Asset Inventory',
    desc:  'Subdomains, exposed services, and cloud assets automatically discovered during each scan.',
    href:  '/assets',
    cta:   'Browse assets',
  },
  {
    title: 'Historical Tracking',
    desc:  'Score trends and surface changes tracked over time. Run regular scans to build a security timeline.',
    href:  '/scans',
    cta:   'See history',
  },
  {
    title: 'Shadow IT & Unmanaged Technology',
    desc:  'SaaS portals, third-party scripts and providers observed on your external footprint — classify what is approved and track the rest.',
    href:  '/ws/shadow-it',
    cta:   'Review technology',
  },
]

export default function FirstResultsGuide({ compact = false }) {
  const [dismissed, setDismissed] = useState(
    () => localStorage.getItem(DISMISS_KEY) === '1',
  )

  if (dismissed) return null

  function dismiss() {
    localStorage.setItem(DISMISS_KEY, '1')
    setDismissed(true)
  }

  return (
    <div className="card overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 bg-linear-to-r from-brand-50/40 to-white">
        <div>
          <p className="text-sm font-bold text-gray-900">Understand Your Results</p>
          <p className="text-xs text-gray-400">Your first scan is complete — here's what everything means.</p>
        </div>
        <button
          onClick={dismiss}
          title="Dismiss results guide"
          aria-label="Dismiss results guide"
          className="w-7 h-7 rounded-lg flex items-center justify-center text-gray-300 hover:text-gray-600 hover:bg-gray-100 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Feature cards */}
      <div className={`grid gap-0 divide-y divide-gray-50 ${compact ? '' : 'sm:grid-cols-1 md:grid-cols-5 sm:divide-y-0 sm:divide-x'}`}>
        {FEATURES.map(feature => {
          return (
            <div
              key={feature.title}
              className="flex flex-col gap-2 p-4 hover:bg-gray-50/60 transition-colors"
            >
              <span className="text-sm font-semibold text-gray-900">{feature.title}</span>
              <p className="text-xs text-gray-400 leading-relaxed">{feature.desc}</p>
              <Link
                to={feature.href}
                className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 hover:text-brand-800 transition-colors mt-auto pt-1"
              >
                {feature.cta}
              </Link>
            </div>
          )
        })}
      </div>

      {/* Footer */}
      <div className="px-6 py-3 border-t border-gray-100 bg-gray-50/40 flex items-center justify-between">
        <p className="text-xs text-gray-400">
          Results update automatically with each new scan.
        </p>
        <button
          onClick={dismiss}
          className="text-xs text-gray-400 hover:text-gray-600 font-medium transition-colors"
        >
          Got it, dismiss
        </button>
      </div>
    </div>
  )
}
