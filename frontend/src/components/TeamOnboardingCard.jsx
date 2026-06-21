/**
 * TeamOnboardingCard — shown once to users who joined a workspace via invitation.
 *
 * Explains the 5 core modules they now have access to.
 * Dismissed via localStorage key `cybermeters_team_onboarding_dismissed`.
 *
 * Props: none (self-contained, reads/writes localStorage).
 */
import { useState } from 'react'
import {
  X, Users, LayoutDashboard, Server, AlertTriangle, FileText, Package2,
} from 'lucide-react'

const DISMISSED_KEY = 'cybermeters_team_onboarding_dismissed'

const FEATURES = [
  {
    icon: LayoutDashboard,
    color: 'bg-brand-50 text-brand-600',
    title: 'Dashboard',
    desc: 'Your workspace home — cyber score, recent scans, key findings, and domain health at a glance.',
  },
  {
    icon: Server,
    color: 'bg-amber-50 text-amber-600',
    title: 'Assets',
    desc: 'Every subdomain, certificate, cloud service, and admin panel discovered during scanning.',
  },
  {
    icon: AlertTriangle,
    color: 'bg-red-50 text-red-500',
    title: 'Findings',
    desc: 'Prioritised security issues with severity ratings, evidence, and remediation guidance.',
  },
  {
    icon: FileText,
    color: 'bg-purple-50 text-purple-600',
    title: 'Reports',
    desc: 'Executive PDF reports you can share with clients, management, or auditors.',
  },
  {
    icon: Package2,
    color: 'bg-green-50 text-green-600',
    title: 'Vendor Risk',
    desc: 'Third-party services detected on your domains — SaaS tools, CDNs, analytics, and more.',
  },
]

export default function TeamOnboardingCard() {
  const [dismissed, setDismissed] = useState(
    () => localStorage.getItem(DISMISSED_KEY) === 'true'
  )

  if (dismissed) return null

  function dismiss() {
    localStorage.setItem(DISMISSED_KEY, 'true')
    setDismissed(true)
  }

  return (
    <div className="bg-white rounded-2xl border border-brand-100 shadow-sm overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-4 border-b border-gray-50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-brand-50 flex items-center justify-center flex-shrink-0">
            <Users className="w-4 h-4 text-brand-600" />
          </div>
          <div>
            <h3 className="text-base font-bold text-gray-900">Welcome to your team workspace</h3>
            <p className="text-xs text-gray-400 mt-0.5">
              Here's a quick guide to what you can do.
            </p>
          </div>
        </div>
        <button
          onClick={dismiss}
          className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-300 hover:text-gray-600 hover:bg-gray-100 transition-colors flex-shrink-0"
          aria-label="Dismiss"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Feature grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-px bg-gray-100">
        {FEATURES.map(({ icon: Icon, color, title, desc }) => (
          <div key={title} className="bg-white px-5 py-4">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-2.5 ${color}`}>
              <Icon className="w-4 h-4" />
            </div>
            <p className="text-sm font-semibold text-gray-900 mb-1">{title}</p>
            <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="px-6 py-3 bg-gray-50 border-t border-gray-100 flex items-center justify-between">
        <p className="text-xs text-gray-400">
          Use the sidebar navigation to explore each area.
        </p>
        <button
          onClick={dismiss}
          className="text-xs font-medium text-gray-400 hover:text-gray-700 transition-colors"
        >
          Got it, dismiss
        </button>
      </div>
    </div>
  )
}
