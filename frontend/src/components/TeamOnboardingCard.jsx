/**
 * TeamOnboardingCard — shown once to users who joined a workspace via invitation.
 *
 * Explains the 5 core modules they now have access to.
 * Dismissed via localStorage key `cybermeters_team_onboarding_dismissed`.
 *
 * Props: none (self-contained, reads/writes localStorage).
 */
import { useState } from 'react'
import { X } from 'lucide-react'

const DISMISSED_KEY = 'cybermeters_team_onboarding_dismissed'

const FEATURES = [
  {
    title: 'Dashboard',
    desc: 'Your workspace home — cyber score, recent scans, key findings, and domain health at a glance.',
  },
  {
    title: 'Assets',
    desc: 'The subdomains, certificates, cloud services and admin pages found during scanning.',
  },
  {
    title: 'Findings',
    desc: 'Prioritised security issues with severity ratings, evidence, and remediation guidance.',
  },
  {
    title: 'Reports',
    desc: 'Executive PDF reports you can share with clients, management, or auditors.',
  },
  {
    title: 'Shadow IT & Unmanaged Technology',
    desc: 'SaaS portals, third-party scripts and providers observed on your domains — classified as approved, under review or unmanaged.',
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
        <div>
          <h3 className="text-base font-bold text-gray-900">Welcome to your team workspace</h3>
          <p className="text-xs text-gray-400 mt-0.5">
            Here's a quick guide to what you can do.
          </p>
        </div>
        <button
          onClick={dismiss}
          className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-300 hover:text-gray-600 hover:bg-gray-100 transition-colors flex-shrink-0"
          aria-label="Dismiss team invitation card"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Feature grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-px bg-gray-100">
        {FEATURES.map(({ title, desc }) => (
          <div key={title} className="bg-white px-5 py-4">
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
