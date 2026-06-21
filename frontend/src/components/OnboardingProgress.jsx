/**
 * OnboardingProgress — compact 4-step progress tracker for new users.
 *
 * Steps:
 *   1. Create Workspace
 *   2. Add Domain
 *   3. Run Scan
 *   4. Review Results
 *
 * Shown on the main Dashboard when onboarding is in progress.
 * Dismissible at any time; dismissed state stored in localStorage.
 * Auto-hides if all 4 steps are complete AND the user dismisses.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle, X, ChevronRight, Briefcase, Globe, ScanLine, BarChart2 } from 'lucide-react'

const DISMISS_KEY = 'cybermeters_onboarding_dismissed'

function StepDot({ done, active, number }) {
  if (done) {
    return (
      <div className="w-7 h-7 rounded-full bg-brand-500 flex items-center justify-center flex-shrink-0">
        <CheckCircle className="w-4 h-4 text-white" />
      </div>
    )
  }
  if (active) {
    return (
      <div className="w-7 h-7 rounded-full bg-gray-900 flex items-center justify-center flex-shrink-0">
        <span className="text-xs font-bold text-white">{number}</span>
      </div>
    )
  }
  return (
    <div className="w-7 h-7 rounded-full border-2 border-gray-200 flex items-center justify-center flex-shrink-0">
      <span className="text-xs font-semibold text-gray-300">{number}</span>
    </div>
  )
}

export default function OnboardingProgress({ hasWorkspace, hasDomain, hasCompletedScan }) {
  const [dismissed, setDismissed] = useState(
    () => localStorage.getItem(DISMISS_KEY) === '1',
  )

  if (dismissed) return null

  const steps = [
    {
      number:  1,
      label:   'Create Workspace',
      detail:  'Set up your first monitoring workspace.',
      icon:    Briefcase,
      done:    hasWorkspace,
      href:    '/onboarding',
      cta:     'Create',
    },
    {
      number:  2,
      label:   'Add Domain',
      detail:  'Add the domain you want to monitor.',
      icon:    Globe,
      done:    hasDomain,
      href:    hasWorkspace ? '/ws/dashboard' : '/onboarding',
      cta:     'Add domain',
    },
    {
      number:  3,
      label:   'Run Scan',
      detail:  'Launch your first security assessment.',
      icon:    ScanLine,
      done:    hasCompletedScan,
      href:    '/scans/new',
      cta:     'Start scan',
    },
    {
      number:  4,
      label:   'Review Results',
      detail:  'Explore findings, score and asset inventory.',
      icon:    BarChart2,
      done:    hasCompletedScan,
      href:    '/scans',
      cta:     'View results',
    },
  ]

  const doneCount  = steps.filter(s => s.done).length
  const allDone    = doneCount === steps.length
  const progressPct = Math.round((doneCount / steps.length) * 100)
  const activeStep = steps.find(s => !s.done)

  function dismiss() {
    localStorage.setItem(DISMISS_KEY, '1')
    setDismissed(true)
  }

  return (
    <div className="card p-5 border-brand-100 bg-gradient-to-br from-brand-50/60 to-white">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <p className="text-sm font-bold text-gray-900">
              {allDone ? 'Setup complete!' : 'Getting started with CyberMeters'}
            </p>
            {allDone && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-brand-100 text-brand-700 uppercase tracking-wide">
                <CheckCircle className="w-3 h-3" />
                Done
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400">
            {allDone
              ? 'You\'ve completed the onboarding steps. Your first scan results are ready.'
              : `Step ${doneCount + 1} of ${steps.length} — ${activeStep?.label}`}
          </p>
        </div>
        <button
          onClick={dismiss}
          title="Dismiss"
          className="w-7 h-7 rounded-lg flex items-center justify-center text-gray-300 hover:text-gray-600 hover:bg-gray-100 transition-colors flex-shrink-0"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 bg-gray-100 rounded-full mb-4 overflow-hidden">
        <div
          className="h-full bg-brand-500 rounded-full transition-all duration-500"
          style={{ width: `${progressPct}%` }}
        />
      </div>

      {/* Steps */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {steps.map((step, i) => {
          const isActive = !step.done && (i === 0 || steps[i - 1].done)
          return (
            <div
              key={step.number}
              className={`flex flex-col gap-2 p-3 rounded-xl border transition-colors ${
                step.done
                  ? 'border-brand-100 bg-brand-50/60'
                  : isActive
                    ? 'border-gray-200 bg-white shadow-sm'
                    : 'border-gray-100 bg-gray-50/40'
              }`}
            >
              <div className="flex items-center gap-2">
                <StepDot done={step.done} active={isActive} number={step.number} />
                <span className={`text-xs font-semibold leading-tight ${
                  step.done ? 'text-brand-700' : isActive ? 'text-gray-900' : 'text-gray-400'
                }`}>
                  {step.label}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 leading-relaxed pl-9">
                {step.done ? '✓ Complete' : step.detail}
              </p>
              {isActive && !step.done && (
                <Link
                  to={step.href}
                  className="self-start ml-9 inline-flex items-center gap-1 text-xs font-semibold text-brand-600 hover:text-brand-700 transition-colors"
                >
                  {step.cta}
                  <ChevronRight className="w-3 h-3" />
                </Link>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
