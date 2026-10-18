import { canonicalScoreView } from '../lib/canonical-score-presentation'

function establishedTone(rating) {
  if (rating === 'excellent' || rating === 'good') {
    return 'bg-brand-50 text-brand-700 border-brand-100'
  }
  if (rating === 'moderate') return 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
  if (rating === 'high') return 'bg-red-50 text-red-700 border-red-100'
  if (rating === 'critical') return 'bg-red-50 text-red-700 border-red-100'
  return 'bg-gray-50 text-gray-600 border-gray-200'
}

/**
 * Renders only the backend's canonical assessment presentation. A legacy score
 * is deliberately not accepted: missing, inconsistent or future state fails to
 * a dash instead of silently becoming an established numeric conclusion.
 */
export default function CanonicalScore({ assessment }) {
  const view = canonicalScoreView(assessment)

  if (view.state === 'not_established') {
    return (
      <div className="max-w-[16rem]">
        <span className="text-xs text-gray-400 font-medium">—</span>
        <p className="text-xs text-gray-500 mt-1 leading-tight">{view.reason}</p>
      </div>
    )
  }

  if (view.state === 'provisional') {
    return (
      <div className="max-w-[16rem]" aria-label={`Score ${view.score}, provisional. ${view.reason}`}>
        {/* Explanation first; the number is secondary and labelled provisional. */}
        <p className="text-xs text-brand-700 leading-tight">{view.reason}</p>
        <div className="inline-flex items-center gap-1.5 mt-1">
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border bg-transparent text-brand-700 border-[1.5px] border-brand-700">
            {view.score}
          </span>
          <span className="text-xs font-semibold text-brand-700">Provisional</span>
        </div>
      </div>
    )
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold border ${establishedTone(view.rating)}`}
      aria-label={`Established score ${view.score}`}
    >
      {view.score}
    </span>
  )
}
