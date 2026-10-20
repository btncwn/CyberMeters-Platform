import { Link } from 'react-router-dom'

// The latest finished scan gave no established score (the backend's
// assessment is not final): say so calmly, say what that means, and point to
// the report that lists what was and was not measured. Never a red banner.
export default function IncompleteAssessmentNote({ scan, first }) {
  if (!scan?.id) return null
  return (
    <section aria-labelledby="incomplete-assessment-heading" className="card px-6 py-5 border-l-4 border-l-slate-300" data-testid="incomplete-assessment-note">
      <h2 id="incomplete-assessment-heading" className="text-base font-bold text-gray-900">
        {first ? 'First assessment incomplete' : 'Latest assessment incomplete'}
      </h2>
      <p className="text-sm text-gray-600 mt-1 leading-relaxed">
        Some checks did not complete in the scan of {scan.domain}, so there is no score yet. The areas below show what CyberMeters did measure, and the report lists what it could not and why. A later scan completes the picture.
      </p>
      <Link to={`/scans/${encodeURIComponent(scan.id)}`} className="mt-3 inline-block text-sm font-semibold text-brand-700 underline underline-offset-2">See what was measured</Link>
    </section>
  )
}
