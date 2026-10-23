// Cyber Essentials summary helpers, shared by the area page (S1-SHELL-V2b).
// Its own file: the page's exact text is mutation-anchored.

// "What we observed" (S1-SHELL-V2b), under the R1 rules: backend facts only,
// never 0 for "not known". The indicator mirrors ResultSummary exactly (hidden
// until the questionnaire is complete; "Not assessed" when the backend says so —
// the page passes its own readinessIsNotAssessed()).
export function ceSummaryFigures({ readiness, readinessLoaded, notAssessed = false, progress, controls, controlsError }) {
  const score = !readinessLoaded || !readiness ? 'Not available'
    : notAssessed ? 'Not assessed'
      : readiness?.questionnaire?.complete === false ? 'Questionnaire first'
        : typeof readiness.score === 'number' ? `${readiness.score}/100` : 'Not available'
  const answered = progress?.total > 0 ? `${progress.answered} of ${progress.total}` : 'Not available'
  // The workspace total (pagination.total), never the loaded page's length (50 by default).
  const observed = controlsError ? 'Not available' : !controls ? 'Loading…'
    : Number.isInteger(controls.pagination?.total) ? controls.pagination.total : 'Not available'
  return [
    { key: 'score', id: 'ce-score', label: 'External readiness indicator', value: score, explanation: 'From external evidence only; not a certification' },
    { key: 'answered', id: 'ce-answered', label: 'Questions answered', value: answered, explanation: 'Your self-declared answers' },
    { key: 'observed', id: 'ce-observed', label: 'Observed control records', value: observed, explanation: 'Controls a completed scan could assess externally' },
  ]
}
