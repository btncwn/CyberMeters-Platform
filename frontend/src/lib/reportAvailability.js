export const REPORT_PREPARING_DELAYS_MS = Object.freeze([
  2000,
  4000,
  8000,
  12000,
  16000,
  20000,
  20000,
])

export const REPORT_PREPARING_MAX_ATTEMPTS = REPORT_PREPARING_DELAYS_MS.length

export function isReportPreparing(availability) {
  return availability?.status === 'report_preparing' && availability?.retryable === true
}

export function isReportReady(availability) {
  return availability?.status === 'report_ready'
}

export function nextReportPreparationDelay(attempt, serverDelayMs = null) {
  if (!Number.isInteger(attempt) || attempt < 0 || attempt >= REPORT_PREPARING_MAX_ATTEMPTS) {
    return null
  }
  const serverDelay = Number(serverDelayMs)
  const boundedServerDelay = Number.isFinite(serverDelay) && serverDelay > 0
    ? Math.min(serverDelay, 20000)
    : 0
  return Math.max(REPORT_PREPARING_DELAYS_MS[attempt], boundedServerDelay)
}

export function reportPreparationPresentation(availability, exhausted = false) {
  if (exhausted) {
    return {
      title: 'Report preparation is taking longer than expected',
      message:
        'The assessment completed, but the report is not available yet. You can try again without running another scan.',
      canRetry: true,
    }
  }
  if (isReportPreparing(availability)) {
    return {
      title: 'Your report is being prepared',
      message:
        availability.message ||
        'Your assessment is complete. CyberMeters is preparing the report.',
      canRetry: false,
    }
  }
  return null
}
