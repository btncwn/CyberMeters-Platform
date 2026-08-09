export const ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION =
  'asset-lifecycle-claim-projection-v1'

const LIFECYCLE_TYPES = new Set(['asset_no_longer_seen', 'asset_reappeared'])
const SUPPORT_STATES = new Set(['supported', 'unsupported', 'uncertain'])

export function assetLifecycleClaimDisplay(event = {}) {
  if (!LIFECYCLE_TYPES.has(event.event_type)) {
    return {
      title: event.title,
      description: event.description,
      supportLabel: null,
      evaluated: true,
    }
  }
  const claim = event.lifecycle_claim_support
  if (
    claim?.version === ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION &&
    SUPPORT_STATES.has(claim?.state)
  ) {
    return {
      title: event.title,
      description: event.description,
      supportLabel:
        claim.state === 'supported'
          ? 'Evidence supported'
          : claim.state === 'unsupported'
            ? 'Evidence not supported'
            : 'Support undetermined',
      evaluated: true,
    }
  }
  return {
    title: 'Historical lifecycle record — support not evaluated',
    description: 'Support for this historical record was not evaluated.',
    supportLabel: 'Support not evaluated',
    evaluated: false,
  }
}

export function projectedCountDisplay(value, projection) {
  if (
    projection?.version !== ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION ||
    projection?.coverage !== 'complete' ||
    !Number.isInteger(value) ||
    value < 0
  ) {
    return { value: null, label: 'Not evaluated' }
  }
  return { value, label: String(value) }
}
