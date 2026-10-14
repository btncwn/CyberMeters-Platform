// Presentation of the backend's `hosting_network` (workers/scan-api/src/lib/cloud-networks.js).
// The backend decides which published provider range an address is in; this
// module only turns that result into words. It never infers a provider itself.

const SERVICE_LABELS = Object.freeze({
  EC2: 'EC2 compute',
  S3: 'S3 storage',
  CLOUDFRONT: 'CloudFront',
  GLOBALACCELERATOR: 'Global Accelerator',
  API_GATEWAY: 'API Gateway',
  ROUTE53: 'Route 53',
  ROUTE53_HEALTHCHECKS: 'Route 53 health checks',
  DYNAMODB: 'DynamoDB',
})

export function hostingServiceLabel(code) {
  const key = String(code || '').toUpperCase()
  if (!key) return null
  if (SERVICE_LABELS[key]) return SERVICE_LABELS[key]
  return key.toLowerCase().split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
}

/** One short line for a table cell. `null` when the API sent nothing. */
export function hostingNetworkShort(hostingNetwork) {
  if (!hostingNetwork || typeof hostingNetwork !== 'object') return null
  switch (hostingNetwork.status) {
    case 'attributed': {
      const labels = [...new Set((hostingNetwork.networks || []).map((n) => n.provider_label).filter(Boolean))]
      return labels.length ? { text: labels.join(', '), tone: 'info' } : null
    }
    case 'unattributed':
      return { text: 'Other network', tone: 'muted' }
    case 'no_address':
      return { text: 'No address recorded', tone: 'muted' }
    default:
      return null
  }
}

/** One line per matched address for the asset detail panel. */
export function hostingNetworkRows(hostingNetwork) {
  if (hostingNetwork?.status !== 'attributed') return []
  return (hostingNetwork.networks || []).map((n) => ({
    key: `${n.address}|${n.range}`,
    address: n.address,
    provider: n.provider_label,
    detail: [n.region, hostingServiceLabel(n.service), n.kind === 'edge' ? 'edge network' : null].filter(Boolean).join(' · '),
  }))
}

/** Counts for the summary line above the asset table; zero counts are left out. */
export function hostingSummaryItems(summary) {
  if (!summary || !summary.assets || summary.unavailable === summary.assets) return []
  const items = (summary.by_provider || []).map((p) => ({ key: p.provider, label: p.provider_label, count: p.count }))
  if (summary.other_networks) items.push({ key: 'other', label: 'Other networks', count: summary.other_networks })
  if (summary.no_address) items.push({ key: 'none', label: 'No address recorded', count: summary.no_address })
  return items
}
