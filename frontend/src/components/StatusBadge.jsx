const STATUS_CONFIG = {
  queued: {
    label: 'Queued',
    dot: 'bg-gray-400',
    bg: 'bg-gray-100', text: 'text-gray-600', border: 'border-gray-200',
  },
  running: {
    label: 'Running',
    dot: 'bg-blue-500 animate-pulse',
    bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-100',
  },
  processing: {
    label: 'Processing',
    dot: 'bg-blue-500 animate-pulse',
    bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-100',
  },
  completed: {
    label: 'Completed',
    dot: 'bg-brand-500',
    bg: 'bg-brand-50', text: 'text-brand-700', border: 'border-brand-100',
  },
  failed: {
    label: 'Failed',
    dot: 'bg-red-500',
    bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-100',
  },
  error: {
    label: 'Error',
    dot: 'bg-red-500',
    bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-100',
  },
}

const DEFAULT = { label: 'Unknown', dot: 'bg-gray-300', bg: 'bg-gray-100', text: 'text-gray-500', border: 'border-gray-200' }

// A run that finished is not the same as checks that all completed. A completed
// scan whose quality says some checks did not complete reads as partial results,
// never in the success colour (the backend's scan_quality decides; this only shows it).
const PARTIAL_RESULTS = {
  label: 'Partial results',
  dot: 'bg-brand-700',
  bg: 'bg-transparent', text: 'text-brand-700', border: 'border-[1.5px] border-brand-700',
}
const PARTIAL_QUALITIES = new Set(['partial', 'degraded'])

export default function StatusBadge({ status, quality = null }) {
  const key = status?.toLowerCase()
  const cfg = key === 'completed' && PARTIAL_QUALITIES.has(String(quality || '').toLowerCase())
    ? PARTIAL_RESULTS
    : STATUS_CONFIG[key] || DEFAULT
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-semibold whitespace-nowrap ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}
