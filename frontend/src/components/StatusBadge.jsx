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

export default function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status?.toLowerCase()] || DEFAULT
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-semibold ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}
