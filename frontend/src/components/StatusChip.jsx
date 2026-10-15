// StatusChip — the one way a vocabulary word is shown. Presentation only: it
// takes a word already chosen by lib/statusVocabulary.js from backend values
// and renders it. A word the vocabulary does not know renders as "Error",
// never as a settled or healthy-looking state.
import { statusMeta, STATUS_TONE_CLASS, STATUS_VOCABULARY } from '../lib/statusVocabulary'

export default function StatusChip({ status, size = 'sm', className = '', title = null }) {
  const key = STATUS_VOCABULARY[status] ? status : 'error'
  const meta = statusMeta(key)
  const pad = size === 'md' ? 'px-3 py-1 text-sm' : 'px-2.5 py-0.5 text-xs'
  return (
    <span
      data-status={key}
      title={title || undefined}
      className={`inline-flex max-w-full items-center rounded-lg border font-semibold leading-5 whitespace-normal text-left ${pad} ${STATUS_TONE_CLASS[meta.tone] || STATUS_TONE_CLASS.gray} ${className}`}
    >
      {meta.label}
    </span>
  )
}
