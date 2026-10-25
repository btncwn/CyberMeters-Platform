// StatusChip — the one way a vocabulary word is shown. Presentation only: it
// takes a word already chosen by lib/statusVocabulary.js from backend values
// and renders it. A word the vocabulary does not know renders as "Error",
// never as a settled or healthy-looking state.
import { useId } from 'react'
import { statusMeta, STATUS_TONE_CLASS, STATUS_VOCABULARY } from '../lib/statusVocabulary'
import { statusExplanation } from '../lib/statusExplanations'

export default function StatusChip({ status, size = 'sm', className = '', title = null }) {
  const key = STATUS_VOCABULARY[status] ? status : 'error'
  const meta = statusMeta(key)
  const pad = size === 'md' ? 'px-3 py-1 text-sm' : 'px-2.5 py-0.5 text-xs'
  // Every chip says what its word means (10d): a tooltip and an accessible
  // description. A caller's own title (a specific reason) wins.
  const explanation = statusExplanation(key)
  const describedBy = useId()
  return (
    <>
    <span
      data-status={key}
      title={title || explanation}
      aria-describedby={describedBy}
      className={`inline-flex max-w-full items-center rounded-lg border font-semibold leading-5 whitespace-normal text-left ${pad} ${STATUS_TONE_CLASS[meta.tone] || STATUS_TONE_CLASS.gray} ${className}`}
    >
      {meta.label}
    </span>
    <span id={describedBy} hidden>{explanation}</span>
    </>
  )
}
