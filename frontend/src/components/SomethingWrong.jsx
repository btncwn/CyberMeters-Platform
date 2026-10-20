import { useId, useRef, useState } from 'react'
import { buildFeedbackPayload, FEEDBACK_MAX_CHARS, recentErrorCode, sendFeedback } from '../lib/feedback'

const OUTCOME_COPY = {
  sent: 'Thanks, sent. We read every report.',
  rate_limited: 'You have sent several reports in the last hour. Please try again later, or email hello@cybermeters.com.',
  failed: 'Couldn’t send right now. Email hello@cybermeters.com.',
}

/**
 * "Something wrong?" — a quiet link that opens one text box. The page path,
 * the build and the error code on screen go with the message; nothing that
 * identifies the visitor unless they type it.
 */
export default function SomethingWrong({ surface, tool = null, errorCode = null, className = '' }) {
  const [open, setOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [outcome, setOutcome] = useState(null)
  const textRef = useRef(null)
  const id = useId()

  function toggle() {
    setOpen((was) => !was)
    setOutcome(null)
    setTimeout(() => textRef.current?.focus(), 0)
  }

  async function submit(event) {
    event.preventDefault()
    if (!message.trim() || busy) return
    setBusy(true)
    const result = await sendFeedback(buildFeedbackPayload({
      message, surface, tool, errorCode: errorCode || recentErrorCode(),
    }))
    setBusy(false)
    setOutcome(result)
    if (result === 'sent') setMessage('')
  }

  return (
    <div className={`text-sm ${className}`}>
      <button type="button" onClick={toggle} aria-expanded={open} aria-controls={`${id}-panel`}
        className="text-inherit underline underline-offset-2 opacity-90 hover:opacity-100 focus-visible:outline-2 focus-visible:outline-offset-2 rounded">
        Something wrong?
      </button>
      {open && (
        <form id={`${id}-panel`} onSubmit={submit} className="mt-3 max-w-xl rounded-xl border border-gray-200 bg-white p-4 space-y-3 text-left">
          <label htmlFor={`${id}-text`} className="block font-semibold text-gray-900">Tell us what looks wrong</label>
          <textarea id={`${id}-text`} ref={textRef} value={message} maxLength={FEEDBACK_MAX_CHARS} rows={4}
            onChange={(e) => { setMessage(e.target.value); if (outcome !== 'rate_limited') setOutcome(null) }}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-base text-gray-900" />
          <p className="text-xs text-gray-500">We attach this page&rsquo;s address (without anything after ? or #), the app version and any error code shown. Nothing else identifies you unless you type it.</p>
          <div className="flex flex-wrap items-center gap-3">
            <button type="submit" className="btn-primary" disabled={busy || !message.trim()}>{busy ? 'Sending…' : 'Send'}</button>
            <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>Close</button>
          </div>
          <p role="status" aria-live="polite" className={outcome === 'sent' ? 'text-emerald-800' : 'text-gray-700'}>{outcome ? OUTCOME_COPY[outcome] : ''}</p>
        </form>
      )}
    </div>
  )
}
