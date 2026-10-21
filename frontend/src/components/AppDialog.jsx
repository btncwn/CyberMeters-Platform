import { useCallback, useId, useMemo, useRef, useState } from 'react'
import { useDialog } from '../lib/useDialog'

// The app's own confirm / prompt / alert, replacing the browser's native
// dialogs (founder, 21 Oct 2026): accessible (focus moves in and stays inside,
// Escape cancels, focus returns to the opener — lib/useDialog), titled, and
// every action button says what it does ("Move to Reject anyway", not "OK").
//
//   const dialog = useAppDialog()
//   …
//   if (!(await dialog.confirm({ title, message, confirmLabel, tone: 'danger' }))) return
//   const reason = await dialog.prompt({ title, label, confirmLabel, required: true })
//   await dialog.alert({ title, message })
//   …
//   return <>{…}{dialog.element}</>
//
// Each component renders its own dialog.element, so no provider is needed.
// confirm → true/false; prompt → the trimmed text, or null when cancelled;
// alert → undefined once acknowledged.

function Paragraphs({ text }) {
  if (!text) return null
  return String(text).split(/\n{2,}/).map((block, i) => (
    <p key={i} className="whitespace-pre-line">{block}</p>
  ))
}

const BUTTON_DANGER = 'inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white bg-red-700 hover:bg-red-800 active:bg-red-900 transition-colors select-none'

function DialogView({ request, onResolve }) {
  const titleId = useId()
  const bodyId = useId()
  const inputId = useId()
  const errorId = useId()
  const [value, setValue] = useState(request.defaultValue ?? '')
  const [error, setError] = useState(null)
  const isPrompt = request.kind === 'prompt'
  const isAlert = request.kind === 'alert'
  const cancel = useCallback(() => onResolve(request.kind === 'confirm' ? false : isAlert ? undefined : null), [onResolve, request.kind, isAlert])
  const ref = useDialog(cancel)

  function submit(event) {
    event.preventDefault()
    if (isPrompt) {
      const text = value.trim()
      if (request.required && !text) { setError(request.requiredMessage || `${request.label || 'This field'} is required.`); return }
      if (request.pattern && text && !request.pattern.test(text)) { setError(request.patternMessage || 'Check the format.'); return }
      onResolve(text)
      return
    }
    onResolve(isAlert ? undefined : true)
  }

  return (
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center bg-gray-900/40 px-4"
      onMouseDown={(event) => { if (event.target === event.currentTarget) cancel() }}
    >
      <form
        ref={ref}
        role={request.tone === 'danger' ? 'alertdialog' : 'dialog'}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={request.message ? bodyId : undefined}
        tabIndex={-1}
        onSubmit={submit}
        noValidate
        className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl"
        data-testid="app-dialog"
      >
        <h2 id={titleId} className="text-lg font-bold text-gray-900">{request.title}</h2>
        {request.message && (
          <div id={bodyId} className="mt-2 space-y-2 text-sm leading-relaxed text-gray-600"><Paragraphs text={request.message} /></div>
        )}
        {isPrompt && (
          <div className="mt-4">
            <label htmlFor={inputId} className="block text-sm font-semibold text-gray-800">{request.label}</label>
            <input
              id={inputId}
              type={request.inputType || 'text'}
              value={value}
              onChange={(event) => { setValue(event.target.value); setError(null) }}
              placeholder={request.placeholder}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? errorId : undefined}
              className="input mt-1"
            />
            {request.hint && <p className="mt-1 text-xs text-gray-500">{request.hint}</p>}
            {error && <p id={errorId} role="alert" className="mt-1 text-xs text-red-700">{error}</p>}
          </div>
        )}
        <div className="mt-6 flex flex-wrap justify-end gap-2">
          {!isAlert && <button type="button" onClick={cancel} className="btn-secondary">{request.cancelLabel || 'Cancel'}</button>}
          <button type="submit" className={request.tone === 'danger' ? BUTTON_DANGER : 'btn-primary'}>
            {request.confirmLabel || (isAlert ? 'Close' : 'Continue')}
          </button>
        </div>
      </form>
    </div>
  )
}

export function useAppDialog() {
  const [request, setRequest] = useState(null)
  const resolver = useRef(null)
  const sequence = useRef(0)

  const open = useCallback((kind, options) => new Promise((resolve) => {
    // A new request replaces an unanswered one, which resolves as cancelled.
    if (resolver.current) resolver.current(kind === 'confirm' ? false : null)
    resolver.current = resolve
    sequence.current += 1
    setRequest({ ...options, kind, id: sequence.current })
  }), [])

  const onResolve = useCallback((result) => {
    const resolve = resolver.current
    resolver.current = null
    setRequest(null)
    resolve?.(result)
  }, [])

  return useMemo(() => ({
    confirm: (options) => open('confirm', options),
    prompt: (options) => open('prompt', options),
    alert: (options) => open('alert', options),
    element: request ? <DialogView key={request.id} request={request} onResolve={onResolve} /> : null,
  }), [open, onResolve, request])
}
