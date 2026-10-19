// Has the person typed into a field on this page that they have not submitted?
//
// Controlled React inputs keep their DOM default in step with their value, so
// comparing value to defaultValue cannot tell. Instead we remember every field
// the person edits, forget a form's fields when it is submitted, and forget
// fields that have left the page. A form saved by a button click outside a
// <form> stays "unsaved": the check errs towards keeping someone's input.

const EXCLUDED_INPUT_TYPES = new Set(['button', 'submit', 'reset', 'hidden', 'search', 'image', 'file'])

const edited = new Set()
let installedOn = null

function isEditableField(el) {
  if (!el || el.nodeType !== 1) return false
  if (el.closest?.('[data-unsaved-ignore]')) return false
  if (el.isContentEditable) return true
  if (el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') return true
  if (el.tagName === 'INPUT') return !EXCLUDED_INPUT_TYPES.has(String(el.type || 'text').toLowerCase())
  return false
}

function onEdit(event) {
  if (isEditableField(event.target)) edited.add(event.target)
}

function onSubmit(event) {
  const form = event.target
  for (const el of edited) if (form.contains?.(el)) edited.delete(el)
}

export function installUnsavedInputTracker(doc = globalThis.document) {
  if (!doc || installedOn === doc) return
  installedOn = doc
  doc.addEventListener('input', onEdit, true)
  doc.addEventListener('change', onEdit, true)
  doc.addEventListener('submit', onSubmit, true)
}

export function hasUnsavedInput() {
  for (const el of edited) if (!el.isConnected) edited.delete(el)
  return edited.size > 0
}

export function resetUnsavedInputTracker() {
  edited.clear()
  if (installedOn) {
    installedOn.removeEventListener('input', onEdit, true)
    installedOn.removeEventListener('change', onEdit, true)
    installedOn.removeEventListener('submit', onSubmit, true)
  }
  installedOn = null
}
