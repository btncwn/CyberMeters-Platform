import { useEffect, useRef } from 'react'

// Keyboard behaviour for a modal dialog or drawer:
//  - focus moves into the dialog when it opens (its first control, else the panel);
//  - Tab and Shift+Tab stay inside it;
//  - Escape closes it (pass no onClose to keep it open, e.g. while a delete runs);
//  - focus returns to whatever opened it when it closes.
// Attach the returned ref to the panel and give the panel role="dialog",
// aria-modal="true", an accessible name and tabIndex={-1}.

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
].join(',')

function focusables(node) {
  return [...node.querySelectorAll(FOCUSABLE)].filter((el) => !el.closest('[hidden], [inert]'))
}

export function useDialog(onClose) {
  const ref = useRef(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    const node = ref.current
    if (!node) return undefined
    const opener = document.activeElement
    ;(focusables(node)[0] || node).focus()

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        if (onCloseRef.current) { e.stopPropagation(); onCloseRef.current() }
        return
      }
      if (e.key !== 'Tab') return
      const items = focusables(node)
      if (!items.length) { e.preventDefault(); node.focus(); return }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (e.shiftKey && (active === first || !node.contains(active))) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && (active === last || !node.contains(active))) { e.preventDefault(); first.focus() }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus()
    }
  }, [])

  return ref
}
