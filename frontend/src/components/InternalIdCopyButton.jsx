import { useState } from 'react'

export default function InternalIdCopyButton({ id, label = 'reference' }) {
  const [copied, setCopied] = useState(false)
  if (!id) return null
  return <button
    type="button"
    title={String(id)}
    aria-label={`Copy ${label} ID`}
    className="text-xs font-medium text-brand-700 hover:text-brand-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-700"
    onClick={async event => {
      event.stopPropagation()
      try {
        await navigator.clipboard.writeText(String(id))
        setCopied(true)
        setTimeout(() => setCopied(false), 1800)
      } catch { /* Clipboard may be unavailable; the identifier remains in the tooltip. */ }
    }}
  >{copied ? 'Copied' : 'Copy ID'}</button>
}
