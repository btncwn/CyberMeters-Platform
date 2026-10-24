import { useState } from 'react'
import { Copy } from 'lucide-react'

// A small secondary button with its own space (Executive 24 Oct 2026): it never
// runs into the text beside it ("example.comCopy ID"), and wraps to its own line
// at narrow widths rather than colliding.

export default function InternalIdCopyButton({ id, label = 'reference' }) {
  const [copied, setCopied] = useState(false)
  if (!id) return null
  return <button
    type="button"
    title={String(id)}
    aria-label={`Copy ${label} ID`}
    data-testid="internal-id-copy"
    className="cm-idcopy ml-2 inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border border-slate-300 bg-white px-2 py-0.5 align-middle text-xs font-medium text-slate-700 hover:border-brand-300 hover:text-brand-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-700"
    onClick={async event => {
      event.stopPropagation()
      try {
        await navigator.clipboard.writeText(String(id))
        setCopied(true)
        setTimeout(() => setCopied(false), 1800)
      } catch { /* Clipboard may be unavailable; the identifier remains in the tooltip. */ }
    }}
  ><Copy className="h-3 w-3" aria-hidden="true" />{copied ? 'Copied' : 'Copy ID'}</button>
}
