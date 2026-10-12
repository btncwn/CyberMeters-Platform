import { useEffect, useRef, useState } from 'react'
import { Check, Copy, Mail, X } from 'lucide-react'

// Email links open the visitor's email app — but only when one is set up on
// that computer. Many people read email in a browser, so a mailto link can look
// as if nothing happened. This listens to every mailto click on the site, lets
// the email app open as usual, copies the address and shows it on screen so
// there is always a visible next step.

export function addressFromMailto(href) {
  const raw = String(href || '').replace(/^mailto:/i, '').split('?')[0]
  try { return decodeURIComponent(raw).trim() } catch { return raw.trim() }
}

async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch { /* fall back below */ }
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.setAttribute('aria-hidden', 'true')
  Object.assign(area.style, { position: 'fixed', top: '0', left: '0', opacity: '0', pointerEvents: 'none' })
  document.body.appendChild(area)
  try {
    area.select()
    return document.execCommand('copy') === true
  } catch {
    return false
  } finally {
    area.remove()
  }
}

export default function MailtoAssist() {
  const [address, setAddress] = useState(null)
  const [copied, setCopied] = useState(false)
  const timer = useRef(0)

  useEffect(() => {
    const onClick = (event) => {
      if (event.defaultPrevented || event.button !== 0) return
      const link = event.target instanceof Element ? event.target.closest('a[href^="mailto:"]') : null
      if (!link) return
      const email = addressFromMailto(link.getAttribute('href'))
      if (!email) return
      setAddress(email)
      setCopied(false)
      copyText(email).then(setCopied)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setAddress(null), 12000)
    }
    document.addEventListener('click', onClick)
    return () => {
      document.removeEventListener('click', onClick)
      window.clearTimeout(timer.current)
    }
  }, [])

  if (!address) return null
  return (
    <div role="status" aria-live="polite" className="fixed inset-x-0 bottom-4 z-[100] flex justify-center px-4 pointer-events-none">
      <div className="pointer-events-auto w-full max-w-[460px] rounded-2xl bg-gray-900 text-white shadow-2xl px-5 py-4 flex items-start gap-4">
        <Mail className="w-5 h-5 mt-0.5 flex-shrink-0 text-emerald-300" aria-hidden="true" />
        <div className="flex-1 min-w-0">
          <p className="text-base font-semibold break-all">{address}</p>
          <p className="text-sm text-gray-300 mt-1">
            {copied
              ? 'Address copied. If your email app did not open, paste it into a new email.'
              : 'If your email app did not open, copy the address into a new email.'}
          </p>
          <button
            type="button"
            onClick={() => copyText(address).then(setCopied)}
            className="mt-3 inline-flex items-center gap-2 rounded-lg bg-white/10 hover:bg-white/20 px-3 py-1.5 text-sm font-semibold"
          >
            {copied ? <Check className="w-4 h-4" aria-hidden="true" /> : <Copy className="w-4 h-4" aria-hidden="true" />}
            {copied ? 'Copied' : 'Copy address'}
          </button>
        </div>
        <button type="button" onClick={() => setAddress(null)} aria-label="Close" className="p-1 rounded-md text-gray-400 hover:text-white">
          <X className="w-5 h-5" aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}
