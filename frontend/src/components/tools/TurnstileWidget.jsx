import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'

// Cloudflare Turnstile, loaded only on the free-tool pages. The CSP in
// public/_headers allows exactly this origin for the script and its frame.
const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

let loading = null
export function loadTurnstile() {
  if (typeof window === 'undefined') return Promise.reject(new Error('no window'))
  if (window.turnstile) return Promise.resolve(window.turnstile)
  if (!loading) {
    loading = new Promise((resolve, reject) => {
      const script = document.createElement('script')
      script.src = SCRIPT_URL
      script.async = true
      script.defer = true
      script.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error('turnstile missing')))
      script.onerror = () => { loading = null; reject(new Error('turnstile failed to load')) }
      document.head.appendChild(script)
    })
  }
  return loading
}

/**
 * The human check. Each token works once, so the parent calls reset() after
 * every submission. `action` binds the token to one tool on the server.
 */
const TurnstileWidget = forwardRef(function TurnstileWidget({ siteKey, action, onToken }, ref) {
  const container = useRef(null)
  const widgetId = useRef(null)
  const [failed, setFailed] = useState(false)
  const tokenCallback = useRef(onToken)
  tokenCallback.current = onToken

  useImperativeHandle(ref, () => ({
    reset() {
      tokenCallback.current?.(null)
      if (widgetId.current != null) window.turnstile?.reset(widgetId.current)
    },
  }), [])

  useEffect(() => {
    let cancelled = false
    if (!siteKey) return undefined
    loadTurnstile().then((turnstile) => {
      if (cancelled || !container.current) return
      widgetId.current = turnstile.render(container.current, {
        sitekey: siteKey,
        action,
        appearance: 'interaction-only',
        callback: (token) => tokenCallback.current?.(token),
        'expired-callback': () => tokenCallback.current?.(null),
        'error-callback': () => tokenCallback.current?.(null),
      })
    }).catch(() => { if (!cancelled) setFailed(true) })
    return () => {
      cancelled = true
      if (widgetId.current != null) window.turnstile?.remove?.(widgetId.current)
      widgetId.current = null
    }
  }, [siteKey, action])

  return (
    <div>
      <div ref={container} data-testid="turnstile" />
      {failed && <p className="text-sm text-gray-600 mt-2">The human check could not load. Check that nothing is blocking challenges.cloudflare.com, then reload the page.</p>}
    </div>
  )
})

export default TurnstileWidget
