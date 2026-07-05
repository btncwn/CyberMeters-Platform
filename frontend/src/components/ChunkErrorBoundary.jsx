import { Component } from 'react'
import { useLocation } from 'react-router-dom'
import { RefreshCw, WifiOff } from 'lucide-react'

// ── Stale-deploy recovery ──────────────────────────────────────────────────
//
// Production deploys replace the hashed asset files. A user with a long-
// running session who navigates to a lazy route the browser hasn't loaded
// yet gets "Failed to fetch dynamically imported module" and, without this
// boundary, a blank white screen.
//
// Recovery strategy:
//   1. Chunk/module-load failures trigger ONE automatic hard reload so the
//      browser picks up the new asset manifest.
//   2. Guardrails: never auto-reload while the browser reports offline, and
//      at most one auto-reload per RELOAD_WINDOW_MS per tab (sessionStorage),
//      so a truly broken deploy cannot cause an infinite reload loop.
//   3. If the guardrails refuse (offline, or the reload didn't fix it), a
//      customer-safe fallback card renders instead. Raw error text is never
//      shown. When the browser comes back online, it retries automatically.

const RELOAD_FLAG = 'cybermeters_chunk_reload_at'
const RELOAD_WINDOW_MS = 60_000

const CHUNK_ERROR_PATTERNS = [
  /failed to fetch dynamically imported module/i, // Chrome / Edge
  /error loading dynamically imported module/i,   // Firefox
  /importing a module script failed/i,            // Safari
  /unable to preload css/i,                       // Vite CSS preload failure
  /loading (css )?chunk .+ failed/i,
]

export function isChunkLoadError(error) {
  if (!error) return false
  if (error.name === 'ChunkLoadError') return true
  const msg = String(error.message || error)
  return CHUNK_ERROR_PATTERNS.some((re) => re.test(msg))
}

function lastAutoReloadAt() {
  try {
    return Number(sessionStorage.getItem(RELOAD_FLAG)) || 0
  } catch {
    // Storage unavailable (private mode) — fall back to "never reloaded",
    // meaning at most one reload per page lifetime since the flag can't stick.
    return 0
  }
}

function canAutoReload() {
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return false
  return Date.now() - lastAutoReloadAt() > RELOAD_WINDOW_MS
}

function markReloadAttempt() {
  try {
    sessionStorage.setItem(RELOAD_FLAG, String(Date.now()))
  } catch {
    /* still reload; the online check remains as a guardrail */
  }
}

// One guarded hard reload to fetch the latest asset manifest.
// Returns false when the guardrails refused (offline / recently reloaded).
// Also used by the vite:preloadError listener in main.jsx.
export function reloadForFreshAssets() {
  if (!canAutoReload()) return false
  markReloadAttempt()
  window.location.reload()
  return true
}

class ChunkBoundaryInner extends Component {
  state = { error: null, autoReloading: false }

  static getDerivedStateFromError(error) {
    // Decide here (read-only checks) whether a silent reload is coming, so
    // the very first fallback frame shows a spinner instead of flashing the
    // error card. The actual reload side effect runs in componentDidCatch.
    return { error, autoReloading: isChunkLoadError(error) && canAutoReload() }
  }

  componentDidCatch(error) {
    if (isChunkLoadError(error)) {
      const reloading = reloadForFreshAssets()
      if (reloading !== this.state.autoReloading) this.setState({ autoReloading: reloading })
    }
  }

  componentDidMount() {
    window.addEventListener('online', this.handleOnline)
  }

  componentWillUnmount() {
    window.removeEventListener('online', this.handleOnline)
  }

  componentDidUpdate(prevProps) {
    // Route changed while the fallback was showing (browser back/forward) —
    // clear the error and let the new route try to render.
    if (this.state.error && prevProps.routeKey !== this.props.routeKey) {
      this.setState({ error: null, autoReloading: false })
    }
  }

  handleOnline = () => {
    if (this.state.error && isChunkLoadError(this.state.error)) {
      if (reloadForFreshAssets()) this.setState({ autoReloading: true })
    }
  }

  // A deliberate click always reloads — the loop guardrail only limits
  // automatic reloads.
  handleManualReload = () => {
    markReloadAttempt()
    window.location.reload()
  }

  render() {
    const { error, autoReloading } = this.state
    if (!error) return this.props.children

    if (autoReloading) {
      return (
        <div className="min-h-[60vh] flex flex-col items-center justify-center gap-3 px-6">
          <div className="w-6 h-6 border-2 border-brand-600 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-gray-500">Loading the latest version of CyberMeters…</p>
        </div>
      )
    }

    const offline = typeof navigator !== 'undefined' && navigator.onLine === false
    const staleChunk = isChunkLoadError(error)

    return (
      <div className="min-h-[60vh] flex items-center justify-center px-6">
        <div className="card max-w-md w-full p-8 text-center">
          <div className="w-12 h-12 rounded-xl bg-brand-50 flex items-center justify-center mx-auto mb-4">
            {offline
              ? <WifiOff className="w-6 h-6 text-brand-600" />
              : <RefreshCw className="w-6 h-6 text-brand-600" />}
          </div>
          <h1 className="text-lg font-bold text-gray-900 mb-2">
            {staleChunk ? 'A new version of CyberMeters is available' : 'Something went wrong'}
          </h1>
          <p className="text-sm text-gray-600 leading-relaxed mb-6">
            {offline
              ? 'You appear to be offline. This page will refresh automatically once your connection returns.'
              : staleChunk
                ? 'This page could not be opened because the application was updated. Reload to continue with the latest version.'
                : 'An unexpected error occurred while displaying this page. Reloading usually resolves it.'}
          </p>
          <button onClick={this.handleManualReload} className="btn-primary mx-auto">
            <RefreshCw className="w-4 h-4" />
            Reload page
          </button>
        </div>
      </div>
    )
  }
}

// Wrapper so the class boundary can reset itself when the route changes.
export default function ChunkErrorBoundary({ children }) {
  const { pathname } = useLocation()
  return <ChunkBoundaryInner routeKey={pathname}>{children}</ChunkBoundaryInner>
}
