import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { RUNNING_BUILD_ID, fetchDeployedBuildId, isDifferentBuild } from '../lib/appVersion'
import { hasUnsavedInput, installUnsavedInputTracker } from '../lib/unsavedInput'
import { freshReload } from '../lib/freshReload'

// A tab left open across a deploy keeps running the old bundle, which can talk
// to a changed API and look broken until a hard refresh (seen live 19 Oct 2026
// on the company form). On navigation and when the tab regains focus, compare
// this bundle's build id with /version.json and offer a refresh.
//
// The page never reloads itself mid-task. If the person has typed something
// they have not submitted, the banner says so and the button becomes "Refresh
// anyway". During onboarding a first-time user is never interrupted: no banner,
// and the new version loads on their next navigation when nothing is unsaved.
//
// The banner is a bar in the page flow, above the app, so it reserves its own
// space and can never cover a card (founder, 21 Oct 2026: it covered step 5).

const MIN_CHECK_INTERVAL_MS = 60_000
const isOnboarding = (pathname) => pathname === '/onboarding' || pathname.startsWith('/onboarding/')

export default function NewVersionBanner({
  runningBuildId = RUNNING_BUILD_ID,
  fetchBuildId = fetchDeployedBuildId,
  minCheckIntervalMs = MIN_CHECK_INTERVAL_MS,
  reload = () => freshReload(),
}) {
  const { pathname } = useLocation()
  const [available, setAvailable] = useState(false)
  const [dismissedOn, setDismissedOn] = useState(null)
  const [unsavedWarning, setUnsavedWarning] = useState(false)
  // The tab has just loaded the current build, so the first check waits.
  const lastCheckAt = useRef(Date.now())
  const inFlight = useRef(false)

  const check = useCallback(async () => {
    if (!runningBuildId || available || inFlight.current) return
    if (Date.now() - lastCheckAt.current < minCheckIntervalMs) return
    inFlight.current = true
    lastCheckAt.current = Date.now()
    try {
      if (isDifferentBuild(runningBuildId, await fetchBuildId())) setAvailable(true)
    } finally {
      inFlight.current = false
    }
  }, [runningBuildId, available, fetchBuildId, minCheckIntervalMs])

  useEffect(() => { installUnsavedInputTracker() }, [])

  const checkRef = useRef(check)
  checkRef.current = check
  useEffect(() => { checkRef.current() }, [pathname])

  useEffect(() => {
    const onFocus = () => { check() }
    const onVisible = () => { if (document.visibilityState === 'visible') check() }
    window.addEventListener('focus', onFocus)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      window.removeEventListener('focus', onFocus)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [check])

  // A warning about one page's input does not carry to the next page.
  useEffect(() => { setUnsavedWarning(false) }, [pathname])

  // Onboarding: apply a waiting version quietly on the next navigation.
  const silentFrom = useRef(null)
  useEffect(() => {
    if (!available) return
    if (silentFrom.current && silentFrom.current !== pathname && !hasUnsavedInput()) { reload(); return }
    if (isOnboarding(pathname)) silentFrom.current = pathname
  }, [available, pathname, reload])

  if (!available || dismissedOn === pathname || isOnboarding(pathname)) return null

  const onRefresh = () => {
    if (!unsavedWarning && hasUnsavedInput()) {
      setUnsavedWarning(true)
      return
    }
    reload()
  }

  return (
    <div className="border-b border-brand-200 bg-white" data-testid="new-version-banner">
      <div role="status" aria-live="polite" className="mx-auto flex max-w-(--breakpoint-xl) flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 py-2 sm:px-6">
        <p className="text-sm text-gray-700">
          <span className="font-semibold text-gray-900">A new version is available.</span>{' '}
          {unsavedWarning
            ? 'You have unsaved changes on this page. Save them first, then refresh.'
            : 'Refresh to load the latest CyberMeters.'}
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setDismissedOn(pathname)}
            className="rounded-xl px-3 py-1.5 text-xs font-semibold text-gray-600 hover:bg-gray-100"
          >
            Later
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="rounded-xl bg-brand-700 px-4 py-1.5 text-xs font-bold text-white transition-colors hover:bg-brand-800"
          >
            {unsavedWarning ? 'Refresh anyway' : 'Refresh'}
          </button>
        </div>
      </div>
    </div>
  )
}
