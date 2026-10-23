// First: clear any token from the address bar before other code reads the URL.
import './lib/urlSecretsOnLoad'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App, { preloadOpeningRoute } from './App.jsx'
import { reloadForFreshAssets, clearReloadBudget } from './components/ChunkErrorBoundary.jsx'
import { stripFreshParam } from './lib/freshReload'
import './index.css'

// A fresh reload (lib/freshReload) adds ?_fresh=… to beat the cache; take it out of the address bar.
stripFreshParam()

// Vite fires this when a dynamic-import preload (JS or CSS) 404s — typically
// because a deploy replaced the hashed assets. Reload once to pick up the new
// manifest; if the guardrails refuse (offline / just reloaded), let the error
// propagate so ChunkErrorBoundary can show its fallback instead.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadForFreshAssets(event.payload)) event.preventDefault()
})

function start() {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  )
}

// Load the opening public page first so its heading paints as soon as its code
// arrives (no loading fallback, no extra wait). A slow or failed load never
// holds the app back: after 3 s, or on an error, it renders as before and the
// usual loading and error handling take over.
const opening = preloadOpeningRoute(window.location.hostname, window.location.pathname)
if (opening) {
  let started = false
  const once = () => { if (!started) { started = true; start() } }
  opening.then(once, once)
  window.setTimeout(once, 3000)
} else {
  start()
}

// Restore the stale-chunk auto-reload budget once the app has loaded and run
// healthily for a few seconds. This lets a *later*, independent deploy auto-heal
// again instead of being mistaken for a reload loop (two deploys inside the
// 60s window used to dead-end the second one on the "Reload page" card). A real
// reload loop re-throws within this window — before the timer fires — so the
// loop guardrail stays intact.
window.setTimeout(clearReloadBudget, 10_000)
