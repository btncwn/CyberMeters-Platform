import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { reloadForFreshAssets, clearReloadBudget } from './components/ChunkErrorBoundary.jsx'
import './index.css'

// Vite fires this when a dynamic-import preload (JS or CSS) 404s — typically
// because a deploy replaced the hashed assets. Reload once to pick up the new
// manifest; if the guardrails refuse (offline / just reloaded), let the error
// propagate so ChunkErrorBoundary can show its fallback instead.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadForFreshAssets()) event.preventDefault()
})

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

// Restore the stale-chunk auto-reload budget once the app has loaded and run
// healthily for a few seconds. This lets a *later*, independent deploy auto-heal
// again instead of being mistaken for a reload loop (two deploys inside the
// 60s window used to dead-end the second one on the "Reload page" card). A real
// reload loop re-throws within this window — before the timer fires — so the
// loop guardrail stays intact.
window.setTimeout(clearReloadBudget, 10_000)
