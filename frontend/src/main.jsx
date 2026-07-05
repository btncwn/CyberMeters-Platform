import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { reloadForFreshAssets } from './components/ChunkErrorBoundary.jsx'
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
