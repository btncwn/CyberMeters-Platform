import { lazy, useState } from 'react'

// A lazily loaded page that can also be loaded before the first render.
//
// React shows a Suspense fallback while a lazy page downloads, and once it has
// shown one it holds the real content back for at least 300 ms more. On the
// first visit to a public page (the homepage, the free scan) that wait sat
// between the code arriving and the heading painting. main.jsx loads the page
// for the opening route first, so the first render has it and no fallback is
// shown. Every later navigation behaves exactly as React.lazy.
export function preloadableLazy(factory) {
  let loaded = null
  let pending = null
  const load = () => {
    pending ??= factory().then(
      (mod) => { loaded = mod; return mod },
      (error) => { pending = null; throw error },
    )
    return pending
  }
  const Lazy = lazy(load)

  function PreloadableLazy(props) {
    // Decided once per mount: switching from the lazy wrapper to the module
    // later would remount the page and lose its state.
    const [Page] = useState(() => loaded?.default ?? null)
    return Page ? <Page {...props} /> : <Lazy {...props} />
  }
  PreloadableLazy.load = load
  return PreloadableLazy
}
