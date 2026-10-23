// Removes the cache-busting ?_fresh=… that a fresh reload (src/lib/freshReload.js)
// adds, BEFORE the app's modules load — so it leaves the address bar even when
// the app then fails to boot (Codex C-42 on #925). A classic script outside
// /assets/: served no-cache, never part of a stale build. main.jsx strips it too.
(function () {
  try {
    var u = new URL(window.location.href)
    if (!u.searchParams.has('_fresh')) return
    u.searchParams['delete']('_fresh')
    window.history.replaceState(window.history.state, '', u.pathname + u.search + u.hash)
  } catch (e) { /* leave the address as it is */ }
})()
