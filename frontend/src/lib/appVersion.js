// Which build this tab is running, and which build is deployed now.
//
// __APP_BUILD_ID__ is compiled into the bundle by version-manifest.js, and the
// same id is written to /version.json, which is never cached. A tab left open
// across a deploy keeps running its old bundle until it reloads; comparing the
// two ids is how it finds out. Dev and test builds have no id, so the check is off.

export const RUNNING_BUILD_ID = typeof __APP_BUILD_ID__ === 'string' ? __APP_BUILD_ID__ : null

// The deployed build id, or null when it cannot be read. The SPA fallback
// answers a missing file with index.html, which fails to parse and reads as null.
export async function fetchDeployedBuildId(fetchImpl = globalThis.fetch) {
  try {
    const res = await fetchImpl('/version.json', { cache: 'no-store', headers: { accept: 'application/json' } })
    if (!res.ok) return null
    const body = await res.json()
    return typeof body?.build_id === 'string' && body.build_id ? body.build_id : null
  } catch {
    return null
  }
}

// Any different deployed build counts, a rollback included: either way the
// code in this tab is not what the server expects.
export function isDifferentBuild(running, deployed) {
  return Boolean(running && deployed && running !== deployed)
}
