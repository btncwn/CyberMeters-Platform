// Browser binding for Microsoft sign-in.
//
// Before leaving for Microsoft, this browser keeps a random verifier and sends
// only its SHA-256 challenge. When Microsoft sends the user back, the API
// releases the sign-in only to a request that presents the verifier, so a
// sign-in link finished in another browser cannot sign that browser in.
//
// The verifier stays in this browser's storage and is sent only in the body of
// the exchange request; the challenge goes in the body of the start request.
// Neither appears in a URL.

const STORAGE_KEY = 'cm_ms_login_bindings'
const MAX_AGE_MS = 15 * 60 * 1000
// Sign-ins started in other tabs keep their own verifiers; the API reads at
// most five.
const MAX_KEPT = 5

function base64Url(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function storageOf(storage) {
  return storage ?? globalThis.localStorage
}

function readEntries(storage, now = Date.now()) {
  try {
    const list = JSON.parse(storageOf(storage).getItem(STORAGE_KEY) || '[]')
    return Array.isArray(list)
      ? list.filter(entry => typeof entry?.verifier === 'string' && Number.isFinite(entry?.at) && now - entry.at < MAX_AGE_MS)
      : []
  } catch {
    return []
  }
}

async function challengeOf(verifier, cryptoImpl) {
  const digest = await cryptoImpl.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64Url(new Uint8Array(digest))
}

/**
 * Create and store a verifier; returns its challenge for the start request.
 * Throws when the browser does not allow storage — sign-in cannot be bound.
 */
export async function createMicrosoftLoginBinding({ storage, cryptoImpl = globalThis.crypto, now = Date.now() } = {}) {
  const verifier = base64Url(cryptoImpl.getRandomValues(new Uint8Array(32)))
  const entries = [{ verifier, at: now }, ...readEntries(storage, now)].slice(0, MAX_KEPT)
  storageOf(storage).setItem(STORAGE_KEY, JSON.stringify(entries))
  return challengeOf(verifier, cryptoImpl)
}

/** The verifiers of sign-ins this browser started recently, newest first. */
export function microsoftLoginVerifiers({ storage, now = Date.now() } = {}) {
  return readEntries(storage, now).map(entry => entry.verifier)
}

/**
 * Forget the verifier of a finished sign-in (identified by its challenge),
 * keeping the verifiers of sign-ins still in progress in other tabs.
 */
export async function forgetMicrosoftLoginVerifier(challenge, { storage, cryptoImpl = globalThis.crypto, now = Date.now() } = {}) {
  if (typeof challenge !== 'string' || !challenge) return
  const kept = []
  for (const entry of readEntries(storage, now)) {
    if (await challengeOf(entry.verifier, cryptoImpl) !== challenge) kept.push(entry)
  }
  try {
    if (kept.length) storageOf(storage).setItem(STORAGE_KEY, JSON.stringify(kept))
    else storageOf(storage).removeItem(STORAGE_KEY)
  } catch { /* storage unavailable: nothing to forget */ }
}

const MICROSOFT_AUTHORIZE = /^https:\/\/login\.microsoftonline\.com\//

/**
 * Bind this browser, ask the API to start sign-in (`start` posts the
 * challenge and returns { authorize_url }), then leave for Microsoft.
 */
export async function startMicrosoftSignIn({ start, assign = (url) => window.location.assign(url), ...options }) {
  const challenge = await createMicrosoftLoginBinding(options)
  const result = await start(challenge)
  const url = result?.authorize_url
  if (typeof url !== 'string' || !MICROSOFT_AUTHORIZE.test(url)) throw new Error('Microsoft sign-in could not be started.')
  assign(url)
}
