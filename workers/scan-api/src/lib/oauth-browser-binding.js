// ── Browser binding for Microsoft sign-in ────────────────────────────────────
// The browser that starts Microsoft sign-in keeps a random verifier and sends
// only its SHA-256 challenge with the start request. The one-time result of the
// sign-in is released only to a request that presents a verifier whose
// challenge matches. A callback or result link opened in another browser has
// no verifier, so it cannot finish someone else's sign-in there.
//
// The verifier never travels in a URL; the challenge is not secret.

// base64url of a 32-byte SHA-256 digest.
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
// base64url of at least 32 random bytes, bounded.
const VERIFIER = /^[A-Za-z0-9_-]{43,128}$/;

// A browser may hold a few verifiers from sign-ins started in other tabs.
export const MAX_BINDING_VERIFIERS = 5;

export function isBrowserBindingChallenge(value) {
  return typeof value === "string" && CHALLENGE.test(value);
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function browserBindingChallenge(verifier) {
  if (typeof verifier !== "string" || !VERIFIER.test(verifier)) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

// Challenges for the verifiers a request presents: well-formed ones only,
// de-duplicated and bounded.
export async function browserBindingChallenges(verifiers) {
  const list = Array.isArray(verifiers) ? verifiers.slice(0, MAX_BINDING_VERIFIERS) : [];
  const challenges = [];
  for (const verifier of list) {
    const challenge = await browserBindingChallenge(verifier);
    if (challenge && !challenges.includes(challenge)) challenges.push(challenge);
  }
  return challenges;
}
