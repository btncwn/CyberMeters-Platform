// Only five SHA-1 hex characters leave the server. Never log the password,
// hash, suffix, request URL or provider response. SHA-1 is only the lookup
// protocol; password storage continues to use the existing password hasher.
export async function checkPwnedPassword(password, { fetchImpl = fetch, timeoutMs = 5000 } = {}) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const controller = new AbortController();
  let timer;
  const operation = (async () => {
    const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
      headers: { 'Add-Padding': 'true', 'User-Agent': 'CyberMeters-Password-Screening', Accept: 'text/plain' },
      redirect: 'manual',
      signal: controller.signal,
    });
    if (response.status !== 200 ||
        !/^text\/plain(?:;|$)/i.test(response.headers.get('content-type') || '') ||
        Number(response.headers.get('content-length')) > 262144) {
      response.body?.cancel().catch(() => {});
      throw new Error();
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error();
    let size = 0, text = '';
    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 262144) throw new Error();
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
    } finally {
      reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    if (!text.trim()) throw new Error();
    let matched = false;
    for (const line of text.trim().split(/\r?\n/)) {
      const match = /^([A-F0-9]{35}):([0-9]{1,12})$/.exec(line);
      if (!match) throw new Error();
      // Zero-count entries are privacy padding, not compromised passwords.
      if (match[1] === hash.slice(5) && Number(match[2]) > 0) matched = true;
    }
    return matched ? 'compromised' : 'not_found';
  })();
  try {
    // A stalled body must obey the same deadline as the initial request.
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new Error()); }, timeoutMs);
    })]);
  } catch {
    return 'unavailable';
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

export async function newPasswordRejection(password) {
  const result = await checkPwnedPassword(password);
  if (result === 'compromised') return {
    status: 400,
    body: { code: 'password_compromised', error: 'This password appears in known breaches. Choose a different password.' },
  };
  if (result === 'unavailable') return {
    status: 503,
    body: { code: 'password_check_unavailable', error: 'The password security check is temporarily unavailable. Please try again.' },
  };
  return null;
}
