// Request-local provider adapter. Product routes enforce workspace authority,
// explicit confirmation and durable, one-attempt action records. No secret store.
const GRAPH = 'https://graph.microsoft.com/v1.0';
const SELECT = 'id,userPrincipalName,displayName,userType,accountEnabled,signInSessionsValidFromDateTime';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOTE = 'Microsoft accepted the session revocation request. Propagation can take several minutes. Existing access tokens and application-owned sessions may remain valid. This is not proof of a completed logout or remediation.';

export class EntraSessionError extends Error {
  constructor(code, uncertain = false) {
    super('The Entra request could not be confirmed.');
    this.name = 'EntraSessionError';
    this.code = code;
    this.uncertain = uncertain;
  }
}
const fail = (code, uncertain = false) => { throw new EntraSessionError(code, uncertain); };
const uuid = value => {
  if (typeof value !== 'string' || !UUID.test(value)) fail('invalid_input');
  return value.toLowerCase();
};
export function normalizeEntraUpn(value) {
  // Initial cloud-member pilot excludes B2B guests, OData punctuation and lists.
  if (typeof value !== 'string' || value.length > 254 || value !== value.trim() ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$/.test(value)) fail('invalid_input');
  return value.toLowerCase();
}
async function readJson(response) {
  const maximum = 32768;
  if (Number(response.headers.get('content-length')) > maximum) fail('invalid_provider_response');
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')) fail('invalid_provider_response');
  const reader = response.body?.getReader();
  if (!reader) fail('invalid_provider_response');
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) fail('invalid_provider_response');
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_provider_response');
    return value;
  } catch (error) {
    if (error instanceof EntraSessionError) throw error;
    fail('invalid_provider_response');
  } finally {
    // The request deadline aborts the transport too. Do not await a malicious
    // stream's cancel promise before releasing the bounded provider operation.
    reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function createEntraSessionClient(credentials, { fetchImpl = fetch, timeoutMs = 8000, now = () => Date.now() } = {}) {
  const tenantId = uuid(credentials?.tenantId), clientId = uuid(credentials?.clientId);
  const secret = credentials?.clientSecret;
  if (typeof secret !== 'string' || secret.length < 16 || secret.length > 2048 || /[\r\n\0]/.test(secret) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15000) fail('invalid_input');
  // Request-local token only. Never a module/global cache shared by tenants.
  let token, tokenExpires = 0;
  const previews = new WeakMap();
  async function request(stage, url, options, writing = false) {
    const controller = new AbortController();
    let timer, httpStatus = null;
    const operation = (async () => {
      const response = await fetchImpl(url, { ...options, redirect: 'manual', signal: controller.signal });
      httpStatus = response.status;
      if (response.status === 401 || response.status === 403) fail('provider_access_denied');
      if (response.status === 404 && !writing) fail('user_not_found');
      if (response.status === 429) fail('provider_rate_limited', writing);
      if (!response.ok) fail('provider_unavailable', writing && response.status >= 300);
      if (writing && response.status === 204) return { value: true };
      // A 202 is not the completed result of a user lookup or token grant.
      if (response.status !== 200) fail('invalid_provider_response', writing);
      return await readJson(response);
    })();
    try {
      return await Promise.race([operation, new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new EntraSessionError('provider_timeout', writing)); }, timeoutMs);
      })]);
    } catch (error) {
      const failure = error instanceof EntraSessionError ? error : new EntraSessionError('provider_unavailable', writing);
      if (writing && failure.code === 'invalid_provider_response') failure.uncertain = true;
      // Only a code-owned phase and HTTP status leave the provider boundary.
      // Never include request URLs, headers, credentials or provider error bodies.
      failure.stage = stage;
      failure.httpStatus = httpStatus;
      throw failure;
    } finally { clearTimeout(timer); controller.abort(); }
  }
  async function accessToken() {
    if (token && now() < tokenExpires) return token;
    const started = now();
    const body = new URLSearchParams({ client_id: clientId, client_secret: secret, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' });
    const data = await request('token_exchange', `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(),
    });
    if (data.token_type?.toLowerCase() !== 'bearer' || typeof data.access_token !== 'string' ||
        !/^[a-zA-Z0-9._~+\/-]+={0,2}$/.test(data.access_token) || data.access_token.length > 24000 ||
        !Number.isInteger(data.expires_in) || data.expires_in < 60 || data.expires_in > 86400) fail('invalid_provider_response');
    token = data.access_token; tokenExpires = started + (data.expires_in - 30) * 1000;
    return token;
  }
  async function readUser(identifier, expectedUpn, expectedId) {
    const bearer = await accessToken();
    const user = await request('user_lookup', `${GRAPH}/users/${encodeURIComponent(identifier)}?${new URLSearchParams({ '$select': SELECT })}`, {
      method: 'GET', headers: { Authorization: `Bearer ${bearer}`, Accept: 'application/json' },
    });
    let id, upn;
    try { id = uuid(user.id); upn = normalizeEntraUpn(user.userPrincipalName); } catch { fail('invalid_provider_response'); }
    if (upn !== expectedUpn || (expectedId && id !== expectedId)) fail('target_changed');
    if (user.userType !== 'Member' || user.accountEnabled !== true) fail('unsupported_user');
    const validFrom = user.signInSessionsValidFromDateTime;
    if (validFrom !== null && (typeof validFrom !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/.test(validFrom) || !Number.isFinite(Date.parse(validFrom)))) fail('invalid_provider_response');
    return {
      id, upn,
      displayName: typeof user.displayName === 'string' ? user.displayName.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 256) : '',
      sessionsValidFrom: validFrom,
    };
  }
  return Object.freeze({
    async read(upnInput, expectedId) {
      const upn = normalizeEntraUpn(upnInput);
      return { tenantId, clientId, ...await readUser(expectedId ? uuid(expectedId) : upn, upn, expectedId ? uuid(expectedId) : undefined) };
    },
    async observe(upnInput) {
      const upn = normalizeEntraUpn(upnInput), user = await readUser(upn, upn);
      const bearer = await accessToken();
      const headers = { Authorization: `Bearer ${bearer}`, Accept: 'application/json' };
      let roles = { state: 'unavailable', items: [], scope: 'direct_membership_only' };
      let authentication = { state: 'unavailable', mfaRegistered: null, mfaEnforced: 'not_assessed' };
      try {
        const data = await request('role_lookup', `${GRAPH}/users/${user.id}/memberOf/microsoft.graph.directoryRole?$select=id,displayName&$top=100`, { method: 'GET', headers });
        if (!Array.isArray(data.value) || data.value.length > 100) fail('invalid_provider_response');
        const items = data.value.map(item => ({ id: uuid(item.id), name: typeof item.displayName === 'string' ? item.displayName.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 256) : null }));
        roles = { state: data['@odata.nextLink'] || items.some(i => i.name === null) ? 'partial' : 'observed', items, scope: 'direct_membership_only' };
      } catch { /* Missing permission/provider response is not "no roles". */ }
      try {
        const data = await request('authentication_registration', `${GRAPH}/reports/authenticationMethods/userRegistrationDetails/${user.id}`, { method: 'GET', headers });
        if (uuid(data.id) !== user.id || normalizeEntraUpn(data.userPrincipalName) !== upn || typeof data.isMfaRegistered !== 'boolean') fail('invalid_provider_response');
        authentication = { state: 'observed', mfaRegistered: data.isMfaRegistered, mfaEnforced: 'not_assessed', reportUpdatedAt: typeof data.lastUpdatedDateTime === 'string' && Number.isFinite(Date.parse(data.lastUpdatedDateTime)) ? data.lastUpdatedDateTime : null };
      } catch { /* Report permissions and Microsoft licensing may be absent. */ }
      return { tenantId, clientId, ...user, accountEnabled: true, accountType: 'Member', checkedAt: new Date(now()).toISOString(), roles, authentication, breachMonitoring: 'not_available' };
    },
    async preview(upnInput) {
      const upn = normalizeEntraUpn(upnInput), user = await readUser(upn, upn);
      const value = Object.freeze({ tenantId, clientId, ...user, action: 'revoke_sessions', createdAt: new Date(now()).toISOString(), expiresAt: new Date(now() + 300000).toISOString() });
      previews.set(value, { user, expires: now() + 300000, consumed: false });
      return value;
    },
    async revoke(preview, { confirmedUpn, authorize } = {}) {
      const state = previews.get(preview);
      if (!state || state.consumed || now() >= state.expires) fail('preview_expired_or_used');
      if (normalizeEntraUpn(confirmedUpn) !== state.user.upn || typeof authorize !== 'function') fail('confirmation_required');
      // One attempt per in-memory preview, including concurrency and uncertain
      // outcomes. A durable product action layer must additionally prevent replay.
      state.consumed = true;
      if (await authorize() !== true) fail('authorization_changed');
      const current = await readUser(state.user.id, state.user.upn, state.user.id);
      if (current.sessionsValidFrom !== state.user.sessionsValidFrom) fail('target_changed');
      const bearer = await accessToken();
      if (await authorize() !== true) fail('authorization_changed');
      if (now() >= state.expires) fail('preview_expired_or_used');
      const requestedAt = new Date(now()).toISOString();
      const data = await request('session_revocation', `${GRAPH}/users/${state.user.id}/revokeSignInSessions`, {
        method: 'POST', headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json' },
      }, true);
      if (data.value !== true) fail('invalid_provider_response', true);
      return Object.freeze({ status: 'provider_accepted', tenantId, userId: state.user.id, upn: state.user.upn, requestedAt, logoutVerified: false, note: NOTE });
    },
  });
}
