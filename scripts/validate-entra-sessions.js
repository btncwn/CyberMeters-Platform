#!/usr/bin/env node
// Offline provider contract. Every fetch is synthetic; no credentials or real
// directory users are loaded. Network is forbidden unless the injected stub runs.
import assert from 'node:assert/strict';
import { createEntraSessionClient, EntraSessionError } from '../workers/scan-api/src/engines/entra-sessions.js';

globalThis.fetch = async () => { throw new Error('Unexpected live network call'); };
const tenantId = '11111111-1111-4111-8111-111111111111';
const clientId = '22222222-2222-4222-8222-222222222222';
const userId = '33333333-3333-4333-8333-333333333333';
const upn = 'test@example.onmicrosoft.com';
const credentials = { tenantId, clientId, clientSecret: 'SYNTHETIC.secret+not-real/123' };
const initial = '2026-10-09T12:00:00Z';
let total = 0;
async function test(name, fn) { await fn(); total++; console.log('PASS ' + name); }
function setup(overrides = {}) {
  let time = Date.parse('2026-10-09T16:00:00Z');
  const calls = [];
  const user = { id: userId, userPrincipalName: upn, displayName: 'Synthetic test user', userType: 'Member', accountEnabled: true, signInSessionsValidFromDateTime: initial };
  const fetchImpl = async (url, options) => {
    calls.push({ url, ...options });
    assert.equal(options.redirect, 'manual'); assert(options.signal instanceof AbortSignal);
    if (url === `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`) {
      const form = new URLSearchParams(options.body);
      assert.equal(form.get('client_id'), clientId);
      assert.equal(form.get('client_secret'), credentials.clientSecret);
      assert.equal(form.get('scope'), 'https://graph.microsoft.com/.default');
      assert.equal(form.get('grant_type'), 'client_credentials');
      return overrides.token ? overrides.token(options) : Response.json({ token_type: 'Bearer', access_token: 'SYNTHETIC-access-token', expires_in: 3600 });
    }
    assert.equal(new URL(url).origin, 'https://graph.microsoft.com');
    assert.equal(options.headers.Authorization, 'Bearer SYNTHETIC-access-token');
    assert(!url.includes(credentials.clientSecret));
    if (url.endsWith('/revokeSignInSessions')) {
      assert.equal(url, `https://graph.microsoft.com/v1.0/users/${userId}/revokeSignInSessions`);
      assert.equal(options.method, 'POST'); assert.equal(options.body, undefined);
      return overrides.revoke ? overrides.revoke(options) : Response.json({ value: true });
    }
    assert.equal(options.method, 'GET');
    const path = new URL(url).pathname;
    assert([`/v1.0/users/${encodeURIComponent(upn)}`, `/v1.0/users/${userId}`].includes(path));
    assert.deepEqual([...new URL(url).searchParams.keys()], ['$select']);
    return overrides.user ? overrides.user(user, options) : Response.json(user);
  };
  const client = createEntraSessionClient(credentials, { fetchImpl, now: () => time, timeoutMs: 50 });
  return { client, calls, user, advance: ms => { time += ms; }, posts: () => calls.filter(c => c.url.endsWith('/revokeSignInSessions')) };
}
async function rejects(fn, code, uncertain = false) {
  await assert.rejects(fn, error => error instanceof EntraSessionError && error.code === code && error.uncertain === uncertain && !error.message.includes('SYNTHETIC'));
}
const confirm = { confirmedUpn: upn, authorize: async () => true };

await test('preview only reads one exact user and never revokes', async () => {
  const s = setup(), p = await s.client.preview(upn.toUpperCase());
  assert.equal(p.id, userId); assert.equal(p.upn, upn); assert.equal(p.tenantId, tenantId); assert(Object.isFrozen(p));
  assert.equal(s.calls.length, 2); assert.equal(s.posts().length, 0);
  assert(!JSON.stringify(p).includes('SYNTHETIC')); assert(!JSON.stringify(p).includes(credentials.clientSecret));
});
await test('confirmed action checks exact immutable id again and reports acceptance only', async () => {
  const s = setup(), p = await s.client.preview(upn);
  let authorized = 0;
  const result = await s.client.revoke(p, { ...confirm, authorize: async () => { authorized++; return true; } });
  assert.equal(s.posts().length, 1); assert.equal(authorized, 2);
  assert.equal(result.status, 'provider_accepted'); assert.equal(result.logoutVerified, false);
  assert.match(result.note, /not proof/); assert.equal(result.userId, userId);
  assert.equal(s.calls[2].url.split('?')[0], `https://graph.microsoft.com/v1.0/users/${userId}`);
});
for (const bad of ['common', 'organizations', '../other', `${tenantId}/../common`, '', null]) await test('invalid tenant before network: ' + String(bad), async () => {
  assert.throws(() => createEntraSessionClient({ ...credentials, tenantId: bad }), EntraSessionError);
});
for (const bad of ['test@example.onmicrosoft.com/other', "x')/users@tenant.test", 'guest#EXT#@tenant.test', 'a@b.test,c@d.test', ' https://example.test', null]) await test('invalid UPN before network: ' + String(bad), async () => {
  const s = setup(); await rejects(() => s.client.preview(bad), 'invalid_input'); assert.equal(s.calls.length, 0);
});
await test('preview copy is not an authorized provider action', async () => {
  const s = setup(), p = await s.client.preview(upn);
  await rejects(() => s.client.revoke({ ...p }, confirm), 'preview_expired_or_used'); assert.equal(s.posts().length, 0);
});
await test('preview cannot cross client/tenant instances', async () => {
  const a = setup(), b = setup(), p = await a.client.preview(upn);
  await rejects(() => b.client.revoke(p, confirm), 'preview_expired_or_used'); assert.equal(b.calls.length, 0);
});
await test('wrong confirmation or absent authorization never writes', async () => {
  const s = setup(), p = await s.client.preview(upn);
  await rejects(() => s.client.revoke(p, { ...confirm, confirmedUpn: 'other@example.test' }), 'confirmation_required');
  await rejects(() => s.client.revoke(p, { confirmedUpn: upn }), 'confirmation_required'); assert.equal(s.posts().length, 0);
});
await test('expired preview does not even re-read user', async () => {
  const s = setup(), p = await s.client.preview(upn); s.advance(300000);
  await rejects(() => s.client.revoke(p, confirm), 'preview_expired_or_used'); assert.equal(s.calls.length, 2);
});
await test('concurrent action attempts send exactly one POST', async () => {
  const s = setup(), p = await s.client.preview(upn);
  const results = await Promise.allSettled([s.client.revoke(p, confirm), s.client.revoke(p, confirm)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1); assert.equal(s.posts().length, 1);
});
await test('authorization withdrawn before or during read prevents write', async () => {
  for (const allowance of [0, 1]) {
    const s = setup(), p = await s.client.preview(upn); let calls = 0;
    await rejects(() => s.client.revoke(p, { ...confirm, authorize: async () => calls++ < allowance }), 'authorization_changed'); assert.equal(s.posts().length, 0);
  }
});
for (const [field, value, code] of [
  ['id', clientId, 'target_changed'], ['userPrincipalName', 'other@example.test', 'target_changed'],
  ['userType', 'Guest', 'unsupported_user'], ['accountEnabled', false, 'unsupported_user'],
  ['signInSessionsValidFromDateTime', '2026-10-09T15:00:00Z', 'target_changed'],
]) await test('changed ' + field + ' cancels before revoke', async () => {
  const s = setup(), p = await s.client.preview(upn); s.user[field] = value;
  await rejects(() => s.client.revoke(p, confirm), code); assert.equal(s.posts().length, 0);
});
for (const validFrom of [undefined, '', 'bad-time', 123]) await test('missing/invalid session baseline is not silently accepted: ' + String(validFrom), async () => {
  const s = setup(); s.user.signInSessionsValidFromDateTime = validFrom;
  await rejects(() => s.client.preview(upn), 'invalid_provider_response'); assert.equal(s.posts().length, 0);
});
await test('explicit null baseline can be previewed without inventing timestamp', async () => {
  const s = setup(); s.user.signInSessionsValidFromDateTime = null;
  assert.equal((await s.client.preview(upn)).sessionsValidFrom, null);
});
for (const status of [301, 401, 403, 429, 500]) await test('token HTTP ' + status + ' cannot reach Graph', async () => {
  const s = setup({ token: () => new Response('SYNTHETIC-secret-error', { status }) });
  await rejects(() => s.client.preview(upn), [401,403].includes(status) ? 'provider_access_denied' : status === 429 ? 'provider_rate_limited' : 'provider_unavailable');
  assert.equal(s.calls.length, 1);
});
for (const data of [{}, { token_type: 'Bearer', access_token: 'x\r\ninjected', expires_in: 3600 }, { token_type: 'Bearer', access_token: 'token', expires_in: '3600' }]) await test('malformed token response never reaches Graph ' + JSON.stringify(data), async () => {
  const s = setup({ token: () => Response.json(data) });
  await rejects(() => s.client.preview(upn), 'invalid_provider_response'); assert.equal(s.calls.length, 1);
});
for (const status of [301, 401, 403, 404, 429, 500]) await test('user lookup HTTP ' + status + ' prevents revoke', async () => {
  const s = setup({ user: () => new Response('', { status }) });
  await assert.rejects(() => s.client.preview(upn), EntraSessionError); assert.equal(s.posts().length, 0);
});
for (const [name, response] of [
  ['oversized header', () => new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '32769' } })],
  ['oversized stream', () => new Response('x'.repeat(32769), { headers: { 'Content-Type': 'application/json' } })],
  ['HTML', () => new Response('<html>private</html>')],
  ['broken JSON', () => new Response('{', { headers: { 'Content-Type': 'application/json' } })],
  ['array', () => Response.json([])],
]) await test('bounded provider parser refuses ' + name, async () => {
  const s = setup({ user: response }); await rejects(() => s.client.preview(upn), 'invalid_provider_response'); assert.equal(s.posts().length, 0);
});
for (const [status, code, uncertain] of [[302,'provider_unavailable',true],[401,'provider_access_denied',false],[403,'provider_access_denied',false],[429,'provider_rate_limited',true],[500,'provider_unavailable',true]]) await test('revoke HTTP ' + status + ' is never a success and never retried', async () => {
  const s = setup({ revoke: () => new Response('provider-private-details', { status }) }), p = await s.client.preview(upn);
  await rejects(() => s.client.revoke(p, confirm), code, uncertain);
  await rejects(() => s.client.revoke(p, confirm), 'preview_expired_or_used'); assert.equal(s.posts().length, 1);
});
for (const data of [{ value: false }, {}, { value: 'true' }]) await test('non-affirmative revoke body is uncertain ' + JSON.stringify(data), async () => {
  const s = setup({ revoke: () => Response.json(data) }), p = await s.client.preview(upn);
  await rejects(() => s.client.revoke(p, confirm), 'invalid_provider_response', true);
});
await test('empty HTTP204 is provider acceptance, not logout proof', async () => {
  const s = setup({ revoke: () => new Response(null, { status: 204 }) }), p = await s.client.preview(upn);
  const r = await s.client.revoke(p, confirm); assert.equal(r.status, 'provider_accepted'); assert.equal(r.logoutVerified, false);
});
await test('stalled lookup has bounded deadline', async () => {
  const s = setup({ user: () => new Promise(() => {}) });
  await rejects(() => s.client.preview(upn), 'provider_timeout'); assert.equal(s.posts().length, 0);
});
await test('stalled response body has the same deadline', async () => {
  const s = setup({ user: () => new Response(new ReadableStream({ start() {} }), { headers: { 'Content-Type': 'application/json' } }) });
  await rejects(() => s.client.preview(upn), 'provider_timeout'); assert.equal(s.posts().length, 0);
});
await test('lost revoke response remains uncertain with one physical attempt', async () => {
  const s = setup({ revoke: () => new Promise(() => {}) }), p = await s.client.preview(upn);
  await rejects(() => s.client.revoke(p, confirm), 'provider_timeout', true);
  await rejects(() => s.client.revoke(p, confirm), 'preview_expired_or_used'); assert.equal(s.posts().length, 1);
});
await test('expiry during final authorization is checked before mutation', async () => {
  const s = setup(), p = await s.client.preview(upn); let count = 0;
  await rejects(() => s.client.revoke(p, { ...confirm, authorize: async () => { if (++count === 2) s.advance(300000); return true; } }), 'preview_expired_or_used');
  assert.equal(s.posts().length, 0);
});
console.log(`${total}/${total} Entra adapter controls passed. Live provider calls: 0.`);
