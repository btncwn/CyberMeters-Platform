#!/usr/bin/env node
// New passwords (signup, password reset) are screened against a bundled list of
// commonly used passwords. No outside service is called and nothing about the
// password leaves the server. Production auth routes, real migrated SQLite and
// synthetic identities only.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { setup } from './lib/password-screening-fixture.js';
import { buildEntries, digest, MAX_LENGTH, MIN_LENGTH } from './build-common-password-list.js';
import { COMMON_PASSWORD_LIST } from '../workers/scan-api/src/lib/common-passwords-data.js';
import { createCommonPasswordChecker, newPasswordRejection } from '../workers/scan-api/src/lib/common-passwords.js';
import { authRoutes } from '../workers/scan-api/src/routes/auth.js';
import { verifyPassword, hashPassword } from '../workers/scan-api/src/lib/password.js';

let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log('PASS ' + name); };

// Any outbound call fails the run: screening must be local.
let outbound = 0;
globalThis.fetch = async (url) => { outbound++; throw new Error(`Unexpected outbound call: ${url}`); };

const entries = COMMON_PASSWORD_LIST.entries.split('\n');
const common = entries[0];
const clear = 'Synthetic test password 2026!';
assert.ok(!entries.includes(clear.normalize('NFKC').toLowerCase()), 'fixture password must not be on the list');

await test('the bundled list verifies: count, SHA-256, length bounds, lowercase, sorted and unique', async () => {
  assert.equal(entries.length, COMMON_PASSWORD_LIST.count);
  assert.equal(digest(entries), COMMON_PASSWORD_LIST.sha256);
  assert.ok(COMMON_PASSWORD_LIST.count > 10000, 'the list is not a stub');
  assert.match(COMMON_PASSWORD_LIST.version, /^\d{4}-\d{2}-\d{2}\.\d+$/);
  assert.deepEqual(buildEntries(COMMON_PASSWORD_LIST.entries), entries, 'rebuilding the list from itself changes nothing');
  for (const entry of entries) {
    assert.ok(entry.length >= MIN_LENGTH && entry.length <= MAX_LENGTH, `length bound: ${entry.length}`);
    assert.equal(entry, entry.normalize('NFKC').toLowerCase());
  }
});

await test('listed passwords are refused in any letter case; others pass', async () => {
  const check = createCommonPasswordChecker(COMMON_PASSWORD_LIST);
  assert.equal(await check(common), 'common');
  assert.equal(await check(common.toUpperCase()), 'common');
  assert.equal(await check(entries.at(-1)), 'common');
  assert.equal(await check(clear), 'not_listed');
  const rejection = await newPasswordRejection(common);
  assert.equal(rejection.status, 400);
  assert.equal(rejection.body.code, 'password_too_common');
  assert.doesNotMatch(rejection.body.error, /breach/i, 'the message claims only the list it checked');
  assert.equal(await newPasswordRejection(clear), null);
});

await test('a missing, truncated or altered list fails closed', async () => {
  for (const broken of [
    { ...COMMON_PASSWORD_LIST, entries: '' },
    { ...COMMON_PASSWORD_LIST, entries: COMMON_PASSWORD_LIST.entries.slice(0, -100) },
    { ...COMMON_PASSWORD_LIST, entries: COMMON_PASSWORD_LIST.entries.replace(common, 'replaced entry here') },
    { ...COMMON_PASSWORD_LIST, sha256: '0'.repeat(64) },
    null,
  ]) {
    const check = createCommonPasswordChecker(broken);
    assert.equal(await check(clear), 'unavailable');
    const rejection = await newPasswordRejection(clear, { check });
    assert.equal(rejection.status, 503);
    assert.equal(rejection.body.code, 'password_check_unavailable');
  }
});

await test('over-long and unusual input is handled safely', async () => {
  const check = createCommonPasswordChecker(COMMON_PASSWORD_LIST);
  assert.equal(await check('x'.repeat(100000)), 'not_listed');
  assert.equal(await check('\u0000￿'), 'not_listed');
});

await test('first use stays within Worker limits', async () => {
  const check = createCommonPasswordChecker(COMMON_PASSWORD_LIST);
  const heapBefore = process.memoryUsage().heapUsed;
  const started = performance.now();
  await check(clear);
  const firstMs = performance.now() - started;
  const heapMb = (process.memoryUsage().heapUsed - heapBefore) / 1e6;
  const laterStarted = performance.now();
  for (let i = 0; i < 1000; i++) await check(`${clear}${i}`);
  const laterMs = (performance.now() - laterStarted) / 1000;
  console.log(`  list ${COMMON_PASSWORD_LIST.count} entries; first use ${firstMs.toFixed(1)} ms, ~${heapMb.toFixed(1)} MB; later checks ${laterMs.toFixed(3)} ms each`);
  assert.ok(firstMs < 2000, `first use ${firstMs} ms`);
  assert.ok(heapMb < 64, `heap ${heapMb} MB`);
  assert.ok(laterMs < 5, `later check ${laterMs} ms`);
});

function context(f, path, body) { return { ...f.context(path, { method: 'POST', body }), rateLimitScopeId: async (_, ip) => ip }; }

await test('a common signup password is refused before any email lookup or write', async () => {
  const f = setup(); let reads = 0;
  f.setFault(sql => { if (sql.includes('FROM users WHERE email')) reads++; return false; });
  for (const email of ['owner@example.com', 'new@example.com']) {
    const r = await authRoutes(context(f, '/api/auth/signup', { email, password: common, name: 'Synthetic' }));
    assert.equal(r.status, 400);
    assert.equal((await r.json()).code, 'password_too_common');
  }
  assert.equal(reads, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) n FROM users').get().n, 3);
});

await test('signup stores a clear password, with no outbound call', async () => {
  const f = setup(), before = outbound;
  const r = await authRoutes(context(f, '/api/auth/signup', { email: 'new@example.com', password: clear, name: 'Synthetic' }));
  assert.equal(r.status, 201, await r.clone().text());
  const row = f.db.prepare("SELECT password_hash FROM users WHERE email='new@example.com'").get();
  assert(await verifyPassword(clear, row.password_hash));
  assert.equal(outbound, before);
});

await test('clear-password signup has the same response for existing and new emails', async () => {
  const f = setup();
  try {
    for (const email of ['owner@example.com', 'new@example.com']) {
      const r = await authRoutes(context(f, '/api/auth/signup', { email, password: clear }));
      assert.equal(r.status, 201); const body = await r.json(); assert.equal(body.success, true); assert.equal(body.verification_required, true);
    }
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM users WHERE email='owner@example.com'").get().n, 1);
  } finally { f.db.close(); }
});

function resetFixture() {
  const f = setup(), token = 'SYNTHETIC-RESET-GUARD';
  f.db.prepare("INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES('reset','owner',?,?)")
    .run(createHash('sha256').update(token).digest('hex'), new Date(Date.now() + 3600000).toISOString());
  f.db.exec("UPDATE users SET password_hash='original' WHERE id='owner'");
  f.db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES('session','owner','fake',?)")
    .run(new Date(Date.now() + 3600000).toISOString());
  f.db.exec("INSERT INTO api_tokens(id,user_id,name,token_hash,scope,status) VALUES('api','owner','synthetic','fake-api','read','active')");
  return { ...f, invoke: (overrides, password = clear) => authRoutes({ ...context(f, '/api/auth/reset-password', { token, password }), ...overrides }) };
}
function unchanged(f) {
  assert.equal(f.db.prepare("SELECT password_hash FROM users WHERE id='owner'").get().password_hash, 'original');
  assert.equal(f.db.prepare("SELECT COUNT(*) n FROM user_sessions WHERE user_id='owner'").get().n, 1);
  assert.equal(f.db.prepare("SELECT status FROM api_tokens WHERE id='api'").get().status, 'active');
  assert.equal(f.db.prepare("SELECT COUNT(*) n FROM audit_events WHERE event_type='password_reset_completed'").get().n, 0);
}
const USER_READ = 'SELECT id, email FROM users WHERE id = ?';

await test('a common reset password preserves the token, password and sessions', async () => {
  const f = resetFixture();
  try {
    const r = await f.invoke({}, common);
    assert.equal(r.status, 400); assert.equal((await r.json()).code, 'password_too_common');
    unchanged(f); assert.equal(f.db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='reset'").get().used_at, null);
  } finally { f.db.close(); }
});

await test('a clear reset password resets, signs out and revokes, with no outbound call', async () => {
  const f = resetFixture(), before = outbound;
  try {
    const r = await f.invoke();
    assert.equal(r.status, 200, await r.clone().text());
    assert(await verifyPassword(clear, f.db.prepare("SELECT password_hash FROM users WHERE id='owner'").get().password_hash));
    assert(f.db.prepare('SELECT used_at FROM password_reset_tokens').get().used_at);
    assert.equal(f.db.prepare('SELECT COUNT(*) n FROM user_sessions').get().n, 0);
    assert.equal(outbound, before);
  } finally { f.db.close(); }
});

await test('expiry or token consumption mid-request cannot reset passwords or revoke sessions', async () => {
  for (const change of ["UPDATE password_reset_tokens SET used_at=datetime('now') WHERE id='reset'", "UPDATE password_reset_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE id='reset'"]) {
    const f = resetFixture();
    try {
      f.setPause(async (sql) => { if (sql.includes(USER_READ)) f.db.exec(change); });
      assert.equal((await f.invoke()).status, 400); unchanged(f);
    } finally { f.db.close(); }
  }
});

await test('two simultaneous requests can consume a reset link exactly once', async () => {
  const f = resetFixture(); let arrived = 0, release;
  const barrier = new Promise(resolve => { release = resolve; });
  try {
    f.setPause(async (sql) => { if (sql.includes(USER_READ)) { if (++arrived === 2) release(); await barrier; } });
    const result = await Promise.all([f.invoke(), f.invoke()]);
    assert.deepEqual(result.map(r => r.status).sort(), [200, 400]);
    assert.equal(arrived, 2);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM audit_events WHERE event_type='password_reset_completed'").get().n, 1);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM user_sessions WHERE user_id='owner'").get().n, 0);
    assert.equal(f.db.prepare("SELECT status FROM api_tokens WHERE id='api'").get().status, 'revoked');
  } finally { f.db.close(); }
});

await test('an error consuming the reset token rolls back password and credential changes', async () => {
  const f = resetFixture();
  try {
    f.setFault(sql => sql.startsWith('UPDATE password_reset_tokens SET used_at = ?'));
    assert.equal((await f.invoke()).status, 500); unchanged(f);
    assert.equal(f.db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='reset'").get().used_at, null);
  } finally { f.db.close(); }
});

await test('invalid reset links and denied abuse limits change nothing', async () => {
  const f = resetFixture();
  try {
    assert.equal((await authRoutes(context(f, '/api/auth/reset-password', { token: 'wrong', password: clear }))).status, 400);
    for (const status of [429, 503]) {
      let limited = 0;
      const r = await f.invoke({ consumeApiRateLimit: async (_env, scopes, name, limit, window, options) => {
        assert.deepEqual(scopes, [{ scope: 'user', scope_id: 'owner' }]); assert.equal(name, 'new_password_check');
        assert.equal(limit, 10); assert.equal(window, 900); assert.equal(options.failClosed, true); limited++; return { status };
      } });
      assert.equal(r.status, status); assert.equal(limited, 1);
      const signup = await authRoutes({ ...context(f, '/api/auth/signup', { email: 'new@example.com', password: clear }), consumeApiRateLimit: async () => ({ status }) });
      assert.equal(signup.status, status);
    }
    unchanged(f);
  } finally { f.db.close(); }
});

await test('existing users whose password is on the list still sign in (no forced change)', async () => {
  const f = setup(), before = outbound;
  try {
    f.db.prepare("UPDATE users SET password_hash=? WHERE id='owner'").run(await hashPassword(common));
    const r = await authRoutes(context(f, '/api/auth/login', { email: 'owner@example.com', password: common }));
    assert.equal(r.status, 200, await r.clone().text()); assert.equal(outbound, before);
  } finally { f.db.close(); }
});

await test('successful reset preserves another account credentials and sessions', async () => {
  const f = resetFixture();
  try {
    f.db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES('other-session','other','other-fake',?)")
      .run(new Date(Date.now() + 3600000).toISOString());
    f.db.exec("UPDATE users SET password_hash='other-original' WHERE id='other'; INSERT INTO api_tokens(id,user_id,name,token_hash,scope,status) VALUES('other-api','other','synthetic','other-fake-api','read','active')");
    assert.equal((await f.invoke()).status, 200);
    assert.equal(f.db.prepare("SELECT password_hash FROM users WHERE id='other'").get().password_hash, 'other-original');
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM user_sessions WHERE user_id='other'").get().n, 1);
    assert.equal(f.db.prepare("SELECT status FROM api_tokens WHERE id='other-api'").get().status, 'active');
  } finally { f.db.close(); }
});

assert.equal(outbound, 0, 'no screening path made an outbound call');
console.log(`${passed} common-password screening scenarios passed`);
