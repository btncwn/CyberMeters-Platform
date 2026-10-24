// C-58: execute the production SQL over mixed-format, same-day SQLite rows.
// Imported by the existing workflow gate; no live database or network access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { splitStatements, isToleratedStatement } from '../lib/migration-apply-tolerated.js';
import { countScansThisMonth } from '../../workers/scan-api/src/engines/plan-usage.js';
import { purgeExpiredMcpOAuthRefreshUses } from '../../workers/scan-api/src/routes/mcp-oauth-purge.js';
import { collectChangeEvents } from '../../workers/scan-api/src/engines/related-changes-adapter.js';
import { correlateRelatedChanges } from '../../workers/scan-api/src/engines/related-changes.js';
import { reassessExpiredRiskAcceptedCases } from '../../workers/scan-api/src/engines/asm-cases.js';
import { applyCaseTransition } from '../../workers/scan-api/src/engines/case-workflow.js';
import { ASM_CASE_MACHINE, ASM_CASE_TYPE } from '../../workers/scan-api/src/engines/asm-case-machine.js';

const root = new URL('../../', import.meta.url);
const read = file => fs.readFileSync(new URL(file, root), 'utf8');
// These internal route predicates have no public helper. Execute their exact
// source literals instead of adding production exports solely for tests.
function literal(file, includes) {
  const matches = [...read(`workers/scan-api/src/${file}`).matchAll(/`([^`]+)`/g)]
    .map(match => match[1]).filter(sql => includes.every(text => sql.includes(text)));
  assert.equal(matches.length, 1, `one production SQL literal: ${file} ${includes}`);
  return matches[0];
}
function plainComparison(sql) { return sql.replace(/julianday\(([^()]*)\)/g, '$1'); }
function setup() {
  const db = new DatabaseSync(':memory:');
  db.exec(read('database/schema.sql'));
  for (const name of fs.readdirSync(new URL('database/migrations/', root)).filter(f => f.endsWith('.sql')).sort()) {
    const sql = read(`database/migrations/${name}`);
    const hash = createHash('sha256').update(sql).digest('hex');
    for (const statement of splitStatements(sql)) {
      try { db.exec(statement); } catch (error) {
        if (!isToleratedStatement(name, hash, statement, error.message)) throw error;
      }
    }
  }
  const stmt = (sql, args = []) => ({
    bind: (...args) => stmt(sql, args),
    first: async column => { const row = db.prepare(sql).get(...args) ?? null; return column && row ? row[column] : row; },
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => ({ meta: { changes: db.prepare(sql).run(...args).changes } }),
  });
  for (const id of ['owner', 'foreign']) db.prepare('INSERT INTO users(id,email) VALUES(?,?)').run(id, `${id}@example.test`);
  for (const [id, owner] of [['ws', 'owner'], ['other', 'foreign']]) {
    db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').run(id, id, owner);
  }
  db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('dom','owner','example.test')").run();
  db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('ws','dom','verified')").run();
  return { db, env: { cybermeters_db: { prepare: sql => stmt(sql) } } };
}
let sites = 0;
async function test(name, run) { await run(); sites++; console.log(`PASS timestamp comparisons: ${name}`); }
const RealDate = Date;
const now = '2026-10-01T12:00:00.000Z';
// Freeze JavaScript's month boundary and case timestamps. The password-reset
// fixture freezes SQLite's clock literal independently in its production SQL.
globalThis.Date = class extends RealDate {
  constructor(...args) { super(...(args.length ? args : [now])); }
  static now() { return RealDate.parse(now); }
};
try {
  await test('month counts, display counts and atomic network admission', async () => {
    const { db, env } = setup();
    const add = db.prepare("INSERT INTO scans(id,workspace_id,domain_id,domain,status,created_at) VALUES(?,?, 'dom','example.test','completed',?)");
    for (const [id, at] of [['sql','2026-10-01 10:00:00'], ['iso','2026-10-01T11:00:00.000Z'],
      ['boundary','2026-10-01 00:00:00'], ['before','2026-09-30T23:59:59.999Z']]) add.run(id, 'ws', at);
    add.run('foreign', 'other', '2026-10-01 10:00:00');
    db.prepare("INSERT INTO network_targets(id,workspace_id,target,target_type,address_count,addresses_json,authorization_status,authorized_by,authorized_at,created_at) VALUES('target','ws','192.0.2.1','ip',1,'[]','attested','owner',?,?)").run(now,now);
    db.prepare("INSERT INTO network_scans(id,workspace_id,target_id,requested_by,ports_json,status,receipt_key,created_at) VALUES('net','ws','target','owner','[443]','completed','fixture','2026-10-01 10:00:00')").run();
    assert.equal(await countScansThisMonth('owner', env), 4);
    const month = '2026-10-01T00:00:00.000Z';
    const usage = literal('routes/network-assets.js', ['SELECT (SELECT COUNT(*) FROM scans', 'AS cnt']);
    assert.equal(db.prepare(usage).get('owner', month, 'owner', month).cnt, 4);
    assert.equal(db.prepare(plainComparison(usage)).get('owner', month, 'owner', month).cnt, 1);
    const quota = literal('routes/network-assets.js', ['((SELECT COUNT(*) FROM scans', '))<?']);
    assert.equal(db.prepare(`SELECT ${quota} AS allowed`).get('owner', month, 'owner', month, 4).allowed, 0);
    assert.equal(db.prepare(`SELECT ${plainComparison(quota)} AS allowed`).get('owner', month, 'owner', month, 4).allowed, 1);
    for (const completed of [false, true]) {
      const display = literal('routes/workspace-insights.js', ['COUNT(DISTINCT s.id)', completed ? "s.status = 'completed'" : 'WHERE julianday(s.created_at)']);
      assert.equal(db.prepare(display).get(month, 'ws', 'ws').n, 3);
      assert.equal(db.prepare(plainComparison(display)).get(month, 'ws', 'ws').n, 1);
    }
    db.close();
  });

  await test('refresh retention delete and pending bounds', async () => {
    const { db, env } = setup();
    db.prepare("INSERT INTO mcp_oauth_connections(id,user_id,client_id,resource,workspace_id,portfolio_read,granted_scopes) VALUES('connection','owner','fixture','https://mcp.example.test/mcp','ws',0,'[]')").run();
    const add = db.prepare("INSERT INTO mcp_oauth_refresh_uses(token_hash,connection_id,expires_at) VALUES(?,'connection',?)");
    for (const [id, at] of [['old','2026-10-01 10:00:00'], ['boundary','2026-10-01 12:00:00'], ['future','2026-10-01 13:00:00']]) add.run(id, at);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM mcp_oauth_refresh_uses WHERE expires_at < ?').get(now).n, 3);
    assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now, { batchSize: 1, maxBatches: 1 }), { deleted: 1, pending: false });
    assert.deepEqual(db.prepare('SELECT token_hash FROM mcp_oauth_refresh_uses ORDER BY token_hash').all().map(r => r.token_hash), ['boundary', 'future']);
    add.run('old_again', '2026-10-01T11:00:00.000Z');
    add.run('old_third', '2026-10-01 11:30:00');
    const warn = console.warn;
    console.warn = () => {};
    try { assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now, { batchSize: 1, maxBatches: 1 }), { deleted: 1, pending: true }); }
    finally { console.warn = warn; }
    assert.deepEqual(await purgeExpiredMcpOAuthRefreshUses(env, now), { deleted: 1, pending: false });
    db.close();
  });

  await test('adjacent complete scan uses chronological bound and ordering', async () => {
    const { db, env } = setup();
    const insert = db.prepare("INSERT INTO scans(id,workspace_id,domain_id,domain,status,scan_quality,created_at) VALUES(?,'ws','dom','example.test','completed','complete',?)");
    for (const [id, at] of [['old','2026-10-01T09:00:00.000Z'], ['latest','2026-10-01 10:00:00'], ['future','2026-10-01 13:00:00'], ['current',now]]) insert.run(id, at);
    const query = literal('engines/related-changes.js', ['SELECT created_at FROM scans', 'ORDER BY']);
    assert.equal(db.prepare(query).get('dom','ws','current',now).created_at, '2026-10-01 10:00:00');
    assert.equal(db.prepare(plainComparison(query)).get('dom','ws','current',now).created_at, '2026-10-01T09:00:00.000Z');
    assert.equal((await correlateRelatedChanges(env, { workspaceId:'ws',domainId:'dom',scanId:'current',scanQuality:'complete',assessedAt:now })).ran, true);
    db.close();
  });

  await test('all changed event window predicates include both formats and exclude outside/foreign rows', async () => {
    const { db, env } = setup();
    const times = [['inside','2026-10-01 11:00:00'], ['iso','2026-10-01T11:00:00.000Z'],
      ['start','2026-10-01 10:00:00'], ['end','2026-10-01 12:00:00'], ['early','2026-10-01 09:59:59'], ['late','2026-10-01 12:00:01']];
    for (const [id, time] of times) {
      db.prepare("INSERT INTO asset_events(id,workspace_id,domain_id,scan_id,event_type,hostname,severity,description,created_at) VALUES(?,'ws','dom','scan','new_asset_discovered','login.example.test','info','fixture',?)").run(`asset_${id}`,time);
      db.prepare("INSERT INTO brand_abuse_campaigns(id,workspace_id,brand_profile_id,linked_domains,first_seen_at,last_seen_at) VALUES(?,'ws','profile','[\"example.test\"]',?,?)").run(`brand_${id}`,time,time);
      db.prepare("INSERT INTO shadow_it_inventory(id,workspace_id,canonical_technology_key,display_name,source_type,observed_hostnames_json,first_seen_at,last_changed_at,last_seen_at) VALUES(?,'ws',?,'fixture','dns','[\"example.test\"]',?,?,?)").run(`shadow_${id}`,id,time,time,time);
    }
    db.prepare("INSERT INTO asset_events(id,workspace_id,domain_id,scan_id,event_type,hostname,severity,description,created_at) VALUES('foreign','other','dom','scan','new_asset_discovered','login.example.test','info','fixture','2026-10-01 11:00:00')").run();
    for (const windowStart of ['2026-10-01T10:00:00.000Z','2026-10-01 10:00:00']) {
      for (const windowEnd of [now,'2026-10-01 12:00:00']) {
        const events = await collectChangeEvents(env, { workspaceId:'ws',windowStart,windowEnd });
        for (const prefix of ['asset','brand','shadow']) {
          assert.deepEqual(events.filter(e => e.source_record_id.startsWith(prefix+'_')).map(e => e.source_record_id).sort(),
            ['end','inside','iso','start'].map(id => `${prefix}_${id}`).sort());
        }
        assert.ok(!events.some(e => e.source_record_id === 'foreign'));
      }
    }
    // The email adapter has an admission contract in addition to its time
    // predicate; test this exact production query with deliberately inert rows.
    const email = literal('engines/related-changes-adapter.js', ['SELECT id, event_type, detail_json, created_at']);
    db.exec("CREATE TEMP TABLE email_fixture(id,event_type,detail_json,created_at,workspace_id,record_type)");
    for (const [id, at] of times) db.prepare("INSERT INTO email_fixture VALUES(?,'fixture','{}',?,'ws','fixture')").run(id, at);
    const query = email.replace('FROM email_protection_events', 'FROM email_fixture');
    assert.deepEqual(db.prepare(query).all('ws','fixture','2026-10-01T10:00:00.000Z',now).map(r=>r.id).sort(), ['end','inside','iso','start']);
    assert.deepEqual(db.prepare(plainComparison(query)).all('ws','fixture','2026-10-01T10:00:00.000Z',now).map(r=>r.id), ['iso']);
    // Exercise last_changed_at independently of first_seen_at.
    db.prepare("UPDATE shadow_it_inventory SET first_seen_at='2026-09-01 00:00:00' WHERE id='shadow_inside'").run();
    assert.ok((await collectChangeEvents(env, { workspaceId:'ws',windowStart:'2026-10-01T10:00:00.000Z',windowEnd:now })).some(e=>e.source_record_id==='shadow_inside'));
    db.close();
  });

  await test('risk acceptance stores UTC ISO and legacy expiry uses time order', async () => {
    const base = { id:'case',status:'risk_acceptance_requested',workspace_id:'ws',case_type:ASM_CASE_TYPE,domain_key:'attack_surface' };
    const ctx = { reason:'fixture',risk_accepted_until:'2026-10-01T16:00:00+04:00' };
    const transitioned = applyCaseTransition(ASM_CASE_MACHINE, base, 'risk_accepted', ctx);
    assert.equal(transitioned.ok, true);
    assert.equal(transitioned.case.risk_accepted_until, now);
    assert.equal(ctx.risk_accepted_until, '2026-10-01T16:00:00+04:00');
    assert.equal(base.status, 'risk_acceptance_requested');
    assert.equal(applyCaseTransition(ASM_CASE_MACHINE, base, 'risk_accepted', { reason:'fixture',risk_accepted_until:'invalid' }).ok, false);
    const { db, env } = setup();
    const add = db.prepare("INSERT INTO managed_cases(id,workspace_id,domain,case_type,domain_key,finding_id,status,risk_accepted_until) VALUES(?,?,'example.test',?,'attack_surface',?,'risk_accepted',?)");
    for (const [id, at] of [['expired','2026-10-01 11:00:00'], ['boundary','2026-10-01 12:00:00'], ['future','2026-10-01 13:00:00']]) add.run(id,'ws',ASM_CASE_TYPE,id,at);
    add.run('foreign','other',ASM_CASE_TYPE,'foreign','2026-10-01 11:00:00');
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws' AND risk_accepted_until <= ?").get(now).n,3);
    assert.deepEqual(await reassessExpiredRiskAcceptedCases(env,'ws',now), { reassessed:2 });
    assert.deepEqual(db.prepare("SELECT id FROM managed_cases WHERE status='risk_accepted' ORDER BY id").all().map(r=>r.id), ['foreign','future']);
    db.close();
  });

  await test('password reset invalidation compares instants', async () => {
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE password_reset_tokens(id,user_id,used_at,expires_at)');
    for (const [id, expires] of [['old','2026-10-01T11:00:00.000Z'], ['future','2026-10-01T13:00:00.000Z']]) {
      db.prepare("INSERT INTO password_reset_tokens VALUES(?,'owner',NULL,?)").run(id,expires);
    }
    db.prepare("INSERT INTO password_reset_tokens VALUES('foreign','foreign',NULL,'2026-10-01T13:00:00.000Z')").run();
    // Freeze only SQLite's clock literal in the production query as well.
    const query = literal('routes/auth.js', ['SET used_at = datetime', 'WHERE user_id = ? AND used_at IS NULL'])
      .replaceAll("'now'", "'2026-10-01 12:00:00'");
    assert.equal(db.prepare(plainComparison(query)).run('owner').changes,2);
    db.exec('UPDATE password_reset_tokens SET used_at=NULL');
    assert.equal(db.prepare(query).run('owner').changes,1);
    assert.equal(db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='old'").get().used_at,null);
    assert.equal(db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='foreign'").get().used_at,null);
    db.close();
  });
} finally { globalThis.Date = RealDate; }
console.log(`PASS timestamp comparison fixtures: ${sites}/6 sites`);
