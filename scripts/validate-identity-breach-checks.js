#!/usr/bin/env node
// Actual production entry with local D1. Every outbound request is rejected.
// Prove removal stops egress without losing historical tenant-scoped observations.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { splitStatements, isToleratedStatement } from './lib/migration-apply-tolerated.js';
import { extractSchemaResourcesFromSources } from './security/lib/tenant-resources.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(path.join(root, 'workers/scan-api/package.json'));
const { build } = require('esbuild');
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-breach-validation-'));
let mf, db, checks = 0;
const pass = (name, fn) => { fn(); checks++; console.log('PASS ' + name); };
const equal = (name, actual, expected) => pass(name, () => assert.deepEqual(actual, expected));
const providerCalls = [];
const outbound = async request => { providerCalls.push(request.url); throw new Error('Unexpected external request'); };
const opts = () => convertV4MiniflareOptions({ cf: false, modules: true,
  resourcePersistencePath: path.join(scratch, 'state'),
  script: fs.readFileSync(path.join(scratch, 'worker.mjs'), 'utf8'), compatibilityDate: '2026-06-18', compatibilityFlags: ['global_fetch_strictly_public'],
  bindings: { ALLOWED_ORIGIN: 'https://app.cybermeters.test', MAINTENANCE_MODE: 'off' },
  d1Databases: { cybermeters_db: 'synthetic-breach' },
  outboundService: outbound,
});
async function call({ user = 'owner', ws = 'wa', method = 'GET', id = '', body, raw } = {}) {
  const response = await mf.dispatchFetch(`https://local.invalid/api/workspaces/${ws}/identity-breach-checks${id ? '/' + id : ''}`, {
    method, headers: { ...(user ? { Authorization: `Bearer ${user === 'token' ? 'cm_synthetic' : 'test-' + user}` } : {}), Origin: 'https://app.cybermeters.test', 'Content-Type': 'application/json' },
    ...(method === 'POST' ? { body: raw ?? JSON.stringify(body ?? input()) } : {}),
  });
  return { status: response.status, body: await response.json() };
}
const input = extra => ({ domain_id: 'da', email: 'Person@Example.Test', consent: true, consent_version: '2026-10-09', request_id: randomUUID(), ...extra });
try {
  const built = await build({ entryPoints: [path.join(root, 'workers/scan-api/src/worker.js')], outfile: path.join(scratch, 'worker.mjs'), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', external: ['cloudflare:*'], logLevel: 'silent' });
  assert.equal(built.errors.length, 0);
  mf = new Miniflare(opts()); db = await mf.getD1Database('cybermeters_db');
  // Build the actual migration-composed schema first; deploy only its schema to
  // disposable local D1. No production backup or customer records are loaded.
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(fs.readFileSync(path.join(root, 'database/schema.sql'), 'utf8'));
  for (const name of fs.readdirSync(path.join(root,'database/migrations')).filter(n => n.endsWith('.sql')).sort()) {
    if (name === '112-remove-external-breach-provider.sql') {
      sqlite.exec("INSERT INTO users(id,email) VALUES('survivor','survivor@example.test'); INSERT INTO workspaces(id,name,owner_user_id) VALUES('survivor','Keep me','survivor'); INSERT INTO domains(id,user_id,domain) VALUES('survivor','survivor','example.test');");
      sqlite.exec("INSERT INTO identity_breach_checks(id,workspace_id,domain_id,request_id,subject_hash,masked_address,consent_version,consented_at,checked_at) VALUES('retire','survivor','survivor','retire','hash','mask','old','old','old');");
    }
    const source = fs.readFileSync(path.join(root,'database/migrations',name),'utf8');
    const hash = createHash('sha256').update(source).digest('hex');
    for (const sql of splitStatements(source)) { try { sqlite.exec(sql); } catch (e) { if (!isToleratedStatement(name, hash, sql, e.message)) throw e; } }
  }
  equal('provider tables and indexes removed after migration',sqlite.prepare("SELECT name FROM sqlite_schema WHERE name LIKE '%identity_breach%'").all(),[]);
  equal('existing unrelated account preserved',sqlite.prepare("SELECT email FROM users WHERE id='survivor'").get().email,'survivor@example.test');
  equal('existing unrelated workspace preserved',sqlite.prepare("SELECT name FROM workspaces WHERE id='survivor'").get().name,'Keep me');
  equal('database integrity preserved',sqlite.prepare('PRAGMA integrity_check').get().integrity_check,'ok');
  // Re-running this exact retirement is safe and cannot touch other product data.
  sqlite.exec(fs.readFileSync(path.join(root,'database/migrations/112-remove-external-breach-provider.sql'),'utf8'));
  equal('reapplying retirement preserves unrelated data',sqlite.prepare("SELECT COUNT(*) n FROM users WHERE id='survivor'").get().n,1);
  const model = extractSchemaResourcesFromSources([
    { file:'one.sql', migration:true, sql:'CREATE TABLE old_provider (id TEXT);\nCREATE TABLE retained (id TEXT);' },
    { file:'two.sql', migration:true, sql:'DROP TABLE IF EXISTS old_provider;' },
  ]);
  equal('schema model handles cross-file retirement',Object.keys(model.tables),['retained']);
  const schema = sqlite.prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END").all(); sqlite.close();
  await db.batch(schema.map(row => db.prepare(row.sql)));
  for (const user of ['owner','admin','analyst','viewer','other','actor']) {
    await db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').bind(user, `${user}@example.test`).run();
    await db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+1 day'))").bind('s_'+user,user,createHash('sha256').update('test-'+user).digest('hex')).run();
  }
  for (const [ws, owner] of [['wa','owner'],['wb','other']]) {
    await db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').bind(ws,ws,owner).run();
    await db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,'owner')").bind(ws,owner).run();
    await db.prepare('INSERT INTO workspace_retention_settings(workspace_id,retention_days,auto_cleanup) VALUES(?,30,1)').bind(ws).run();
  }
  for (const role of ['admin','analyst','viewer']) await db.prepare('INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,?)').bind('wa',role,role).run();
  for (const [id,domain,ws] of [['da','example.test','wa'],['db','other.test','wb'],['unverified','pending.test','wa']]) {
    await db.prepare('INSERT INTO domains(id,user_id,domain) VALUES(?,?,?)').bind(id,ws==='wa'?'owner':'other',domain).run();
    await db.prepare('INSERT INTO workspace_domains(workspace_id,domain_id,verification_status,verified_at) VALUES(?,?,?,?)').bind(ws,id,id==='unverified'?'pending':'verified',id==='unverified'?null:new Date().toISOString()).run();
  }
  await db.prepare("INSERT INTO api_tokens(id,user_id,workspace_id,name,token_hash,scope,status) VALUES('tok','owner','wa','synthetic',?,'write','active')").bind(createHash('sha256').update('cm_synthetic').digest('hex')).run();
  const before = (await db.prepare('SELECT COUNT(*) n FROM users').first()).n;
  for (const method of ['GET','POST','DELETE']) {
    const result = await call({method, ...(method==='DELETE'?{id:'old-record'}:{})});
    equal(`old ${method} endpoint no longer exists`,result.status,404);
  }
  equal('no external requests from removed endpoints',providerCalls.length,0);
  equal('unrelated account rows remain unchanged',(await db.prepare('SELECT COUNT(*) n FROM users').first()).n,before);
  equal('no provider storage is recreated',(await db.prepare("SELECT name FROM sqlite_schema WHERE name LIKE '%identity_breach%'").all()).results,[]);
  // Also reject accidental reintroduction into the production bundle or binding.
  const bundle=fs.readFileSync(path.join(scratch,'worker.mjs'),'utf8');
  pass('production bundle has no removed provider endpoint or coordinator',()=>assert(!/leakcheck\.io|LEAKCHECK_PUBLIC|class LeakCheckPublic/.test(bundle)));
  const config=fs.readFileSync(path.join(root,'workers/scan-api/wrangler.toml'),'utf8');
  pass('provider binding removed; namespace retirement appended',()=>{assert(!/name\s*=\s*"LEAKCHECK_PUBLIC"/.test(config));assert(config.includes('deleted_classes = ["LeakCheckPublic"]'));});
  const ui=fs.readFileSync(path.join(root,'frontend/src/pages/ws/IdentityExposurePage.jsx'),'utf8');
  pass('no provider UI component remains',()=>assert(!ui.includes('IdentityBreachChecks')));
  console.log(`Identity breach disconnect: ${checks}/${checks} passed (no external requests).`);
} finally { await mf?.dispose(); fs.rmSync(scratch,{recursive:true,force:true}); }
