#!/usr/bin/env node
// Real SQLite admissions and production report generators; no external calls.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { splitStatements, isToleratedStatement } from './lib/migration-apply-tolerated.js';
globalThis.fetch = async () => { throw new Error('external network disabled'); };
const { admitDomainScan, checkScanLimit, checkReportLimit, claimReportOccurrence, getOperationAdmission,
  readOrGenerateTrialTechnicalPdf, generateWorkspaceExecutiveReport, getWorkspaceBillingUserId } = await import('../workers/scan-api/src/engines/plan-usage.js');
const { trialUsage, trialDay, getTrialAllowance } = await import('../workers/scan-api/src/engines/trial-allowance.js');
const { getEffectivePlanState, getEffectiveDomainLimit } = await import('../workers/scan-api/src/engines/entitlements.js');
const { networkAssetRoutes } = await import('../workers/scan-api/src/routes/network-assets.js');
const { scanRoutes } = await import('../workers/scan-api/src/routes/scans.js');
const { workspaceReportsRoutes } = await import('../workers/scan-api/src/routes/workspace-reports.js');
const { requireWorkspaceRole, requireScanReadAccess } = await import('../workers/scan-api/src/index.js');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`); }
function setup() {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync(path.join(root, 'database/schema.sql'), 'utf8'));
  for (const name of fs.readdirSync(path.join(root, 'database/migrations')).filter(n => n.endsWith('.sql')).sort()) {
    const sql = fs.readFileSync(path.join(root, 'database/migrations', name), 'utf8');
    const hash = createHash('sha256').update(sql).digest('hex');
    for (const statement of splitStatements(sql)) {
      try { db.exec(statement); } catch (error) { if (!isToleratedStatement(name, hash, statement, error.message)) throw error; }
    }
  }
  db.exec('PRAGMA foreign_keys=ON');
  let fault = null;
  const stmt = (sql, args = []) => ({ bind: (...args) => stmt(sql, args),
    first: async () => { if (fault?.(sql)) throw new Error('storage'); return db.prepare(sql).get(...args) || null; },
    all: async () => { if (fault?.(sql)) throw new Error('storage'); return { results: db.prepare(sql).all(...args) }; },
    run: async () => { if (fault?.(sql)) throw new Error('storage'); return { meta: { changes: db.prepare(sql).run(...args).changes } }; },
  });
  for (const user of ['owner', 'other', 'member']) db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').run(user, `${user}@example.com`);
  for (const [id, owner] of [['wa','owner'],['wb','owner'],['foreign','other']]) {
    db.prepare('INSERT INTO workspaces(id,name,owner_user_id) VALUES(?,?,?)').run(id,id,owner);
    db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,'owner')").run(id,owner);
  }
  db.prepare("INSERT INTO workspace_members(workspace_id,user_id,role) VALUES('wa','member','admin')").run();
  const future = new Date(Date.now() + 86400000).toISOString();
  db.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,trial_end) VALUES('trial','owner','wa','professional','trialing','trialing',?)").run(future);
  db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('domain','owner','example.com')").run();
  db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status,verified_at) VALUES('wa','domain','verified',datetime('now'))").run();
  const objects = new Map(), queued = [];
  const env = { cybermeters_db: { prepare: sql => stmt(sql) },
    SCAN_QUEUE: { send: async value => { queued.push(value); } }, SCAN_DISPATCH_MODE: 'queue', NETWORK_PROBE: { fetch: async () => { throw new Error('not run'); } },
    cybermeters_reports: {
      put: async (key, bytes) => { objects.set(key, bytes); },
      get: async key => objects.has(key) ? { body: objects.get(key), arrayBuffer: async () => objects.get(key) } : null,
    },
  };
  const seedScan = (id, { workspace = 'wa', status = 'completed', at = new Date().toISOString() } = {}) => db.prepare('INSERT INTO scans(id,domain_id,workspace_id,domain,status,created_at) VALUES(?,?,?,?,?,?)').run(id,'domain',workspace,'example.com',status,at);
  const context = (route, { user = 'owner', method = 'GET', body } = {}) => ({ env, url: new URL(`https://test.invalid${route}`),
    request: new Request(`https://test.invalid${route}`, { method, ...(body ? { body: JSON.stringify(body) } : {}) }),
    requireAuth: async () => user ? { id: user } : null, requireWorkspaceRole, requireScanReadAccess,
    getWorkspaceBillingUserId, getAccessibleWorkspaceIds: async () => ['wa'], consumeApiRateLimit: async () => null,
    json: (body, status = 200) => Response.json(body,{status}), corsHeaders: {},
    ctx: { waitUntil: () => { throw new Error('engine should use queue'); } },
    serverError: (_scope, error) => Response.json({error: error.message},{status:500}),
  });
  return { db, env, objects, queued, seedScan, context, setFault: value => { fault = value; } };
}
await test('one account admits exactly three overlapping scans across workspaces', async () => {
  const f=setup();
  const results=await Promise.all(Array.from({length:12},(_,i)=>admitDomainScan(f.env,{scanId:`s${i}`,domainId:'domain',workspaceId:i%2?'wb':'wa',domain:`d${i}.example.com`,status:'queued',userId:'owner'})));
  assert.equal(results.filter(x=>!x).length,3); assert.equal(f.db.prepare('SELECT COUNT(*) n FROM scans').get().n,3);
  assert(results.filter(Boolean).every(x=>x.status===403 && x.body.resource==='scans_per_day'));
  f.db.exec("UPDATE scans SET status='failed' WHERE id='s0'");
  assert.equal(await admitDomainScan(f.env,{scanId:'retry',domainId:'domain',workspaceId:'wa',domain:'example.com',status:'queued',userId:'owner'}),null);
  assert.equal(await trialUsage(f.env,'scans','owner'),3);
});
await test('UTC reset counts SQLite and ISO timestamps and ignores other accounts', async()=>{
  const f=setup(), now=new Date(), day=trialDay(now);
  f.seedScan('iso'); f.seedScan('sqlite',{at:`${day.start} 00:00:00`});
  f.seedScan('yesterday',{at:new Date(now.getTime()-86400000).toISOString()});
  f.seedScan('tomorrow',{at:`${day.end}T00:00:00.000Z`});
  f.seedScan('foreign',{workspace:'foreign'});
  assert.equal(await trialUsage(f.env,'scans','owner',now),2);
  assert.equal(await trialUsage(f.env,'scans','owner',new Date(day.reset_at)),1);
  f.db.exec("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'");
  assert.equal(await trialUsage(f.env,'scans','owner',now),2);
});
await test('real manual route keeps verification visible and mandatory; failed queue releases allowance',async()=>{
  const f=setup();
  f.db.exec("UPDATE workspace_domains SET verification_status='unverified',verified_at=NULL");
  let res=await scanRoutes(f.context('/api/scan',{method:'POST',body:{domain:'example.com',workspace_id:'wa'}}));
  assert.equal(res.status,403); assert.equal((await res.json()).error,'domain_verification_required');
  assert.equal(f.queued.length,0); assert.equal(await trialUsage(f.env,'scans','owner'),0);
  f.db.exec("UPDATE workspace_domains SET verification_status='verified',verified_at=datetime('now')");
  for(let i=0;i<3;i++) {
    res=await scanRoutes(f.context('/api/scan',{method:'POST',body:{domain:'example.com',workspace_id:'wa'}}));
    assert.equal(res.status,202,await res.text()); f.db.exec("UPDATE scans SET status='completed'");
  }
  res=await scanRoutes(f.context('/api/scan',{method:'POST',body:{domain:'example.com',workspace_id:'wa'}}));
  assert.equal(res.status,403); assert.equal(f.queued.length,3);
  f.db.exec("UPDATE scans SET status='failed' WHERE id=(SELECT id FROM scans LIMIT 1)");
  f.env.SCAN_QUEUE.send=async()=>{throw new Error('queue unavailable');};
  res=await scanRoutes(f.context('/api/scan',{method:'POST',body:{domain:'example.com',workspace_id:'wa'}}));
  assert.equal(res.status,503); assert.equal(await trialUsage(f.env,'scans','owner'),2);
});
await test('network scan uses same allowance and member uses billing owner',async()=>{
  const f=setup(); f.seedScan('one');f.seedScan('two');
  f.db.prepare("INSERT INTO network_targets(id,workspace_id,target,target_type,addresses_json,address_count,authorization_status,authorized_by,authorized_at,created_at) VALUES('target','wa','8.8.8.8','ip','[\"8.8.8.8\"]',1,'attested','owner',datetime('now'),datetime('now'))").run();
  const call=()=>networkAssetRoutes(f.context('/api/workspaces/wa/network-targets/target/scans',{method:'POST',user:'member',body:{ports:[443]}}));
  let res=await call();assert.equal(res.status,202,await res.text());assert.equal(await trialUsage(f.env,'scans','owner'),3);
  f.db.exec("UPDATE network_scans SET status='completed'");
  res=await call();assert.equal(res.status,403);assert.equal(f.queued.length,1);
  assert.equal((await checkScanLimit({id:'member'},'wa',f.env)).body.usage,3);
});
await test('executive and technical report claims share atomic three-PDF allowance',async()=>{
  const f=setup();
  const results=await Promise.all(Array.from({length:8},async(_,i)=>{
    try{return await claimReportOccurrence(f.env,{reportId:`r${i}`,workspaceId:i%2?'wb':'wa',report_type:i%2?'technical':'manual',report_period:`p${i}`,r2Key:`k${i}`,retentionPolicy:'standard',createdAt:new Date().toISOString(),admission:await getOperationAdmission(f.env,i%2?'wb':'wa',null,'reports')});}
    catch(e){return e.quota;}
  }));
  assert.equal(results.filter(r=>r.won).length,3);assert.equal(results.filter(r=>r.status===403).length,5);
  f.db.exec("UPDATE workspace_reports SET status='completed',deleted_at=datetime('now') WHERE id='r0'");
  assert.equal(await trialUsage(f.env,'reports','owner'),3);
  f.db.exec("UPDATE workspace_reports SET status='failed' WHERE id='r1'");
  assert.equal(await trialUsage(f.env,'reports','owner'),2);
  const stale=new Date(Date.now()-31*60000).toISOString();
  f.db.prepare("UPDATE workspace_reports SET created_at=? WHERE id='r2'").run(stale);
  assert.equal(await trialUsage(f.env,'reports','owner'),1);
});
await test('same technical PDF is generated once, downloadable after trial, scoped to workspace',async()=>{
  const f=setup();f.seedScan('scan');const scan={id:'scan',workspace_id:'wa',domain:'example.com'};
  let renders=0;
  const render=async()=>{renders++;return new TextEncoder().encode('%PDF-test');};
  await readOrGenerateTrialTechnicalPdf(f.env,scan,'owner',render,{snapshot_id:'snapshot-proof'});
  const evidence={};
  await readOrGenerateTrialTechnicalPdf(f.env,scan,'owner',render,evidence);
  assert.equal(evidence.snapshot_id,'snapshot-proof');
  assert.equal(renders,1);assert.equal(await trialUsage(f.env,'reports','owner'),1);
  f.db.prepare("UPDATE subscriptions SET trial_end=?").run(new Date(Date.now()-60000).toISOString());
  await readOrGenerateTrialTechnicalPdf(f.env,scan,'owner',render);assert.equal(renders,1);
  assert.equal((await scanRoutes(f.context('/api/scans/scan/report/pdf',{user:'other'}))).status,403);
  assert.equal((await scanRoutes(f.context('/api/scans/scan/report/pdf'))).status,200);
  const row=f.db.prepare('SELECT id FROM workspace_reports').get();
  assert.equal((await workspaceReportsRoutes(f.context(`/api/workspaces/wa/reports/${row.id}/download`))).status,200);
  assert.equal((await workspaceReportsRoutes(f.context(`/api/workspaces/wa/reports/${row.id}/download`,{user:'other'}))).status,403);
  await assert.rejects(()=>readOrGenerateTrialTechnicalPdf(f.env,{...scan,id:'another'},'owner',render),e=>e.quota?.body.reason==='trial_expired');
  assert.equal(renders,1);
});
await test('render and R2 failures release PDF reservations',async()=>{
  const f=setup(),scan={id:'scan',workspace_id:'wa'};
  await assert.rejects(()=>readOrGenerateTrialTechnicalPdf(f.env,scan,'owner',async()=>{throw new Error('renderer failed');}));
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
  f.env.cybermeters_reports.put=async()=>{throw new Error('storage failed');};
  await assert.rejects(()=>readOrGenerateTrialTechnicalPdf(f.env,scan,'owner',async()=>new Uint8Array([1])));
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
  await assert.rejects(()=>generateWorkspaceExecutiveReport('wa',f.env));
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
});
await test('report admission stamps the same day it counts, even for delayed requests',async()=>{
  const f=setup();
  const oldStamp=new Date(Date.now()-86400000).toISOString();
  for(let i=0;i<3;i++) {
    const result=await claimReportOccurrence(f.env,{reportId:`delayed${i}`,workspaceId:'wa',report_type:'manual',report_period:`delayed${i}`,r2Key:`key${i}`,retentionPolicy:'standard',createdAt:oldStamp,admission:await getOperationAdmission(f.env,'wa',null,'reports')});
    assert.equal(result.won,true);
  }
  assert.equal(await trialUsage(f.env,'reports','owner'),3);
  // Use the production admission guard: a fourth delayed report must be refused.
  await assert.rejects(async()=>claimReportOccurrence(f.env,{reportId:'guarded-fourth',workspaceId:'wa',report_type:'manual',report_period:'guarded-fourth',r2Key:'guarded-fourth',retentionPolicy:'standard',createdAt:oldStamp,admission:await getOperationAdmission(f.env,'wa',null,'reports')}),e=>e.quota?.body.reason==='trial_daily_allowance');
});
await test('report completion storage failures refund the reserved slot',async()=>{
  const f=setup();
  f.setFault(sql=>/UPDATE workspace_reports\s+SET status = 'completed'/.test(sql));
  await assert.rejects(()=>readOrGenerateTrialTechnicalPdf(f.env,{id:'scan',workspace_id:'wa'},'owner',async()=>new Uint8Array([1])),/storage/);
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
  await assert.rejects(()=>generateWorkspaceExecutiveReport('wa',f.env),/storage/);
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
  f.setFault(null);
  const result=await generateWorkspaceExecutiveReport('wa',f.env);
  assert.equal(result.status,'completed');
  assert.equal(await trialUsage(f.env,'reports','owner'),1);
});
await test('billing precedence, expiry, daily display and storage errors',async()=>{
  const f=setup(); f.seedScan('one');
  let state=await getEffectivePlanState('owner',f.env);
  assert.equal(getEffectiveDomainLimit(state.plan,state.is_trial),1);
  let usage=await getTrialAllowance(f.env,'owner',state);
  assert.deepEqual(usage.scans,{used:1,limit:3,remaining:2});assert.equal(usage.reset_at,trialDay().reset_at);
  f.db.prepare("INSERT INTO subscriptions(id,owner_user_id,plan,status,subscription_status,stripe_subscription_id) VALUES('paid','owner','starter','active','active','sub_paid')").run();
  state=await getEffectivePlanState('owner',f.env);assert.equal(state.plan,'starter');assert.equal(state.is_trial,false);
  for(let i=0;i<5;i++) f.seedScan(`paid${i}`);
  assert.equal(await checkScanLimit({id:'owner'},'wa',f.env),null);
  f.db.exec("DELETE FROM subscriptions WHERE id='paid'");
  f.setFault(sql=>sql.includes('AS cnt'));
  assert.equal((await checkScanLimit({id:'owner'},'wa',f.env)).status,503);
  assert.equal((await checkReportLimit({id:'owner'},'wa',f.env)).status,503);
  f.setFault(null);
  f.db.prepare("UPDATE subscriptions SET trial_end=?").run(new Date(Date.now()-60000).toISOString());
  assert.equal((await checkReportLimit({id:'owner'},'wa',f.env)).body.reason,'trial_expired');
  assert.equal((await checkScanLimit({id:'owner'},'wa',f.env)).body.reason,'trial_expired');
});
console.log(`Trial daily allowance: ${passed} scenarios passed`);
