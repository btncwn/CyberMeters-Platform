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
const { portfolioRoutes } = await import('../workers/scan-api/src/routes/portfolio.js');
const { workspaceAnalyticsRoutes } = await import('../workers/scan-api/src/routes/workspace-analytics.js');
const { workspaceReportsRoutes } = await import('../workers/scan-api/src/routes/workspace-reports.js');
const { composeSnapshot } = await import('../workers/scan-api/src/engines/report-snapshot.js');
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
  const objects = new Map(), queued = [], readKeys = [];
  const env = { cybermeters_db: { prepare: sql => stmt(sql) },
    SCAN_QUEUE: { send: async value => { queued.push(value); } }, SCAN_DISPATCH_MODE: 'queue', NETWORK_PROBE: { fetch: async () => { throw new Error('not run'); } },
    cybermeters_reports: {
      put: async (key, bytes) => { objects.set(key, bytes); },
      get: async key => {
        readKeys.push(key);
        if (!objects.has(key)) return null;
        const value = objects.get(key);
        const text = () => typeof value === 'string' ? value : new TextDecoder().decode(value);
        return { body: value, arrayBuffer: async () => value, text: async () => text(), json: async () => JSON.parse(text()) };
      },
    },
  };
  const seedScan = (id, { workspace = 'wa', status = 'completed', at = new Date().toISOString(), domainId = 'domain', domain = 'example.com' } = {}) => db.prepare('INSERT INTO scans(id,domain_id,workspace_id,domain,status,created_at) VALUES(?,?,?,?,?,?)').run(id,domainId,workspace,domain,status,at);
  const seedSnapshot = (scanId, { workspace = 'wa', domainId = 'domain', domain = 'example.com', at = new Date().toISOString() } = {}) => {
    db.prepare('INSERT OR IGNORE INTO domains(id,user_id,domain) VALUES(?,?,?)').run(domainId,'owner',domain);
    seedScan(scanId, { workspace, domainId, domain, at });
    const report = { scan_id: scanId, domain_id: domainId, domain, status: 'completed', started_at: at, completed_at: at,
      cyber_metrics_score: 80, scan_quality: { status: 'partial' }, findings: [], modules: {} };
    const snapshot = composeSnapshot({ snapshotId: `snap_${scanId}`, workspaceId: workspace, domainId, scanId, domain,
      report, cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [], builtAt: at });
    const raw = JSON.stringify(snapshot), identity = snapshot.snapshot;
    const key = `reports/snapshots/${workspace}/${scanId}/${identity.snapshot_id}.json`;
    objects.set(key, raw); objects.set(`reports/${scanId}.json`, JSON.stringify(report));
    db.prepare(`INSERT INTO scan_report_snapshots
      (id,workspace_id,domain_id,scan_id,status,r2_key,checksum_sha256,snapshot_schema_version,resolver_version,assessed_at)
      VALUES(?,?,?,?,'completed',?,?,?,?,?)`).run(identity.snapshot_id,workspace,domainId,scanId,key,
      createHash('sha256').update(raw).digest('hex'),String(identity.snapshot_schema_version),'test',at);
    return { key, snapshot };
  };
  const context = (route, { user = 'owner', method = 'GET', body } = {}) => ({ env, url: new URL(`https://test.invalid${route}`),
    request: new Request(`https://test.invalid${route}`, { method, ...(body ? { body: JSON.stringify(body) } : {}) }),
    requireAuth: async () => user ? { id: user } : null, requireWorkspaceRole, requireScanReadAccess,
    getWorkspaceBillingUserId, getAccessibleWorkspaceIds: async () => ['wa'], consumeApiRateLimit: async () => null,
    json: (body, status = 200) => Response.json(body,{status}), corsHeaders: {},
    ctx: { waitUntil: () => { throw new Error('engine should use queue'); } },
    serverError: (_scope, error) => Response.json({error: error.message},{status:500}),
  });
  return { db, env, objects, queued, readKeys, seedScan, seedSnapshot, context, setFault: value => { fault = value; } };
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
await test('both legacy PDF routes share admission, enforce expiry and preserve downloads', async()=>{
  const f=setup();
  const calls = [
    () => portfolioRoutes(f.context('/api/workspaces/wa/report')),
    () => workspaceAnalyticsRoutes(f.context('/api/workspaces/wb/scorecard/pdf',{user:'owner'})),
    () => portfolioRoutes(f.context('/api/workspaces/wa/report',{user:'member'})),
  ];
  const results=await Promise.all([...calls,...calls].map(call=>call()));
  assert.equal(results.filter(r=>r.status===200).length,3);
  assert.equal(results.filter(r=>r.status===403).length,3);
  for(const r of results) {
    if(r.status===200) assert.equal(r.headers.get('content-type'),'application/pdf');
    else assert.equal((await r.json()).reason,'trial_daily_allowance');
  }
  assert.equal(await trialUsage(f.env,'reports','owner'),3);
  assert.equal(f.objects.size,3);
  assert.equal((await portfolioRoutes(f.context('/api/workspaces/wa/report',{user:'other'}))).status,403);
  assert.equal((await workspaceAnalyticsRoutes(f.context('/api/workspaces/wa/scorecard/pdf',{user:'other'}))).status,403);
  f.db.prepare("UPDATE subscriptions SET trial_end=?").run(new Date(Date.now()-60000).toISOString());
  for(const call of calls) { const r=await call(); assert.equal(r.status,403);assert.equal((await r.json()).reason,'trial_expired'); }
  const row=f.db.prepare("SELECT id FROM workspace_reports WHERE workspace_id='wa' AND status='completed'").get();
  assert.equal((await workspaceReportsRoutes(f.context(`/api/workspaces/wa/reports/${row.id}/download`))).status,200);
});
await test('legacy PDF storage failure refunds the reservation and paid behaviour stays unchanged',async()=>{
  const f=setup();
  f.env.cybermeters_reports.put=async()=>{throw new Error('R2 unavailable');};
  assert.equal((await portfolioRoutes(f.context('/api/workspaces/wa/report'))).status,500);
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
  f.db.exec("UPDATE subscriptions SET status='active',subscription_status='active',stripe_subscription_id='sub_paid'");
  for(let i=0;i<4;i++) assert.equal((await workspaceAnalyticsRoutes(f.context('/api/workspaces/wa/scorecard/pdf'))).status,200);
  assert.equal(await trialUsage(f.env,'reports','owner'),0);
});
await test('stale same-period claim does not hide a full allowance behind preparing',async()=>{
  const f=setup(), scan={id:'stale-scan',workspace_id:'wa'};
  const createdAt=new Date(Date.now()-31*60000).toISOString();
  await claimReportOccurrence(f.env,{reportId:'stale',workspaceId:'wa',report_type:'technical',report_period:'scan-stale-scan',r2Key:'stale',retentionPolicy:'standard',createdAt});
  for(let i=0;i<3;i++) await claimReportOccurrence(f.env,{reportId:`fresh${i}`,workspaceId:'wa',report_type:'manual',report_period:`fresh${i}`,r2Key:`fresh${i}`,retentionPolicy:'standard',createdAt:new Date().toISOString()});
  await assert.rejects(()=>readOrGenerateTrialTechnicalPdf(f.env,scan,'owner',async()=>{throw new Error('must not render');}),e=>e.quota?.status===403 && e.quota?.body.reason==='trial_daily_allowance');
});
await test('subscription storage failure is unavailable, not an upgrade request',async()=>{
  const f=setup(); f.setFault(sql=>sql.includes('FROM subscriptions'));
  assert.equal((await checkReportLimit({id:'owner'},'wa',f.env)).status,503);
  assert.equal((await checkScanLimit({id:'owner'},'wa',f.env)).status,503);
  for(const [route,handler] of [['/api/workspaces/wa/report',portfolioRoutes],['/api/workspaces/wa/scorecard/pdf',workspaceAnalyticsRoutes]]) {
    const r=await handler(f.context(route)); assert.equal(r.status,503); assert.equal((await r.json()).error,'plan_state_unavailable');
  }
  assert.equal(f.objects.size,0);
  await assert.rejects(()=>readOrGenerateTrialTechnicalPdf(f.env,{id:'new',workspace_id:'wa'},'owner',async()=>new Uint8Array()),e=>e.quota?.status===503);
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
function storedState(f) {
  const tables = f.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
  return JSON.stringify({
    tables: tables.map(({name}) => [name, f.db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all()]),
    objects: [...f.objects].map(([key,value]) => [key, createHash('sha256').update(value).digest('hex')]),
  });
}
const generate = (f, body) => workspaceReportsRoutes(f.context('/api/workspaces/wa/reports/generate', { method: 'POST', body }));
const pdfText = (f, report) => new TextDecoder().decode(f.objects.get(report.report_key));
function seedReportScope(f) {
  f.seedSnapshot('selected_older', { at: '2026-06-01T12:00:00Z' });
  f.seedSnapshot('newer_same_domain', { at: '2026-06-02T12:00:00Z' });
  f.seedSnapshot('other_domain', { domainId: 'second_domain', domain: 'second.example.com', at: '2026-06-03T12:00:00Z' });
}
await test('Scan Snapshot renders only the selected older scan, not latest or other domains', async()=>{
  const f=setup(); seedReportScope(f);
  const immutableBefore = [...f.objects].map(([key,value]) => [key,value]);
  const res=await generate(f,{report_type:'scan_snapshot',scan_id:'selected_older'});
  assert.equal(res.status,201,await res.clone().text());
  const {report}=await res.json(), text=pdfText(f,report);
  assert(text.startsWith('%PDF-'));
  assert(text.includes('Scan reference: selected_older'));
  assert(!text.includes('newer_same_domain')); assert(!text.includes('second.example.com'));
  assert(!f.readKeys.some(key=>key.includes('newer_same_domain') || key.includes('other_domain')));
  const binding=JSON.parse(f.db.prepare('SELECT metadata_json FROM workspace_reports WHERE id=?').get(report.id).metadata_json);
  assert.deepEqual(binding.snapshots.map(s=>s.scan_id),['selected_older']);
  assert.equal(await trialUsage(f.env,'reports','owner'),1);
  for(const [key,value] of immutableBefore) assert.equal(f.objects.get(key),value);
});
await test('Scan Snapshot ignores period overrides, deduplicates selected evidence, and preserves legacy aggregate PDFs',async()=>{
  const f=setup(); seedReportScope(f);
  f.db.prepare(`INSERT INTO workspace_reports(id,workspace_id,report_type,report_period,report_key,status,created_at)
    VALUES('legacy','wa','scan_snapshot','scan-selected_older','legacy.pdf','completed',?)`).run(new Date().toISOString());
  f.objects.set('legacy.pdf',new TextEncoder().encode('%PDF-legacy workspace aggregate'));
  const oldRow=f.db.prepare("SELECT * FROM workspace_reports WHERE id='legacy'").get();
  const body={report_type:'scan_snapshot',scan_id:'selected_older',report_period:'scan-selected_older'};
  let res=await generate(f,body); assert.equal(res.status,201,await res.clone().text());
  const first=(await res.json()).report;
  assert.notEqual(first.id,'legacy'); assert.match(first.report_period,/^scan-v2-selected_older-snap_selected_older-/);
  assert(!pdfText(f,first).includes('second.example.com'));
  res=await generate(f,{...body,report_period:'arbitrary-alias'}); assert.equal(res.status,201);
  const repeat=(await res.json()).report;
  assert.equal(repeat.id,first.id); assert.equal(repeat.deduplicated,true);
  assert.equal(await trialUsage(f.env,'reports','owner'),2);
  assert.deepEqual(f.db.prepare("SELECT * FROM workspace_reports WHERE id='legacy'").get(),oldRow);
  const download=await workspaceReportsRoutes(f.context('/api/workspaces/wa/reports/legacy/download'));
  assert.equal(download.status,200); assert.equal(await download.text(),'%PDF-legacy workspace aggregate');
});
for (const [name,body,prepare,status,error] of [
  ['missing scan',{report_type:'scan_snapshot'},()=>{},400,'scan_id_required'],
  ['blank scan',{report_type:'scan_snapshot',scan_id:'  '},()=>{},400,'scan_id_required'],
  ['non-string scan',{report_type:'scan_snapshot',scan_id:['selected']},()=>{},400,'scan_id_required'],
  ['unknown scan',{report_type:'scan_snapshot',scan_id:'missing'},()=>{},404,'scan_not_found'],
  ['foreign workspace scan',{report_type:'scan_snapshot',scan_id:'selected'},f=>f.seedSnapshot('selected',{workspace:'foreign'}),404,'scan_not_found'],
  ['unfinished scan',{report_type:'scan_snapshot',scan_id:'selected'},f=>f.seedScan('selected',{status:'running'}),409,'scan_not_completed'],
  ['no immutable snapshot',{report_type:'scan_snapshot',scan_id:'selected'},f=>f.seedScan('selected'),409,'scan_report_not_ready'],
  ['building immutable snapshot',{report_type:'scan_snapshot',scan_id:'selected'},f=>{f.seedSnapshot('selected');f.db.exec("UPDATE scan_report_snapshots SET status='building'");},409,'scan_report_not_ready'],
  ['missing snapshot object',{report_type:'scan_snapshot',scan_id:'selected'},f=>{const s=f.seedSnapshot('selected');f.objects.delete(s.key);},409,'scan_report_not_ready'],
  ['missing checksum',{report_type:'scan_snapshot',scan_id:'selected'},f=>{f.seedSnapshot('selected');f.db.exec('UPDATE scan_report_snapshots SET checksum_sha256=NULL');},409,'scan_report_not_ready'],
  ['corrupt immutable snapshot',{report_type:'scan_snapshot',scan_id:'selected'},f=>{const s=f.seedSnapshot('selected');f.objects.set(s.key,'{}');},409,'scan_report_not_ready'],
  ['foreign snapshot row',{report_type:'scan_snapshot',scan_id:'selected'},f=>{f.seedSnapshot('selected');f.db.exec("UPDATE scan_report_snapshots SET workspace_id='foreign'");},409,'scan_report_not_ready'],
  ['wrong snapshot body identity',{report_type:'scan_snapshot',scan_id:'selected'},f=>{const s=f.seedSnapshot('selected');s.snapshot.snapshot.scan_id='different';const raw=JSON.stringify(s.snapshot);f.objects.set(s.key,raw);f.db.prepare('UPDATE scan_report_snapshots SET checksum_sha256=?').run(createHash('sha256').update(raw).digest('hex'));},409,'scan_report_not_ready'],
]) {
  await test(`Scan Snapshot refuses ${name} before any database or object changes`,async()=>{
    const f=setup(); prepare(f); const before=storedState(f);
    const res=await generate(f,body); assert.equal(res.status,status,await res.clone().text());
    assert.equal((await res.json()).error,error);
    assert.equal(storedState(f),before); assert.equal(await trialUsage(f.env,'reports','owner'),0);
    if(name==='foreign workspace scan' || name==='foreign snapshot row') assert.deepEqual(f.readKeys,[]);
  });
}
for(const report_type of ['manual','weekly_executive','monthly_executive','quarterly_executive']) {
  await test(`${report_type} still renders latest workspace snapshots and preserves its requested period`,async()=>{
    const f=setup(); seedReportScope(f);
    const res=await generate(f,{report_type,report_period:'existing-period',scan_id:'selected_older'});
    assert.equal(res.status,201,await res.clone().text());
    const {report}=await res.json(), text=pdfText(f,report);
    assert.equal(report.report_period,'existing-period');
    assert(text.includes('Scan reference: newer_same_domain')); assert(text.includes('second.example.com'));
    assert(!text.includes('Scan reference: selected_older'));
    const binding=JSON.parse(f.db.prepare('SELECT metadata_json FROM workspace_reports WHERE id=?').get(report.id).metadata_json);
    assert.deepEqual(binding.snapshots.map(s=>s.scan_id).sort(),['newer_same_domain','other_domain']);
    assert.equal(await trialUsage(f.env,'reports','owner'),1);
  });
}
console.log(`Trial daily allowance: ${passed} scenarios passed`);
