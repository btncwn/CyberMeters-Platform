#!/usr/bin/env node
// A completed, conclusive external job must survive the real scan engine and
// resolver without acquiring a false partial/budget label.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { runScanEngine } from '../workers/scan-api/src/engines/scan-engine.js';
import { exposureIdentity } from '../shared/exposure/redaction.js';

const root=path.join(path.dirname(fileURLToPath(import.meta.url)),'..');
const db=new DatabaseSync(':memory:');
const apply=file=>{try{db.exec(fs.readFileSync(file,'utf8'));}catch(error){
  // Early billing migrations predate the later subscriptions table DDL.
  const earlyBilling=/^0(?:28|29)-/.test(path.basename(file));
  if(earlyBilling&&/^no such table: subscriptions$/i.test(String(error?.message)))return;
  if(!/already exists|duplicate column name/i.test(String(error?.message)))throw error;
}};
apply(path.join(root,'database/schema.sql'));
for(const name of fs.readdirSync(path.join(root,'database/migrations')).filter(name=>name.endsWith('.sql')).sort())
  apply(path.join(root,'database/migrations',name));
db.exec('PRAGMA foreign_keys=OFF');
const statement=(sql,args=[])=>({__sql:sql,bind:(...bound)=>statement(sql,bound),
  first:async column=>{const row=db.prepare(sql).get(...args)||null;return column&&row?row[column]:row;},
  all:async()=>({results:db.prepare(sql).all(...args),success:true,meta:{}}),
  run:async()=>{const result=db.prepare(sql).run(...args);return {success:true,meta:{changes:result.changes,last_row_id:Number(result.lastInsertRowid||0)}};}});
const d1={prepare:sql=>statement(sql),batch:async entries=>{
  const results=[];db.exec('BEGIN');try{for(const entry of entries)results.push(/^\s*select/i.test(entry.__sql)?await entry.all():await entry.run());
    db.exec('COMMIT');return results;}catch(error){db.exec('ROLLBACK');throw error;}
}};
const store=new Map();
const r2={get:async key=>{const body=store.get(String(key));return body==null?null:{text:async()=>body,json:async()=>JSON.parse(body)};},
  put:async(key,body)=>{store.set(String(key),String(body));return {};},delete:async key=>{store.delete(String(key));return {};},
  head:async()=>null,list:async()=>({objects:[]})};
const NOW='2026-10-17T21:00:00.000Z';
const ms=Date.parse(NOW),domain='example.com',scanId='scan_p1b';
db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES ('user','owner@example.com','Owner','starter','active',1,0)").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id,deleted_at) VALUES ('ws','Workspace','user',NULL)").run();
db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('member','ws','user','admin')").run();
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom','user',?)").run(domain);
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws','dom')").run();
db.prepare("UPDATE workspace_domains SET verification_status='verified' WHERE workspace_id='ws'").run();
db.prepare("INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,current_period_end,created_at) VALUES ('sub','user','starter','active','2099-12-31T23:59:59.000Z',?)").run(NOW);
db.prepare("INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,created_at) VALUES (?,?,?,?,?,?,?)")
  .run(scanId,'ws','dom',domain,'running',null,NOW);

const url=`https://${domain}/.env`;
const results=[{rule_id:'env-config',url,identity:exposureIdentity('env-config',url),indicators:[],
  state:'not_present_soft404',comparable:true,finding:null,observation:null,reason:'matches_two_negative_controls',observed_at:NOW}];
const endpoint={hostname:domain,sni:domain,address:'93.184.216.34',port:443,transport:'tcp',application_protocol:'https'};
const tlsRows=['tls1_2','tls1_3'].map(protocol=>({endpoint_index:0,control:'protocol',protocol,cipher_id:null,
  state:'accepted',reason:'handshake_completed',observed_at:NOW,
  evidence:{authenticated_finished:true,negotiated:{version:protocol,cipher:'AES128-GCM-SHA256',pfs:true,group:'X25519',group_bits:253},
    certificates:null,ocsp:null,extensions:null,vulnerability:null,limitations:[]},
  physical_telemetry:{connections:1,bytes_sent:120,bytes_received:300,duration_ms:10}}));
const plan={content_state:'complete',checks:[{rule_id:'env-config',url}],pending_assets:0,omitted_checks:0,
  hosts_not_applicable:[],tls:{profile_version:'fixture',policy_version:'fixture',
    endpoints:[{endpoint,endpoint_identity:`${domain}|${domain}|93.184.216.34|443|tcp|https`,scope:{kind:'standard_https'}}],
    gaps:[],selected:tlsRows.map(row=>({endpoint_index:0,check:{control:row.control,protocol:row.protocol,cipher_id:null}})),
    static_results:[],results:tlsRows,cursor:2,omitted_checks:0,omitted_services:0,deferred_hosts:[],deferred_endpoints:[],state:'complete'}};
db.prepare(`INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,plan_json,results_json,state,cursor,created_ms,deadline_ms,updated_at)
  VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(scanId,'ws','dom',domain,JSON.stringify(plan),JSON.stringify(results),'complete',1,ms,ms+1800000,NOW);

const originalFetch=globalThis.fetch;
globalThis.fetch=async input=>{
  const target=new URL(String(input));
  if(target.hostname==='www.cisa.gov'&&target.pathname.endsWith('known_exploited_vulnerabilities.json'))
    return new Response(JSON.stringify({title:'CISA Known Exploited Vulnerabilities Catalog',catalogVersion:'fixture',dateReleased:NOW,count:0,vulnerabilities:[]}),
      {status:200,headers:{'content-type':'application/json'}});
  if(['cloudflare-dns.com','dns.google'].includes(target.hostname)){
    const name=String(target.searchParams.get('name')||'').toLowerCase(),type=String(target.searchParams.get('type')||'A').toUpperCase();
    const answer=name===domain&&type==='A'?[{type:1,data:'93.184.216.34'}]:[];
    return new Response(JSON.stringify({Status:0,Answer:answer}),{status:200,headers:{'content-type':'application/dns-json'}});
  }
  return new Response('<html><head><title>Site</title></head><body>ok</body></html>',
    {status:200,headers:{'content-type':'text/html',server:'fixture'}});
};
const env={cybermeters_db:d1,cybermeters_reports:r2,SCAN_CAPACITY_MODE:'legacy',SCAN_SUBREQUEST_LIMIT:'200',
  SCAN_DEADLINE_MS:'115000',EXPOSURE_SCAN_MODE:'evidence-v1',TLS_ASSESSMENT_MODE:'evidence-v1',
  APP_VERSION:'p1b-single-domain-fixture',MFA_ENCRYPTION_KEY:'fixture-key',ALLOWED_ORIGIN:'https://app.example.com',
  FRONTEND_URL:'https://app.example.com',RESEND_API_KEY:'',ADMIN_EMAILS:''};
try{
  await runScanEngine(scanId,'dom','ws',domain,env,{now:()=>ms,executionContext:'queue',trigger:'manual'});
  const scan=db.prepare('SELECT status,scan_quality FROM scans WHERE id=?').get(scanId);
  assert.equal(scan.status,'completed');
  assert.equal(scan.scan_quality,'complete','conclusive completed phases stay complete');
  const report=[...store.entries()].find(([key])=>/^reports\/[^/]+\.json$/.test(key));
  assert(report,'scan report is persisted');
  const payload=JSON.parse(report[1]);
  assert.equal(payload.modules?.external_exposure?.quality,'complete');
  assert.equal(payload.modules?.tls_assessment?.quality,'complete');
  assert(!JSON.stringify(payload).includes('did not complete within the scan budget'));
  console.log('P1b single-domain runScanEngine: completed job, complete phases, complete scan, no false budget wording');
}finally{globalThis.fetch=originalFetch;db.close();}
