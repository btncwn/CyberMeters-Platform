#!/usr/bin/env node
// Real SQLite exercises the production route: permissions are not scan jobs.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {tlsAuthorizationRoutes,TLS_SPECIAL_CONSENT_VERSION,TLS_SERVICE_PORTS,TLS_SERVICE_LIMIT} from '../workers/scan-api/src/routes/tls-authorization.js';

const sql = new DatabaseSync(':memory:');
sql.exec(`CREATE TABLE workspaces(id TEXT PRIMARY KEY,deleted_at TEXT);
  CREATE TABLE domains(id TEXT PRIMARY KEY,domain TEXT);
  CREATE TABLE workspace_domains(workspace_id TEXT,domain_id TEXT,verification_status TEXT);
  CREATE TABLE network_targets(id TEXT PRIMARY KEY,workspace_id TEXT,target TEXT,authorization_status TEXT,addresses_json TEXT,scope_state TEXT);
  CREATE TABLE audit_events(id TEXT PRIMARY KEY,workspace_id TEXT,user_id TEXT,actor_type TEXT,event_type TEXT,entity_type TEXT,entity_id TEXT,description TEXT,metadata_json TEXT,created_at TEXT);
  INSERT INTO workspaces VALUES('a',NULL),('b',NULL),('deleted','2026-10-13');
  INSERT INTO domains VALUES('domain_a','owned.example.com'),('domain_b','other.example.com'),('unverified','pending.example.com');
  INSERT INTO workspace_domains VALUES('a','domain_a','verified'),('b','domain_b','verified'),('a','unverified','pending');
  INSERT INTO network_targets VALUES('target_a','a','8.8.8.8','attested','["8.8.8.8"]','in_scope'),('target_b','b','8.8.4.4','attested','["8.8.4.4"]','in_scope'),('revoked_target','a','1.1.1.1','revoked','["1.1.1.1"]','in_scope'),('unobserved_target','a','9.9.9.9','attested','["9.9.9.9"]','out_of_scope');`);
sql.exec(readFileSync(new URL('../database/migrations/120-tls-authorization.sql',import.meta.url),'utf8'));
const prepare = (text,args=[]) => ({bind:(...values)=>prepare(text,values),first:async()=>sql.prepare(text).get(...args)||null,all:async()=>({results:sql.prepare(text).all(...args)}),run:async()=>({meta:{changes:sql.prepare(text).run(...args).changes}})});
let networkCalls = 0;
const noNetwork = () => {networkCalls++;throw new Error('unexpected_network');};
let beforeBatch;
const db = {prepare,batch:async statements=>{if(beforeBatch){const change=beforeBatch;beforeBatch=null;change();}sql.exec('BEGIN');try{const result=[];for(const s of statements)result.push(await s.run());sql.exec('COMMIT');return result;}catch(error){sql.exec('ROLLBACK');throw error;}}};
const env = {cybermeters_db:db,TLS_ASSESSMENT_MODE:'evidence-v1',SCAN_QUEUE:{send:noNetwork},NETWORK_PROBE:{fetch:noNetwork}};
let specialControlsAvailable = false;
let assertions=0;
const check=(actual,expected)=>{assert.deepEqual(actual,expected);assertions++;};
const enable={enabled:true,authorization_confirmed:true,consent_version:TLS_SPECIAL_CONSENT_VERSION};
const service={domain_id:'domain_a',hostname:'mail.owned.example.com',sni:'mail.owned.example.com',port:587,application_protocol:'smtp',network_target_id:'target_a',authorization_confirmed:true};
async function request(method='GET',path='',body,options={}) {
  const workspace=options.workspace||'a';
  const url=new URL(`https://api.example.com/api/workspaces/${workspace}/tls-authorization${path}`);
  const req=new Request(url,{method,...(body!==undefined?{body:typeof body==='string'?body:JSON.stringify(body)}:{})});
  const response=await tlsAuthorizationRoutes({request:req,url,env,json:(value,status=200)=>Response.json(value,{status}),requireAuth:async()=>options.anonymous?null:{id:'admin_a'},requireWorkspaceRole:async(_u,scope,permission)=>scope===(options.allowedWorkspace||'a')&&(permission==='workspace:read'||options.role!=='viewer'),serverError:()=>Response.json({error:'storage_failed'},{status:500})},{specialControlsAvailable});
  return {status:response.status,body:await response.json()};
}
let response=await request();
check(response.status,200);check(response.body.authorization.enabled,false);check(response.body.authorization.generation,0);
check(response.body.capabilities.assessment_available,true);
check(response.body.capabilities.special_controls_available,false);
check((await request('PUT','',enable)).status,409);
check(sql.prepare('SELECT COUNT(*) AS n FROM workspace_tls_authorizations').get().n,0);
env.TLS_ASSESSMENT_MODE='disabled';
check((await request()).body.capabilities.assessment_available,false);
check((await request('PUT','',enable)).status,409);
check((await request('POST','/services',service)).status,409);
env.TLS_ASSESSMENT_MODE='evidence-v1';
specialControlsAvailable=true;
check((await request()).body.capabilities.special_controls_available,true);
check(response.body.verified_domains,[{domain_id:'domain_a',domain:'owned.example.com'}]);check(response.body.network_targets,[{id:'target_a',target:'8.8.8.8'}]);
check((await request('GET','',undefined,{anonymous:true})).status,401);
check((await request('GET','',undefined,{workspace:'b'})).status,403);
check((await request('PUT','',enable,{role:'viewer'})).status,403);
check((await request('GET','',undefined,{role:'viewer'})).body.capabilities.can_manage,false);
check((await request('GET','',undefined,{workspace:'deleted',allowedWorkspace:'deleted'})).status,404);
for (const invalid of [{enabled:true},{...enable,consent_version:'old'},{...enable,authorization_confirmed:false},{...enable,workspace_id:'b'},[],{enabled:'true'}]) check((await request('PUT','',invalid)).status,400);
check((await request('PUT','',JSON.stringify({enabled:false,padding:'x'.repeat(5000)}))).status,400);
response=await request('PUT','',enable);check(response.status,200);check(response.body.authorization.enabled,true);check(response.body.authorization.generation,1);check(response.body.authorization.authorized_by,'admin_a');
check(sql.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n,1);
check(JSON.parse(sql.prepare('SELECT metadata_json FROM audit_events').get().metadata_json).generation,1);
response=await request('PUT','',{enabled:false});check(response.body.authorization.enabled,false);check(response.body.authorization.generation,2);check(response.body.authorization.revoked_by,'admin_a');check(!!response.body.authorization.revoked_at,true);
// A stale special-control phase holding generation1 no longer has authority.
check(sql.prepare('SELECT enabled FROM workspace_tls_authorizations WHERE workspace_id=? AND generation=? AND enabled=1').get('a',1),undefined);
response=await request('PUT','',enable);check(response.body.authorization.generation,3);
for (const change of [{domain_id:'domain_b'},{domain_id:'unverified'},{hostname:'other.example.com',sni:'other.example.com'},{hostname:'owned.example.com.evil.net',sni:'owned.example.com.evil.net'},{sni:'another.owned.example.com'},{hostname:'127.0.0.1',sni:'127.0.0.1'},{port:443},{application_protocol:'https'},{application_protocol:'__proto__'},{port:'587'},{authorization_confirmed:false},{transport_override:'udp'}]) check((await request('POST','/services',{...service,...change})).status,400);
for (const target of ['target_b','revoked_target','unobserved_target','missing']) check((await request('POST','/services',{...service,network_target_id:target})).status,409);
check((await request('POST','/services',service,{role:'viewer'})).status,403);
response=await request('POST','/services',service);check(response.status,201);const id=response.body.service.id;
check(response.body.service.sni,service.hostname);check(response.body.service.authorization_status,'active');check(response.body.authorization.generation,4);
check((await request('POST','/services',service)).status,409);check((await request()).body.authorization.generation,4);
check((await request('GET','/services')).body.services.length,1);
// A valid second workspace cannot enumerate or revoke the first one's record.
check((await request('POST',`/services/${id}/revoke`,{},{workspace:'b',allowedWorkspace:'b'})).status,404);
check(sql.prepare('SELECT COUNT(*) AS n FROM workspace_tls_authorizations WHERE workspace_id=?').get('b').n,0);
check((await request('POST',`/services/${id}/revoke`,{},{role:'viewer'})).status,403);
response=await request('POST',`/services/${id}/revoke`,{});check(response.status,200);check(response.body.services,[]);check(response.body.authorization.generation,5);
const revoked=sql.prepare('SELECT * FROM workspace_tls_service_authorizations WHERE id=?').get(id);check(revoked.generation,2);check(revoked.revoked_by,'admin_a');check(revoked.authorization_status,'revoked');
check((await request('POST',`/services/${id}/revoke`,{})).status,404);check((await request()).body.authorization.generation,5);
// Failure to retain the audit rolls the permission write back atomically.
sql.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'controlled audit failure'); END;");
check((await request('PUT','',{enabled:false})).status,500);check((await request()).body.authorization.enabled,true);check((await request()).body.authorization.generation,5);
check((await request('POST','/services',service)).status,500);check((await request('GET','/services')).body.services,[]);
sql.exec('DROP TRIGGER fail_audit');
for (const [application_protocol,ports] of Object.entries(TLS_SERVICE_PORTS)) {
  for (const port of ports) check((await request('POST','/services',{...service,application_protocol,port})).status,201);
}
// Scope can change after the preliminary read; the conditional write rechecks it.
const generationBeforeRace=(await request()).body.authorization.generation;
const auditsBeforeRace=sql.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n;
beforeBatch=()=>sql.prepare("UPDATE workspace_domains SET verification_status='pending' WHERE workspace_id='a' AND domain_id='domain_a'").run();
check((await request('POST','/services',{...service,hostname:'new.owned.example.com',sni:'new.owned.example.com'})).status,409);
check((await request()).body.authorization.generation,generationBeforeRace);
check(sql.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n,auditsBeforeRace);
check((await request('POST','/services',{...service,hostname:'new.owned.example.com',sni:'new.owned.example.com'})).status,400);
sql.prepare("UPDATE workspace_domains SET verification_status='verified' WHERE workspace_id='a' AND domain_id='domain_a'").run();
beforeBatch=()=>sql.prepare("UPDATE network_targets SET authorization_status='revoked' WHERE id='target_a'").run();
check((await request('POST','/services',{...service,hostname:'new.owned.example.com',sni:'new.owned.example.com'})).status,409);
check((await request()).body.authorization.generation,generationBeforeRace);
sql.prepare("UPDATE network_targets SET authorization_status='attested' WHERE id='target_a'").run();
const activeCount=sql.prepare("SELECT COUNT(*) AS n FROM workspace_tls_service_authorizations WHERE workspace_id='a' AND authorization_status='active'").get().n;
for(let i=activeCount;i<TLS_SERVICE_LIMIT;i++) sql.prepare(`INSERT INTO workspace_tls_service_authorizations(id,workspace_id,domain_id,hostname,sni,port,application_protocol,network_target_id,authorization_status,generation,authorized_by,authorized_at,updated_at) VALUES(?,'a','domain_a',?,?,587,'smtp','target_a','active',1,'admin_a','2026-10-13','2026-10-13')`).run(`cap_${i}`,`cap${i}.owned.example.com`,`cap${i}.owned.example.com`);
check((await request('POST','/services',{...service,hostname:'overflow.owned.example.com',sni:'overflow.owned.example.com'})).status,409);
check((await request()).body.authorization.generation,generationBeforeRace);
check(sql.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n,auditsBeforeRace);
check(networkCalls,0);
console.log(`TLS authorization: ${assertions} assertions passed; tenant, role, scope, revocation generation, atomic audit and zero scan dispatch.`);
sql.close();
