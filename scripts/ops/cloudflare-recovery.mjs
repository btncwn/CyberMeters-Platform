#!/usr/bin/env node
// Bounded manual Cloudflare-only backup and disposable restore. No production
// schema/data mutation except the verified backup_completed evidence event.
import { readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const ACCOUNT = 'e0241806b7f2f8408c75f5e938be3271';
const SOURCE_DB = 'fd6792cb-441a-44a7-8ca2-9a0b411ec706';
const SOURCE_BUCKET = 'cybermeters-reports';
const BACKUP_BUCKET = 'cybermeters-recovery';
const MAX_BYTES = 100 * 1024 * 1024;
const MAX_OBJECTS = 1000;
const sha = b => createHash('sha256').update(b).digest('hex');
const quote = s => '"' + s.replaceAll('"', '""') + '"';
const sleep = ms => new Promise(r => setTimeout(r, ms));

export function seal(bytes, key) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  return Buffer.concat([iv, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
}
export function open(bytes, key) {
  if (bytes.length < 28) throw Error('Truncated encrypted recovery member');
  const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12), { authTagLength: 16 });
  decipher.setAuthTag(bytes.subarray(-16));
  return Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
}
export function inventory(rows) {
  return JSON.stringify(rows.map(r => [r.key, r.etag, r.size]).sort((a,b) => a[0].localeCompare(b[0])));
}
export function validateManifest(m) {
  if (m?.schema !== 1 || m.account !== ACCOUNT || m.source_db !== SOURCE_DB ||
      m.source_bucket !== SOURCE_BUCKET || !/^\d{8}T\d{6}Z-[a-f0-9]{8}$/.test(m.run) ||
      !Array.isArray(m.members) || m.members.length > MAX_OBJECTS + 1 ||
      m.members.filter(x => x.kind === 'd1').length !== 1) throw Error('Invalid recovery manifest');
  const slots = new Set(), keys = new Set();
  for (const x of m.members) {
    if (!['d1','r2'].includes(x.kind) || !/^[a-f0-9]{64}$/.test(x.sha256) ||
        !Number.isSafeInteger(x.size) || x.size < 0 || x.size > MAX_BYTES ||
        !/^members\/[a-f0-9]{64}$/.test(x.slot) || slots.has(x.slot) ||
        (x.kind === 'r2' && (typeof x.key !== 'string' || keys.has(x.key)))) throw Error('Invalid recovery member');
    slots.add(x.slot); if (x.kind === 'r2') keys.add(x.key);
  }
  if (m.members.reduce((n,x) => n+x.size,0) > MAX_BYTES) throw Error('Recovery exceeds manual size bound');
}

async function main() {
  const [action, arg] = process.argv.slice(2);
  if (!['backup','restore'].includes(action)) throw Error('Usage: node scripts/ops/cloudflare-recovery.mjs backup | restore <run>');
  const keyPath = process.env.CM_RECOVERY_KEY_FILE;
  if (!keyPath || (statSync(keyPath).mode & 0o077)) throw Error('CM_RECOVERY_KEY_FILE must name a private 0600 key file');
  const key = readFileSync(keyPath); if (key.length !== 32) throw Error('Recovery key must contain 32 random bytes');
  // An explicit API token supports unattended runs. A local Wrangler session is
  // a manual fallback, never copied into logs, subprocess arguments or manifests.
  const token = process.env.CLOUDFLARE_API_TOKEN || readFileSync(resolve(homedir(), '.wrangler/config/default.toml'),'utf8').match(/^oauth_token\s*=\s*"([^"]+)"/m)?.[1];
  if (!token) throw Error('Cloudflare authentication unavailable');
  async function raw(url, { method='GET', body, headers={}, auth=true }={}) {
    let response;
    for(let attempt=0;attempt<3;attempt++){
      response=await fetch(url, {method, body, redirect:'error', headers:{...(auth?{Authorization:`Bearer ${token}`} : {}),...headers},signal:AbortSignal.timeout(60000)});
      if(response.ok)break;
      if(!['GET','PUT'].includes(method)||![429,500,502,503,504].includes(response.status)||attempt===2)throw Error(`Cloudflare request failed: HTTP ${response.status}`);
      await response.body?.cancel();await sleep(1000*(attempt+1));
    }
    const bytes=Buffer.from(await response.arrayBuffer()); if(bytes.length>MAX_BYTES) throw Error('Response exceeds size bound');
    return {bytes,headers:response.headers};
  }
  const base=`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/`;
  async function api(path, body, method=body===undefined?'GET':'POST') {
    const {bytes}=await raw(base+path,{method,body:body===undefined?undefined:JSON.stringify(body),headers:{'Content-Type':'application/json'}});
    const parsed=JSON.parse(bytes); if(parsed.success!==true) throw Error('Cloudflare operation did not succeed');return parsed;
  }
  async function list(bucket) {
    let cursor='',rows=[];
    do {
      const p=await api(`r2/buckets/${bucket}/objects?per_page=1000${cursor?'&cursor='+encodeURIComponent(cursor):''}`);
      rows.push(...p.result);if(rows.length>MAX_OBJECTS)throw Error('Object count exceeds manual bound');
      cursor=p.result_info?.is_truncated?p.result_info.cursor:'';
      if(p.result_info?.is_truncated&&!cursor)throw Error('Missing pagination cursor');
    } while(cursor);
    return rows;
  }
  const objectPath=(bucket,key)=>`r2/buckets/${bucket}/objects/${encodeURIComponent(key)}`;
  const get=async(bucket,key)=>(await raw(base+objectPath(bucket,key))).bytes;
  async function put(bucket,key,bytes) {
    await raw(base+objectPath(bucket,key),{method:'PUT',body:bytes,headers:{'Content-Type':'application/octet-stream'}});
    if(sha(await get(bucket,key))!==sha(bytes))throw Error('Destination readback mismatch');
  }
  async function createBucket(name) {await api('r2/buckets',{name,storageClass:'Standard'});}
  async function exportSql(id) {
    let r=(await api(`d1/database/${id}/export`,{output_format:'polling'})).result;
    for(let i=0;r.status!=='complete';i++){
      if(i>=60||r.status==='error'||!r.at_bookmark)throw Error('D1 export failed or timed out');
      await sleep(1000);r=(await api(`d1/database/${id}/export`,{output_format:'polling',current_bookmark:r.at_bookmark})).result;
    }
    const url=new URL(r.result.signed_url);
    if(url.protocol!=='https:'||!url.hostname.endsWith('.r2.cloudflarestorage.com'))throw Error('Unexpected export download origin');
    return (await raw(url,{auth:false})).bytes;
  }
  const evidenceDir=process.env.CM_RECOVERY_EVIDENCE_DIR;
  if(!evidenceDir)throw Error('CM_RECOVERY_EVIDENCE_DIR is required');
  mkdirSync(evidenceDir,{recursive:true,mode:0o700});
  const evidence=(name,value)=>writeFileSync(resolve(evidenceDir,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
  if(action==='backup') {
    const run=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d+Z/,'Z')+'-'+randomBytes(4).toString('hex');
    const before=await list(SOURCE_BUCKET);
    if(before.some(x=>x.storage_class&&x.storage_class!=='Standard')||before.reduce((n,x)=>n+x.size,0)>MAX_BYTES)throw Error('Backup exceeds free-standard manual bounds');
    const buckets=(await api('r2/buckets')).result.buckets;
    if(!buckets.some(x=>x.name===BACKUP_BUCKET))await createBucket(BACKUP_BUCKET);
    const m={schema:1,run,account:ACCOUNT,source_db:SOURCE_DB,source_bucket:SOURCE_BUCKET,started_at:new Date().toISOString(),members:[]};
    async function member(kind,bytes,keyName) {
      const slot='members/'+sha(Buffer.from(kind+':'+(keyName??'database')));
      const x={kind,slot,size:bytes.length,sha256:sha(bytes),...(keyName===undefined?{}:{key:keyName})};
      const encrypted=seal(bytes,key);await put(BACKUP_BUCKET,run+'/'+slot,encrypted);
      if(sha(open(await get(BACKUP_BUCKET,run+'/'+slot),key))!==x.sha256)throw Error('Encrypted member mismatch');
      m.members.push(x);
    }
    await member('d1',await exportSql(SOURCE_DB));
    for(const [i,x] of before.entries()){
      const bytes=await get(SOURCE_BUCKET,x.key);if(bytes.length!==x.size)throw Error('Source object changed during backup');
      await member('r2',bytes,x.key);if((i+1)%20===0)console.log(`Verified ${i+1}/${before.length} report objects`);
    }
    if(inventory(before)!==inventory(await list(SOURCE_BUCKET)))throw Error('Source inventory changed; backup is incomplete');
    m.completed_at=new Date().toISOString();validateManifest(m);
    await put(BACKUP_BUCKET,run+'/manifest',seal(Buffer.from(JSON.stringify(m)),key));
    const stored=(await list(BACKUP_BUCKET)).filter(x=>x.key.startsWith(run+'/'));
    if(stored.length!==m.members.length+1)throw Error('Backup destination inventory mismatch');
    // This event records a verified same-provider copy, never an independent domain.
    const id='opev_'+randomBytes(16).toString('hex');
    await api(`d1/database/${SOURCE_DB}/query`,{sql:"INSERT INTO operational_events (id,event_type,correlation_id,status,attempts) VALUES (?,'backup_completed',?,'ok',1)",params:[id,'cloudflare:'+run]});
    const summary={run,completed_at:m.completed_at,bucket:BACKUP_BUCKET,d1_bytes:m.members[0].size,r2_objects:before.length,r2_bytes:before.reduce((n,x)=>n+x.size,0),event_id:id,independent_recovery_domain:false};
    evidence(run+'-backup.json',summary);console.log(JSON.stringify(summary));
  } else {
    const run=arg;if(!/^\d{8}T\d{6}Z-[a-f0-9]{8}$/.test(run??''))throw Error('Invalid backup run');
    const m=JSON.parse(open(await get(BACKUP_BUCKET,run+'/manifest'),key));validateManifest(m);if(m.run!==run)throw Error('Manifest run mismatch');
    const scratchPath=resolve(evidenceDir,run+'-scratch.json');
    const resume=process.argv[4]==='--resume';
    const previous=resume?JSON.parse(readFileSync(scratchPath)):null;
    if(resume&&(!previous.replay_completed||!previous.name?.startsWith('restore-scratch-'+run.toLowerCase()+'-')||previous.bucket!==previous.name||previous.database_id===SOURCE_DB))throw Error('Cannot resume an unverified scratch identity');
    const name=previous?.name??('restore-scratch-'+run.toLowerCase()+'-'+randomBytes(2).toString('hex'));
    const db=resume?(await api('d1/database/'+previous.database_id)).result:(await api('d1/database',{name})).result;
    if(db.uuid===SOURCE_DB||db.name!==name)throw Error('Scratch database identity mismatch');
    if(!resume){await createBucket(name);evidence(run+'-scratch.json',{database_id:db.uuid,bucket:name,name});}
    async function restoredBytes(x){const bytes=open(await get(BACKUP_BUCKET,run+'/'+x.slot),key);if(sha(bytes)!==x.sha256||bytes.length!==x.size)throw Error('Recovery manifest mismatch');return bytes;}
    const sql=await restoredBytes(m.members.find(x=>x.kind==='d1'));
    // Bound parameters keep large JSON values out of SQL text. The exported
    // dump contains individual rows > D1's SQL-text limit, so direct file import
    // is insufficient. Replay the same captured state in one deferred-FK batch.
    const local=new DatabaseSync(':memory:');local.exec(sql.toString());
    const schema=local.prepare("SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'view' THEN 1 WHEN 'index' THEN 2 ELSE 3 END,name").all();
    const tables=schema.filter(x=>x.type==='table').map(({name,sql})=>({name,sql})).sort((a,b)=>a.name.localeCompare(b.name));
    const batch=[{sql:'PRAGMA defer_foreign_keys=ON'}];
    for(const t of schema.filter(x=>x.type==='table'))batch.push({sql:t.sql});
    for(const t of tables){
      const cols=local.prepare('PRAGMA table_xinfo('+quote(t.name)+')').all().filter(x=>x.hidden===0).map(x=>x.name);
      const insert='INSERT INTO '+quote(t.name)+' ('+cols.map(quote).join(',')+') VALUES ('+cols.map(()=>'?').join(',')+')';
      for(const row of local.prepare('SELECT '+cols.map(quote).join(',')+' FROM '+quote(t.name)).all()){
        const params=cols.map(c=>row[c]);
        if(params.some(x=>ArrayBuffer.isView(x)))throw Error('Blob restore needs an explicitly tested encoding');
        batch.push({sql:insert,params});
      }
    }
    if(local.prepare("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").get()){
      for(const x of local.prepare('SELECT name,seq FROM sqlite_sequence').all()){
        batch.push({sql:'UPDATE sqlite_sequence SET seq=? WHERE name=?',params:[x.seq,x.name]});
        batch.push({sql:'INSERT INTO sqlite_sequence(name,seq) SELECT ?,? WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name=?)',params:[x.name,x.seq,x.name]});
      }
    }
    for(const t of schema.filter(x=>x.type!=='table'))batch.push({sql:t.sql});
    if(Buffer.byteLength(JSON.stringify({batch}))>MAX_BYTES)throw Error('Scratch batch exceeds manual bound');
    if(!resume)await api(`d1/database/${db.uuid}/query`,{batch});
    evidence(run+'-scratch.json',{database_id:db.uuid,bucket:name,name,replay_completed:true});
    console.log('Scratch D1 replay completed; verifying schema and every table');
    const query=async sql=>(await api(`d1/database/${db.uuid}/query`,{sql})).result;
    // D1 rejects remote PRAGMA integrity_check (SQLITE_AUTH). Check the
    // captured SQL locally, then prove remote schema/data equality and FKs.
    if(local.prepare('PRAGMA integrity_check').get().integrity_check!=='ok')throw Error('Captured database integrity check failed');
    if((await query('PRAGMA foreign_key_check;'))[0].results.length)throw Error('Scratch FK check failed');
    const remote=(await query("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name"))[0].results;
    if(JSON.stringify(tables)!==JSON.stringify(remote.sort((a,b)=>a.name.localeCompare(b.name))))throw Error('Restored schema differs from backup');
    const digest=rows=>sha(JSON.stringify(rows.map(x=>JSON.stringify(x)).sort()));
    for(const t of tables){const select='SELECT * FROM '+quote(t.name);if(digest(local.prepare(select).all())!==digest((await query(select))[0].results))throw Error('Restored table data differs from backup');}
    local.close();
    for(const [i,x] of m.members.filter(x=>x.kind==='r2').entries()){
      await put(name,x.key,await restoredBytes(x));if((i+1)%20===0)console.log(`Restored and verified ${i+1} report objects`);
    }
    if(inventory((await list(name)).map(x=>({key:x.key,size:x.size,etag:''})))!==inventory(m.members.filter(x=>x.kind==='r2').map(x=>({key:x.key,size:x.size,etag:''}))))throw Error('Restored object inventory differs');
    const summary={run,restored_at:new Date().toISOString(),scratch_database:db.uuid,scratch_name:name,scratch_bucket:name,tables_verified:tables.length,r2_objects_verified:m.members.length-1,captured_sql_integrity:'ok',remote_schema_and_all_rows:'identical',remote_integrity_pragma:'unsupported',foreign_key_violations:0,production_overwritten:false};
    evidence(run+'-restore.json',summary);console.log(JSON.stringify(summary));
  }
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(new URL(import.meta.url).pathname))main().catch(error=>{console.error('Recovery failed; no success claimed:', String(error.message).replace(/https?:\/\/\S+/g,'[URL omitted]'));process.exitCode=1;});
