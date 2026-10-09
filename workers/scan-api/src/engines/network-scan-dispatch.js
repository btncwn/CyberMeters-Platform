import { normalizeNetworkTarget, normalizeNetworkPorts } from './network-targets.js';
import { createId } from '../lib/util.js';

export async function networkReceiptHash(text) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))),n=>n.toString(16).padStart(2,'0')).join('');
}
const tupleKey=o=>`${o.address}|${o.port}|${o.transport}`;
const observed=o=>o.state==='open'||o.state==='closed';
const details=o=>JSON.stringify({
  service:o.service ? {name:o.service.name,basis:o.service.basis,banner_sha256:o.service.banner_sha256} : null,
  tls:o.tls ? {leaf:o.tls.leaf_certificate?.certificate_identity,protocol:o.tls.protocol,cipher:o.tls.cipher,alpn:o.tls.alpn,hostname_match:o.tls.hostname_match?.result,trust:o.tls.trust_store_validation?.validation_result} : null,
});
export function networkObservationChanges(previous,observations) {
  const before=new Map(previous.map(r=>[tupleKey(r),r]));
  const changes=[];
  for(const current of observations) {
    if(!observed(current))continue; // Unknown is not absence or remediation.
    const old=before.get(tupleKey(current));let type=null;
    if(current.state==='open'&&!old?.last_observed_state)type='discovered';
    else if(current.state==='open'&&old.last_observed_state==='closed')type='opened';
    else if(current.state==='closed'&&old?.last_observed_state==='open')type='closed';
    else if(current.state==='open'&&old?.last_observed_state==='open'&&details(current)!==details({service:JSON.parse(old.service_json||'null'),tls:JSON.parse(old.tls_json||'null')}))type='changed';
    if(type)changes.push({type,address:current.address,port:current.port,transport:'tcp'});
  }
  return changes;
}
async function failScan(env,row,reason) {
  await env.cybermeters_db.prepare("UPDATE network_scans SET status='failed',quality=NULL,reason=?,completed_at=? WHERE id=? AND workspace_id=? AND status IN ('queued','running')").bind(reason,new Date().toISOString(),row.id,row.workspace_id).run();
}

export async function processNetworkScanMessage(body,env,deps={}) {
  if(!body||body.kind!=='network_probe'||body.v!==1||typeof body.scan_id!=='string'||body.scan_id.length>100)return {action:'ack',outcome:'malformed'};
  let row;
  try{row=await env.cybermeters_db.prepare(`SELECT s.*,t.target,t.addresses_json,t.authorization_status FROM network_scans s JOIN network_targets t ON t.id=s.target_id AND t.workspace_id=s.workspace_id JOIN workspaces w ON w.id=s.workspace_id AND w.deleted_at IS NULL WHERE s.id=?`).bind(body.scan_id).first();}
  catch{return {action:'retry',delaySeconds:60,outcome:'storage_unavailable'};}
  if(!row)return {action:'ack',outcome:'missing'};
  if(body.workspace_id!=null&&body.workspace_id!==row.workspace_id)return {action:'ack',outcome:'identity_mismatch'};
  if(row.status!=='queued')return {action:'ack',outcome:'already_claimed'};
  if(!env.NETWORK_PROBE?.fetch)return {action:'retry',delaySeconds:60,outcome:'collector_unavailable'};
  let normalized,ports;
  try{
    normalized=await normalizeNetworkTarget(row.target);ports=normalizeNetworkPorts(JSON.parse(row.ports_json),normalized.address_count);
    if(row.receipt_key!==`network-reports/${row.workspace_id}/${row.id}.json`||row.authorization_status!=='attested'||JSON.stringify(normalized.addresses)!==row.addresses_json)throw new Error('scope');
  }catch{try{await failScan(env,row,'network_scope_invalid');}catch{return {action:'retry',delaySeconds:60,outcome:'storage_unavailable'};}return {action:'ack',outcome:'scope_rejected'};}
  let claimed;
  try{claimed=await env.cybermeters_db.prepare("UPDATE network_scans SET status='running',started_at=? WHERE id=? AND status='queued'").bind(new Date().toISOString(),row.id).run();}
  catch{return {action:'retry',delaySeconds:60,outcome:'storage_unavailable'};}
  if(claimed.meta?.changes!==1)return {action:'ack',outcome:'already_claimed'};
  try {
    const adapter=deps.adapter||await import('./network-probe.js');
    const request={schema_version:'network-probe-request-v1',request_id:row.id,workspace_id:row.workspace_id,scan_id:row.id,profile:'network_services',deadline_at:new Date(Date.now()+90_000).toISOString(),targets:normalized.addresses.map(address=>({address,hostname:null})),ports};
    const receipt=await adapter.collectNetworkProbe(env,request,{signal:AbortSignal.timeout(90_000)});
    if(adapter.validateNetworkProbeReceipt(request,receipt).ok!==true)throw new Error('invalid_receipt');
    const active=await env.cybermeters_db.prepare("SELECT s.id FROM network_scans s JOIN workspaces w ON w.id=s.workspace_id WHERE s.id=? AND s.workspace_id=? AND s.status='running' AND w.deleted_at IS NULL").bind(row.id,row.workspace_id).first();
    if(!active)throw new Error('finalization_refused');
    const prior=await env.cybermeters_db.prepare('SELECT * FROM network_assets WHERE workspace_id=?').bind(row.workspace_id).all();
    const changes=networkObservationChanges(prior.results||[],receipt.observations);
    const text=JSON.stringify(receipt),hash=await networkReceiptHash(text),now=new Date().toISOString();
    const stored=await env.cybermeters_reports.put(`network-reports/${row.workspace_id}/${row.id}.json`,text,{onlyIf:new Headers({'If-None-Match':'*'}),httpMetadata:{contentType:'application/json'},sha256:hash});
    if(!stored)throw new Error('receipt_exists');
    // Completed state, inventory and audit are one transaction, only after the
    // immutable receipt is durable. No findings, scores or closed cases invented.
    const statements=[env.cybermeters_db.prepare(`UPDATE network_scans SET status=CASE WHEN status='running' AND EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) THEN 'running' ELSE 'invalid_finalization' END WHERE id=? AND workspace_id=?`).bind(row.workspace_id,row.id,row.workspace_id)];
    for(const item of receipt.observations) {
      statements.push(env.cybermeters_db.prepare(`INSERT INTO network_assets (workspace_id,address,port,transport,state,last_observed_state,service_json,tls_json,first_seen_at,last_seen_at,last_checked_at,last_scan_id) SELECT ?,?,?,'tcp',?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL) ON CONFLICT(workspace_id,address,port,transport) DO UPDATE SET state=excluded.state,last_observed_state=COALESCE(excluded.last_observed_state,network_assets.last_observed_state),service_json=CASE WHEN excluded.last_observed_state IS NULL THEN network_assets.service_json ELSE excluded.service_json END,tls_json=CASE WHEN excluded.last_observed_state IS NULL THEN network_assets.tls_json ELSE excluded.tls_json END,first_seen_at=COALESCE(network_assets.first_seen_at,excluded.first_seen_at),last_seen_at=COALESCE(excluded.last_seen_at,network_assets.last_seen_at),last_checked_at=excluded.last_checked_at,last_scan_id=excluded.last_scan_id`)
        .bind(row.workspace_id,item.address,item.port,item.state,observed(item)?item.state:null,JSON.stringify(item.service??null),JSON.stringify(item.tls??null),observed(item)?now:null,observed(item)?now:null,now,row.id,row.workspace_id));
    }
    statements.push(env.cybermeters_db.prepare(`UPDATE network_scans SET status='completed',quality=?,receipt_sha256=?,coverage_json=?,changes_json=?,completed_at=? WHERE id=? AND workspace_id=? AND status='running' AND EXISTS(SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL)`)
      .bind(receipt.quality,hash,JSON.stringify(receipt.coverage),JSON.stringify(changes),now,row.id,row.workspace_id,row.workspace_id));
    statements.push(env.cybermeters_db.prepare(`INSERT INTO audit_events (id,workspace_id,user_id,actor_type,event_type,entity_type,entity_id,description,metadata_json,created_at) SELECT ?,?,?,'system','network_scan_completed','network_scan',?,'Network service observation completed',?,? WHERE EXISTS(SELECT 1 FROM network_scans WHERE id=? AND workspace_id=? AND status='completed')`)
      .bind(createId('audit'),row.workspace_id,row.requested_by,row.id,JSON.stringify({receipt_sha256:hash,quality:receipt.quality,coverage:receipt.coverage,changes:changes.length}),now,row.id,row.workspace_id));
    const results=await env.cybermeters_db.batch(statements);
    if(results[receipt.observations.length+1]?.meta?.changes!==1)throw new Error('finalization_refused');
    return {action:'ack',outcome:'completed'};
  } catch {
    try{await failScan(env,row,'network_measurement_failed');}catch{return {action:'retry',delaySeconds:60,outcome:'finalization_unavailable'};}
    return {action:'ack',outcome:'failed'};
  }
}
export async function handleNetworkScanBatch(batch,env,ctx,deps={}) {
  for(const message of batch?.messages||[]) {
    const decision=await processNetworkScanMessage(message.body,env,deps);
    if(decision.action==='retry')message.retry({delaySeconds:decision.delaySeconds||60});else message.ack();
  }
}
// Hook into the existing hourly recovery, never schedule additional scans.
export async function recoverNetworkScans(env) {
  return env.cybermeters_db.prepare(`UPDATE network_scans SET status='failed',quality=NULL,reason='network_execution_interrupted',completed_at=? WHERE (status='running' AND julianday(started_at)<julianday('now','-5 minutes')) OR (status='queued' AND julianday(created_at)<julianday('now','-15 minutes'))`).bind(new Date().toISOString()).run();
}
