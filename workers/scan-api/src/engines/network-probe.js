import { PROBE_LIMITS, readBoundedJson, validateNetworkProbeRequest } from '../../../network-probe/src/contract.js';
import { validateNetworkProbeReceipt } from '../../../network-probe/src/receipt.js';
export { validateNetworkProbeReceipt, validateNetworkProbeRequest };
export { PROBE_PORTS, isPublicProbeAddress } from '../../../network-probe/src/contract.js';
// The collector's per-port TCP connect window (network-probe/src/collector.js:
// Math.min(1500, ...)). With less time left a request gets a shortened window,
// so its 'timeout' is not conclusive. Kept here (scan-api side) so the probe
// image is unchanged; a fixture pins it to collector.js.
export const PROBE_CONNECT_TIMEOUT_MS = 1500;
// A probe call needs a full connect window plus a margin, or a live port could
// read 'timeout' (R1 #1003). Below this, the call is not sent: 'deadline'.
export const PROBE_DEADLINE_MARGIN_MS = 1500;
export const PROBE_MIN_REMAINING_MS = PROBE_CONNECT_TIMEOUT_MS + PROBE_DEADLINE_MARGIN_MS;
// The probe's scan slots (network-probe index.js: probe-slot-0 / probe-slot-1);
// a third concurrent call is refused 503 collector_busy.
export const PROBE_SCAN_SLOTS = 2;

// One scan's own probe calls (live TLS, mail transport, remote admin) share the
// slots through this gate, so they queue instead of being refused (#1001 live
// test #2: mail's batch of two held both slots and the 16-port call was
// refused). FIFO; the permit is released on every path (resolve, throw, abort).
// A call whose deadline leaves less than PROBE_MIN_REMAINING_MS when its turn
// comes is not sent and throws 'probe_gate_deadline' - never a false timeout.
// Other scans and jobs use the same slots; the gate cannot see them, so a
// caller may still meet collector_busy.
export function createProbeGate(capacity=PROBE_SCAN_SLOTS,{now=Date.now}={}){
  let active=0;const waiting=[];
  const release=()=>{const next=waiting.shift();if(next)next.grant();else active--;};
  const acquire=signal=>{
    if(signal?.aborted)return Promise.reject(new Error('collector_aborted'));
    if(active<capacity){active++;return Promise.resolve();}
    return new Promise((resolve,reject)=>{
      const onAbort=()=>{const at=waiting.indexOf(entry);if(at>=0)waiting.splice(at,1);reject(new Error('collector_aborted'));};
      const entry={grant:()=>{signal?.removeEventListener('abort',onAbort);resolve();}};
      signal?.addEventListener('abort',onAbort,{once:true});
      waiting.push(entry);
    });
  };
  async function run(task,{deadlineAt=null,signal=null}={}){
    await acquire(signal);
    try{
      if(signal?.aborted)throw new Error('collector_aborted');
      if(deadlineAt!=null&&!(Date.parse(deadlineAt)-now()>=PROBE_MIN_REMAINING_MS))throw new Error('probe_gate_deadline');
      return await task();
    }finally{release();}
  }
  return {
    run,
    wrap:collect=>(env,request,options={})=>run(()=>collect(env,request,options),{deadlineAt:request?.deadline_at??null,signal:options?.signal??null}),
    get active(){return active;},
    get waiting(){return waiting.length;},
  };
}
// Why a probe call failed, recorded beside the customer reason (which stays as
// it is): collector_busy | deadline | budget | collector_unavailable.
export function probeErrorDetail(error,signal=null){
  const message=String(error?.message||'');
  if(message==='collector_busy')return 'collector_busy';
  if(message==='probe_gate_deadline'||message==='collector_aborted'||signal?.aborted)return 'deadline';
  if(error?.name==='SubrequestBudgetExhaustedError'||/budget/i.test(message))return 'budget';
  return 'collector_unavailable';
}

export async function collectNetworkProbe(env,request,{signal}={}) {
  const checked=validateNetworkProbeRequest(request);
  if(!checked.ok)throw new Error(checked.reason);
  if(!env.NETWORK_PROBE?.fetch)throw new Error('collector_not_configured');
  if(signal?.aborted)throw new Error('collector_aborted');
  const controller=new AbortController();
  const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});
  const aborted=new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>reject(new Error('collector_aborted')),{once:true}));
  const timeout=setTimeout(abort,Math.max(1,Date.parse(request.deadline_at)-Date.now()));
  try{
    const response=await Promise.race([aborted,env.NETWORK_PROBE.fetch('https://network-probe.internal/collect',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(request),signal:controller.signal})]);
    // The probe answers 503 when both scan slots are in use: say so, so a caller can retry once.
    if(!response.ok){await response.body?.cancel();throw new Error(response.status===503?'collector_busy':'collector_unavailable');}
    const receipt=await Promise.race([aborted,readBoundedJson(response.body,PROBE_LIMITS.responseBytes)]);
    if(controller.signal.aborted)throw new Error('collector_aborted');
    const validation=validateNetworkProbeReceipt(request,receipt);
    if(!validation.ok)throw new Error(validation.reason);
    return receipt;
  }finally{clearTimeout(timeout);signal?.removeEventListener('abort',abort);}
}
export async function collectLiveTls(env,{domain,scanId,workspaceId,requestId,signal,collect=collectNetworkProbe}){
  const request={schema_version:'network-probe-request-v1',request_id:requestId,workspace_id:workspaceId,scan_id:scanId,profile:'live_tls',deadline_at:new Date(Date.now()+20_000).toISOString(),targets:[{address:null,hostname:domain}],ports:[443]};
  try{return {receipt:await collect(env,request,{signal}),error:null};}
  catch{return {receipt:null,error:signal?.aborted?'live_tls_aborted':'live_tls_unavailable'};}
}

// Preserve every SSL module field. The live certificate is additive and bound
// to the exact endpoint/receipt; it never upgrades HTTP measurements.
export function attachLiveTlsToSsl(ssl,result){
  const previous=ssl&&typeof ssl==='object'?ssl:{};
  const receipt=result?.receipt;
  const observed=(receipt?.observations||[]).filter(row=>row.tls?.leaf_collected===true);
  const rank=row=>{
    const live=row.tls;const leaf=live.leaf_certificate;
    return (Date.parse(leaf.not_after)<Date.parse(receipt.finished_at)?8:0)+(live.hostname_match.result==='mismatched'?4:0)+(live.trust_store_validation.validation_result==='invalid'?2:0);
  };
  const selected=[...observed].sort((a,b)=>rank(b)-rank(a)||Date.parse(a.tls.leaf_certificate.not_after)-Date.parse(b.tls.leaf_certificate.not_after)||a.address.localeCompare(b.address))[0];
  const complete=!!receipt&&receipt.quality==='complete'&&observed.length===receipt.observations.length;
  const reason=result?.error||(complete?null:'live_tls_not_fully_observed');
  const live=selected?.tls||{leaf_collected:false,chain_collected:false,leaf_certificate:{collection_performed:false,collection_complete:false,certificate_identity:null},hostname_match:{assessment_performed:false,result:'unknown'},trust_store_validation:{validation_performed:false,validation_result:'unknown'},reason};
  return {...previous,network_probe:receipt||null,live_certificate:selected?{...live.leaf_certificate,endpoint:live.endpoint,hostname_match:live.hostname_match.result,trust_validation:live.trust_store_validation.validation_result,observed_at:live.observed_at,receipt_request_id:receipt.request_id}:null,certificate_evidence:{...(previous.certificate_evidence||{}),schema_version:'external-certificate-observation-v4',live_tls:{...live,receipt_request_id:receipt?.request_id||null,endpoint_observations:receipt?.observations||[],all_planned_endpoints_observed:complete}},...(!complete?{incomplete:true,incomplete_reason:previous.incomplete_reason||reason}:{} )};
}

// These findings require a captured leaf from the validated private collector.
// Evaluate every observed endpoint: a healthy endpoint cannot hide a bad one.
export function liveCertificateFindings(ssl,domain){
  const receipt=ssl?.network_probe;
  if(!receipt||receipt.schema_version!=='network-probe-receipt-v1'||receipt.profile!=='live_tls')return [];
  const groups=new Map();
  const add=(id,title,description,severity,row)=>{
    if(!groups.has(id))groups.set(id,{signal:id,finding_type:'finding',severity,score_impact:0,title,description,evidence_source:'live_tls',live_certificate_verified:true,evidence_basis:'pinned_public_address_tls_handshake',evidence:[]});
    groups.get(id).evidence.push({type:'live_tls',request_id:receipt.request_id,observed_at:row.tls.observed_at,endpoint:row.tls.endpoint,certificate_identity:row.tls.leaf_certificate.certificate_identity,not_after:row.tls.leaf_certificate.not_after,hostname_match:row.tls.hostname_match.result,trust_validation:row.tls.trust_store_validation.validation_result,trust_store_context:row.tls.trust_store_context});
  };
  for(const row of receipt.observations||[]){
    const live=row.tls,leaf=live?.leaf_certificate;
    if(row.hostname!==domain||row.port!==443||row.state!=='open'||live?.leaf_collected!==true||leaf?.collection_complete!==true)continue;
    const remaining=Date.parse(leaf.not_after)-Date.parse(receipt.finished_at);
    if(!Number.isFinite(remaining))continue;
    if(remaining<=0)add('certificate_expired','The live certificate has expired','A certificate served by the tested endpoint has expired. Renew and deploy a replacement, then run a fresh TLS check.','high',row);
    else if(remaining<14*86400000)add('certificate_expiring_critical','The live certificate expires within 14 days','Renew and deploy the certificate served by this endpoint before its observed expiry.','high',row);
    else if(remaining<30*86400000)add('certificate_expiring_soon','The live certificate expires within 30 days','Plan renewal of the certificate served by this endpoint before its observed expiry.','medium',row);
    if(live.hostname_match?.result==='mismatched')add('certificate_hostname_mismatch','The live certificate does not cover this hostname','Deploy a certificate whose subject alternative names cover the tested hostname.','high',row);
    if(live.trust_store_validation?.validation_result==='invalid')add('certificate_untrusted','The live certificate did not pass trust validation','The tested endpoint failed validation against the recorded Node.js Mozilla CA roots. Check the certificate dates and deployed chain; revocation was not assessed.','high',row);
  }
  return [...groups.values()];
}
