#!/usr/bin/env node
// Local controlled evidence only. Terminal execution must never certify health
// or clear a prior finding when the host did not provide assessable content.
import { runExposureModule, runAdminSurfaceModule } from '../workers/scan-api/src/engines/asset-intel.js';
import { resolveCyberMotDomainStates } from '../workers/scan-api/src/engines/cyber-mot-domains.js';
import { deriveAttackSurfaceSignalCompleteness } from '../workers/scan-api/src/engines/attack-surface-signal-completeness.js';
import { buildScanAssetEvidence } from '../workers/scan-api/src/engines/asset-evidence.js';
import { moduleCompletionGate } from '../workers/scan-api/src/engines/asm-cases.js';
import { externalExposureModule, evaluateExposureCondition, exposureConditionKey } from '../workers/scan-api/src/engines/exposure-findings.js';
import { exposureIdentity } from '../shared/exposure/redaction.js';

let passed=0,failed=0;
const check=(name,condition)=>{console.log(`${condition?'PASS':'FAIL'} ${name}`);condition?passed++:failed++;};
const host='fixture.example.com';
const originalFetch=globalThis.fetch;
globalThis.fetch=async value=>{
  const url=new URL(String(value));
  if(!['cloudflare-dns.com','dns.google'].includes(url.hostname))throw new Error('unexpected_network');
  const type=url.searchParams.get('type');
  return Response.json({Status:0,Answer:type==='A'?[{name:host+'.',type:1,TTL:60,data:'93.184.216.34'}]:[]});
};
let requests=0;
let exposure;
let edgeExposure;
let recoveredExposure;
try{
  exposure=await runExposureModule(host,[host],{fetcher:async()=>{
    requests++;
    return new Response('Unavailable',{status:requests===1?500:503,headers:{server:'fixture'}});
  },retryDelay:async()=>{}});
  let edgeRequests=0;
  edgeExposure=await runExposureModule(host,[host],{fetcher:async()=>{
    edgeRequests++;
    return new Response('Origin unavailable',{status:edgeRequests===1?522:523,headers:{server:'cloudflare'}});
  },retryDelay:async()=>{}});
  check('T1_EDGE_RETRIED_ONCE',edgeRequests===2);
  let recoveryRequests=0;
  recoveredExposure=await runExposureModule(host,[host],{fetcher:async()=>{
    recoveryRequests++;
    return new Response(recoveryRequests===1?'Unavailable':'<title>Available</title>',
      {status:recoveryRequests===1?500:200,headers:{'content-type':'text/html'}});
  },retryDelay:async()=>{}});
  check('T1_RECOVERY_RETRIED_ONCE',recoveryRequests===2);
}finally{globalThis.fetch=originalFetch;}
const asset=exposure.assets[0];
check('T1_TWO_STATUSES_RECORDED',JSON.stringify(asset.server_error_statuses)==='[500,503]'&&requests===2);
check('T1_TERMINAL_EXECUTION_NOT_CONTENT_ASSESSMENT',asset.probe_status==='target_unavailable'&&asset.http_assessed===false&&!exposure.incomplete);
check('T1_EDGE_STATUSES_AND_REASON',JSON.stringify(edgeExposure.assets[0].server_error_statuses)==='[522,523]'&&
  edgeExposure.assets[0].reason==='edge_origin_unreachable'&&edgeExposure.assets[0].probe_status==='target_unavailable');
check('T1_RECOVERED_TARGET_ASSESSED',recoveredExposure.assets[0].status===200&&
  recoveredExposure.assets[0].probe_status===undefined&&!recoveredExposure.incomplete);
check('T1_ADMIN_ZERO_NOT_HEALTHY',runAdminSurfaceModule({asset_exposure:exposure}).evidence_status==='not_assessed');
const signals=deriveAttackSurfaceSignalCompleteness({asset_exposure:exposure,admin_surface_detection:runAdminSurfaceModule({asset_exposure:exposure})}).signals;
check('T1_SERVICE_SIGNAL_UNKNOWN',signals.http_https_service.state==='incomplete');
check('T1_ADMIN_SIGNAL_UNKNOWN',signals.exposure_admin_surface.state==='incomplete');
check('T1_MANAGED_CASE_DEFERRED',moduleCompletionGate({asset_exposure:exposure},{status:'complete',modules_skipped:[]}).canVerify('asset_exposure')===false);
check('T1_ASSET_EVIDENCE_NAMES_CONTENT_GAP',buildScanAssetEvidence({domain:host,modules:{asset_exposure:exposure}})
  .get(host)?.not_checked.some(row=>row.part==='content'&&row.reason==='server_error'));

const report=assets=>({modules:{subdomains:{checked:1},dns:{resolves:true},admin_surface_detection:{checked:1},
  cloud_storage_discovery:{checked:1},asset_exposure:{checked:assets.length,assets},
  external_exposure:{quality:'complete',coverage:{completed:1,pending:0,blocked:0,budget_exhausted:0,uncertain:0,
    target_unavailable_hosts:0,non_resolving_hosts:0,not_applicable_hosts:0,pending_assets:0}},
  tls_assessment:{quality:'complete',coverage:{completed:1}}},findings:[],
  scan_quality:{status:'complete',modules_skipped:[],modules_incomplete:[],degradations:[]},
  monitoring_states:{version:'signal-monitoring-state-v3',signals:{
    attack_surface:{state:'monitoring_healthy'},website_security:{state:'monitoring_healthy'}}}});
const area=(assets,domain)=>resolveCyberMotDomainStates(report(assets)).find(row=>row.domain_key===domain);
check('T2_CLEAN_CONTROL_CAN_BE_HEALTHY',area([{host,status:200,reachable:true}],'attack_surface')?.state==='assessed_healthy');
check('T2_UNAVAILABLE_HOST_NEVER_HEALTHY',area([asset],'attack_surface')?.state==='evidence_insufficient');
check('T2_NON_RESOLVING_HOST_NEVER_HEALTHY',area([{host,probe_status:'not_applicable',reason:'authoritative_no_address',reachable:null}],'attack_surface')?.state==='evidence_insufficient');
const edge=area([{host,probe_status:'target_unavailable',reason:'edge_origin_unreachable',status:523,
  server_error_statuses:[522,523],reachable:false}],'attack_surface');
check('T2_EDGE_ORIGIN_WORDING',edge?.state==='evidence_insufficient'&&edge.summary.includes("Cloudflare could not reach this host's origin during this scan."));

for(const outcome of [{state:'target_unavailable',reason:'server_error',statuses:[500,503]},
  {state:'host_does_not_resolve',reason:'authoritative_no_address',statuses:[]}]){
  const receipt={source:'external_exposure',quality:'partial',job_state:'complete',phase_state:'complete',
    incomplete_reason:outcome.state,hosts_not_applicable:[],host_outcomes:[{hostname:host,...outcome,skipped_checks:134,observed_at:new Date().toISOString()}],
    coverage:{completed:0,pending:0,blocked:0,not_applicable:0,budget_exhausted:0,uncertain:0,recorded_total:0,
      omitted_checks:0,pending_assets:0,not_applicable_hosts:0,target_unavailable_hosts:outcome.state==='target_unavailable'?1:0,
      non_resolving_hosts:outcome.state==='host_does_not_resolve'?1:0,execution_complete_hosts:1},checks:[],findings:[],observed_at:new Date().toISOString()};
  const module=externalExposureModule(receipt);
  const website=resolveCyberMotDomainStates({...report([]),modules:{...report([]).modules,headers:{accessible:true,headers_assessed:true},
    ssl:{https_available:true,https_probe_executed:true},external_exposure:module}})
    .find(row=>row.domain_key==='website_security');
  const key=exposureConditionKey({rule_id:'env-config',url:`https://${host}/.env`,identity:exposureIdentity('env-config',`https://${host}/.env`)});
  check(`T3_${outcome.state}_WEBSITE_NOT_HEALTHY`,website?.state==='evidence_insufficient');
  check(`T3_${outcome.state}_PREVIOUS_FINDING_DEFERRED`,evaluateExposureCondition(key,module).state==='deferred');
  check(`T3_${outcome.state}_HOST_RECEIPT_PRESERVED`,module.host_outcomes[0]?.skipped_checks===134);
}
console.log(`Target outcome honesty: ${passed}/${passed+failed} assertions passed`);
if(failed)process.exitCode=1;
