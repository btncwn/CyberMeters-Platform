#!/usr/bin/env node
// Offline, company-controlled loopback acceptance only. No public targets,
// provider credentials, customer workspaces or production resources are used.
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { createTlsFixtures } from '../workers/network-probe/test/fixtures/create-tls-fixtures.js';
import { Readable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { runExposureCollector } from '../workers/network-probe/src/exposure-collector.js';
import { validateExposureReceipt } from '../workers/network-probe/src/exposure-contract.js';
import { EXPOSURE_RULES } from '../shared/exposure/catalog.js';
import { EXPOSURE_FIXTURES } from './fixtures/exposure/cases.js';
import { probeAsset, runAdminSurfaceModule } from '../workers/scan-api/src/engines/asset-intel.js';

const root=fileURLToPath(new URL('../',import.meta.url));
const scratch=mkdtempSync(resolve(tmpdir(),'cm-exposure-validation-'));
process.once('exit',()=>rmSync(scratch,{recursive:true,force:true}));
const config=resolve(scratch,'wrangler.toml'),bundle=resolve(scratch,'bundle');
writeFileSync(config,`name="cybermeters-exposure-local-validation"\nmain=${JSON.stringify(resolve(root,'workers/network-probe/src/index.js'))}\ncompatibility_date="2026-10-09"\ncompatibility_flags=["enable_request_signal"]\nworkers_dev=false\npreview_urls=false\n[[containers]]\nclass_name="NetworkProbeContainer"\nscheduling_policy="durable_object"\n[[durable_objects.bindings]]\nname="PROBE_CONTAINERS"\nclass_name="NetworkProbeContainer"\n[exports.NetworkProbeContainer]\ntype="durable-object"\nstorage="sqlite"\n`);
const buildEnv={...process.env,XDG_CONFIG_HOME:resolve(scratch,'config'),WRANGLER_SEND_METRICS:'false'};
const program=spawnSync(process.execPath,['scripts/build-website-content-program.js','--check'],{cwd:root,env:buildEnv,stdio:'inherit',timeout:60000});
if(program.status!==0)process.exit(program.status||1);
const built=spawnSync(process.execPath,[resolve(root,'workers/scan-api/node_modules/wrangler/bin/wrangler.js'),'versions','upload','--dry-run','--config',config,'--outdir',bundle],{cwd:root,env:buildEnv,stdio:'inherit',timeout:60000});
if(built.status!==0)process.exit(built.status||1);
const tested=spawnSync(process.execPath,['--test','workers/network-probe/test/exposure-collector.test.js','workers/network-probe/test/website-content.test.js'],{cwd:root,env:{...buildEnv,EXPOSURE_PROBE_BUNDLE:resolve(bundle,'index.js'),CYBERMETERS_CONTENT_METRICS_PATH:resolve(root,'artifacts/exposure-content-acceptance.json')},stdio:'inherit',timeout:90000});
if(tested.status!==0){process.exitCode=1;}else{
  const records=[];
  const totals={baseline:{requests:0,bytes_wire:0,duration_ms:0,tp:0,fp:0,fn:0,tn:0},candidate:{requests:0,bytes_wire:0,bytes_decoded:0,duration_ms:0,tp:0,fp:0,fn:0,tn:0,uncertain:0}};
  const classify=(counts,predicted,positive)=>{counts[predicted?(positive?'tp':'fp'):(positive?'fn':'tn')]++;};
  const portalTls=createTlsFixtures();
  for(const f of EXPOSURE_FIXTURES){
    const portal=f.ruleId==='remote-access-portal',protocol=portal?'https':'http';
    const rule=EXPOSURE_RULES.find(rule=>rule.id===f.ruleId);
    const pathname=f.path||rule.paths[0];let served=0;
    const handler=(req,res)=>{
      served++;
      if(req.url.includes('cybermeters-missing')){res.writeHead(404,{'content-type':'text/plain'});return res.end('Not found');}
      res.writeHead(f.status??200,{'content-type':String(f.body).trimStart().startsWith('<')?'text/html':'text/plain',...(f.headers||{})});res.end(f.body);
    };
    const server=portal?https.createServer({key:portalTls.read('valid.key'),cert:portalTls.read('valid.pem')},handler):http.createServer(handler);
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const port=server.address().port;
    try{
      let baselineBytes=0,baselineRequests=0;
      const fetcher=()=>new Promise((resolve,reject)=>{
        baselineRequests++;
        const request=(portal?https:http).get({hostname:'127.0.0.1',port,path:pathname,agent:false,...(portal?{ca:portalTls.read('ca.pem'),servername:'owned.example.com'}:{})},response=>{
          response.on('data',chunk=>{baselineBytes+=chunk.length;});
          const headers=new Headers();for(const [key,value] of Object.entries(response.headers))if(value!=null)headers.set(key,Array.isArray(value)?value.join(','):value);
          resolve(new Response(Readable.toWeb(response),{status:response.statusCode,headers}));
        });request.once('error',reject);request.setTimeout(2000,()=>request.destroy(new Error('timeout')));
      });
      const oldStart=performance.now();
      const oldAsset=await probeAsset('owned.example.com',{fetcher});
      const oldModule=runAdminSurfaceModule({asset_exposure:{assets:[oldAsset]}});
      const oldMs=performance.now()-oldStart;
      const oldPositive=(oldModule.services||[]).some(row=>row.finding_type==='finding');
      const request={schema_version:'exposure-request-v1',request_id:'benchmark_request',workspace_id:'fixture_workspace',scan_id:'fixture_scan',origin:protocol+'://owned.example.com',deadline_at:new Date(Date.now()+12000).toISOString(),checks:[{rule_id:f.ruleId,url:protocol+'://owned.example.com'+pathname}],max_requests:12,max_bytes:524288};
      const observedBefore=served;
      const receipt=await runExposureCollector(request,{resolve:async(_host,family)=>family===4?['93.184.216.34']:[],connectTarget:()=>({hostname:'127.0.0.1',port}),peerAddress:()=> '93.184.216.34',...(portal?{trustedRoots:[portalTls.read('ca.pem')]}:{})});
      assert.deepEqual(validateExposureReceipt(request,receipt),{ok:true});assert.equal(receipt.telemetry.requests,served-observedBefore);
      const state=receipt.results[0].state;
      assert.equal(state,f.expectedState,f.id);
      const positive=f.expectedState==='finding';
      classify(totals.baseline,oldPositive,positive);classify(totals.candidate,state==='finding',positive);
      totals.baseline.requests+=baselineRequests;totals.baseline.bytes_wire+=baselineBytes;totals.baseline.duration_ms+=oldMs;
      for(const name of ['requests','bytes_wire','bytes_decoded','duration_ms'])totals.candidate[name]+=receipt.telemetry[name];
      if(['uncertain','blocked','not_applicable'].includes(state))totals.candidate.uncertain++;
      records.push({fixture_id:f.id,rule_id:f.ruleId,expected_state:f.expectedState,baseline_finding:oldPositive,candidate_state:state,baseline:{requests:baselineRequests,bytes_wire:baselineBytes,duration_ms:Number(oldMs.toFixed(3))},candidate:receipt.telemetry});
    }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  }
  portalTls.cleanup();
  const metrics=counts=>({...counts,duration_ms:Number(counts.duration_ms.toFixed(3)),precision:counts.tp+counts.fp?counts.tp/(counts.tp+counts.fp):null,recall:counts.tp+counts.fn?counts.tp/(counts.tp+counts.fn):null});
  const evidence={schema_version:'exposure-local-acceptance-v1',measured_at:new Date().toISOString(),source_baseline:'asset-intel.js probeAsset + runAdminSurfaceModule at a227d1fd',corpus_size:records.length,active_rules:EXPOSURE_RULES.filter(rule=>rule.active).length,scope:'Actual HTTP over loopback only; injected public DNS plan and verified local peer adapter. Not production acceptance.',byte_metric:'Encoded HTTP response body bytes delivered to the client; excludes request/response headers, TCP/TLS overhead, and kernel-buffer bytes not delivered to JavaScript. Actual final-chunk overread is counted.',baseline_limits:'Existing host title/technology/admin classifier has no sensitive-file content coverage. The same fixture response is given to its public fetcher seam; no fictional legacy content detector is substituted.',candidate_limits:'Two random-path controls per slice; max 12 HTTP requests, 32KiB body processing per response, 512KiB aggregate cut-off, 15s deadline; final chunks can cross the threshold and are honestly counted.',baseline:metrics(totals.baseline),candidate:metrics(totals.candidate),records};
  const at=process.argv.indexOf('--output');const output=resolve(root,at>=0?process.argv[at+1]:'artifacts/exposure-collector-acceptance.json');mkdirSync(dirname(output),{recursive:true});writeFileSync(output,JSON.stringify(evidence,null,2)+'\n');
  console.log(JSON.stringify({acceptance:'PASS',fixtures:records.length,active_rules:evidence.active_rules,baseline:evidence.baseline,candidate:evidence.candidate,evidence_file:output},null,2));
}
