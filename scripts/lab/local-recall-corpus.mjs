// Offline recall contract: actual HTTPS bytes -> production collector -> finding.
// Logical public host/address pass the existing TEST-ONLY transport seams; every
// physical socket is pinned to 127.0.0.1, with no native DNS or remote fetch.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import { createHash } from 'node:crypto';
import { createTlsFixtures } from '../../workers/network-probe/test/fixtures/create-tls-fixtures.js';
import { runExposureCollector } from '../../workers/network-probe/src/exposure-collector.js';
import { createBoundedHttpSession } from '../../workers/network-probe/src/bounded-http-session.js';
import { validateExposureReceipt } from '../../workers/network-probe/src/exposure-contract.js';
import { externalExposureModule } from '../../workers/scan-api/src/engines/exposure-findings.js';
import { REMOTE_ACCESS_ADVISORIES, REMOTE_ACCESS_TABLE_VERSION } from '../../shared/exposure/remote-access.js';
import { phpRuntimeFindings, PHP_RUNTIME_TABLE_VERSION } from '../../workers/scan-api/src/engines/php-runtime.js';
import { corpusRequest, phpHeaderObservation } from './production-collector-corpus.mjs';

const at=process.argv.indexOf('--output');
assert.ok(at>0&&process.argv[at+1], 'Usage: node scripts/lab/local-recall-corpus.mjs --output /tmp/recall.json');
const inputBytes=fs.readFileSync(new URL('./local-recall-corpus.json',import.meta.url));
const corpus=JSON.parse(inputBytes), host='owned.example.com', origin='https://'+host;
// Time is pinned to the public snapshot, not falsified as a current refresh.
const now=Date.parse(corpus.kev_snapshot.released_at)+3600000;
const catalogue={...corpus.kev_snapshot,fetched_at:new Date(now).toISOString()};
const profiles=new Map(corpus.portal_profiles.map(p=>[p.id,p]));
assert.equal(profiles.size,5);
assert.deepEqual([...new Set(corpus.portal_boundaries.map(r=>r.cve))].sort(),[...corpus.kev_snapshot.cves].sort());
assert.deepEqual([...new Set(REMOTE_ACCESS_ADVISORIES.map(r=>r.cve))].sort(),[...corpus.kev_snapshot.cves].sort(),'explicit corpus covers every unconditional CVE in scope');
assert.deepEqual([...new Set(REMOTE_ACCESS_ADVISORIES.map(r=>r.product_id))].sort(),[...profiles.keys()].sort());
const tls=createTlsFixtures(), records=[];
let active={body:'',server:'local-recall'}, requests=[];
const server=https.createServer({key:tls.read('valid.key'),cert:tls.read('valid.pem')},(req,res)=>{
  requests.push({path:req.url,method:req.method,range:req.headers.range,peer:req.socket.remoteAddress});
  if(/^\/\.cybermeters-missing-[a-f0-9]{32}(?:\.txt)?$/.test(req.url)) {
    res.writeHead(404,{'content-type':'text/plain'});return res.end('No such local resource');
  }
  if(req.url!==active.path){res.writeHead(404);return res.end('Unknown local path');}
  res.writeHead(200,{'content-type':'text/html',server:active.server});res.end(active.body);
});
const originalFetch=globalThis.fetch;
globalThis.fetch=async()=>{throw new Error('Remote fetch forbidden in local recall runner');};
const page=(profile,version)=>profile.html.replace('{{VERSION_FIELD}}',version===null?'':profile.label+' version: '+version);
const project=receipt=>externalExposureModule({source:'external_exposure',quality:receipt.quality,
  checks:receipt.results.map(r=>({...r,observed_at:receipt.finished_at})),
  coverage:{completed:receipt.results.length,pending:0,blocked:0,not_applicable:0,budget_exhausted:0,uncertain:0},
  observed_at:receipt.finished_at},{catalogue,now});
const counts={portal:{tp:0,fp:0,tn:0,fn:0,unknown:0},php:{tp:0,fp:0,tn:0,fn:0,unknown:0},hidden:{portal:0,portal_missed:0,php:0},fixed_boundary_deferred:0};
async function capture(id,fn) {
  try { const row=await fn();records.push({id,passed:true,...row}); }
  catch(error){records.push({id,passed:false,error:error.message});}
}
try {
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  assert.equal(server.address().address,'127.0.0.1');
  const dependencies={
    resolve:async(name,family)=>{assert.equal(name,host);return family===4?['93.184.216.34']:[];},
    connectTarget:({address,port})=>{assert.equal(address,'93.184.216.34');assert.equal(port,443);return {hostname:'127.0.0.1',port:server.address().port};},
    peerAddress:socket=>{assert.equal(socket.remoteAddress,'127.0.0.1');return '93.184.216.34';},
    trustedRoots:[tls.read('ca.pem')],
  };
  const transportProof=expected=>{
    assert.equal(requests.length,expected);
    assert.ok(requests.every(r=>r.peer==='127.0.0.1'&&r.method==='GET'&&r.range==='bytes=0-32767'));
  };
  async function collect(body,path) {
    active={body,path,server:'local-recall'};requests=[];
    const request=corpusRequest(host);request.checks[0].url=origin+path;
    const receipt=await runExposureCollector(request,dependencies);
    assert.equal(validateExposureReceipt(request,receipt).ok,true,'wire receipt validates');
    assert.equal(receipt.telemetry.controls_completed,2);
    transportProof(3);assert.equal(new Set(requests.slice(0,2).map(r=>r.path)).size,2);
    return {receipt,module:project(receipt),body_sha256:createHash('sha256').update(body).digest('hex')};
  }
  // Golden family/version/CVE/fix values are explicit corpus data, not generated
  // from the production signatures or advisory range table.
  for(const row of corpus.portal_boundaries) {
    const profile=profiles.get(row.profile);
    for(const kind of ['affected','fixed'])await capture(row.profile+'-'+row.cve+'-'+kind,async()=>{
      const version=row[kind],observed=await collect(page(profile,version),profile.path);
      const check=observed.receipt.results[0];
      assert.equal(check.portal.product_id,row.profile);assert.equal(check.portal.version,version);
      assert.equal(check.portal.version_state,'explicit');
      // Isolate each real snapshot CVE: overlapping CVEs cannot mask a wrong
      // match. A fixed boundary may defer because another CVE is still affected.
      const isolated=externalExposureModule({source:'external_exposure',quality:observed.receipt.quality,
        checks:[{...check,observed_at:observed.receipt.finished_at}]},{catalogue:{...catalogue,cves:[row.cve]},now});
      const assessment=isolated.checks[0].portal_assessment;
      const finding=isolated.findings[0];
      if(kind==='affected') {
        assert.equal(observed.receipt.quality,'complete');
        const exact=finding?.severity==='high'&&assessment.cve===row.cve&&assessment.advisory===row.advisory;
        counts.portal[exact?'tp':'fn']++;
        assert.equal(exact,true,'affected family/version must emit exact KEV CVE + advisory');
        assert.equal(finding.finding_type,'finding');assert.equal(finding.score_impact,0);
        assert.equal(finding.evidence[0].assessment.cve,row.cve);
        assert.equal(observed.module.findings[0]?.severity,'high','also fires with complete public snapshot');
        const absentKev=externalExposureModule({source:'external_exposure',quality:'complete',checks:[check]},
          {catalogue:{...catalogue,cves:[]},now});
        assert.equal(absentKev.findings.length,0,'version alone cannot claim KEV membership');
        assert.equal(absentKev.checks[0].portal_assessment.state,'deferred');
      } else {
        counts.portal[isolated.findings.length?'fp':assessment.state==='deferred'?'unknown':'tn']++;
        assert.equal(isolated.findings.length,0,'fixed boundary must not emit a finding');
        assert.notEqual(assessment.cve,row.cve);assert.ok(['clear','deferred'].includes(assessment.state));
        if(assessment.state==='deferred')counts.fixed_boundary_deferred++;
      }
      return {detector:'portal',expected:kind,profile:row.profile,version,cve:row.cve,advisory:row.advisory,
        kev_date_added:corpus.kev_snapshot.date_added[row.cve],assessment,findings:isolated.findings,
        collector_state:check.state,collector_quality:observed.receipt.quality,physical_requests:3,body_sha256:observed.body_sha256};
    });
  }
  for(const profile of profiles.values())for(const kind of ['all-fixed','hidden','unreadable','benign','quoted']) {
    await capture(profile.id+'-'+kind,async()=>{
      let body=page(profile,kind==='all-fixed'?profile.fixed:kind==='unreadable'?'unknown':null);
      if(kind==='benign')body=body.replace(/<form[\s\S]*?<\/form>/,'<p>Product documentation only</p>');
      if(kind==='quoted')body='<article>'+body+'</article>';
      const observed=await collect(body,profile.path), findings=observed.module.findings;
      if(kind==='hidden') {
        assert.equal(findings.length,1);assert.equal(findings[0].severity,'medium');
        assert.equal(observed.module.checks[0].portal.version_state,'absent');
        assert.equal(observed.module.checks[0].portal_assessment.cve,undefined);
        counts.hidden.portal++;
      } else {
        counts.portal[findings.length?'fp':observed.module.quality==='partial'?'unknown':'tn']++;
        assert.equal(findings.length,0);
        if(kind==='all-fixed')assert.equal(observed.module.checks[0].portal_assessment.state,'clear');
        if(kind==='unreadable')assert.equal(observed.module.checks[0].portal_assessment.state,'deferred');
      }
      return {detector:'portal',expected:kind,profile:profile.id,findings,
        portal:observed.module.checks[0].portal||null,assessment:observed.module.checks[0].portal_assessment||null,
        collector_state:observed.receipt.results[0].state,collector_quality:observed.receipt.quality,physical_requests:3,body_sha256:observed.body_sha256};
    });
  }
  // Preserve an actual documented form spelling, instead of silently adapting
  // it to the detector's regex. A miss is a recall failure, not a true negative.
  for(const variant of corpus.public_template_variants)await capture(variant.id,async()=>{
    const profile=profiles.get(variant.profile);
    const body=page(profile,null).replace(/<form\b[^>]*>/,variant.form_start);
    const observed=await collect(body,profile.path),finding=observed.module.findings[0];
    const detected=finding?.severity==='medium';
    counts.hidden[detected?'portal':'portal_missed']++;
    const quotedBody=body.replace('action=login.cgi','action="login.cgi"');
    const quotedControl=await collect(quotedBody,profile.path);
    assert.equal(quotedControl.module.findings[0]?.severity,'medium','changing only action quotes isolates the parse gap');
    const details={detector:'portal',expected:variant.expected,profile:profile.id,source:variant.source,
      collector_state:observed.receipt.results[0].state,collector_quality:observed.receipt.quality,
      reason:observed.receipt.results[0].reason,findings:observed.module.findings,physical_requests:6,body_sha256:observed.body_sha256,
      quoted_control:{severity:quotedControl.module.findings[0].severity,body_sha256:quotedControl.body_sha256}};
    return {...details,passed:detected,...(!detected?{error:'Documented unquoted relative form action was not recognised; medium hidden-version path missed. Runtime unchanged.'}:{})};
  });
  // Server is retained by the unmodified production native session. The PHP
  // finding builder consumes its actual HTTP header observation, not a stub.
  for(const row of corpus.php_cases)await capture(row.id,async()=>{
    active={path:'/',body:'<!doctype html><title>Local application</title><p>Welcome</p>',server:row.server};requests=[];
    const session=await createBoundedHttpSession(corpusRequest(host),dependencies);
    let response;try{response=await session.fetchBounded(origin+'/');}finally{session.close();}
    transportProof(1);assert.equal(response.error,null);assert.equal(response.headers.server,row.server);
    const {observation}=phpHeaderObservation(response,host),findings=phpRuntimeFindings(observation);
    const high=findings.some(f=>f.severity==='high');
    if(row.expected==='outdated')counts.php[high?'tp':'fn']++;
    else if(row.expected!=='hidden')counts.php[findings.length?'fp':observation.state==='unreadable'?'unknown':'tn']++;
    assert.equal(observation.state,row.expected);
    if(row.expected==='outdated') {
      assert.equal(findings.length,1);assert.equal(high,true);assert.equal(findings[0].score_impact,0);
      assert.match(findings[0].description,/CVE-2026-109618, CVE-2026-109619/);
      assert.equal(observation.reported_version,row.server.split('PHP/')[1]);
    } else if(row.expected==='hidden') {
      assert.equal(findings.length,1);assert.equal(findings[0].severity,'info');
      assert.equal(findings[0].finding_type,'observation');assert.equal(findings[0].score_impact,0);counts.hidden.php++;
    } else assert.equal(findings.length,0);
    return {detector:'php',expected:row.expected,observation,findings,physical_requests:1,
      header_sha256:createHash('sha256').update(row.server).digest('hex')};
  });
} finally {
  globalThis.fetch=originalFetch;server.closeAllConnections();
  if(server.listening)await new Promise(resolve=>server.close(resolve));tls.cleanup();
}
const failures=records.filter(r=>!r.passed);
const report={schema:'local-recall-output-v1',observed_at:new Date().toISOString(),
  corpus_sha256:createHash('sha256').update(inputBytes).digest('hex'),table_versions:{portal:REMOTE_ACCESS_TABLE_VERSION,php:PHP_RUNTIME_TABLE_VERSION},
  catalogue:corpus.kev_snapshot,catalogue_evaluation_time:new Date(now).toISOString(),
  scope:corpus.scope,transport:'Physical localhost HTTPS only; existing test seams for logical host/public DNS/peer; actual TLS verification/native HTTP/collector/evaluator/finding builders.',
  coverage:{portal_profiles:profiles.size,unconditional_cves:new Set(corpus.portal_boundaries.map(r=>r.cve)).size,
    advisory_boundary_pairs:corpus.portal_boundaries.length,php_supported_fix_branches:4,conditional_excluded:corpus.conditional_excluded,
    limitation:'One selected boundary per product+CVE, not every branch/theme/configuration. Public templates are reconstructed and explicit versions controlled; no real appliance/image or population recall claim. Existing105-domain FP harness retained unchanged; public unknown rows are not measured true negatives.'},
  counts,physical_requests:records.reduce((n,r)=>n+(r.physical_requests||0),0),
  recall:{portal_affected:counts.portal.tp/corpus.portal_boundaries.length,php_affected:counts.php.tp/corpus.php_cases.filter(r=>r.expected==='outdated').length,
    portal_hidden:counts.hidden.portal/(counts.hidden.portal+counts.hidden.portal_missed)},
  passed:failures.length===0,records};
fs.writeFileSync(process.argv[at+1],JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({passed:report.passed,counts,recall:report.recall,cases:records.length,failures}));
assert.equal(failures.length,0,'local recall corpus failed; inspect output metadata');
