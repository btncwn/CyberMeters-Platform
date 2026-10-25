// Real loopback transport; compare the lab's narrow projection to the actual
// production collector. Public DNS/peer/TLS seams are the existing test seams.
import assert from 'node:assert/strict';
import https from 'node:https';
import { gzipSync } from 'node:zlib';
import { createTlsFixtures } from '../../workers/network-probe/test/fixtures/create-tls-fixtures.js';
import { runExposureCollector } from '../../workers/network-probe/src/exposure-collector.js';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runTechModule } from '../../workers/scan-api/src/engines/tech-scan.js';
import { measureCorpusHost, measureCorpusOrigins, corpusRequest, unknownKind, sameSiteRedirectOrigin, phpHeaderObservation, projectCorpusRecord, originUnknownReasons } from './production-collector-corpus.mjs';

const tls=createTlsFixtures();
const host='owned.example.com';
const page='<html><title>GlobalProtect Portal</title><form action="/global-protect/login.esp"><input name="user"><input type="password"></form><p>PAN-OS version: 11.1.2-h2</p></html>';
let scenario='portal',seen=[];
const server=https.createServer({key:tls.read('valid.key'),cert:tls.read('valid.pem')},(req,res)=>{
  seen.push({url:req.url,range:req.headers.range,method:req.method});
  const control=req.url.includes('cybermeters-missing');
  if(control&&scenario==='control-challenge'){res.writeHead(200,{'content-type':'text/html'});return res.end('<html>verify you are human</html>');}
  if(control){res.writeHead(404,{'content-type':'text/plain'});return res.end(scenario==='control-size'?'x'.repeat(40000):'Missing');}
  if(scenario==='timeout'){res.writeHead(200);res.flushHeaders();return;}
  if(scenario==='redirect'){res.writeHead(302,{location:'https://foreign.example.com/'});return res.end();}
  const body=scenario==='size'?page+' '.repeat(40000):page;
  const headers={'content-type':'text/html',...(scenario==='php-absent'?{}:{'x-powered-by':scenario==='php-hidden'?'PHP':'PHP/8.4.26'})};
  if(scenario==='gzip'||scenario==='decode')headers['content-encoding']='gzip';
  res.writeHead(scenario==='partial206'?206:200,headers);
  res.end(scenario==='gzip'?gzipSync(body):scenario==='decode'?'invalid gzip':body);
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const dependencies={resolve:async(_h,family)=>family===4?['93.184.216.34']:[],
  connectTarget:()=>({hostname:'127.0.0.1',port:server.address().port}),peerAddress:()=> '93.184.216.34',trustedRoots:[tls.read('ca.pem')]};
try {
  for(const name of ['portal','php-hidden','php-absent','size','gzip','decode','partial206','control-size','control-challenge','timeout','redirect']) {
    scenario=name;seen=[];
    const measured=await measureCorpusHost(host,{dependencies});
    const measuredRequests=[...seen];seen=[];
    const receipt=await runExposureCollector(corpusRequest(host),dependencies);
    assert.equal(measured.portal_state,receipt.results[0].state,name+' state parity');
    assert.equal(measured.portal_comparable,receipt.results[0].comparable,name+' comparability parity');
    assert.deepEqual(measured.portal,receipt.results[0].portal||null,name+' portal parity');
    assert.equal(measured.telemetry.requests,receipt.telemetry.requests,name+' physical requests');
    assert.equal(measured.controls.length,2,name+' two controls');
    assert.ok(measuredRequests.every(r=>r.method==='GET'&&r.range==='bytes=0-32767'));
    assert.equal(measured.response.bytes_retained<=32768,true,name+' retained bytes bounded');
    assert.equal(JSON.stringify(measured).includes('<html>'),false,'no body in metadata');
    assert.equal(JSON.stringify(measured).includes('PHP/8.4.26'),false,'no raw header value');
    if(['portal','gzip','php-hidden','php-absent'].includes(name)) {
      assert.equal(measured.php_runtime.state,name==='php-hidden'?'hidden':name==='php-absent'?'absent':'outdated');
      assert.equal(measured.portal.version_state,'explicit');
      assert.equal(measured.response.bytes_retained,Buffer.byteLength(page));
    } else {
      assert.equal(measured.portal,null);
      if(['size','partial206','control-size','control-challenge'].includes(name))assert.equal(measured.php_runtime.state,'outdated','headers do not depend on body/control completeness');
      else assert.equal(measured.php_runtime,null);
    }
    if(name==='size'){assert.equal(measured.response.bytes_retained,32768);assert.equal(measured.unknown_kind,'size');}
    if(name==='control-size')assert.equal(measured.reason,'control_decoded_limit');
    if(name==='control-challenge')assert.equal(measured.reason,'control_content');
    if(name==='partial206')assert.equal(measured.unknown_kind,'partial_206');
    if(name==='decode')assert.equal(measured.unknown_kind,'decode');
    if(name==='timeout')assert.equal(measured.unknown_kind,'time');
    if(name==='redirect')assert.equal(measured.unknown_kind,'redirect');
    console.log('PASS production collector parity + metadata: '+name);
  }
  assert.equal(unknownKind('wire_limit'),'size');assert.equal(unknownKind('deadline_exhausted'),'time');
  console.log('Production collector parity and metadata checks PASS');
} finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));tls.cleanup();}

// Compare header admission with the real technology module. The fake fetch is
// confined to this local test and is restored before any transport checks.
const realFetch=globalThis.fetch;
try {
  for(const status of [200,206,401,403,404,429,500,530]) {
    const headers={'content-type':'text/html','x-powered-by':'PHP/8.4.26',server:status===530?'cloudflare':'fixture'};
    const response={url:'https://'+host+'/',status,headers,body:page,truncated:status===200,error:status===200?'decoded_limit':null};
    let calls=0;
    globalThis.fetch=async()=>{calls++;const r=new Response(page,{status,headers});Object.defineProperty(r,'url',{value:response.url});return r;};
    const tech=await runTechModule(host);
    const lab=phpHeaderObservation(response,host).observation;
    assert.equal(lab?.state||null,tech.php_runtime?.state||null,'real technology header admission '+status);
    assert.equal(calls,1);
  }
  assert.equal(phpHeaderObservation({url:'https://'+host+'/',status:200,headers:{'x-powered-by':'PHP/8.4.26'},truncated:false,error:'request_timeout'},host).observation,null);
  globalThis.fetch=async()=>{
    const stream=new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode(page));},pull(){return new Promise(()=>{});}});
    const r=new Response(stream,{headers:{'x-powered-by':'PHP/8.4.26'}});
    Object.defineProperty(r,'url',{value:'https://'+host+'/'});return r;
  };
  const firstChunkTech=await runTechModule(host);
  const firstChunkLab=phpHeaderObservation({url:'https://'+host+'/',status:200,headers:{'x-powered-by':'PHP/8.4.26'},
    bytesRead:Buffer.byteLength(page),truncated:false,error:'request_timeout'},host).observation;
  assert.equal(firstChunkLab.state,firstChunkTech.php_runtime.state,'later body failure cannot erase already observed headers');
  console.log('PASS PHP admission matches real technology module on2xx/206/capped/error/access/first-chunk responses');
} finally {globalThis.fetch=realFetch;}

const redirect=(location)=>({url:'https://'+host+'/',status:302,error:'off_origin_redirect',headers:{location}});
assert.equal(sameSiteRedirectOrigin(host,redirect('https://www.'+host+'/')), 'https://www.'+host);
assert.equal(sameSiteRedirectOrigin(host,redirect('https://login.'+host+'/')), 'https://login.'+host);
for(const location of ['https://foreign.example.com/','https://'+host+'.foreign.example.com/','http://www.'+host+'/',
  'https://user:pass@www.'+host+'/', 'https://www.'+host+':8443/','https://127.0.0.1/'])
  assert.equal(sameSiteRedirectOrigin(host,redirect(location)),null,'unsafe asset origin refused');

const scratch=mkdtempSync(join(tmpdir(),'cm-c60b-origin-'));
try {
  const made=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(scratch,'key.pem'),
    '-out',join(scratch,'cert.pem'),'-days','2','-subj','/CN='+host,'-addext',
    'subjectAltName=DNS:'+host+',DNS:www.'+host+',DNS:login.'+host],{stdio:'ignore',timeout:15000});
  assert.equal(made.status,0,'local multi-origin TLS fixture');
  let scenario='www',requests=[];
  const server=https.createServer({key:readFileSync(join(scratch,'key.pem')),cert:readFileSync(join(scratch,'cert.pem'))},(req,res)=>{
    const authority=req.headers.host;requests.push({authority,path:req.url});
    const original=scenario==='apex'?'www.'+host:host;
    const target=scenario==='apex'?host:'www.'+host;
    if(authority===original||scenario==='again') {
      const next=scenario==='foreign'?'foreign.example.com':authority===original?target:'login.'+host;
      res.writeHead(302,{location:'https://'+next+req.url});return res.end();
    }
    if(req.url.includes('cybermeters-missing')){res.writeHead(scenario==='target-control206'?206:404);return res.end('Missing');}
    res.writeHead(200,{'content-type':'text/html','x-powered-by':'PHP/8.4.26'});res.end(page);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    for(const name of ['www','apex','again','foreign','private','target-control206']) {
      scenario=name;requests=[];
      const start=name==='apex'?'www.'+host:host;
      const dependencies={resolve:async(h,family)=>family===4?[name==='private'&&h==='www.'+host?'10.0.0.1':'93.184.216.34']:[],
        connectTarget:()=>({hostname:'127.0.0.1',port:server.address().port}),peerAddress:()=> '93.184.216.34',trustedRoots:[readFileSync(join(scratch,'cert.pem'))]};
      const rows=await measureCorpusOrigins(start,{dependencies});
      assert.equal(rows.length,name==='foreign'?1:2,name+' retained origin rows');
      assert.equal(rows.filter(r=>r.selected_for_summary).length,1,name+' exactly one headline row');
      assert.equal(rows.at(-1).origin,'https://'+start,name+' apex/listed result preserved');
      if(name!=='foreign')assert.equal(rows.at(-1).selected_for_summary,false);
      if(['www','apex'].includes(name)) {
        assert.equal(rows[0].portal_state,'observed');assert.equal(rows[0].controls_usable,true);
        const target=name==='apex'?host:'www.'+host;
        assert.equal(requests.filter(r=>r.authority===target&&r.path.includes('cybermeters-missing')).length,2,'target has own controls');
        assert.equal(rows[0].php_runtime.state,'outdated');
      } else assert.equal(rows[0].portal_comparable,false,name+' no optimistic classification');
      if(name==='again')assert.ok(requests.every(r=>r.authority!=='login.'+host),'no second cross-origin transition');
      if(name==='private')assert.ok(requests.every(r=>r.authority===host),'private DNS target receives no HTTP');
      if(name==='foreign')assert.ok(requests.every(r=>r.authority===host),'foreign target never requested');
      if(name==='target-control206')assert.equal(projectCorpusRecord(rows[0],'php-runtime','fixture').classification,'review_required','PHP does not depend on exposure controls');
      const projected=rows.map(r=>projectCorpusRecord(r,'remote-access','fixture'));
      for(const role of ['listed_origin','redirect_target'])assert.equal(Object.values(originUnknownReasons(projected,role)).reduce((a,b)=>a+b,0),projected.filter(r=>r.origin_role===role&&r.classification==='unknown').length,'role reasons use origin rows, not the105 selected count');
      console.log('PASS single same-site asset transition + preserved apex: '+name);
    }
  } finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
} finally {rmSync(scratch,{recursive:true,force:true});}
console.log('C-60b production-origin and PHP admission proof PASS');
