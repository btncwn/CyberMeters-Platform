// Real loopback transport; compare the lab's narrow projection to the actual
// production collector. Public DNS/peer/TLS seams are the existing test seams.
import assert from 'node:assert/strict';
import https from 'node:https';
import { gzipSync } from 'node:zlib';
import { createTlsFixtures } from '../../workers/network-probe/test/fixtures/create-tls-fixtures.js';
import { runExposureCollector } from '../../workers/network-probe/src/exposure-collector.js';
import { measureCorpusHost, corpusRequest, unknownKind } from './production-collector-corpus.mjs';

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
    } else {assert.equal(measured.portal,null);assert.equal(measured.php_runtime,null);}
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
  console.log('C-60a corpus transport and failure-reason checks PASS');
} finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));tls.cleanup();}
