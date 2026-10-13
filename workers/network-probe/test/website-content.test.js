import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import {createTlsFixtures} from './fixtures/create-tls-fixtures.js';
import {runWebsiteContentCollector} from '../src/website-content-collector.js';
import {WEBSITE_CONTENT_PROGRAM} from '../src/website-content-program.generated.js';
import {validateWebsiteContentRequest,validateWebsiteContentReceipt} from '../src/website-content-contract.js';
import {EXPOSURE_FIXTURES} from '../../../scripts/fixtures/exposure/cases.js';
const address='93.184.216.34',domain='owned.example.com';
const input=(extra={})=>({schema_version:'website-content-request-v1',request_id:'shared_request',workspace_id:'shared_workspace',scan_id:'shared_scan',domain,deadline_at:new Date(Date.now()+24000).toISOString(),max_requests:32,max_bytes:2097152,...extra});
const tls=createTlsFixtures();after(()=>tls.cleanup());
const missing=(req,res)=>{res.writeHead(404,{'content-type':'text/plain'});res.end('Not found');};
const secret=EXPOSURE_FIXTURES.find(f=>f.id==='client-secret-positive').body;
const page=(req,res)=>{
  if(req.url.includes('cybermeters-'))return missing(req,res);
  if(req.url==='/'){res.writeHead(200,{'content-type':'text/html','strict-transport-security':'max-age=31536000','set-cookie':['sessionid=NeverPersistThisCookie; HttpOnly; Secure; SameSite=Lax','SecretName729=NeverPersistEither'],'x-powered-by':'PHP/8.3'});return res.end('<html><title>Owned website</title><a href="/admin">Admin</a><a href="/logout">logout</a><a href="https://unrelated.example.net/.env">External</a><script src="/app.js?v=cachetoken"></script><script src="/app.js"></script></html>');}
  if(req.url==='/robots.txt'){res.setHeader('content-type','text/plain');return res.end('Sitemap: https://owned.example.com/sitemap.xml\nDisallow: /config/.env\nAllow: https://staging.owned.example.com/admin');}
  if(req.url==='/sitemap.xml'){res.setHeader('content-type','application/xml');return res.end('<urlset><url><loc>https://owned.example.com/admin</loc></url><url><loc>https://owned.example.com/backup/app.sql</loc></url></urlset>');}
  if(req.url==='/app.js'){res.setHeader('content-type','application/javascript');res.setHeader('sourcemap','/maps/app.js.map');return res.end(secret+'\nconst path="/admin"; //# sourceMappingURL=/maps/app.js.map');}
  if(req.url==='/admin'){res.setHeader('content-type','text/html');return res.end('<html><title>Grafana administration</title><form action="/login"><input type="password"></form></html>');}
  return missing(req,res);
};
async function fixture(handler,callback,{secure=true,bind='127.0.0.1',mapped=address}={}){
  const seen=[],server=(secure?https.createServer({key:tls.read('valid.key'),cert:tls.read('valid.pem')},handle):http.createServer(handle));
  function handle(req,res){seen.push({path:req.url,host:req.headers.host,headers:req.headers});handler(req,res);}
  seen.connections=0;server.on('connection',()=>seen.connections++);
  await new Promise(resolve=>server.listen(0,bind,resolve));
  const port=server.address().port,deps={resolve:async(_host,family)=>family===(mapped.includes(':')?6:4)?[mapped]:[],connectTarget:()=>({hostname:bind,port}),peerAddress:()=>mapped,trustedRoots:tls.read('ca.pem')};
  try{return await callback(deps,seen,port);}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}
const collect=async(deps,request=input())=>{const receipt=await runWebsiteContentCollector(request,deps);assert.deepEqual(validateWebsiteContentReceipt(request,receipt),{ok:true});return receipt;};

test('website request rejects arbitrary targets, executable fields and unbounded budgets',()=>{
  assert.equal(validateWebsiteContentRequest(input()).ok,true);
  for(const extra of [{domain:'127.0.0.1'},{domain:'owned.example.com:8080'},{headers:{cookie:'secret'}},{program:'arbitrary'},{max_requests:33},{max_bytes:2097153}])assert.equal(validateWebsiteContentRequest(input(extra)).ok,false);
});

test('real TLS pages and exposure evaluation reuse one physical GET with same-scan safe references',async()=>{
  await fixture(page,async(deps,seen)=>{
    const resourcesBefore=process.resourceUsage();
    const receipt=await collect(deps);
    const resourcesAfter=process.resourceUsage();
    for(const path of ['/','/robots.txt','/sitemap.xml','/app.js','/admin'])assert.equal(seen.filter(r=>r.path===path).length,1,path);
    assert.equal(receipt.telemetry.requests,seen.length);assert.ok(seen.every(r=>r.headers.authorization===undefined&&r.headers.cookie===undefined&&!r.path.includes('?')));
    assert.equal(receipt.results.find(r=>r.rule_id==='client-secret'&&r.url.endsWith('/app.js')).state,'finding');
    const entry=receipt.discoveries.find(d=>d.origin==='https://'+domain);assert.equal(entry.controls_completed,2);
    for(const path of ['/config/.env','/backup/app.sql','/maps/app.js.map'])assert.ok(entry.paths.includes(path),path);
    assert.ok(entry.hosts.includes('staging.'+domain));assert.deepEqual(entry.technologies,['php']);
    const home=receipt.page_discovery.pages.find(p=>p.path==='/');assert.equal(home.cookies[0].secure,true);assert.ok(home.security_headers.present.includes('strict-transport-security'));
    assert.equal(home.cookies[1].name,'[redacted-cookie-name]');
    const serialized=JSON.stringify(receipt);for(const value of ['CmFixture-7391','NeverPersist','SecretName729','cachetoken','<html','client_secret:'])assert.ok(!serialized.includes(value),value);
    assert.ok(!seen.some(r=>r.path==='/logout'));assert.ok(!seen.some(r=>r.host==='unrelated.example.net'));
    if(process.env.CYBERMETERS_CONTENT_METRICS_PATH)writeFileSync(process.env.CYBERMETERS_CONTENT_METRICS_PATH,JSON.stringify({
      schema_version:'shared-content-local-acceptance-v1',measured_at:new Date().toISOString(),
      scope:'Real TLS over company-controlled loopback; injected public DNS and mapped verified peer. No live customer endpoint or Cloudflare cost claim.',
      byte_metric:'Delivered encoded and decoded HTTP response body bytes; excludes HTTP headers and TCP/TLS overhead.',
      telemetry:receipt.telemetry,physical_connections:seen.connections,
      shared_paths:['/','/robots.txt','/sitemap.xml','/app.js','/admin'].map(path=>({path,physical_gets:seen.filter(r=>r.path===path).length})),
      pages:receipt.page_discovery.pages.length,rule_results:receipt.results.length,
      findings:receipt.results.filter(r=>r.state==='finding').length,uncertain:receipt.results.filter(r=>r.state==='uncertain').length,
      process_user_cpu_ms:(resourcesAfter.userCPUTime-resourcesBefore.userCPUTime)/1000,
      process_system_cpu_ms:(resourcesAfter.systemCPUTime-resourcesBefore.systemCPUTime)/1000,
      process_peak_rss_kib:resourcesAfter.maxRSS,
      resource_scope:'Node test process CPU during this collector call; process peak RSS includes fixture/runtime initialization.',
    },null,2)+'\n');
  });
});

test('forged result path, unknown rule, raw body/header/cookie fields and wrong origin control proof fail closed',async()=>{
  await fixture(page,async deps=>{
    const request=input(),receipt=await collect(deps,request);
    for(const mutate of [r=>r.results[0].url+='?token=hidden',r=>r.results[0].rule_id='unknown',r=>r.results[0].body='raw',r=>r.page_discovery.pages[0].headers={cookie:'raw'},r=>r.page_discovery.pages[0].cookies[0].value='raw',r=>r.discoveries[0].controls_completed=0,r=>r.discoveries[0].technologies=['raw-token']]){const bad=structuredClone(receipt);mutate(bad);assert.equal(validateWebsiteContentReceipt(request,bad).ok,false);}
  });
});

test('private DNS answers, peer mismatch and out-of-scope redirects send no unauthorized HTTP bytes',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-'))return missing(req,res);res.writeHead(302,{location:'https://127.0.0.1/secret'});res.end();},async(deps,seen)=>{
    const receipt=await collect(deps);assert.equal(receipt.page_discovery.coverage,'not_run');assert.ok(!seen.some(r=>r.path==='/secret'));
    seen.length=0;const blocked=await collect({...deps,resolve:async(_h,f)=>f===4?[address,'127.0.0.1']:[]});assert.equal(blocked.telemetry.requests,0);assert.equal(seen.length,0);
    const mismatch=await collect({...deps,peerAddress:()=> '127.0.0.1'});assert.ok(mismatch.telemetry.requests>0);assert.equal(seen.length,0);
  });
});

test('shared physical request cap includes controls and returns partial coverage',async()=>{
  await fixture(page,async(deps,seen)=>{const receipt=await collect(deps,input({max_requests:3}));assert.equal(seen.length,3);assert.equal(receipt.telemetry.requests,3);assert.equal(receipt.page_discovery.coverage,'partial');assert.ok(receipt.results.filter(r=>!r.url.endsWith('/')).every(r=>!r.comparable));assert.ok(receipt.results.some(r=>r.url.endsWith('/')&&r.comparable));});
});

test('aggregate bytes count actual bounded overread; truncated negatives do not clear findings',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-'))return missing(req,res);res.setHeader('content-type','text/html');res.end('<html>'+'A'.repeat(4000000));},async deps=>{const receipt=await collect(deps,input({max_bytes:4096}));assert.equal(receipt.quality,'partial');assert.equal(receipt.telemetry.byte_limit_exceeded,true);assert.ok(receipt.telemetry.bytes_wire<=4096+131072);assert.ok(receipt.telemetry.bytes_decoded<=4096+131072);});
});

test('abort cancels an active page socket and prevents later physical requests',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-'))return missing(req,res);},async(deps,seen)=>{
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),100);
    try{const receipt=await collect({...deps,signal:controller.signal});assert.equal(seen.length,3);assert.equal(receipt.quality,'partial');assert.ok(receipt.telemetry.duration_ms<1000);}finally{clearTimeout(timer);}
  });
});

test('actual IPv6 public peer mapping remains eligible and supplies shared page evidence',async()=>{
  await fixture(page,async deps=>{const receipt=await collect(deps);assert.ok(receipt.page_discovery.pages.some(p=>p.path==='/'&&p.outcome==='observed'));},{bind:'::1',mapped:'2606:4700:4700::1111'});
});

test('HTTP fallback keeps protocol-specific controls separate',async()=>{
  await fixture(page,async(deps,seen)=>{const receipt=await collect(deps);assert.ok(receipt.page_discovery.homepage_url.startsWith('http:'));assert.equal(receipt.discoveries.find(d=>d.origin==='https://'+domain).controls_completed,0);assert.equal(receipt.discoveries.find(d=>d.origin==='http://'+domain).controls_completed,2);assert.equal(receipt.telemetry.requests,seen.connections);assert.ok(seen.connections>=seen.length+3);},{secure:false});
});

test('reviewed generated Node program runs over stdin against the same local TLS fixture',async()=>{
  await fixture(page,async(deps,seen,port)=>{
    const request=input(),program=WEBSITE_CONTENT_PROGRAM+`const result=await __runWebsiteContentCollector(${JSON.stringify(request)},{resolve:async(_h,f)=>f===4?[${JSON.stringify(address)}]:[],connectTarget:()=>({hostname:'127.0.0.1',port:${port}}),peerAddress:()=>${JSON.stringify(address)},trustedRoots:${JSON.stringify(tls.read('ca.pem'))}});process.stdout.write(JSON.stringify(result));`;
    const child=spawn(process.execPath,['--input-type=module','-'],{stdio:['pipe','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',c=>stdout+=c);child.stderr.on('data',c=>stderr+=c);child.stdin.end(program);
    const code=await new Promise(resolve=>child.once('close',resolve));assert.equal(code,0,stderr);const receipt=JSON.parse(stdout);assert.deepEqual(validateWebsiteContentReceipt(request,receipt),{ok:true});assert.equal(seen.filter(r=>r.path==='/app.js').length,1);assert.ok(!stdout.includes('CmFixture-7391'));
  });
});

test('private website route shares exactly two fixed slots and rejects arbitrary program input',async()=>{
  const url=new URL('../src/index.js',import.meta.url);let source=readFileSync(url,'utf8');source=source.replace(/import\s*\{\s*DurableObject\s*\}\s*from\s*['"]cloudflare:workers['"];?/,'class DurableObject { constructor(ctx,env){this.ctx=ctx;this.env=env;} }').replace(/from '([^']+)'/g,(match,path)=>path.startsWith('.')?`from '${new URL(path,url).href}'`:match);
  const {default:worker}=await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`),calls=[];
  const env={PROBE_CONTAINERS:{getByName:name=>{calls.push(name);return {fetch:async url=>{assert.equal(url,'http://container/website-content');return new Response('',{status:503});}};}}};
  assert.equal((await worker.fetch(new Request('http://private/website-content',{method:'POST',body:JSON.stringify(input())}),env)).status,503);assert.deepEqual(calls,['probe-slot-0','probe-slot-1']);
  assert.equal((await worker.fetch(new Request('http://private/website-content',{method:'POST',body:JSON.stringify(input({program:'arbitrary'}))}),env)).status,400);assert.equal(calls.length,2);
});

// This suffix is outside the reviewed exposure evaluator's 32KiB window,
// although the page crawler can read 256KiB. It must never prove removal.
test('large JavaScript shared reads cannot certify absence beyond the evaluator prefix',async()=>{
  await fixture((req,res)=>{if(req.url==='/app.js'){res.setHeader('content-type','application/javascript');return res.end('/*'+' '.repeat(40000)+'*/'+secret+'\n//# sourceMappingURL=/assets/footer.js.map');}return page(req,res);},async deps=>{
    const receipt=await collect(deps),row=receipt.results.find(r=>r.rule_id==='client-secret'&&r.url.endsWith('/app.js'));
    assert.equal(row.state,'uncertain');assert.equal(row.comparable,false);assert.equal(row.reason,'body_limit');assert.ok(receipt.discoveries.some(d=>d.paths.includes('/assets/footer.js.map')));assert.equal(receipt.quality,'partial');
    const forged=structuredClone(receipt),changed=forged.results.find(r=>r.identity===row.identity);changed.state='not_found';changed.comparable=true;assert.equal(validateWebsiteContentReceipt(input(),forged).ok,false);
  });
});

test('oversized absent-path controls cannot authorize a comparable finding or negative',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-missing')){res.writeHead(404,{'content-type':'text/plain'});return res.end('X'.repeat(40000));}return page(req,res);},async deps=>{
    const receipt=await collect(deps);assert.equal(receipt.telemetry.controls_completed,0);assert.ok(receipt.results.every(row=>!row.comparable));assert.ok(receipt.results.every(row=>row.state==='uncertain'));
  });
});
