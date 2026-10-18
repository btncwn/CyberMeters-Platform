import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { createTlsFixtures } from './fixtures/create-tls-fixtures.js';
import { gzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { runExposureCollector, exposureCollectorProgram, matchesSoft404Baseline } from '../src/exposure-collector.js';
import { validateExposureRequest, validateExposureReceipt } from '../src/exposure-contract.js';
import { EXPOSURE_RULES } from '../../../shared/exposure/catalog.js';

const address='93.184.216.34';
const input=(rule='env-config',path='/.env',options={})=>({schema_version:'exposure-request-v1',request_id:'fixture_request',workspace_id:'fixture_workspace',scan_id:'fixture_scan',origin:'http://owned.example.com',deadline_at:new Date(Date.now()+12000).toISOString(),checks:[{rule_id:rule,url:'http://owned.example.com'+path}],max_requests:12,max_bytes:524288,...options});
const missing=(req,res)=>{res.writeHead(404,{'content-type':'text/plain'});res.end('Not found');};
const envBody='APP_NAME=FixtureApp\nDB_HOST=db.internal\nDB_PASSWORD=FixtureSecretValueNotLive729\n';
async function fixture(handler,callback){
  const seen=[];
  const server=http.createServer((req,res)=>{seen.push({path:req.url,headers:req.headers});handler(req,res);});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  const deps={resolve:async(_host,family)=>family===4?[address]:[],connectTarget:()=>({hostname:'127.0.0.1',port}),peerAddress:()=>address};
  try{return await callback(deps,seen);}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}
const handlerFor=(body,status=200,headers={})=>(req,res)=>{if(req.url.includes('cybermeters-missing'))return missing(req,res);res.writeHead(status,{'content-type':String(body).trimStart().startsWith('<')?'text/html':'text/plain',...headers});res.end(body);};
const collect=async(deps,request=input())=>{const receipt=await runExposureCollector(request,deps);assert.deepEqual(validateExposureReceipt(request,receipt),{ok:true});return receipt;};

test('wire contract rejects executable fields, off-origin URLs, dangerous verbs and arbitrary ports',()=>{
  assert.equal(validateExposureRequest(input()).ok,true);
  for(const alteration of [{command:'whoami'},{resolve:['127.0.0.1']},{max_requests:13},{max_bytes:524289},{origin:'http://127.0.0.1'},{origin:'http://owned.example.com:8080'},{checks:[{rule_id:'env-config',url:'http://other.example.com/.env'}]},{checks:[{rule_id:'env-config',url:'http://owned.example.com/delete/.env'}]},{checks:[{rule_id:'env-config',url:'http://owned.example.com/.env?token=hidden'}]}])assert.equal(validateExposureRequest(input('env-config','/.env',alteration)).ok,false,JSON.stringify(alteration));
});

test('real HTTP capture returns only static indicators and exact physical counters',async()=>{
  await fixture(handlerFor(envBody),async(deps,seen)=>{
    const result=await collect(deps);assert.equal(result.results[0].state,'finding');
    assert.equal(result.telemetry.requests,seen.length);assert.equal(seen.length,3);assert.equal(result.telemetry.retries,0);
    assert.equal(result.telemetry.bytes_wire,Buffer.byteLength(envBody)+18);assert.equal(result.telemetry.bytes_decoded,result.telemetry.bytes_wire);
    assert.ok(seen.every(row=>row.headers.authorization===undefined&&row.headers.cookie===undefined));
    const serialized=JSON.stringify(result);assert.ok(!serialized.includes('FixtureSecret'));assert.ok(!serialized.includes('DB_PASSWORD'));
    for(const key of ['body','snippet','headers','raw']){const bad=structuredClone(result);bad.results[0][key]=envBody;assert.equal(validateExposureReceipt(input(),bad).ok,false);}
  });
});

test('soft-404 content, dynamic SPA shells, WAF and status-only candidates do not become findings',async()=>{
  for(const variant of ['soft404','spa','waf','status'])await fixture((req,res)=>{
    res.writeHead(variant==='waf'?403:200,{'content-type':'text/html'});
    if(variant==='soft404')res.end(envBody);
    else if(variant==='spa')res.end(`<html><head><title>App</title></head><body><div id="root"></div><script src="app.js"></script><p>${Date.now()} ${req.url}</p></body></html>`);
    else if(variant==='waf')res.end('Cloudflare challenge: Just a moment. Verify you are human.');
    else res.end('Welcome to our website');
  },async deps=>{const receipt=await collect(deps);assert.notEqual(receipt.results[0].state,'finding',variant);
    if(variant==='soft404')assert.equal(receipt.results[0].state,'not_present_soft404','an identical catch-all secret-shaped body is absent');
  });
});

test('stable SPA catch-all is a conclusive soft-404 with two bounded baseline summaries',async()=>{
  await fixture((req,res)=>{res.writeHead(200,{'content-type':'text/html; charset=utf-8'});
    res.end(`<html><head><title>App</title></head><body><div id="root"></div><p>${req.url}</p></body></html>`);
  },async deps=>{
    const receipt=await collect(deps);
    const row=receipt.results[0];
    assert.equal(row.state,'not_present_soft404',JSON.stringify({reason:row.reason,baseline:receipt.baseline,observed:row.response_summary}));assert.equal(row.comparable,true);
    assert.equal(row.reason,'matches_two_negative_controls');assert.equal(receipt.quality,'complete');
    assert.equal(receipt.baseline.length,2);
    assert.ok(receipt.baseline.every(control=>control.status===200&&control.content_type==='text/html'&&
      control.body_length>0&&/^[a-f0-9]{64}$/.test(control.body_sha256)));
    assert.ok(matchesSoft404Baseline(receipt.baseline,row.response_summary));
    const forged=structuredClone(receipt);forged.results[0].response_summary.normalized_sha256='0'.repeat(64);
    assert.equal(validateExposureReceipt(input(),forged).ok,false);
    // Mutating away baseline agreement must fail this positive fixture.
    const disabled=Function(`return (${matchesSoft404Baseline.toString().replace('first.normalized_sha256===second.normalized_sha256','false&&first.normalized_sha256===second.normalized_sha256')})`)();
    assert.equal(disabled(receipt.baseline,row.response_summary),false);
  });
});

test('DNS A and AAAA vetting prevents mixed-public/private, rebinding and mapped-local connections',async()=>{
  await fixture(handlerFor(envBody),async(deps,seen)=>{
    for(const bad of ['127.0.0.1','10.1.2.3','169.254.169.254','::1','::ffff:127.0.0.1','fc00::1','2001:db8::1']){
      const receipt=await collect({...deps,resolve:async(_host,family)=>family===4?[address]:[bad]});
      assert.equal(receipt.telemetry.requests,0);assert.equal(receipt.results[0].state,'uncertain');assert.equal(seen.length,0);
    }
    let calls=0;
    const receipt=await collect({...deps,resolve:async(_host,family)=>{calls++;return family===4?(calls>2?['127.0.0.1']:[address]):[];}});
    assert.equal(receipt.telemetry.requests,1);assert.equal(seen.length,1);assert.equal(receipt.results[0].state,'uncertain');
  });
});

test('pinned peer mismatch fails closed and consumes the attempted request',async()=>{
  await fixture(handlerFor(envBody),async(deps,seen)=>{const receipt=await collect({...deps,peerAddress:()=> '127.0.0.1'});assert.equal(receipt.results[0].state,'uncertain');assert.equal(receipt.telemetry.requests,3);assert.equal(seen.length,0,'peer validation precedes HTTP bytes');});
});

test('same-origin redirects count each hop; off-origin and loops never escape',async()=>{
  for(const mode of ['same','foreign','loop'])await fixture((req,res)=>{
    if(req.url.includes('cybermeters-missing'))return missing(req,res);
    if(req.url==='/.env'){res.writeHead(302,{location:mode==='same'?'/config/.env':mode==='foreign'?'http://127.0.0.1/secret':'/.env'});return res.end();}
    res.end(envBody);
  },async(deps,seen)=>{const receipt=await collect(deps);assert.equal(receipt.telemetry.requests,seen.length);assert.equal(receipt.results[0].state,mode==='same'?'finding':'uncertain');assert.equal(seen.length,mode==='same'?4:3);});
});

test('redirect exhaustion cannot exceed physical request budget',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-missing'))return missing(req,res);res.writeHead(302,{location:req.url==='/.env'?'/config/.env':'/config/.env.local'});res.end();},async(deps,seen)=>{
    const receipt=await collect(deps,input('env-config','/.env',{max_requests:3}));assert.equal(seen.length,3);assert.equal(receipt.telemetry.requests,3);assert.equal(receipt.results[0].state,'uncertain');
  });
});

test('ignored Range and compressed bombs stop before unbounded buffering; actual overread is counted',async()=>{
  for(const compressed of [false,true])await fixture(handlerFor(compressed?gzipSync(Buffer.from(envBody+'A'.repeat(2000000))):envBody+'A'.repeat(2000000),200,compressed?{'content-encoding':'gzip'}:{}),async deps=>{
    const receipt=await collect(deps,input('env-config','/.env',{max_bytes:4096}));assert.equal(receipt.results[0].state,'uncertain');assert.equal(receipt.quality,'partial');assert.equal(receipt.telemetry.byte_limit_exceeded,true);assert.ok(receipt.telemetry.bytes_wire<=4096+131072);assert.ok(receipt.telemetry.bytes_decoded<=4096+131072);
  });
});

test('slow responses, dropped sockets and unsupported encodings remain incomplete',async()=>{
  for(const mode of ['slow','drop','encoding'])await fixture((req,res)=>{
    if(req.url.includes('cybermeters-missing'))return missing(req,res);
    if(mode==='slow')return;
    if(mode==='drop'){res.writeHead(200,{'content-length':'999'});res.write(envBody);return res.socket.destroy();}
    res.writeHead(200,{'content-encoding':'unknown'});res.end(envBody);
  },async deps=>{const request=input('env-config','/.env',{deadline_at:new Date(Date.now()+200).toISOString()});const result=await collect(deps,request);assert.equal(result.results[0].state,'uncertain');assert.equal(result.quality,'partial');assert.ok(result.telemetry.duration_ms<1200);});
});

test('revocation AbortSignal ends active socket and starts no later check',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-missing'))return missing(req,res);},async(deps,seen)=>{
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),60);
    try{const receipt=await collect({...deps,signal:controller.signal},input('env-config','/.env',{checks:[{rule_id:'env-config',url:'http://owned.example.com/.env'},{rule_id:'env-config',url:'http://owned.example.com/.env.local'}]}));assert.equal(receipt.results[1].state,'uncertain');assert.equal(seen.length,3);assert.ok(receipt.telemetry.duration_ms<1000);}finally{clearTimeout(timer);}
  });
});

test('serialized production source has no customer-program execution entry point',()=>{
  const source=exposureCollectorProgram();
  const rejected=spawnSync(process.execPath,['--input-type=module','-e',source],{input:JSON.stringify({...input(),command:'echo sentinel-secret'}),encoding:'utf8',timeout:5000});assert.equal(rejected.status,1);assert.equal(rejected.stdout,'');assert.ok(!rejected.stderr.includes('sentinel-secret'));
  const program=source.slice(0,source.indexOf("let raw='';"))+`const result=await runExposureCollector(${JSON.stringify(input())},{resolve:async()=>['127.0.0.1']});process.stdout.write(JSON.stringify(result));`;
  const result=spawnSync(process.execPath,['--input-type=module','-e',program],{encoding:'utf8',timeout:5000});assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).telemetry.requests,0);
});

async function importWorker(bundlePath){
  const url=bundlePath?new URL('file://'+bundlePath):new URL('../src/index.js',import.meta.url);let source=readFileSync(url,'utf8');
  source=source.replace(/import\s*\{\s*DurableObject\s*\}\s*from\s*['"]cloudflare:workers['"];?/, 'class DurableObject { constructor(ctx,env){this.ctx=ctx;this.env=env;} }');
  source=source.replace(/from '([^']+)'/g,(match,path)=>path.startsWith('.')?`from '${new URL(path,url).href}'`:match);
  if(bundlePath)source+='\nexport { exposureCollectorProgram };';
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
test('private /exposure dispatcher preserves two shared slots and cannot choose a third',async()=>{
  const {default:worker}=await importWorker();const calls=[];
  const env={PROBE_CONTAINERS:{getByName:name=>{calls.push(name);return{fetch:async(url)=>{assert.equal(url,'http://container/exposure');return new Response('',{status:503});}};}}};
  const response=await worker.fetch(new Request('http://container/exposure',{method:'POST',body:JSON.stringify(input())}),env);assert.equal(response.status,503);assert.deepEqual(calls,['probe-slot-0','probe-slot-1']);
});

// Actual network fixtures for every active rule are intentionally loaded from
// the shared catalog corpus so the evaluator and collector cannot drift.
test('all active rule fixtures traverse real HTTP sockets and preserve expected classifications',async()=>{
  const {EXPOSURE_FIXTURES}=await import('../../../scripts/fixtures/exposure/cases.js');
  const covered=new Set();
  for(const f of EXPOSURE_FIXTURES){
    const rule=EXPOSURE_RULES.find(rule=>rule.id===f.ruleId);assert.ok(rule,f.id);
    const path=f.path||rule.paths[0];
    await fixture(handlerFor(f.body,f.status??200,f.headers||{}),async deps=>{
      const receipt=await collect(deps,input(f.ruleId,path));assert.equal(receipt.results[0].state,f.expectedState,f.id);covered.add(f.ruleId);
    });
  }
  assert.deepEqual([...covered].sort(),EXPOSURE_RULES.filter(rule=>rule.active).map(rule=>rule.id).sort());
});

test('one URL shared by two rule evaluations consumes only one physical request',async()=>{
  await fixture(handlerFor('{"database":{"host":"db.internal","password":"CmFixtureSecret729"}}'),async(deps,seen)=>{
    const request=input('application-config','/config.json',{checks:[{rule_id:'application-config',url:'http://owned.example.com/config.json'},{rule_id:'client-secret',url:'http://owned.example.com/config.json'}],max_requests:4});
    const receipt=await collect(deps,request);assert.equal(seen.length,3);assert.equal(receipt.telemetry.requests,3);assert.equal(receipt.results.length,2);
  });
});

test('observed references remain typed safe candidates and never trigger out-of-origin fetches',async()=>{
  const body='<html><body><script src="/assets/main.js"></script><a href="/app.js.map">map</a><a href="/delete/data.sql">unsafe</a><script src="https://api.owned.example.com/env.js"></script><script src="https://external.example.com/env.js"></script></body></html>';
  await fixture(handlerFor(body),async(deps,seen)=>{
    const receipt=await collect(deps,input('client-secret','/'));assert.equal(receipt.results[0].state,'not_found');assert.deepEqual(receipt.discoveries,{paths:['/assets/main.js','/app.js.map'],hosts:['api.owned.example.com']});assert.equal(seen.length,3);
    const altered=structuredClone(receipt);altered.discoveries.paths.push('/delete/backup.sql');assert.equal(validateExposureReceipt(input('client-secret','/'),altered).ok,false);
  });
});

test('control read failure cannot produce a positive or closeable negative',async()=>{
  await fixture((req,res)=>{if(req.url.includes('cybermeters-missing')){res.writeHead(429);return res.end('Rate limit');}res.end(envBody);},async deps=>{
    const result=await collect(deps);assert.equal(result.results[0].state,'uncertain');assert.equal(result.results[0].comparable,false);assert.equal(result.results[0].finding,null);
  });
});

test('one authoritative no-address resolution ends the host without path requests',async()=>{
  let lookups=0;
  const request=input();
  const receipt=await runExposureCollector(request,{resolve:async()=>{lookups++;return [];}});
  assert.deepEqual(validateExposureReceipt(request,receipt),{ok:true});
  assert.equal(lookups,2,'one A/AAAA resolution');
  assert.equal(receipt.telemetry.requests,0);
  assert.equal(receipt.results.length,0);
  assert.deepEqual(receipt.host_outcome,{state:'host_does_not_resolve',reason:'authoritative_no_address',statuses:[]});
  assert.equal(receipt.quality,'partial');
});

test('two genuine 5xx responses finish execution with both statuses and unknown content',async()=>{
  for(const statuses of [[500,503],[522,523]])await fixture((req,res)=>{
    const status=statuses[req.url.endsWith('.txt')?1:0];
    res.writeHead(status,{'content-type':'text/html',server:status>=522?'cloudflare':'fixture'});
    res.end('Temporarily unavailable');
  },async(deps,seen)=>{
    const request=input();
    const receipt=await collect(deps,request);
    assert.deepEqual(receipt.host_outcome,{state:'target_unavailable',
      reason:statuses[0]===522?'edge_origin_unreachable':'server_error',statuses});
    assert.equal(receipt.results.length,0);
    assert.equal(receipt.telemetry.requests,2);
    assert.equal(seen.length,2,'no catalogue path was requested');
    assert.equal(receipt.quality,'partial');
    const forged=structuredClone(receipt);forged.host_outcome.statuses[1]=200;
    assert.equal(validateExposureReceipt(request,forged).ok,false);
  });
});

test('revocation also interrupts a pending DNS resolver without a connection attempt',async()=>{
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),40);
  try{const receipt=await collect({signal:controller.signal,resolve:()=>new Promise(()=>{})});assert.equal(receipt.telemetry.requests,0);assert.ok(receipt.telemetry.duration_ms<500);}finally{clearTimeout(timer);}
});

test('private DO rejects unsafe receipt fields and destroys aborted exposure execution',async()=>{
  const {NetworkProbeContainer}=await importWorker();
  let destroyed=0,launched=0;
  const ctx={storage:{setAlarm:async()=>{},deleteAlarm:async()=>{}},container:{running:false,start(){this.running=true;launched++;},setInactivityTimeout:async()=>{},destroy:async function(){destroyed++;this.running=false;},exec:async(_args,options)=>({stdout:new ReadableStream({start(controller){options.signal.addEventListener('abort',()=>controller.error(new Error('aborted')),{once:true});}}),exitCode:new Promise((_resolve,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}))})}};
  const worker=new NetworkProbeContainer(ctx,{}),controller=new AbortController();
  const work=worker.fetch(new Request('http://container/exposure',{method:'POST',body:JSON.stringify(input()),signal:controller.signal}));
  const timer=setTimeout(()=>controller.abort(),40);
  try{assert.equal((await work).status,502);assert.equal(launched,1);assert.ok(destroyed>=1);assert.equal(worker.busy,false);}finally{clearTimeout(timer);}
});

if(process.env.EXPOSURE_PROBE_BUNDLE)test('pinned Wrangler bundle emits a runnable exposure program with all immutable helpers',async()=>{
  const compiled=await importWorker(process.env.EXPOSURE_PROBE_BUNDLE),source=compiled.exposureCollectorProgram();
  const program=source.slice(0,source.indexOf("let raw='';"))+`const result=await runExposureCollector(${JSON.stringify(input())},{resolve:async()=>['127.0.0.1']});process.stdout.write(JSON.stringify(result));`;
  const executed=spawnSync(process.execPath,['--input-type=module','-e',program],{encoding:'utf8',timeout:5000});assert.equal(executed.status,0,executed.stderr);assert.equal(JSON.parse(executed.stdout).telemetry.requests,0);
});

test('same-origin action redirects from candidates AND controls never send an operation request',async()=>{
  for(const fromControl of [false,true])await fixture((req,res)=>{
    if(req.url.includes('cybermeters-missing')&&!fromControl)return missing(req,res);
    res.writeHead(302,{location:'/restart'});res.end();
  },async(deps,seen)=>{const receipt=await collect(deps);assert.equal(receipt.results[0].state,'uncertain');assert.ok(seen.every(row=>row.path!=='/restart'));assert.ok(receipt.telemetry.requests<=3);});
});

test('ignored Range retains bounded archive header proof without reading or claiming archive contents',async()=>{
  const prefix=Buffer.from('PK\x03\x04\x14\x00'+'\x00'.repeat(24));
  await fixture(handlerFor(Buffer.concat([prefix,Buffer.alloc(2*1024*1024,65)])),async deps=>{
    const receipt=await collect(deps,input('backup-archive','/backup.zip'));
    assert.equal(receipt.results[0].state,'finding');assert.ok(receipt.results[0].finding.indicators.includes('archive_contents_not_examined'));assert.ok(receipt.telemetry.bytes_wire<150000);assert.ok(receipt.telemetry.bytes_decoded<150000);
  });
  await fixture(handlerFor('PK is harmless prose. '+ 'A'.repeat(2*1024*1024)),async deps=>{
    const receipt=await collect(deps,input('backup-archive','/backup.zip'));assert.equal(receipt.results[0].state,'uncertain');assert.equal(receipt.results[0].comparable,false);
  });
});

test('HTTP401/403/429/5xx and invalid compressed responses cannot certify absence',async()=>{
  for(const status of [401,403,429,500,502])await fixture(handlerFor(envBody,status),async deps=>{
    const receipt=await collect(deps);assert.equal(receipt.results[0].comparable,false);assert.equal(receipt.results[0].finding,null);assert.ok(['blocked','uncertain'].includes(receipt.results[0].state));
  });
  await fixture(handlerFor(envBody,200,{'content-encoding':'gzip'}),async deps=>{
    const receipt=await collect(deps);assert.equal(receipt.results[0].state,'uncertain');assert.equal(receipt.results[0].comparable,false);
  });
});

test('documentation JSON and 200 login screens cannot close a prior content finding',async()=>{
  const examples=[{rule:'application-config',path:'/config.json',body:'{"example":{"password":"SyntheticOnlyValue738"},"description":"Configuration documentation"}',state:'uncertain'},{rule:'env-config',path:'/.env',body:'<html><title>Sign in</title><body><form><input type="password"><button>Login</button></form></body></html>',state:'blocked'}];
  for(const f of examples)await fixture(handlerFor(f.body),async deps=>{const receipt=await collect(deps,input(f.rule,f.path));assert.equal(receipt.results[0].state,f.state);assert.equal(receipt.results[0].comparable,false);assert.equal(receipt.results[0].finding,null);});
  await fixture(handlerFor('APP_ENV=production\nDB_PASSWORD=secret738-A9ActualCredential\n'),async deps=>{const receipt=await collect(deps);assert.equal(receipt.results[0].state,'finding');assert.ok(!JSON.stringify(receipt).includes('secret738'));});
});


test('actual IPv6 socket accepts equivalent normalized public AAAA representations',async()=>{
  let observed=0;const server=http.createServer((req,res)=>{observed++;handlerFor(envBody)(req,res);});
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'::1',resolve));
  try{
    const receipt=await collect({resolve:async(_host,family)=>family===6?['2606:4700:4700:0000:0000:0000:0000:1111']:[],connectTarget:()=>({hostname:'::1',port:server.address().port}),peerAddress:socket=>socket.remoteAddress==='::1'?'2606:4700:4700::1111':socket.remoteAddress});
    assert.equal(receipt.results[0].state,'finding');assert.equal(observed,3);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

test('actual HTTPS verifies trusted hostname before any request; wrong, expired and unknown CA fail closed',async()=>{
  const fixtures=createTlsFixtures();
  try{for(const scenario of [{name:'valid',trust:true,expected:'finding'},{name:'valid',trust:false,expected:'uncertain'},{name:'wrong',trust:true,expected:'uncertain'},{name:'expired',trust:true,expected:'uncertain'}]){
    let observed=0;const sockets=new Set();
    const server=https.createServer({key:fixtures.read(scenario.name+'.key'),cert:fixtures.read(scenario.name+'.pem')},(req,res)=>{observed++;handlerFor(envBody)(req,res);});
    server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});server.on('tlsClientError',()=>{});
    await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
    try{
      const request=input('env-config','/.env',{origin:'https://owned.example.com',checks:[{rule_id:'env-config',url:'https://owned.example.com/.env'}]});
      const receipt=await collect({resolve:async(_host,family)=>family===4?[address]:[],connectTarget:()=>({hostname:'127.0.0.1',port:server.address().port}),peerAddress:()=>address,...(scenario.trust?{trustedRoots:[fixtures.read('ca.pem')]}:{})},request);
      assert.equal(receipt.results[0].state,scenario.expected);assert.equal(observed,scenario.expected==='finding'?3:0);
    }finally{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}
  }}finally{fixtures.cleanup();}
});
