import { isPublicProbeAddress, isProbeHostname } from './contract.js';
import { validateExposureRequest } from './exposure-contract.js';
import { EXPOSURE_RULES, RULES_BY_ID } from '../../../shared/exposure/catalog.js';
import { exposureIdentity, safeExposureUrl, isRulePathAllowed, isSafeExposurePath } from '../../../shared/exposure/redaction.js';
import { evaluateExposure, exposureEvaluatorProgramSource } from '../../../shared/exposure/evaluate.js';

// The sole production entrypoint passes JSON data. Dependency injection exists
// exclusively for controlled local transport tests and is never accepted on wire.
export async function runExposureCollector(input, dependencies={}) {
  const valid=validateExposureRequest(input);if(!valid.ok)throw new Error(valid.reason);
  const builtin=name=>import(name);
  const [http,https,dns,zlib,crypto]=await Promise.all(['node:http','node:https','node:dns/promises','node:zlib','node:crypto'].map(builtin));
  const started=Date.now(),deadline=Date.parse(input.deadline_at),origin=new URL(input.origin);
  const telemetry={requests:0,redirects:0,retries:0,bytes_wire:0,bytes_decoded:0,duration_ms:0,byte_limit_exceeded:false,controls_completed:0};
  const controller=new AbortController();
  const onAbort=()=>controller.abort();
  dependencies.signal?.addEventListener('abort',onAbort,{once:true});
  if(dependencies.signal?.aborted)controller.abort();
  const deadlineTimer=setTimeout(onAbort,Math.max(1,deadline-Date.now()));
  const stopped=()=>controller.signal.aborted||Date.now()>=deadline;
  const failure=(url,error)=>({url,status:0,headers:{},body:'',bytesRead:0,truncated:false,error});
  const resolvePublic=async()=>{
    const resolver=new dns.Resolver({timeout:1000,tries:1});
    const resolve=dependencies.resolve||((host,family)=>family===4?resolver.resolve4(host):resolver.resolve6(host));
    let rejectAbort;
    const cancelled=new Promise((_,reject)=>{rejectAbort=reject;});
    const cancel=()=>{resolver.cancel();rejectAbort(new Error('deadline_exhausted'));};
    controller.signal.addEventListener('abort',cancel,{once:true});
    let timer;
    try{
      const answers=await Promise.race([cancelled,Promise.allSettled([resolve(origin.hostname,4),resolve(origin.hostname,6)]),new Promise((_,reject)=>{timer=setTimeout(()=>{resolver.cancel();reject(new Error('dns_timeout'));},Math.min(1500,Math.max(1,deadline-Date.now())));})]);
      if(stopped())throw new Error('deadline_exhausted');
      if(answers.some(result=>result.status==='rejected'&&!['ENODATA','ENOTFOUND'].includes(result.reason?.code)))throw new Error('dns_unavailable');
      const addresses=[...new Set(answers.flatMap(result=>result.status==='fulfilled'&&Array.isArray(result.value)?result.value:[]))].sort();
      if(!addresses.length)throw new Error('dns_no_address');
      if(addresses.length>16)throw new Error('dns_answer_limit');
      if(addresses.some(address=>!isPublicProbeAddress(address)))throw new Error('dns_non_public_answer');
      return addresses[0];
    }finally{clearTimeout(timer);controller.signal.removeEventListener('abort',cancel);}
  };
  const physicalRequest=async url=>{
    if(stopped())return failure(url,'deadline_exhausted');
    if(telemetry.requests>=input.max_requests)return failure(url,'request_budget_exhausted');
    if(telemetry.byte_limit_exceeded||telemetry.bytes_wire>=input.max_bytes||telemetry.bytes_decoded>=input.max_bytes)return failure(url,'byte_budget_exhausted');
    let address;
    try{address=await resolvePublic();}catch(error){return failure(url,['dns_timeout','dns_unavailable','dns_no_address','dns_answer_limit','dns_non_public_answer','deadline_exhausted'].includes(error.message)?error.message:'dns_unavailable');}
    if(stopped())return failure(url,'deadline_exhausted');
    return new Promise(resolve=>{
      let request,response,decoded,timer,done=false,peerChecked=false,wire=0,length=0;
      const chunks=[];
      const result={url,status:0,headers:{},body:'',bytesRead:0,truncated:false,error:null};
      const finish=(error=null)=>{
        if(done)return;done=true;clearTimeout(timer);controller.signal.removeEventListener('abort',abort);
        if(error){result.error=error;result.truncated=['body_limit','wire_limit','decoded_limit','byte_budget_exhausted'].includes(error);}
        result.bytesRead=length;
        // Raw response bytes never leave this function except as transient input
        // to the reviewed evaluator. They never reach logs, stdout or durable IO.
        result.bytes=Buffer.concat(chunks,length);
        result.body=result.bytes.toString('utf8');
        decoded?.destroy();response?.destroy();request?.destroy();resolve(result);
      };
      const abort=()=>finish('deadline_exhausted');
      controller.signal.addEventListener('abort',abort,{once:true});
      timer=setTimeout(()=>finish('request_timeout'),Math.min(2500,Math.max(1,deadline-Date.now())));
      try{
        const parsed=new URL(url);
        const target=dependencies.connectTarget?dependencies.connectTarget({address,port:parsed.protocol==='https:'?443:80}):{hostname:address,port:parsed.protocol==='https:'?443:80};
        const options={protocol:parsed.protocol,hostname:target.hostname,port:target.port,method:'GET',path:parsed.pathname,servername:origin.hostname,rejectUnauthorized:true,agent:false,highWaterMark:16384,maxHeaderSize:8192,headers:{host:origin.host,'user-agent':'CyberMeters-Exposure-Verification/1.0',accept:'text/plain,text/html,application/json,*/*;q=0.1','accept-encoding':'gzip,deflate','range':'bytes=0-32767',connection:'close'}};
        if(dependencies.trustedRoots)options.ca=dependencies.trustedRoots;
        // Charge immediately before invoking the native client; socket errors,
        // redirects and aborted attempts consume this physical request budget.
        telemetry.requests++;
        request=(parsed.protocol==='https:'?https:http).request(options,incoming=>{
          response=incoming;
          if(!peerChecked)return finish('peer_address_mismatch');
          result.status=incoming.statusCode;
          for(const key of ['content-type','content-encoding','location','content-range','sourcemap','x-sourcemap'])if(typeof incoming.headers[key]==='string')result.headers[key]=incoming.headers[key].slice(0,2048);
          if([301,302,303,307,308].includes(result.status))return finish();
          const encoding=(incoming.headers['content-encoding']||'identity').toLowerCase().trim();
          if(!['identity','gzip','deflate'].includes(encoding))return finish('unsupported_encoding');
          if(encoding==='gzip')decoded=zlib.createGunzip({chunkSize:16384,highWaterMark:16384});
          else if(encoding==='deflate')decoded=zlib.createInflate({chunkSize:16384,highWaterMark:16384});
          const consume=chunk=>{
            if(done)return;
            telemetry.bytes_decoded+=chunk.length;
            if(telemetry.bytes_decoded>input.max_bytes){telemetry.byte_limit_exceeded=true;return finish('byte_budget_exhausted');}
            const part=chunk.subarray(0,Math.max(0,32768-length));
            chunks.push(part);length+=part.length;
            if(part.length<chunk.length)return finish('decoded_limit');
          };
          incoming.on('data',chunk=>{
            if(done)return;wire+=chunk.length;telemetry.bytes_wire+=chunk.length;
            if(telemetry.bytes_wire>input.max_bytes){telemetry.byte_limit_exceeded=true;return finish('byte_budget_exhausted');}
            if(!decoded)consume(chunk);
            if(wire>32768)return finish('wire_limit');
          });
          incoming.once('aborted',()=>finish('connection_dropped'));
          incoming.once('error',()=>finish('connection_dropped'));
          if(decoded){decoded.on('data',consume);decoded.once('error',()=>finish('decode_failed'));decoded.once('end',()=>finish());incoming.pipe(decoded);}
          else incoming.once('end',()=>finish());
        });
        request.once('socket',socket=>{
          const checkPeer=()=>{
            const peer=dependencies.peerAddress?dependencies.peerAddress(socket):socket.remoteAddress;
            const normalize=value=>{
              if(typeof value!=='string')return '';
              const plain=value.replace(/^::ffff:/,'');
              try{return plain.includes(':')?new URL(`http://[${plain}]/`).hostname:plain;}catch{return '';}
            };
            if(normalize(peer)!==normalize(address))finish('peer_address_mismatch');
            else{peerChecked=true;request.end();}
          };
          socket.once(parsed.protocol==='https:'?'secureConnect':'connect',checkPeer);
        });
        request.once('error',()=>finish('connection_failed'));
        request.once('upgrade',(_response,socket)=>{socket.destroy();finish('unsupported_upgrade');});
        // Send no HTTP bytes until the connected peer matches the pinned address.
      }catch{finish('connection_failed');}
    });
  };
  const responses=new Map();
  const requestOnce=url=>{
    if(!responses.has(url))responses.set(url,physicalRequest(url));
    return responses.get(url);
  };
  const fetchBounded=async url=>{
    let current=url;
    const visited=new Set([url]);
    for(let redirects=0;redirects<=2;redirects++){
      const response=await requestOnce(current);
      if(![301,302,303,307,308].includes(response.status)||response.error)return response;
      if(redirects===2)return {...response,error:'redirect_limit'};
      let next;try{next=new URL(response.headers.location,current);}catch{return {...response,error:'invalid_redirect'};}
      if(next.origin!==origin.origin||next.username||next.password||next.search||next.hash||next.href.length>1024||!isSafeExposurePath(next.pathname))return {...response,error:'off_origin_redirect'};
      if(visited.has(next.href))return {...response,error:'redirect_loop'};
      visited.add(next.href);current=next.href;telemetry.redirects++;
    }
  };
  try{
    const token=crypto.randomBytes(16).toString('hex');
    const controls=[];
    for(const suffix of ['', '.txt']){
      const response=await fetchBounded(`${input.origin}/.cybermeters-missing-${token}${suffix}`);
      controls.push(response);
      if(!response.error&&!response.truncated)telemetry.controls_completed++;
    }
    const results=[];
    const discoveredPaths=new Set(),discoveredHosts=new Set();
    for(const check of input.checks){
      const response=await fetchBounded(check.url);
      let evaluated;
      try{evaluated=evaluateExposure({rule:check.rule_id,response,controls});}catch{evaluated={state:'uncertain',comparable:false,finding:null,reason:'evaluation_failed'};}
      // Only a local per-body cap may retain a positive bounded-prefix claim.
      // Network/decode/budget failures and every truncated negative stay unknown.
      const boundedPrefix=response.truncated&&['body_limit','wire_limit','decoded_limit'].includes(response.error);
      if(response.error&&!boundedPrefix||response.truncated&&!['finding','observed'].includes(evaluated.state)||telemetry.controls_completed!==2)evaluated={state:'uncertain',comparable:false,finding:null,reason:response.error||'incomplete_controls'};
      for(const path of evaluated.discoveries?.paths||[])if(discoveredPaths.size<32&&EXPOSURE_RULES.some(rule=>isRulePathAllowed(rule,path)))discoveredPaths.add(path);
      for(const host of evaluated.discoveries?.hosts||[])if(discoveredHosts.size<32&&isProbeHostname(host)&&host.endsWith('.'+origin.hostname))discoveredHosts.add(host);
      const finding=evaluated.state==='finding'&&evaluated.finding?{
        rule_id:check.rule_id,family:RULES_BY_ID[check.rule_id].family,severity:evaluated.finding.severity,
        indicators:evaluated.finding.evidence?.indicators||[],identity:exposureIdentity(check.rule_id,check.url),safe_url:safeExposureUrl(check.url,EXPOSURE_RULES),
      }:null;
      const observation=evaluated.state==='observed'&&evaluated.observation?{rule_id:check.rule_id,family:RULES_BY_ID[check.rule_id].family,severity:'info',indicators:evaluated.observation.evidence?.indicators||[],identity:exposureIdentity(check.rule_id,check.url),safe_url:safeExposureUrl(check.url,EXPOSURE_RULES)}:null;
      results.push({rule_id:check.rule_id,url:check.url,identity:exposureIdentity(check.rule_id,check.url),indicators:evaluated.finding?.evidence?.indicators||evaluated.observation?.evidence?.indicators||[],state:evaluated.state,comparable:evaluated.comparable===true,finding,observation,reason:/^[a-z0-9_]{1,80}$/.test(evaluated.reason||'')?evaluated.reason:null});
    }
    const finished=Date.now();telemetry.duration_ms=finished-started;
    return {schema_version:'exposure-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,origin:input.origin,started_at:new Date(started).toISOString(),finished_at:new Date(finished).toISOString(),discoveries:{paths:[...discoveredPaths],hosts:[...discoveredHosts]},quality:results.every(row=>row.comparable)&&!telemetry.byte_limit_exceeded?'complete':'partial',results,telemetry,limitations:['listed_paths_only','no_authentication_or_exploitation','transport_overread_is_counted']};
  }finally{clearTimeout(deadlineTimer);dependencies.signal?.removeEventListener('abort',onAbort);}
}

// Reviewed built-in module source only, never request-provided code or modules.
export function exposureCollectorProgram() {
  return `const __name=(value)=>value;\n${exposureEvaluatorProgramSource()}\nconst isPublicProbeAddress=${isPublicProbeAddress.toString()};\nconst isProbeHostname=${isProbeHostname.toString()};\nconst validateExposureRequest=${validateExposureRequest.toString()};\nconst runExposureCollector=${runExposureCollector.toString()};\nlet raw='';for await(const chunk of process.stdin){raw+=chunk;if(Buffer.byteLength(raw)>16384)throw new Error('body_limit');}try{const result=await runExposureCollector(JSON.parse(raw));process.stdout.write(JSON.stringify(result));}catch{process.exitCode=1;}`;
}
