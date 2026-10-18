import { isPublicProbeAddress } from './contract.js';
import { isSafeExposurePath } from '../../../shared/exposure/redaction.js';

// All bodies and response headers are process-local. Only reviewed callers may
// project safe observations. This session is shared by both private collectors.
export async function createBoundedHttpSession(input,dependencies={},configuration={}) {
  const builtin=name=>import(name);
  const [http,https,dns,zlib]=await Promise.all(['node:http','node:https','node:dns/promises','node:zlib'].map(builtin));
  const started=Date.now(),deadline=Date.parse(input.deadline_at),origin=new URL(input.origin);
  const bodyBytes=configuration.bodyBytes||32768;
  const approved=configuration.approveUrl||((value)=>{try{const u=new URL(value);return u.origin===origin.origin&&!u.username&&!u.password&&!u.search&&!u.hash&&u.href.length<=1024&&isSafeExposurePath(u.pathname);}catch{return false;}});
  const telemetry={requests:0,redirects:0,retries:0,bytes_wire:0,bytes_decoded:0,duration_ms:0,byte_limit_exceeded:false,controls_completed:0};
  const controller=new AbortController();
  const onAbort=()=>controller.abort();
  dependencies.signal?.addEventListener('abort',onAbort,{once:true});
  if(dependencies.signal?.aborted)controller.abort();
  const deadlineTimer=setTimeout(onAbort,Math.max(1,deadline-Date.now()));
  const stopped=()=>controller.signal.aborted||Date.now()>=deadline;
  const failure=(url,error)=>({url,status:0,headers:{},body:'',bytesRead:0,truncated:false,error});
  const resolvePublic=async(hostname)=>{
    const resolver=new dns.Resolver({timeout:1000,tries:1});
    const resolve=dependencies.resolve||((host,family)=>family===4?resolver.resolve4(host):resolver.resolve6(host));
    let rejectAbort;
    const cancelled=new Promise((_,reject)=>{rejectAbort=reject;});
    const cancel=()=>{resolver.cancel();rejectAbort(new Error('deadline_exhausted'));};
    controller.signal.addEventListener('abort',cancel,{once:true});
    let timer;
    try{
      const answers=await Promise.race([cancelled,Promise.allSettled([resolve(hostname,4),resolve(hostname,6)]),new Promise((_,reject)=>{timer=setTimeout(()=>{resolver.cancel();reject(new Error('dns_timeout'));},Math.min(1500,Math.max(1,deadline-Date.now())));})]);
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
    const parsedScope=new URL(url);
    const controlPath=/^\/\.cybermeters-missing-[a-f0-9]{32}(?:\.txt)?$/.test(parsedScope.pathname)&&!parsedScope.search&&!parsedScope.hash&&!parsedScope.username&&!parsedScope.password&&approved(parsedScope.origin+'/');
    if(!approved(url)&&!controlPath)return failure(url,'out_of_scope');
    if(stopped())return failure(url,'deadline_exhausted');
    if(telemetry.requests>=input.max_requests)return failure(url,'request_budget_exhausted');
    if(telemetry.byte_limit_exceeded||telemetry.bytes_wire>=input.max_bytes||telemetry.bytes_decoded>=input.max_bytes)return failure(url,'byte_budget_exhausted');
    let address;
    try{address=await resolvePublic(new URL(url).hostname);}catch(error){return failure(url,['dns_timeout','dns_unavailable','dns_no_address','dns_answer_limit','dns_non_public_answer','deadline_exhausted'].includes(error.message)?error.message:'dns_unavailable');}
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
        const options={protocol:parsed.protocol,hostname:target.hostname,port:target.port,method:'GET',path:parsed.pathname,servername:parsed.hostname,rejectUnauthorized:true,agent:false,highWaterMark:16384,maxHeaderSize:8192,headers:{host:parsed.host,'user-agent':'CyberMeters-Exposure-Verification/1.0',accept:'text/plain,text/html,application/json,*/*;q=0.1','accept-encoding':'gzip,deflate','range':`bytes=0-${bodyBytes-1}`,connection:'close'}};
        if(dependencies.trustedRoots)options.ca=dependencies.trustedRoots;
        // Charge immediately before invoking the native client; socket errors,
        // redirects and aborted attempts consume this physical request budget.
        telemetry.requests++;
        request=(parsed.protocol==='https:'?https:http).request(options,incoming=>{
          response=incoming;
          if(!peerChecked)return finish('peer_address_mismatch');
          result.status=incoming.statusCode;
          for(const key of ['content-type','content-encoding','location','content-range','sourcemap','x-sourcemap','server',...(configuration.headerNames||[])])if(typeof incoming.headers[key]==='string')result.headers[key]=incoming.headers[key].slice(0,2048);
          if(configuration.retainCookies&&Array.isArray(incoming.headers['set-cookie']))result.headers['set-cookie']=incoming.headers['set-cookie'].slice(0,20);
          if([301,302,303,307,308].includes(result.status))return finish();
          const encoding=(incoming.headers['content-encoding']||'identity').toLowerCase().trim();
          if(!['identity','gzip','deflate'].includes(encoding))return finish('unsupported_encoding');
          if(encoding==='gzip')decoded=zlib.createGunzip({chunkSize:16384,highWaterMark:16384});
          else if(encoding==='deflate')decoded=zlib.createInflate({chunkSize:16384,highWaterMark:16384});
          const consume=chunk=>{
            if(done)return;
            telemetry.bytes_decoded+=chunk.length;
            if(telemetry.bytes_decoded>input.max_bytes){telemetry.byte_limit_exceeded=true;return finish('byte_budget_exhausted');}
            const part=chunk.subarray(0,Math.max(0,bodyBytes-length));
            chunks.push(part);length+=part.length;
            if(part.length<chunk.length)return finish('decoded_limit');
          };
          incoming.on('data',chunk=>{
            if(done)return;wire+=chunk.length;telemetry.bytes_wire+=chunk.length;
            if(telemetry.bytes_wire>input.max_bytes){telemetry.byte_limit_exceeded=true;return finish('byte_budget_exhausted');}
            if(!decoded)consume(chunk);
            if(wire>bodyBytes)return finish('wire_limit');
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
      if(!approved(next.href))return {...response,error:'off_origin_redirect'};
      if(visited.has(next.href))return {...response,error:'redirect_loop'};
      visited.add(next.href);current=next.href;telemetry.redirects++;
    }
  };
  return {started,deadline,telemetry,controller,responses,requestOnce,fetchBounded,stopped,close(){clearTimeout(deadlineTimer);dependencies.signal?.removeEventListener('abort',onAbort);controller.abort();}};
}
