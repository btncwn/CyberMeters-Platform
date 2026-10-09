import { isPublicProbeAddress, isProbeHostname, validateNetworkProbeRequest } from './contract.js';

// This function is serialized from reviewed source by the private DO. Input is
// JSON data only. Test dependency injection is never exposed by the service.
export async function runCollector(input, dependencies={}) {
  const builtin=name=>import(name);
  const net=await builtin('node:net');
  const tls=await builtin('node:tls');
  const dns=await builtin('node:dns/promises');
  const crypto=await builtin('node:crypto');
  const started=Date.now();
  const valid=validateNetworkProbeRequest(input,started);
  if(!valid.ok)throw new Error(valid.reason);
  const deadline=Date.parse(input.deadline_at);
  const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
  const roots=dependencies.trustedRoots||tls.rootCertificates;
  const trustContext={name:dependencies.trustedRoots?'Local fixture CA roots':'Node.js bundled Mozilla CA roots',version:process.version,sha256:hash([...roots].sort().join('\n'))};
  const receipt={schema_version:'network-probe-receipt-v1',request_id:input.request_id,workspace_id:input.workspace_id,scan_id:input.scan_id,profile:input.profile,started_at:new Date(started).toISOString(),finished_at:null,collector:{name:'cybermeters-cloudflare-network-probe',version:'1',node_version:process.version,openssl_version:process.versions.openssl,trust_store:trustContext},coverage:{planned:0,attempted:0,completed:0,not_run:0},quality:'partial',observations:[],limitations:['Only the listed target and TCP port plan was tested.','A timeout does not establish a closed port.','TLS issuer-chain data is runtime-observed, not a capture of the exact wire-presented chain.','Certificate revocation and exhaustive protocol/cipher enumeration were not assessed.']};
  let targets=input.targets;
  let dnsFailure=null;
  if(input.profile==='live_tls'){
    const hostname=input.targets[0].hostname;
    try{
      const resolver=new dns.Resolver({timeout:2000,tries:1});
      const resolve=dependencies.resolve||((host,family)=>family===4?resolver.resolve4(host):resolver.resolve6(host));
      const answers=await Promise.allSettled([resolve(hostname,4),resolve(hostname,6)]);
      if(answers.some(r=>r.status==='rejected'&&!['ENODATA','ENOTFOUND'].includes(r.reason?.code)))throw new Error('dns_unavailable');
      const addresses=[...new Set(answers.flatMap(r=>r.status==='fulfilled'?r.value:[]))].sort();
      if(!addresses.length)throw new Error('dns_no_address');
      if(addresses.some(address=>!isPublicProbeAddress(address)))throw new Error('dns_non_public_answer');
      if(addresses.length>4)throw new Error('dns_address_limit');
      targets=addresses.map(address=>({address,hostname}));
    }catch(error){dnsFailure=['dns_unavailable','dns_no_address','dns_non_public_answer','dns_address_limit'].includes(error.message)?error.message:'dns_unavailable';targets=input.targets;}
  }
  const cleanText=value=>String(value??'').replace(/[\u0000-\u001f\u007f]/g,' ').slice(0,1024);
  const unavailableTls=reason=>({leaf_collected:false,chain_collected:false,reason});
  const describeCertificate=certificate=>{
    const x509=new crypto.X509Certificate(certificate.raw);
    const publicKey=x509.publicKey;
    const keyDetails=publicKey.asymmetricKeyDetails||{};
    const keyBits=keyDetails.modulusLength||({prime256v1:256,secp384r1:384,secp521r1:521}[keyDetails.namedCurve])||null;
    const dnsNames=(x509.subjectAltName||'').split(/, (?=(?:DNS|IP Address|URI|email):)/).filter(value=>value.startsWith('DNS:')).map(value=>value.slice(4)).map(value=>{try{return value.startsWith('"')?JSON.parse(value):value;}catch{return null;}}).filter(value=>typeof value==='string'&&value.length<=253).slice(0,128);
    return {certificate_identity:`sha256:${hash(certificate.raw)}`,der_base64:certificate.raw.toString('base64'),subject:cleanText(x509.subject),issuer:cleanText(x509.issuer),serial_number:x509.serialNumber,not_before:new Date(x509.validFrom).toISOString(),not_after:new Date(x509.validTo).toISOString(),dns_names:dnsNames,subject_alt_name:cleanText(x509.subjectAltName),public_key_algorithm:publicKey.asymmetricKeyType,public_key_size_bits:keyBits,signature_algorithm:null};
  };
  const captureTls=async(target,port)=>new Promise(resolve=>{
    const remaining=deadline-Date.now();
    if(remaining<=0)return resolve(unavailableTls('deadline_exhausted'));
    let socket,timer,finished=false;
    const finish=result=>{if(finished)return;finished=true;clearTimeout(timer);socket?.destroy();resolve(result);};
    try{
      socket=(dependencies.tlsConnect||tls.connect)({host:target.address,port,servername:target.hostname||undefined,rejectUnauthorized:false,ca:roots,checkServerIdentity:()=>undefined,ALPNProtocols:['h2','http/1.1'],minVersion:'TLSv1.2'});
      timer=setTimeout(()=>finish(unavailableTls('tls_timeout')),Math.min(4500,remaining));
      socket.once('error',()=>finish(unavailableTls('tls_handshake_failed')));
      socket.once('secureConnect',()=>{
        try{
          const peer=socket.getPeerCertificate(true);
          if(!peer?.raw||peer.raw.byteLength>65536)return finish(unavailableTls('peer_certificate_unavailable'));
          const leaf=describeCertificate(peer);
          const identityError=tls.checkServerIdentity(target.hostname||target.address,peer);
          const runtimeChain=[];const seen=new Set([leaf.certificate_identity]);let issuer=peer.issuerCertificate;
          while(issuer?.raw&&runtimeChain.length<8){
            if(issuer.raw.byteLength>65536)break;
            const item=describeCertificate(issuer);if(seen.has(item.certificate_identity))break;
            seen.add(item.certificate_identity);runtimeChain.push(item);issuer=issuer.issuerCertificate;
          }
          const authorization=socket.authorized===true;
          finish({leaf_collected:true,chain_collected:false,reason:null,observed_at:new Date().toISOString(),endpoint:{address:target.address,port,hostname:target.hostname},source:'cloudflare_container_node_tls',method:'pinned_public_address_tls_handshake',protocol:socket.getProtocol()||null,cipher:socket.getCipher()?.standardName||socket.getCipher()?.name||null,alpn:socket.alpnProtocol||null,leaf_certificate:{...leaf,collection_performed:true,collection_complete:true,source:'cloudflare_container_node_tls',method:'peer_x509_capture'},runtime_chain:{collection_performed:true,collection_complete:false,observation_scope:'node_tls_issuer_chain',certificates:runtimeChain},presented_chain:{collection_performed:false,collection_complete:false,presentation_state:'unknown',intermediates:[]},hostname_match:{assessment_performed:true,source:'cloudflare_container_node_tls',method:'node_tls_check_server_identity',result:identityError?'mismatched':'matched',reference_hostname:target.hostname||target.address,presented_identifiers:[leaf.subject_alt_name||leaf.subject],certificate_identity:leaf.certificate_identity},trust_store_context:trustContext,trust_store_validation:{validation_performed:true,validation_result:authorization?'valid':'invalid',certificate_identity:leaf.certificate_identity,trust_store_context:trustContext,reason:authorization?null:cleanText(socket.authorizationError||'certificate_validation_failed')},revocation_assurance:{assessment_performed:false,response_validated:false,stapled_ocsp:null,status:'unknown',certificate_identity:leaf.certificate_identity}});
        }catch{finish(unavailableTls('certificate_parse_failed'));}
      });
    }catch{finish(unavailableTls('tls_connection_failed'));}
  });
  const identifyService=bytes=>{
    if(!bytes.length)return null;
    const text=bytes.toString('utf8');let name=null;
    if(/^SSH-\d\.\d-/.test(text))name='ssh';
    else if(/^220[ -].*(?:ESMTP|SMTP)/im.test(text))name='smtp';
    else if(/^220[ -].*FTP/im.test(text))name='ftp';
    else if(/^\* OK\b.*(?:IMAP|Dovecot)/im.test(text))name='imap';
    else if(/^\+OK\b.*(?:POP|Dovecot)/im.test(text))name='pop3';
    return {name:name||'unidentified',basis:'unsolicited_tcp_banner',banner_sha256:hash(bytes),banner_sample:cleanText(text).slice(0,256)};
  };
  const probeTcp=async(target,port)=>new Promise(resolve=>{
    const base={address:target.address,hostname:target.hostname,port,transport:'tcp',state:'not_run',service:null,tls:null,reason:null};
    if(Date.now()>=deadline)return resolve({...base,reason:'deadline_exhausted'});
    let socket,timer,connected=false,finished=false;const chunks=[];let length=0;
    const finish=(state,reason)=>{if(finished)return;finished=true;clearTimeout(timer);socket?.destroy();const result={...base,state,reason,service:state==='open'?identifyService(Buffer.concat(chunks,length)):null};resolve(result);};
    try{
      socket=(dependencies.connect||net.connect)({host:target.address,port});
      timer=setTimeout(()=>finish(connected?'open':'timeout',connected?null:'connect_timeout'),Math.min(1500,deadline-Date.now()));
      socket.once('connect',()=>{connected=true;clearTimeout(timer);timer=setTimeout(()=>finish('open',null),Math.min(450,Math.max(1,deadline-Date.now())));});
      socket.on('data',chunk=>{const part=chunk.subarray(0,Math.max(0,1024-length));chunks.push(part);length+=part.length;if(length>=1024||part.includes(10))finish('open',null);});
      socket.once('error',error=>finish(connected?'open':error.code==='ECONNREFUSED'?'closed':'error',connected?null:error.code==='ECONNREFUSED'?'connection_refused':'connection_failed'));
      socket.once('end',()=>finish(connected?'open':'error',connected?null:'connection_ended'));
    }catch{finish('error','connection_failed');}
  });
  const plan=targets.flatMap(target=>input.ports.map(port=>({target,port})));
  receipt.coverage.planned=plan.length;
  const rows=Array(plan.length);let cursor=0;
  const worker=async()=>{
    while(cursor<plan.length){
      const index=cursor++;const {target,port}=plan[index];
      if(dnsFailure){rows[index]={address:null,hostname:target.hostname,port,transport:'tcp',state:'not_run',service:null,tls:null,reason:dnsFailure};continue;}
      const row=await probeTcp(target,port);
      if(row.state==='open'&&(input.profile==='live_tls'||[443,465,993,995,8443].includes(port))){row.tls=await captureTls(target,port);if(row.tls.leaf_collected)row.service={name:'tls',basis:'tls_handshake',banner_sha256:null,banner_sample:null};}
      rows[index]=row;
    }
  };
  await Promise.all(Array.from({length:Math.min(8,plan.length)},worker));
  receipt.observations=rows;
  receipt.coverage.attempted=rows.filter(row=>row.state!=='not_run').length;
  receipt.coverage.completed=rows.filter(row=>['open','closed'].includes(row.state)&&(!row.tls||row.tls.leaf_collected)).length;
  receipt.coverage.not_run=rows.filter(row=>row.state==='not_run').length;
  receipt.quality=receipt.coverage.completed===receipt.coverage.planned?'complete':'partial';
  receipt.finished_at=new Date().toISOString();
  return receipt;
}

// Build from immutable module code, never request strings. Native exec uses an
// argv array and stdin; no shell and no remote package/code download.
export function collectorProgram() {
  return `const __name=(value)=>value;\nconst isPublicProbeAddress=${isPublicProbeAddress.toString()};\nconst isProbeHostname=${isProbeHostname.toString()};\nconst validateNetworkProbeRequest=${validateNetworkProbeRequest.toString()};\nconst runCollector=${runCollector.toString()};\nlet raw='';for await(const chunk of process.stdin){raw+=chunk;if(Buffer.byteLength(raw)>16384)throw new Error('body_limit');}const result=await runCollector(JSON.parse(raw));process.stdout.write(JSON.stringify(result));`;
}
