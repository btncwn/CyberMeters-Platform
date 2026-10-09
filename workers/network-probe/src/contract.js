// Shared private-service protocol. No client supplies an executable, URL or DO ID.
export const PROBE_PORTS = Object.freeze([21,22,25,53,80,110,143,443,445,465,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017]);
export const PROBE_LIMITS = Object.freeze({ targets:32, ports:16, pairs:256, deadlineMs:90_000, requestBytes:16_384, responseBytes:524_288 });
export function isPublicProbeAddress(value) {
  if (typeof value !== 'string' || value.length > 45 || value !== value.trim()) return false;
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) {
    const [a,b,c,d] = value.split('.').map(Number);
    if ([a,b,c,d].some(x=>x>255)) return false;
    return !(a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&(b===168||(b===0&&(c===0||c===2))||(b===88&&c===99)))||(a===198&&(b===18||b===19||(b===51&&c===100)))||(a===203&&b===0&&c===113));
  }
  if (!/^[0-9a-f:]+$/i.test(value) || !value.includes(':')) return false;
  let normalized;
  try { normalized = new URL(`http://[${value}]/`).hostname.slice(1,-1); } catch { return false; }
  const halves = normalized.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = (halves.length===2 ? [...left,...Array(8-left.length-right.length).fill('0'),...right] : left).map(x=>parseInt(x,16));
  if (words.length!==8 || words.some(x=>!Number.isInteger(x))) return false;
  // Ordinary global unicast only. Transition/mapped, local and special-purpose
  // allocations are not needed for public customer service discovery.
  if ((words[0]&0xe000)!==0x2000) return false;
  if (words[0]===0x2001 && (words[1]<0x200 || words[1]===0xdb8)) return false;
  return words[0]!==0x2002 && !((words[0]===0x3fff)&&(words[1]<0x1000));
}
export function isProbeHostname(value) {
  return typeof value==='string' && value.length<=253 && value===value.toLowerCase()
    && value.includes('.') && !/\.(local|localhost|internal|test|invalid|example)$/.test(value)
    && value.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    && /[a-z]/.test(value.split('.').at(-1));
}
export function validateNetworkProbeRequest(input, now=Date.now()) {
  const fail=reason=>({ok:false,reason});
  if (!input || typeof input!=='object' || Array.isArray(input)) return fail('invalid_request');
  const allowed=new Set(['schema_version','request_id','workspace_id','scan_id','profile','deadline_at','targets','ports']);
  if (Object.keys(input).some(k=>!allowed.has(k))) return fail('unknown_request_field');
  if (input.schema_version!=='network-probe-request-v1') return fail('unknown_schema');
  for(const key of ['request_id','workspace_id','scan_id']) if(typeof input[key]!=='string'||! /^[a-zA-Z0-9_-]{1,100}$/.test(input[key]))return fail('invalid_identity');
  if(!['live_tls','network_services'].includes(input.profile))return fail('unknown_profile');
  const deadline=Date.parse(input.deadline_at);
  if(!Number.isFinite(deadline)||deadline<=now||deadline>now+90_000)return fail('invalid_deadline');
  if(!Array.isArray(input.targets)||!input.targets.length||input.targets.length>32)return fail('target_limit');
  if(!Array.isArray(input.ports)||!input.ports.length||input.ports.length>16||new Set(input.ports).size!==input.ports.length||input.ports.some(p=>!Number.isInteger(p)||![21,22,25,53,80,110,143,443,445,465,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017].includes(p)))return fail('port_limit');
  if(input.targets.length*input.ports.length>256)return fail('pair_limit');
  const seen=new Set();
  for(const target of input.targets){
    if(!target||typeof target!=='object'||Array.isArray(target)||Object.keys(target).some(k=>!['address','hostname'].includes(k)))return fail('invalid_target');
    if(input.profile==='live_tls'){
      if(input.targets.length!==1||input.ports.length!==1||input.ports[0]!==443||target.address!==null||!isProbeHostname(target.hostname))return fail('invalid_tls_target');
    }else if(!isPublicProbeAddress(target.address)||target.hostname!==null)return fail('non_public_target');
    const key=JSON.stringify(target);if(seen.has(key))return fail('duplicate_target');seen.add(key);
  }
  return {ok:true};
}
export async function readBoundedJson(stream, maxBytes) {
  if(!stream)throw new Error('empty_body');
  const reader=stream.getReader();const chunks=[];let total=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>maxBytes){await reader.cancel();throw new Error('body_limit');}chunks.push(value);}}
  finally{reader.releaseLock();}
  const bytes=new Uint8Array(total);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.byteLength;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
