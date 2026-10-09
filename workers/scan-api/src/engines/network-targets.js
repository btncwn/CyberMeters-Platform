import { resolvePublicDnsTarget, STRICT_DNS_STATES } from '../lib/ssrf.js';
import { PROBE_PORTS, PROBE_LIMITS, isPublicProbeAddress } from '../../../network-probe/src/contract.js';

export const NETWORK_LIMITS = Object.freeze({ max_addresses: PROBE_LIMITS.targets, max_ports: PROBE_LIMITS.ports, max_pairs: PROBE_LIMITS.pairs, max_targets: 32 });
export const NETWORK_PORTS = PROBE_PORTS;

function parseAddress(raw) {
  if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(raw)) {
    const bytes = raw.split('.').map(Number);
    if (bytes.some(n => n > 255)) throw new Error('invalid_network_target');
    return { bits:32, value:bytes.reduce((n,b) => (n << 8n) | BigInt(b),0n) };
  }
  if (!/^[0-9a-f:]+$/i.test(raw) || !raw.includes(':')) throw new Error('invalid_network_target');
  let normalized;
  try { normalized = new URL(`http://[${raw}]/`).hostname.slice(1,-1); } catch { throw new Error('invalid_network_target'); }
  const [a,b] = normalized.split('::');
  const left = a ? a.split(':') : [], right = b ? b.split(':') : [];
  const words = normalized.includes('::') ? [...left, ...Array(8-left.length-right.length).fill('0'), ...right] : left;
  if (words.length !== 8) throw new Error('invalid_network_target');
  return { bits:128, value:words.reduce((n,w) => (n << 16n) | BigInt(`0x${w}`),0n) };
}
function addressText(value,bits) {
  if(bits === 32) return [24n,16n,8n,0n].map(s => String((value >> s) & 255n)).join('.');
  const words = Array.from({length:8},(_,i) => ((value >> BigInt((7-i)*16)) & 65535n).toString(16));
  return new URL(`http://[${words.join(':')}]/`).hostname.slice(1,-1);
}

// Only explicitly entered literal address ranges are admitted. DNS evidence,
// domains and provider/CDN associations never create network authorization.
export async function normalizeNetworkTarget(input) {
  if(typeof input !== 'string' || input.length > 80 || input !== input.trim()) throw new Error('invalid_network_target');
  const split=input.split('/');
  if(split.length>2) throw new Error('invalid_network_target');
  const {bits,value}=parseAddress(split[0]);
  if(split.length===2 && !/^(0|[1-9]\d{0,2})$/.test(split[1])) throw new Error('invalid_network_prefix');
  const prefix=split.length===2 ? Number(split[1]) : bits;
  if(prefix>bits || prefix<bits-5) throw new Error('network_target_limit');
  const count=2**(bits-prefix), mask=(1n << BigInt(bits-prefix))-1n;
  if((value & mask)!==0n) throw new Error('network_target_must_be_aligned');
  const addresses=Array.from({length:count},(_,i)=>addressText(value+BigInt(i),bits));
  for(const address of addresses) {
    const result=await resolvePublicDnsTarget(address,async()=>{throw new Error('literal_required');});
    if(!isPublicProbeAddress(address)||result.state!==STRICT_DNS_STATES.PUBLIC || result.literal!==true) throw new Error('network_target_not_public');
  }
  return {target:addressText(value,bits)+(split.length===2 ? `/${prefix}` : ''),target_type:split.length===2?'cidr':'ip',addresses,address_count:count};
}
export function normalizeNetworkPorts(input,addressCount) {
  if(!Array.isArray(input)||!input.length||input.length>NETWORK_LIMITS.max_ports || input.some(p=>!Number.isInteger(p)||!NETWORK_PORTS.includes(p))) throw new Error('invalid_network_ports');
  const ports=[...new Set(input)].sort((a,b)=>a-b);
  if(ports.length!==input.length || ports.length*addressCount>NETWORK_LIMITS.max_pairs) throw new Error('network_pair_limit');
  return ports;
}
