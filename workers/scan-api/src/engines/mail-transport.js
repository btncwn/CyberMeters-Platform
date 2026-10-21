import { isProbeHostname } from '../../../network-probe/src/contract.js';
import { collectTlsAssessment } from './exposure-jobs.js';
import { dnsQuery, dnsQueryGoogle } from './dns.js';
import { parseTlsDnsAnswers } from './tls-planner.js';
import { isWeakTlsCipher } from '../../../../shared/tls/catalog.js';
import { createId } from '../lib/util.js';
import { resolvePublicDnsTarget, STRICT_DNS_STATES } from '../lib/ssrf.js';

export const MAIL_MX_LIMIT = 5;
const CHECK = Object.freeze({ control: 'certificate', protocol: 'tls1_2', cipher_id: null });

export function mailMxPlan(dnsModule) {
  const seen = new Set();
  return (Array.isArray(dnsModule?.mx_records) ? dnsModule.mx_records : [])
    .map(row => {
      const match = /^(\d{1,5})\s+([^\s]+)\.?$/.exec(String(row?.value || '').trim());
      if (!match) return null;
      const host = match[2].replace(/\.$/, '').toLowerCase();
      return isProbeHostname(host) ? { priority: Number(match[1]), host } : null;
    })
    .filter(row => row && !seen.has(row.host) && seen.add(row.host))
    .sort((a,b) => a.priority-b.priority || a.host.localeCompare(b.host))
    .slice(0,MAIL_MX_LIMIT);
}

export function projectMailMxReceipt(mx, receipt) {
  const row = receipt.results[0];
  const evidence = row?.state === 'accepted' && row.evidence?.authenticated_finished ? row.evidence : null;
  const certificate = evidence?.certificates;
  const cipher = evidence?.negotiated?.cipher || null;
  return {
    host: mx.host, priority: mx.priority, tested_address: mx.address || null,
    observed_at: row?.observed_at || null,
    state: row?.reason === 'starttls_unavailable' ? 'not_offered' : evidence ? 'tested' : 'not_tested',
    reason: evidence ? null : row?.reason || 'probe_incomplete',
    starttls_offered: row?.reason === 'starttls_unavailable' ? false :
      evidence || row?.reason === 'starttls_rejected' ? true : null,
    tls_version: evidence?.negotiated?.version || null,
    cipher, cipher_class: cipher ? isWeakTlsCipher(cipher) ? 'weak' : 'not_flagged_weak' : null,
    certificate_hostname_match: certificate?.hostname ?? null,
    certificate_expires_at: certificate?.offered_chain?.[0]?.not_after != null
      ? new Date(certificate.offered_chain[0].not_after * 1000).toISOString() : null,
    chain_validity: certificate?.trust || null,
  };
}

const dnsName=value=>String(value||'').trim().toLowerCase().replace(/\.$/,'');
const nxdomainFor=(packet,name)=>Boolean(packet&&typeof packet==='object'&&!Array.isArray(packet)&&
  packet.Status===3&&packet.TC!==true&&!(Array.isArray(packet.Answer)&&packet.Answer.length)&&
  Array.isArray(packet.Question)&&packet.Question.some(q=>dnsName(q?.name)===name));
// The MX host does not exist: the primary resolver answers NXDOMAIN for both
// A and AAAA (readable, untruncated, this exact question, no records) AND an
// independent resolver confirms NXDOMAIN. A recursive answer's SOA comes and
// goes, so the proof is two resolvers agreeing, never one packet.
export function provesNxdomain(primaryPackets,confirmPacket,host) {
  const name=dnsName(host);
  return Array.isArray(primaryPackets)&&primaryPackets.length===2&&
    primaryPackets.every(packet=>nxdomainFor(packet,name))&&nxdomainFor(confirmPacket,name);
}

export async function runMailTransportModule(env, scan, dnsModule, {
  signal, accounting = null, lookup = (host,type) => dnsQuery(host,type,{accounting}),
  confirmLookup = host => dnsQueryGoogle(host,'A',{accounting}),
  collect = collectTlsAssessment, now = Date.now,
  requestId = () => createId('mailmx'),
} = {}) {
  const empty = reason => ({ source: 'mail_transport', state: 'not_tested', reason, hosts: [],
    coverage: { planned: 0, tested: 0, not_tested: 0 }, observed_at: new Date(now()).toISOString() });
  // A free/anonymous scan has no workspace identity and never reaches the
  // private mail probe. Verify ownership again at this network boundary.
  if (!scan.workspace_id || !scan.domain_id || !scan.id || !isProbeHostname(scan.domain)) return empty('verified_workspace_required');
  const verified = await env.cybermeters_db.prepare(`SELECT 1 AS allowed FROM workspace_domains wd
    JOIN domains d ON d.id=wd.domain_id JOIN workspaces w ON w.id=wd.workspace_id
    WHERE wd.workspace_id=? AND wd.domain_id=? AND d.domain=?
      AND wd.verification_status='verified' AND w.deleted_at IS NULL`)
    .bind(scan.workspace_id,scan.domain_id,scan.domain).first();
  if (!verified) return empty('verified_workspace_required');
  const plan = mailMxPlan(dnsModule);
  if (!plan.length) return empty('mx_not_observed');
  const results = [];
  for (let at=0;at<plan.length;at+=2) {
    const batch=await Promise.all(plan.slice(at,at+2).map(async mx => {
      if(signal?.aborted)return {host:mx.host,priority:mx.priority,state:'not_tested',reason:'scan_deadline',starttls_offered:null};
      try {
        const answers=await Promise.allSettled(['A','AAAA'].map(type=>lookup(mx.host,type)));
        const addresses=parseTlsDnsAnswers(answers.map((result,index)=>[['A','AAAA'][index],result.status==='fulfilled'?result.value:null]),mx.host);
        if(!addresses.length){
          // An MX host with an AUTHORITATIVE negative answer (NXDOMAIN, or no
          // address with an SOA) is a definitive observation: mail for this
          // domain cannot be delivered to it (21 Oct 2026: a cancelled tenant's
          // MX host read only "not tested"). Anything less stays unavailable.
          // NXDOMAIN is about the NAME, so one authoritative NXDOMAIN (an SOA
          // for a zone the host sits under) with no address in either family
          // proves the host does not exist, even when the other family's
          // NXDOMAIN carries no SOA (seen live on a cancelled tenant's MX).
          const packets=answers.map(result=>result.status==='fulfilled'?result.value:null);
          if(packets.every(packet=>nxdomainFor(packet,dnsName(mx.host)))){
            const confirm=await confirmLookup(mx.host).catch(()=>null);
            if(provesNxdomain(packets,confirm,mx.host))return {host:mx.host,priority:mx.priority,state:'no_address',
              reason:'mx_host_does_not_exist',starttls_offered:null};
          }
          const strict=await resolvePublicDnsTarget(mx.host,lookup).catch(()=>null);
          if(strict?.state===STRICT_DNS_STATES.NO_ADDRESS)return {host:mx.host,priority:mx.priority,state:'no_address',
            reason:strict.dns_evidence?.outcome==='nxdomain'?'mx_host_does_not_exist':'mx_host_has_no_address',starttls_offered:null};
          throw new Error('mx_dns_unavailable');
        }
        const observedAt=new Date(now()).toISOString();
        const endpoint={hostname:mx.host,sni:mx.host,address:addresses[0],port:25,transport:'tcp',
          application_protocol:'smtp',dns_addresses:addresses,dns_observed_at:observedAt};
        const request={schema_version:'tls-assessment-request-v1',request_id:requestId(),
          workspace_id:scan.workspace_id,scan_id:scan.id,domain_id:scan.domain_id,domain:scan.domain,
          endpoint,scope:{kind:'mail_mx',service_authorization_id:null,generation:0,special_consent:false,consent_version:null},
          checks:[CHECK],deadline_at:new Date(now()+10_000).toISOString(),max_connections:1,max_bytes:262144};
        accounting?.assertCanIssue?.();
        accounting?.recordAttempt?.();
        return projectMailMxReceipt({...mx,address:endpoint.address},await collect(env,request,{signal}));
      } catch {
        return {host:mx.host,priority:mx.priority,state:'not_tested',reason:'probe_unavailable',starttls_offered:null};
      }
    }));
    results.push(...batch);
  }
  // A definitive "no address" is an observation of the MX host, not a gap.
  const tested=results.filter(row=>row.state==='tested'||row.state==='not_offered'||row.state==='no_address').length;
  return {source:'mail_transport',state:tested===plan.length?'observed':tested?'partial':'not_tested',
    reason:tested===plan.length?null:'some_mx_not_tested',hosts:results,
    coverage:{planned:plan.length,tested,not_tested:plan.length-tested},observed_at:new Date(now()).toISOString()};
}
