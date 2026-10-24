// Existing public accuracy corpus: ordinary HTTPS homepage GETs only. No login
// path enumeration, credentials, accounts or production writes. Product fixtures
// and exact-path lifecycle proof run separately in the CI-blocking local gate.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { safeFetch, SCANNER_PAGE_HEADERS } from '../../workers/scan-api/src/lib/http.js';
import { dnsQuery } from '../../workers/scan-api/src/engines/dns.js';
import { remoteAccessFingerprint, REMOTE_ACCESS_TABLE_VERSION } from '../../shared/exposure/remote-access.js';

const arg=(name,fallback)=>{const i=process.argv.indexOf(name);return i<0?fallback:process.argv[i+1];};
const output=arg('--output','/tmp/remote-access-corpus.json');
const corpus=fs.readFileSync(new URL('./free-scan-corpus.txt',import.meta.url),'utf8');
const hosts=corpus.split(/\r?\n/)
  .map(v=>v.trim().split(/\s+/)[0]).filter(v=>/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v));
const records=new Array(hosts.length);let cursor=0,finished=0;
async function worker(){
  for(;;){const i=cursor++;if(i>=hosts.length)return;
    const record={corpus_id:`entry-${String(i+1).padStart(2,'0')}`,classification:'unknown',reason:'transport_unavailable'};
    let reader;
    try{
      const response=await safeFetch(`https://${hosts[i]}/`,{method:'GET',headers:SCANNER_PAGE_HEADERS,dnsResolver:dnsQuery,signal:AbortSignal.timeout(15000)});
      if(response){
        record.status=response.status;
        reader=response.body?.getReader();const chunks=[];let bytes=0,truncated=false;
        if(reader)for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;
          if(bytes>32768){truncated=true;await reader.cancel();break;}chunks.push(value);}
        record.bytes_observed=bytes;
        if(response.status===200&&!truncated){
          const body=Buffer.concat(chunks).toString('utf8');
          record.body_sha256=createHash('sha256').update(body).digest('hex');
          const portal=remoteAccessFingerprint(body,response.url);
          record.classification=portal?'review_required':'not_detected';
          record.reason=portal?'known_signature_observed':'no_supported_signature';
          if(portal)record.portal=portal;
        }else record.reason=truncated?'bounded_body_incomplete':'non_serviceable_response';
      }
    }catch{/* keep unknown; a failed request never becomes a negative */}
    finally{try{await reader?.cancel();}catch{}}
    records[i]=record;finished++;if(finished%10===0)console.log(`Corpus ${finished}/${hosts.length}`);
  }
}
await Promise.all([worker(),worker(),worker()]);
const review=records.filter(r=>r.classification==='review_required').length;
const report={schema:'remote-access-corpus-v1',observed_at:new Date().toISOString(),corpus_sha256:createHash('sha256').update(corpus).digest('hex'),table_version:REMOTE_ACCESS_TABLE_VERSION,scope:'Existing accuracy corpus; HTTPS homepage only, capped32KiB, no login paths or credentials; no production scan.',
  counts:{total:hosts.length,tp:0,fp:0,unknown:records.filter(r=>r.classification==='unknown').length,
    not_detected:records.filter(r=>r.classification==='not_detected').length,review_required:review},
  limitation:'No real positive portal is assumed in this public-page corpus; positive and negative product truth comes from controlled local fixtures. Every positive here needs independent triage before READY.',records};
fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report.counts));if(review)process.exitCode=1;
