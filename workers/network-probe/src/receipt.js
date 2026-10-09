import { isPublicProbeAddress } from './contract.js';
export function validateNetworkProbeReceipt(request, receipt, {now=Date.now()}={}) {
  const fail=reason=>({ok:false,reason});
  if(!receipt||typeof receipt!=='object'||Array.isArray(receipt)||receipt.schema_version!=='network-probe-receipt-v1')return fail('invalid_receipt');
  for(const field of ['request_id','workspace_id','scan_id','profile'])if(receipt[field]!==request[field])return fail('receipt_identity_mismatch');
  const start=Date.parse(receipt.started_at),finish=Date.parse(receipt.finished_at),deadline=Date.parse(request.deadline_at);
  if(!Number.isFinite(start)||!Number.isFinite(finish)||start>finish||finish>now+1000||start<deadline-90_000||finish>deadline+1000||now-finish>120_000)return fail('receipt_time_mismatch');
  const collector=receipt.collector;
  if(collector?.name!=='cybermeters-cloudflare-network-probe'||collector.version!=='1'||!/^v\d+\.\d+\.\d+/.test(collector.node_version||'')||!collector.openssl_version||collector.trust_store?.name!=='Node.js bundled Mozilla CA roots'||!/^[a-f0-9]{64}$/.test(collector.trust_store?.sha256||''))return fail('receipt_collector_mismatch');
  const rows=receipt.observations;
  if(!Array.isArray(rows)||rows.length<1||rows.length>256)return fail('receipt_observation_limit');
  const key=row=>`${row.address??''}|${row.hostname??''}|${row.port}`;
  const expected=new Set(request.targets.flatMap(target=>request.ports.map(port=>key({...target,port}))));
  const seen=new Set();
  for(const row of rows){
    if(!row||row.transport!=='tcp'||!['open','closed','timeout','error','not_run'].includes(row.state)||!request.ports.includes(row.port))return fail('invalid_observation');
    const identity=key(row);if(seen.has(identity))return fail('duplicate_observation');seen.add(identity);
    if(request.profile==='network_services'){
      if(!expected.has(identity))return fail('unexpected_observation');
    }else{
      if(row.hostname!==request.targets[0].hostname||rows.length>4||(!(row.address===null&&row.state==='not_run'&&rows.length===1)&&!isPublicProbeAddress(row.address)))return fail('unexpected_tls_endpoint');
    }
    if(row.state==='not_run'&&!row.reason)return fail('missing_not_run_reason');
    if(row.service!==null){
      const service=row.service;
      if(row.state!=='open'||!service||!['tls_handshake','unsolicited_tcp_banner'].includes(service.basis)||typeof service.name!=='string'||service.name.length>40)return fail('invalid_service_evidence');
      if(service.basis==='tls_handshake'&&row.tls?.leaf_collected!==true)return fail('unproven_tls_service');
      if(service.basis==='unsolicited_tcp_banner'&&(!/^[a-f0-9]{64}$/.test(service.banner_sha256||'')||typeof service.banner_sample!=='string'||service.banner_sample.length>256))return fail('invalid_banner');
    }
    if(row.tls!==null){
      const live=row.tls;
      if(row.state!=='open'||!live||typeof live.leaf_collected!=='boolean')return fail('invalid_tls_evidence');
      if(live.leaf_collected){
        const leaf=live.leaf_certificate;
        if(live.endpoint?.address!==row.address||live.endpoint.port!==row.port||live.endpoint.hostname!==row.hostname||live.source!=='cloudflare_container_node_tls')return fail('tls_endpoint_mismatch');
        if(!leaf||leaf.collection_performed!==true||leaf.collection_complete!==true||!/^sha256:[a-f0-9]{64}$/.test(leaf.certificate_identity||'')||typeof leaf.der_base64!=='string'||leaf.der_base64.length>90000||!/^[a-zA-Z0-9+/]+={0,2}$/.test(leaf.der_base64)||!Number.isFinite(Date.parse(leaf.not_before))||!Number.isFinite(Date.parse(leaf.not_after)))return fail('invalid_leaf');
        if(live.hostname_match?.assessment_performed!==true||live.hostname_match?.certificate_identity!==leaf.certificate_identity||!['matched','mismatched'].includes(live.hostname_match.result)||live.hostname_match.reference_hostname!==(row.hostname||row.address))return fail('hostname_identity_mismatch');
        if(live.trust_store_validation?.validation_performed!==true||live.trust_store_validation?.certificate_identity!==leaf.certificate_identity||live.trust_store_validation?.trust_store_context?.sha256!==collector.trust_store.sha256||!['valid','invalid'].includes(live.trust_store_validation.validation_result))return fail('trust_identity_mismatch');
        if(live.chain_collected!==false||live.presented_chain?.collection_performed!==false||live.revocation_assurance?.assessment_performed!==false||live.revocation_assurance?.status!=='unknown')return fail('unsupported_tls_claim');
      }else if(typeof live.reason!=='string'||!live.reason)return fail('missing_tls_failure_reason');
    }
  }
  if(request.profile==='network_services'&&(seen.size!==expected.size||[...expected].some(value=>!seen.has(value))))return fail('missing_observation');
  const counts={planned:rows.length,attempted:rows.filter(row=>row.state!=='not_run').length,completed:rows.filter(row=>['open','closed'].includes(row.state)&&(!row.tls||row.tls.leaf_collected)).length,not_run:rows.filter(row=>row.state==='not_run').length};
  for(const field of Object.keys(counts))if(receipt.coverage?.[field]!==counts[field])return fail('coverage_mismatch');
  const quality=counts.completed===counts.planned?'complete':'partial';
  if(receipt.quality!==quality)return fail('quality_mismatch');
  if(!Array.isArray(receipt.limitations)||!receipt.limitations.length||receipt.limitations.length>12||receipt.limitations.some(value=>typeof value!=='string'||value.length>500))return fail('missing_scope_limitations');
  return {ok:true};
}
