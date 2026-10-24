// C-57: reconcile old protocol identities into endpoint + observed leaf identity.
// No schema/backfill/deletion. Original scan proof is required, not a guessed
// fingerprint. Missing history holds only a matching open protocol condition;
// verified/monitoring history cannot suppress a newly observed failure.
import { TLS_PROTOCOLS } from '../../../../shared/tls/catalog.js';
import { readTlsAssessmentForScan } from './exposure-jobs.js';
import { tlsAssessmentFindings, tlsCaseKey, legacyTlsCaseKey } from './tls-findings.js';
import { canTransitionCase } from './managed-case-model.js';
import { newCaseEventId } from './case-workflow.js';

const parse = value => { try { return JSON.parse(value || '{}') || {}; } catch { return {}; } };
const priority = ['awaiting_verification','action_in_progress','approved','assigned','reopened','triaged','detected','accepted_risk','monitoring','verified'];
const historical = new Set(['verified','monitoring']);
const legacyKey = (endpoint,row) => legacyTlsCaseKey({ type:'tls_certificate_trust',
  endpoint_identity:endpoint.endpoint_identity,control:'certificate',protocol:row.protocol,cipher_id:row.cipher_id||null });

export async function reconcileTlsTrustIdentities(env,{workspace_id,domain,tls_assessment,now}) {
  const rows=(await env.cybermeters_db.prepare(`SELECT mc.* FROM managed_cases mc
    JOIN workspaces w ON w.id=mc.workspace_id AND w.deleted_at IS NULL
    WHERE mc.workspace_id=? AND mc.domain=? AND mc.case_type='certificate_case'
      AND mc.source_finding_type='tls_certificate_trust'
      AND mc.status NOT IN ('superseded','rejected','false_positive','closed_no_action','closed')
      AND EXISTS (SELECT 1 FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id
                  WHERE wd.workspace_id=mc.workspace_id AND d.domain=mc.domain)`)
    .bind(workspace_id,domain).all()).results||[];
  const groups=new Map(),unknown=[],scans=new Map(),blocked=new Set(),relevantLegacyKeys=new Set();
  for(const endpoint of tls_assessment.endpoints||[])for(const protocol of TLS_PROTOCOLS)
    relevantLegacyKeys.add(legacyKey(endpoint,{protocol,cipher_id:null}));
  for(const kase of rows){
    const data=parse(kase.evidence_json);
    if(data.tls_identity_alias)continue;
    let condition=data.tls_condition;
    if(!condition?.endpoint_identity || !condition?.leaf_sha256 || tlsCaseKey(condition)!==kase.finding_id){
      condition=null;
      if(!relevantLegacyKeys.has(kase.finding_id))continue;
      if(kase.source_scan_id){
        if(!scans.has(kase.source_scan_id))scans.set(kase.source_scan_id,
          await readTlsAssessmentForScan(env,{workspaceId:workspace_id,scanId:kase.source_scan_id}).catch(()=>null));
        const original=scans.get(kase.source_scan_id);
        for(const endpoint of original?.endpoints||[])for(const row of endpoint.checks||[]){
          if(row.control!=='certificate'||legacyKey(endpoint,row)!==kase.finding_id)continue;
          const finding=tlsAssessmentFindings({source:'tls_assessment',endpoints:[{...endpoint,checks:[row]}]})
            .find(f=>f.tls_condition.type==='tls_certificate_trust');
          if(finding)condition=finding.tls_condition;
        }
      }
    }
    if(!condition){if(!historical.has(kase.status))unknown.push(kase);continue;}
    const key=tlsCaseKey(condition);
    if(!key){if(!historical.has(kase.status))unknown.push(kase);continue;}
    const group=groups.get(key)||{condition,cases:[]};group.cases.push(kase);groups.set(key,group);
  }
  // A v1 key encodes no leaf. Hold only the currently measured protocol which
  // already has an unproven OPEN case. Other protocols can present a distinct
  // leaf; historical verified/monitoring cases must not swallow recurrence.
  for(const endpoint of tls_assessment.endpoints||[])for(const row of endpoint.checks||[]){
    if(row.control!=='certificate'||!unknown.some(k=>k.finding_id===legacyKey(endpoint,row)))continue;
    const finding=tlsAssessmentFindings({source:'tls_assessment',endpoints:[{...endpoint,checks:[row]}]})
      .find(f=>f.tls_condition.type==='tls_certificate_trust');
    if(finding)blocked.add(tlsCaseKey(finding.tls_condition));
  }
  for(const [key,group] of groups){
    group.cases.sort((a,b)=>(priority.indexOf(a.status)<0?99:priority.indexOf(a.status))-(priority.indexOf(b.status)<0?99:priority.indexOf(b.status))||
      String(a.created_at).localeCompare(String(b.created_at))||a.id.localeCompare(b.id));
    const [winner,...others]=group.cases;
    if(!others.length&&winner.finding_id===key)continue;
    const condition={...group.condition,protocol:null,cipher_id:null};
    const survivor={...winner,finding_id:key};
    const decisions=others.map(kase=>historical.has(kase.status)?null:canTransitionCase({
      case:kase,target_status:'superseded',actor:{actor_type:'system'},
      reason:'This case repeats a certificate issue already tracked in another case. Its history has been retained.',
      identity_merge:{canonical_case:survivor,condition},now,
    }));
    if(decisions.some(d=>d&&!d.ok)){blocked.add(key);continue;}
    const guardId=newCaseEventId(),sources=group.cases.map(k=>({case_id:k.id,finding_id:k.finding_id,status:k.status,evidence_json:k.evidence_json,closed_at:k.closed_at,reason:k.reason,updated_at:k.updated_at}));
    // D1 batch is atomic. Claim this precise snapshot once; concurrent retries
    // which no longer match do no writes and append no duplicate events.
    const snapshots=group.cases.map(()=>'(id=? AND finding_id=? AND status=? AND evidence_json IS ?)').join(' OR ');
    const args=group.cases.flatMap(k=>[k.id,k.finding_id,k.status,k.evidence_json??null]);
    const statements=[env.cybermeters_db.prepare(`INSERT INTO managed_case_events
      (id,case_id,workspace_id,actor_type,actor_id,from_status,to_status,action,detail_json,created_at)
      SELECT ?,?,?,'system',NULL,?,?,'evidence_added',?,?
      WHERE (SELECT COUNT(*) FROM managed_cases WHERE workspace_id=? AND domain=? AND (${snapshots}))=?
        AND EXISTS (SELECT 1 FROM workspaces WHERE id=? AND deleted_at IS NULL)
        AND EXISTS (SELECT 1 FROM workspace_domains wd JOIN domains d ON d.id=wd.domain_id
                    WHERE wd.workspace_id=? AND d.domain=?)`)
      .bind(guardId,winner.id,workspace_id,winner.status,null,
        JSON.stringify({evidence_type:'tls_trust_identity_compatibility',evidence_reference:winner.source_scan_id||null,case_key:key,condition,sources}),now,workspace_id,domain,...args,group.cases.length,workspace_id,workspace_id,domain)];
    const guard='EXISTS (SELECT 1 FROM managed_case_events WHERE id=? AND workspace_id=?)';
    for(let i=0;i<others.length;i++){
      const kase=others[i],decision=decisions[i],status=decision?.case.status||kase.status;
      const data={...parse(kase.evidence_json),tls_identity_alias:{canonical_case_id:winner.id,case_key:key}};
      // The existing unique index includes superseded rows. If a previous
      // canonical row loses to a more advanced workflow, retain its old key in
      // the event and free that identity before rekeying the survivor.
      const aliasKey=kase.finding_id===key?`${key}:alias:${kase.id}`:kase.finding_id;
      statements.push(env.cybermeters_db.prepare(`UPDATE managed_cases SET finding_id=?,status=?,evidence_json=?,
        closed_at=?,reason=?,updated_at=? WHERE id=? AND workspace_id=? AND domain=? AND ${guard}`)
        .bind(aliasKey,status,JSON.stringify(data),decision?.case.closed_at||kase.closed_at||null,
          decision?.case.reason||kase.reason||null,now,kase.id,workspace_id,domain,guardId,workspace_id));
      statements.push(env.cybermeters_db.prepare(`INSERT INTO managed_case_events
        (id,case_id,workspace_id,actor_type,actor_id,from_status,to_status,action,detail_json,created_at)
        SELECT ?,?,?,'system',NULL,?,?,?, ?,? WHERE ${guard}`)
        .bind(newCaseEventId(),kase.id,workspace_id,kase.status,decision?status:null,decision?.event.action||'evidence_added',
          JSON.stringify({evidence_type:'tls_trust_identity_alias',evidence_reference:winner.id,canonical_case_id:winner.id,case_key:key,previous_finding_id:kase.finding_id}),now,guardId,workspace_id));
    }
    const data={...parse(winner.evidence_json),tls_condition:condition,
      tls_identity_migration:{version:2,previous_finding_id:winner.finding_id,case_ids:group.cases.map(k=>k.id)}};
    statements.push(env.cybermeters_db.prepare(`UPDATE managed_cases SET finding_id=?,evidence_json=?,updated_at=?
      WHERE id=? AND workspace_id=? AND domain=? AND ${guard}`)
      .bind(key,JSON.stringify(data),now,winner.id,workspace_id,domain,guardId,workspace_id));
    const result=await env.cybermeters_db.batch(statements);
    if(result[0]?.meta?.changes!==1)blocked.add(key);
  }
  return blocked;
}
