// C-59: real alert fan-out over synthetic SQLite rows; every outbound call is stubbed.
import assert from 'node:assert/strict';
import { buildDb, makeD1 } from './lib/worker-harness.js';
import { emitLifecycleAlert, describeRecurrenceEvent, reopenNote } from '../../workers/scan-api/src/engines/alert-consumers.js';
import { resolveRemediation } from '../../workers/scan-api/src/engines/remediation-registry.js';
import { buildAlertChannelPayload } from '../../workers/scan-api/src/engines/alerts.js';

const db=buildDb(),emails=[],webhooks=[],failures=[];
const check=(name,fn)=>{try{fn();console.log(`PASS C-59: ${name}`);}catch(error){failures.push(name);console.error(`FAIL C-59: ${name}: ${error.message}`);}};
const originalFetch=globalThis.fetch;
globalThis.fetch=async(input,init)=>{
  const url=new URL(typeof input==='string'?input:input.url||String(input));
  if(url.hostname==='cloudflare-dns.com')return Response.json({Status:0,Answer:url.searchParams.get('type')==='A'?[{type:1,data:'8.8.8.8'}]:[]});
  if(url.hostname==='api.resend.com'){emails.push(JSON.parse(init.body));return Response.json({id:`fixture_${emails.length}`});}
  if(url.hostname==='alerts.example.org'){webhooks.push({body:JSON.parse(init.body),headers:init.headers});return new Response('{}');}
  throw new Error(`Unexpected fixture outbound: ${url.hostname}`);
};
try{
  db.exec(`INSERT INTO users(id,email,name,email_verified) VALUES('cw-user','owner@example.org','Owner',1);
    INSERT INTO workspaces(id,owner_user_id,name) VALUES('cw','cw-user','Alert fixture');
    INSERT INTO workspace_members(id,workspace_id,user_id,role) VALUES('cw-member','cw','cw-user','owner');
    INSERT INTO subscriptions(id,owner_user_id,plan,status,subscription_status,current_period_end) VALUES('cw-sub','cw-user','professional','active','active',datetime('now','+30 days'));
    INSERT INTO alert_activation(id,workspace_id,domain_key,activated_at,baseline_count) VALUES('cw-active','cw','website_security','2000-01-01T00:00:00.000Z',0);
    INSERT INTO workspace_alert_channels(id,workspace_id,channel_type,webhook_url,secret) VALUES('cw-hook','cw','webhook','https://alerts.example.org/receive','local-fixture-only');`);
  const env={cybermeters_db:makeD1(db),RESEND_API_KEY:'local-fixture-only',ALERT_EMAIL_FROM:'alerts@cybermeters.com',FRONTEND_URL:'https://app.cybermeters.com'};
  const domain='site.example.org',key='header_missing_strict_transport_security',recurrence='browser_protection_missing';
  const title=resolveRemediation({finding_type:key}).customer_title;
  const sentence=describeRecurrenceEvent('website_security',recurrence,domain);
  const occurrence=(id,at)=>db.prepare("INSERT INTO website_security_events(id,record_id,workspace_id,actor_type,event_type,detail_json,created_at) VALUES(?,'condition','cw','system','monitoring_changed',?,?)")
    .run(id,JSON.stringify({to_recurrence_type:recurrence}),at);
  const emit=(extra={})=>emitLifecycleAlert(env,{workspace_id:'cw',domain_key:'website_security',record_id:'condition',entity:`${domain}:${key}`,entity_display:domain,hostname:domain,
    finding_type:key,recurrence,record_severity:'high',cooldownActive:false,...extra});
  occurrence('cw-first','2026-10-24 18:03:00');
  const first=await emit();assert.equal(first.emitted,true,'the real emitter must reach delivery');
  const rows=()=>db.prepare("SELECT * FROM notification_events WHERE workspace_id='cw' ORDER BY rowid").all();
  const [row]=rows();assert.equal(emails.length,1);assert.equal(webhooks.length,1,'a real signed webhook body must be captured');
  const safe=prose=>assert.doesNotMatch(prose,/\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b|surface:|provider:|condition ['"]/i);
  check('raw-key guard rejects old prose and generic finding keys',()=>{
    for(const raw of [key,'tls_certificate_trust','tech_php2shell_outdated','external_exposure_remote-access-portal__abc']) assert.throws(()=>safe(`${domain}:${raw}: condition 'browser protection missing' was observed`));
    for(const raw of ['tls_certificate_trust','tech_php2shell_outdated']) assert.throws(()=>safe(`The finding ${raw} was observed.`));
  });
  check('canonical finding title plus existing plain sentence',()=>assert.equal(row.message,`${title}: ${sentence}`));
  check('email and in-app use the same safe prose',()=>{safe(row.title+' '+row.message+' '+emails[0].text+' '+emails[0].html);assert.ok(emails[0].text.includes(row.message));assert.equal(emails[0].subject,row.title);});
  check('webhook prose matches the in-app message',()=>assert.equal(webhooks[0].body.summary,row.message));
  check('webhook machine keys are retained',()=>{assert.equal(webhooks[0].body.event,'website_security.browser_protection_missing');assert.equal(webhooks[0].body.source,'cybermeters');assert.equal(webhooks[0].body.severity,'high');assert.ok(webhooks[0].headers['X-CyberMeters-Signature'].startsWith('sha256='));});
  occurrence('cw-returned','2026-10-24 18:04:00');
  db.exec("INSERT INTO managed_case_events(id,case_id,workspace_id,actor_type,from_status,to_status,action,created_at) VALUES('cw-verified','cw-case','cw','system','awaiting_verification','verified','transition_verified','2026-10-23 12:00:00')");
  assert.equal((await emit({case_id:'cw-case',case_reopened:true})).emitted,true);
  const returned=rows().at(-1),note='This case was verified on 23 Oct 2026 (UTC) and has reopened — the condition was observed again.';
  check('reopen prose names prior verification date and recurrence',()=>assert.ok(returned.message.endsWith(note)));
  check('reopen prose has email/in-app/webhook parity',()=>{assert.ok(emails.at(-1).text.includes(returned.message));assert.equal(webhooks.at(-1).body.summary,returned.message);safe(returned.message);});
  check('other channel prose uses the same shared summary',()=>{
    const event={title:returned.title,summary:returned.message,kind:returned.type,severity:returned.severity};
    assert.ok(buildAlertChannelPayload('slack',event).text.includes(returned.message));
    assert.equal(buildAlertChannelPayload('teams',event).text,returned.message);
  });
  check('non-reopen alerts do not borrow a reopened case note',()=>assert.ok(!row.message.includes('reopened')));
  db.exec("UPDATE managed_case_events SET actor_type='customer' WHERE id='cw-verified'");
  const customerNote=await reopenNote(env,'cw','cw-case',true);
  check('customer attestation is not claimed as system verification',()=>assert.equal(customerNote,'You marked this fixed on 23 Oct 2026 (UTC); it has been observed again, so the case is reopened.'));
  assert.equal(await reopenNote(env,'foreign','cw-case',true),null);
  assert.equal(await reopenNote(env,'cw','cw-case',false),null);
}finally{globalThis.fetch=originalFetch;db.close();}
assert.deepEqual(failures,[],`C-59 failed contracts: ${failures.join(', ')}`);
console.log('C-59 customer alert wording and channel parity PASS');
