import assert from 'node:assert/strict';
import { buildDb, makeEnv, makeCaller } from './security/lib/worker-harness.js';
// All network is replaced before importing the production router. No real
// credentials, directory accounts or provider calls are involved.
let calls = [], hook = null, mode = '', baseline = '2026-10-09T12:00:00Z';
const tenantId = '11111111-1111-4111-8111-111111111111', clientId = '22222222-2222-4222-8222-222222222222', userId = '33333333-3333-4333-8333-333333333333';
const upn = 'test@example.onmicrosoft.com';
const credentials = { tenantId, clientId, clientSecret: 'SYNTHETIC-only-secret-not-a-real-one' };
globalThis.fetch = async (url, options) => {
  calls.push({ url, method: options.method });
  assert.equal(options.redirect, 'manual');
  if (hook) { const fn = hook; hook = null; await fn(); }
  if (url === `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`) return Response.json({ token_type: 'Bearer', access_token: 'SYNTHETIC-token', expires_in: 3600 });
  assert.equal(new URL(url).origin, 'https://graph.microsoft.com');
  if (url.endsWith('/revokeSignInSessions')) {
    assert.equal(url, `https://graph.microsoft.com/v1.0/users/${userId}/revokeSignInSessions`);
    if (mode === 'uncertain') throw new Error('SYNTHETIC-sensitive-provider-details');
    if (mode === 'denied') return new Response('private', { status: 403 });
    return Response.json({ value: true });
  }
  if (url.includes('/memberOf/') || url.includes('/userRegistrationDetails/')) return new Response('', { status: 403 });
  return Response.json({ id: mode === 'changed' ? clientId : userId, userPrincipalName: upn, userType: mode === 'guest' ? 'Guest' : 'Member', accountEnabled: mode !== 'disabled', displayName: 'Synthetic Test', signInSessionsValidFromDateTime: baseline });
};
const { default: worker, hashToken, WORKSPACE_PURGE_TABLES } = await import('../workers/scan-api/src/index.js');
const db = buildDb(), env = makeEnv(db);
db.exec('PRAGMA foreign_keys=ON');
for (const u of ['owner', 'other', 'viewer', 'admin']) {
  db.prepare('INSERT INTO users(id,email,email_verified) VALUES(?,?,1)').run(u, u+'@example.test');
  db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+1 day'))").run(u,u,await hashToken(u));
}
for (const [ws, owner] of [['wa','owner'],['wb','other']]) {
  db.prepare('INSERT INTO workspaces(id,owner_user_id,name) VALUES(?,?,?)').run(ws,owner,ws);
  db.prepare('INSERT INTO workspace_members(id,workspace_id,user_id,role) VALUES(?,?,?,?)').run(ws,ws,owner,'owner');
}
for (const role of ['viewer','admin']) db.prepare('INSERT INTO workspace_members(id,workspace_id,user_id,role) VALUES(?,?,?,?)').run(role,'wa',role,role);
db.prepare("INSERT INTO domains(id,user_id,domain) VALUES('domain','owner','example.test')").run();
db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id,verification_status,verified_at) VALUES('wa','domain','verified',datetime('now'))").run();
db.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,current_period_end,trial_end) VALUES('trial','owner','wa','professional','active','trialing',datetime('now','+1 day'),datetime('now','+1 day'))").run();
db.prepare("INSERT INTO api_tokens(id,user_id,workspace_id,name,token_hash,scope,status) VALUES('api','owner','wa','fixture',?,'write','active')").run(await hashToken('cm_synthetic'));
const call = makeCaller(worker,env), root='/api/workspaces/wa/', workforce=root+'identity-workforce', response=root+'identity-response';
let n=0;const eq=(name,a,b)=>{assert.deepEqual(a,b,name);n++;console.log('PASS '+name);};
const posts=()=>calls.filter(c=>c.url.endsWith('/revokeSignInSessions')).length;
const clear=()=>{calls=[];db.prepare('DELETE FROM api_rate_limits').run();};
const observe=()=>call('POST',workforce+'/observe','owner',{upn,credentials});
for(const token of [null,'other','viewer','cm_synthetic']) {
 eq('roster not disclosed to '+token,[401,403].includes((await call('GET',workforce,token)).status),true);
 eq('observation denied for '+token,[401,403].includes((await call('POST',workforce+'/observe',token,{upn,credentials})).status),true);
}
eq('denials make no network calls',calls.length,0);
eq('unverified personal address refused',(await call('POST',workforce,'owner',{upn:'personal@elsewhere.test'})).status,403);
let added=await call('POST',workforce,'owner',{upn:'employee@example.test',display_name:'Employee',vip:true});
eq('verified domain account can be added',added.status,201);const manualId=added.data.account.id;
eq('manual account is not provider or breach evidence', [added.data.account.source,added.data.account.observation],['customer',null]);
eq('duplicate account not silently overwritten',(await call('POST',workforce,'owner',{upn:'employee@example.test',vip:false})).status,409);
eq('VIP is user priority',(await call('PATCH',workforce+'/'+manualId,'owner',{vip:false})).data.account.vip,false);
eq('UPN cannot be rebound by editing',(await call('PATCH',workforce+'/'+manualId,'owner',{upn:'other@example.test'})).status,400);
eq('manual account cannot trigger revocation',(await call('POST',response+'/preview','owner',{account_id:manualId,concern:'Synthetic concern',credentials})).status,503);
eq('manual operations make no provider calls',calls.length,0);
let observation=await observe();
eq('exact Entra account imported',observation.status,201);const accountId=observation.data.account.id;
eq('missing permissions remain unknown',[observation.data.account.observation.roles.state,observation.data.account.observation.authentication.state],['unavailable','unavailable']);
eq('source recorded as provider observation',observation.data.account.source,'entra');
eq('roster sorted with VIP separate from evidence',(await call('GET',workforce,'owner')).data.accounts.length,2);
const preview=async(token='owner',extra={})=>call('POST',response+'/preview',token,{account_id:accountId,concern:'Suspicious sign-in reported by customer',credentials,...extra});
const apply=(id,extra={},token='owner')=>call('POST',response+'/'+id+'/apply',token,{credentials,confirmed_upn:upn,...extra});
const verify=id=>call('POST',response+'/'+id+'/verify','owner',{credentials});
let p=await preview();eq('preview creates action',p.status,201);let id=p.data.action.id;
eq('preview evidence is explicitly customer reported',p.data.action.concern_source,'customer_reported');
eq('preview makes no revoke call',posts(),0);
eq('different tenant cannot preview account',(await call('POST','/api/workspaces/wb/identity-response/preview','owner',{account_id:accountId,concern:'x',credentials})).status,403);
eq('different directory binding refused',(await preview('owner',{credentials:{...credentials,tenantId:clientId}})).data.code,'target_changed');
eq('wrong confirmation refused',(await apply(id,{confirmed_upn:'other@example.test'})).status,400);
eq('another admin cannot accept someone else preview',(await apply(id,{},'admin')).status,409);
const pair=await Promise.all([apply(id),apply(id)]);
eq('concurrent acceptance has one success',pair.map(r=>r.status).sort(),[200,409]);
eq('concurrent acceptance sends one physical provider POST',posts(),1);
let accepted=pair.find(r=>r.status===200);
eq('provider accepted is never called verified',[accepted.data.action.status,accepted.data.action.outcome.logoutVerified],['provider_accepted',false]);
eq('used action cannot replay',(await apply(id)).status,409);eq('replay sends no POST',posts(),1);
eq('unchanged timestamp verification is honest',(await verify(id)).data.action.verification.state,'no_timestamp_advance_observed');
baseline=new Date().toISOString();let verified=await verify(id);
eq('provider timestamp advance is visible',verified.data.action.verification.state,'provider_timestamp_advanced');
eq('provider timestamp does not prove logout',verified.data.action.verification.logoutVerified,false);
clear();p=await preview();id=p.data.action.id;
db.prepare("UPDATE identity_response_actions SET expires_at='2000-01-01T00:00:00Z' WHERE id=?").run(id);
eq('expired preview refused',(await apply(id)).status,409);eq('expired preview no provider call',posts(),0);
p=await preview();id=p.data.action.id;mode='changed';
eq('recreated account cannot be targeted',(await apply(id)).data.code,'target_changed');eq('target drift no revoke',posts(),0);mode='';
p=await preview();id=p.data.action.id;mode='uncertain';
eq('lost response stays uncertain',(await apply(id)).status,503);
eq('uncertainty is durable',db.prepare('SELECT status FROM identity_response_actions WHERE id=?').get(id).status,'uncertain');
eq('uncertain attempt not retried',(await apply(id)).status,409);eq('uncertain exactly one attempt',posts(),1);mode='';
clear();p=await preview();id=p.data.action.id;
hook=()=>db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='owner'").run();
eq('permission revoked during provider lookup',(await apply(id)).data.code,'authorization_changed');eq('revoked permission makes no revoke call',posts(),0);
db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();
clear();hook=()=>db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='owner'").run();
eq('permission revoked during observation saves nothing',(await observe()).status,403);
db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();
for(const invalid of ['disabled','guest']){mode=invalid;eq(invalid+' not accepted as supported target',(await preview()).data.code,'unsupported_user');}mode='';
clear();db.prepare("UPDATE subscriptions SET trial_end=datetime('now','-1 day'),current_period_end=datetime('now','-1 day') WHERE id='trial'").run();
eq('expired plan cannot prepare intervention',(await preview()).status,403);eq('expired plan no outbound',calls.length,0);
const prior=accepted.data.action.id;
eq('expired plan may verify old action',(await verify(prior)).status,200);
db.prepare("UPDATE subscriptions SET trial_end=datetime('now','+1 day'),current_period_end=datetime('now','+1 day') WHERE id='trial'").run();
clear();p=await preview();id=p.data.action.id;
const normalPrepare=env.cybermeters_db.prepare;
env.cybermeters_db.prepare=function(sql){
 if(sql.includes("SET status='provider_accepted'"))throw new Error('synthetic storage failure');
 return normalPrepare.call(this,sql);
};
eq('provider acceptance lost from storage is not reported success',(await apply(id)).status,503);
eq('storage uncertainty remains visible',db.prepare('SELECT status FROM identity_response_actions WHERE id=?').get(id).status,'uncertain');
eq('storage uncertainty cannot trigger duplicate',(await apply(id)).status,409);eq('storage failure has exactly one provider request',posts(),1);
env.cybermeters_db.prepare=normalPrepare;
// Atomic write guards must still hold after every earlier role check succeeded.
function revokeAtWrite(fragment) {
 env.cybermeters_db.prepare=function(sql){
   const statement=normalPrepare.call(this,sql);
   if(!sql.includes(fragment))return statement;
   return {...statement,bind(...args){
     const bound=statement.bind(...args);
     return {...bound,run:async()=>{
       db.prepare("UPDATE workspace_members SET role='viewer' WHERE workspace_id='wa' AND user_id='owner'").run();
       return bound.run();
     }};
   }};
 };
}
clear();p=await preview();id=p.data.action.id;
revokeAtWrite("SET status='applying'");
eq('authority revoked at atomic claim is denied',(await apply(id)).status,409);
eq('atomic claim denial sends no provider request',calls.length,2); // preview only
env.cybermeters_db.prepare=normalPrepare;
db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();
clear();
const observationBefore=db.prepare('SELECT observation_json FROM identity_workforce_accounts WHERE id=?').get(accountId).observation_json;
revokeAtWrite("SET source='entra'");
eq('authority revoked at observation commit is denied',(await observe()).status,409);
eq('atomic observation denial preserves prior evidence',db.prepare('SELECT observation_json FROM identity_workforce_accounts WHERE id=?').get(accountId).observation_json,observationBefore);
env.cybermeters_db.prepare=normalPrepare;
db.prepare("UPDATE workspace_members SET role='owner' WHERE workspace_id='wa' AND user_id='owner'").run();
clear();
for(let i=0;i<60;i++)assert.equal((await call('PATCH',workforce+'/'+manualId,'owner',{vip:i%2===0})).status,200);
eq('hourly bound stops additional identity operations',(await observe()).status,429);
eq('quota rejection makes no provider call',calls.length,0);
clear();
const snapshot=JSON.stringify(db.prepare('SELECT * FROM identity_workforce_accounts').all())+JSON.stringify(db.prepare('SELECT * FROM identity_response_actions').all())+JSON.stringify((await call('GET',workforce,'owner')).data);
eq('credential and bearer token not persisted or returned',snapshot.includes(credentials.clientSecret)||snapshot.includes('SYNTHETIC-token'),false);
eq('both tables participate in purge',WORKSPACE_PURGE_TABLES.includes('identity_workforce_accounts')&&WORKSPACE_PURGE_TABLES.includes('identity_response_actions'),true);
db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='wa'").run();clear();
eq('deleted workspace cannot observe',[403,404].includes((await observe()).status),true);eq('deleted workspace no network',calls.length,0);
db.close();console.log(`${n}/${n} workforce and identity response controls passed. Live provider calls: 0.`);
