#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { setup } from './lib/password-screening-fixture.js';
import { checkPwnedPassword } from '../workers/scan-api/src/lib/pwned-passwords.js';
import { authRoutes } from '../workers/scan-api/src/routes/auth.js';
import { verifyPassword } from '../workers/scan-api/src/lib/password.js';
let passed=0; const test=async(name,fn)=>{await fn();passed++;console.log('PASS '+name);};
const password='Synthetic test password 2026!',hash=createHash('sha1').update(password).digest('hex').toUpperCase();
const response=(count=0)=>new Response(`${hash.slice(5)}:${count}\r\n${'A'.repeat(35)}:0\r\n`,{headers:{'Content-Type':'text/plain'}});
await test('five-character prefix only, local suffix matching, padding and no redirects',async()=>{
  const fetchImpl=async(url,options)=>{assert.equal(url,`https://api.pwnedpasswords.com/range/${hash.slice(0,5)}`);assert.equal(options.headers['Add-Padding'],'true');assert.equal(options.redirect,'manual');assert(!JSON.stringify({url,options}).includes(password));assert(!url.includes(hash));return response(9);};
  assert.equal(await checkPwnedPassword(password,{fetchImpl}),'compromised');
  assert.equal(await checkPwnedPassword(password,{fetchImpl:async()=>response()}),'not_found');
});
await test('HTTP errors, redirects, truncated/invalid/empty data, oversized streams and timeout stay unavailable',async()=>{
  for(const make of [()=>new Response('',{status:429}),()=>new Response('',{status:302,headers:{Location:'https://forbidden.invalid'}}),()=>new Response(''),()=>new Response('garbage',{headers:{'Content-Type':'text/plain'}}),()=>new Response('X'.repeat(262145),{headers:{'Content-Type':'text/plain'}}),()=>Promise.reject(new Error('network'))]) assert.equal(await checkPwnedPassword(password,{fetchImpl:async()=>make()}),'unavailable');
  assert.equal(await checkPwnedPassword(password,{fetchImpl:async()=>new Promise(()=>{}),timeoutMs:5}),'unavailable');
  assert.equal(await checkPwnedPassword(password,{fetchImpl:async()=>new Response(new ReadableStream({start(){}}),{headers:{'Content-Type':'text/plain'}}),timeoutMs:5}),'unavailable');
});
function context(f,path,body) {return {...f.context(path,{method:'POST',body}),rateLimitScopeId:async(_,ip)=>ip};}
await test('compromised and unavailable signup passwords are rejected before email lookup or writes',async()=>{
  for(const mode of ['compromised','unavailable']) {
    const f=setup();let reads=0;f.setFault(sql=>{if(sql.includes('FROM users WHERE email'))reads++;return false;});
    globalThis.fetch=async()=>mode==='compromised'?response(1):new Response('',{status:503});
    for(const email of ['owner@example.com','new@example.com']) {
      const r=await authRoutes(context(f,'/api/auth/signup',{email,password,name:'Synthetic'}));assert.equal(r.status,mode==='compromised'?400:503);assert.equal((await r.json()).code,mode==='compromised'?'password_compromised':'password_check_unavailable');
    }
    assert.equal(reads,0);assert.equal(f.db.prepare('SELECT COUNT(*) n FROM users').get().n,3);
  }
});
await test('signup stores a password only after a successful range check',async()=>{
  const f=setup();globalThis.fetch=async(url)=>{if(String(url).startsWith('https://api.pwnedpasswords.com/range/'))return response();throw new Error('Unexpected outbound');};
  const r=await authRoutes(context(f,'/api/auth/signup',{email:'new@example.com',password,name:'Synthetic'}));assert.equal(r.status,201,await r.clone().text());
  const row=f.db.prepare("SELECT password_hash FROM users WHERE email='new@example.com'").get();assert(await verifyPassword(password,row.password_hash));
});
await test('reset screening preserves token, password and sessions on rejection; clear lookup permits actual reset',async()=>{
  const f=setup(), token='SYNTHETIC-RESET-TOKEN';const th=createHash('sha256').update(token).digest('hex');
  f.db.prepare("INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES('reset','owner',?,?)").run(th,new Date(Date.now()+3600000).toISOString());
  f.db.exec("UPDATE users SET password_hash='original' WHERE id='owner'");
  f.db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES('session','owner','fake',?)").run(new Date(Date.now()+3600000).toISOString());
  const invoke=()=>authRoutes(context(f,'/api/auth/reset-password',{token,password}));
  globalThis.fetch=async()=>response(3);assert.equal((await invoke()).status,400);
  assert.equal(f.db.prepare("SELECT password_hash FROM users WHERE id='owner'").get().password_hash,'original');assert.equal(f.db.prepare('SELECT used_at FROM password_reset_tokens').get().used_at,null);assert.equal(f.db.prepare('SELECT COUNT(*) n FROM user_sessions').get().n,1);
  globalThis.fetch=async(url)=>{if(String(url).startsWith('https://api.pwnedpasswords.com/range/'))return response();throw new Error('Unexpected outbound');};
  const r=await invoke();assert.equal(r.status,200,await r.clone().text());assert(await verifyPassword(password,f.db.prepare("SELECT password_hash FROM users WHERE id='owner'").get().password_hash));assert(f.db.prepare('SELECT used_at FROM password_reset_tokens').get().used_at);assert.equal(f.db.prepare('SELECT COUNT(*) n FROM user_sessions').get().n,0);
});

function resetFixture() {
  const f = setup(), token = 'SYNTHETIC-RESET-GUARD';
  f.db.prepare("INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES('reset','owner',?,?)")
    .run(createHash('sha256').update(token).digest('hex'), new Date(Date.now()+3600000).toISOString());
  f.db.exec("UPDATE users SET password_hash='original' WHERE id='owner'");
  f.db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES('session','owner','fake',?)")
    .run(new Date(Date.now()+3600000).toISOString());
  f.db.exec("INSERT INTO api_tokens(id,user_id,name,token_hash,scope,status) VALUES('api','owner','synthetic','fake-api','read','active')");
  return { ...f, invoke: overrides => authRoutes({ ...context(f,'/api/auth/reset-password',{token,password}), ...overrides }) };
}
function unchanged(f) {
  assert.equal(f.db.prepare("SELECT password_hash FROM users WHERE id='owner'").get().password_hash,'original');
  assert.equal(f.db.prepare("SELECT COUNT(*) n FROM user_sessions WHERE user_id='owner'").get().n,1);
  assert.equal(f.db.prepare("SELECT status FROM api_tokens WHERE id='api'").get().status,'active');
  assert.equal(f.db.prepare("SELECT COUNT(*) n FROM audit_events WHERE event_type='password_reset_completed'").get().n,0);
}
await test('provider outage preserves every reset credential and permits a later retry',async()=>{
  const f=resetFixture();
  try {
    globalThis.fetch=async()=>new Response('',{status:503});
    const r=await f.invoke();assert.equal(r.status,503);assert.equal((await r.json()).code,'password_check_unavailable');
    unchanged(f);assert.equal(f.db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='reset'").get().used_at,null);
  } finally {f.db.close();}
});
await test('expiry or token consumption during lookup cannot reset passwords or revoke sessions',async()=>{
  for(const change of ["UPDATE password_reset_tokens SET used_at=datetime('now') WHERE id='reset'", "UPDATE password_reset_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE id='reset'"]) {
    const f=resetFixture();
    try {
      globalThis.fetch=async()=>{f.db.exec(change);return response();};
      assert.equal((await f.invoke()).status,400);unchanged(f);
    } finally {f.db.close();}
  }
});
await test('two simultaneous requests can consume a reset link exactly once',async()=>{
  const f=resetFixture();let count=0, release;
  const barrier=new Promise(resolve=>{release=resolve;});
  try {
    globalThis.fetch=async()=>{if(++count===2)release();await barrier;return response();};
    const result=await Promise.all([f.invoke(),f.invoke()]);
    assert.deepEqual(result.map(r=>r.status).sort(),[200,400]);
    assert.equal(count,2);assert.equal(f.db.prepare("SELECT COUNT(*) n FROM audit_events WHERE event_type='password_reset_completed'").get().n,1);
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM user_sessions WHERE user_id='owner'").get().n,0);
    assert.equal(f.db.prepare("SELECT status FROM api_tokens WHERE id='api'").get().status,'revoked');
  } finally {f.db.close();}
});
await test('an error consuming the reset token rolls back password and credential changes',async()=>{
  const f=resetFixture();
  try {
    globalThis.fetch=async()=>response();f.setFault(sql=>sql.startsWith('UPDATE password_reset_tokens SET used_at = ?'));
    assert.equal((await f.invoke()).status,500);unchanged(f);
    assert.equal(f.db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='reset'").get().used_at,null);
  } finally {f.db.close();}
});
await test('invalid reset links and denied abuse limits make no provider call',async()=>{
  let calls=0;globalThis.fetch=async()=>{calls++;return response();};
  const f=resetFixture();
  try {
    assert.equal((await authRoutes(context(f,'/api/auth/reset-password',{token:'wrong',password}))).status,400);
    for(const status of [429,503]) {
      let limited=0;
      const r=await f.invoke({consumeApiRateLimit:async(_env,scopes,name,limit,window,options)=>{
        assert.deepEqual(scopes,[{scope:'user',scope_id:'owner'}]);assert.equal(name,'new_password_check');
        assert.equal(limit,10);assert.equal(window,900);assert.equal(options.failClosed,true);limited++;return {status};
      }});
      assert.equal(r.status,status);assert.equal(limited,1);
      const signup=await authRoutes({...context(f,'/api/auth/signup',{email:'new@example.com',password}),consumeApiRateLimit:async()=>({status})});
      assert.equal(signup.status,status);
    }
    assert.equal(calls,0);unchanged(f);
  } finally {f.db.close();}
});
await test('ordinary sign-in has no password-screening dependency',async()=>{
  const f=setup();let calls=0;
  try {
    globalThis.fetch=async()=>{calls++;throw new Error('No provider is available');};
    const {hashPassword}=await import('../workers/scan-api/src/lib/password.js');
    f.db.prepare("UPDATE users SET password_hash=? WHERE id='owner'").run(await hashPassword(password));
    const r=await authRoutes(context(f,'/api/auth/login',{email:'owner@example.com',password}));
    assert.equal(r.status,200,await r.clone().text());assert.equal(calls,0);
  } finally {f.db.close();}
});


await test('clear-password signup has the same response for existing and new emails',async()=>{
  const f=setup();
  try {
    globalThis.fetch=async()=>response();
    for(const email of ['owner@example.com','new@example.com']) {
      const r=await authRoutes(context(f,'/api/auth/signup',{email,password}));
      assert.equal(r.status,201);const body=await r.json();assert.equal(body.success,true);assert.equal(body.verification_required,true);
    }
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM users WHERE email='owner@example.com'").get().n,1);
  } finally {f.db.close();}
});
await test('successful reset preserves another account credentials and sessions',async()=>{
  const f=resetFixture();
  try {
    f.db.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES('other-session','other','other-fake',?)")
      .run(new Date(Date.now()+3600000).toISOString());
    f.db.exec("UPDATE users SET password_hash='other-original' WHERE id='other'; INSERT INTO api_tokens(id,user_id,name,token_hash,scope,status) VALUES('other-api','other','synthetic','other-fake-api','read','active')");
    globalThis.fetch=async()=>response();assert.equal((await f.invoke()).status,200);
    assert.equal(f.db.prepare("SELECT password_hash FROM users WHERE id='other'").get().password_hash,'other-original');
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM user_sessions WHERE user_id='other'").get().n,1);
    assert.equal(f.db.prepare("SELECT status FROM api_tokens WHERE id='other-api'").get().status,'active');
  } finally {f.db.close();}
});

console.log(`${passed} password screening scenarios passed`);
