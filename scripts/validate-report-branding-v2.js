#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-report-branding-v2.js  (CI-blocking)
//
// Proves the Report Branding v2 engine's contract against a REAL in-memory D1:
//   • precedence: entitled MSP white-label → per-workspace co-brand → CyberMeters
//   • NEVER unbranded (resolveReportBrandingV2 never returns null)
//   • white-label requires the plan's white_label entitlement (server-side)
//   • tenant isolation: a workspace logo / MSP profile never applies to another tenant
//   • upload validation: PNG/JPEG only by MAGIC BYTES (declared MIME never trusted),
//     SVG/WebP/oversized/too-small rejected
//   • frozen-logo integrity: a sha256 mismatch refuses the logo (→ safe fallback)
//   • attribution: co-brand + fallback keep full CyberMeters wordmark; white-label reduced
// Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { buildDb, makeD1 } from "./security/lib/worker-harness.js";
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  resolveReportBrandingV2, validateLogoUpload, sniffImageType, loadBrandingLogoDataUri,
  brandingAttribution, cyberMetersDescriptor, workspaceLogoKey,
} from "../workers/scan-api/src/engines/report-branding-v2.js";

let passed = 0, failed = 0;
const ok = (n, c) => { c ? passed++ : (failed++, console.error("  ✗ " + n)); };

// ── image fixtures (valid magic bytes + parseable dimensions) ────────────────
function png(w = 64, h = 64) {
  const a = new Uint8Array(64);
  a.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52]);
  a[16] = (w >> 24) & 255; a[17] = (w >> 16) & 255; a[18] = (w >> 8) & 255; a[19] = w & 255;
  a[20] = (h >> 24) & 255; a[21] = (h >> 16) & 255; a[22] = (h >> 8) & 255; a[23] = h & 255;
  return a;
}
function jpeg(w = 64, h = 64) {
  const a = new Uint8Array(32);
  a.set([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, (h >> 8) & 255, h & 255, (w >> 8) & 255, w & 255]);
  return a;
}
const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
const webp = (() => { const a = new Uint8Array(16); a.set([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]); return a; })();

async function main() {
  const db = buildDb();
  const d1 = makeD1(db);
  // R2 stub keyed by object key.
  const r2store = new Map();
  const env = {
    cybermeters_db: d1,
    cybermeters_reports: { get: async (k) => (r2store.has(k) ? { arrayBuffer: async () => r2store.get(k).buffer } : null) },
  };

  // ── Seed: two accounts, three workspaces ─────────────────────────────────
  const seedUser = (id, plan) => db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified) VALUES (?,?,?,?,?,'active',1)").run(id, id + "@x.co", "x", id, plan);
  seedUser("ownerBiz", "free");   // stale legacy plan cannot hide a current paid trial
  seedUser("ownerStarter", "business"); // stale legacy paid flag grants no entitlement
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsBiz','ownerBiz','Biz WS')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsStarter','ownerStarter','Starter WS')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsBizChild','ownerBiz','Child WS')").run();
  const trialEnd = new Date(Date.now()+86400000).toISOString();
  db.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,trial_end,current_period_end) VALUES('sub-biz','ownerBiz','wsBiz','business','active','trialing',?,?)").run(trialEnd,trialEnd);

  // ── Upload validation (magic-byte, not declared MIME) ────────────────────
  const vPng = await validateLogoUpload(png());
  const vJpg = await validateLogoUpload(jpeg());
  ok("PNG upload accepted", vPng.ok && vPng.value.mime === "image/png" && vPng.value.ext === "png");
  ok("JPEG upload accepted", vJpg.ok && vJpg.value.mime === "image/jpeg");
  ok("SVG upload rejected (no sanitisation path)", !(await validateLogoUpload(svg)).ok);
  ok("WebP upload rejected", !(await validateLogoUpload(webp)).ok);
  ok("oversized upload rejected", !(await validateLogoUpload(new Uint8Array(600 * 1024))).ok);
  ok("too-small dimensions rejected", !(await validateLogoUpload(png(8, 8))).ok);
  ok("magic bytes beat a lying MIME (raw text is not an image)", sniffImageType(new TextEncoder().encode("PNGly text")) === null);

  // ── No branding yet → CyberMeters fallback, never null ───────────────────
  const bare = await resolveReportBrandingV2(env, { workspaceId: "wsStarter" });
  ok("no branding → CyberMeters fallback (never null)", bare && bare.mode === "cybermeters");
  ok("unknown workspace → CyberMeters fallback (never null)", (await resolveReportBrandingV2(env, { workspaceId: "nope" })).mode === "cybermeters");

  // ── Per-workspace co-brand logo (any plan) ───────────────────────────────
  db.prepare("INSERT INTO workspace_branding (workspace_id, logo_r2_key, logo_mime, logo_sha256, display_name) VALUES ('wsStarter', ?, 'image/png', ?, 'Starter Co')").run(workspaceLogoKey("wsStarter", vPng.value.sha256, "png"), vPng.value.sha256);
  const co = await resolveReportBrandingV2(env, { workspaceId: "wsStarter" });
  ok("workspace logo (starter) → co_brand, full attribution", co.mode === "co_brand" && co.attribution === "full" && co.source === "workspace");
  ok("co-brand keeps 'Generated by CyberMeters' footer", /Generated by CyberMeters/.test(brandingAttribution(co).footer));

  // ── Tenant isolation: wsStarter's logo must not appear for wsBiz ──────────
  ok("workspace logo does NOT leak to another workspace", (await resolveReportBrandingV2(env, { workspaceId: "wsBizChild" })).mode === "cybermeters");

  // ── MSP white-label profile, entitled account ────────────────────────────
  db.prepare("INSERT INTO msp_branding_profiles (id, owner_user_id, name, logo_r2_key, logo_mime, logo_sha256, mode, is_default) VALUES ('mbp1','ownerBiz','ACME MSP', ?, 'image/png', ?, 'white_label', 1)").run(workspaceLogoKey("wsBiz", vPng.value.sha256, "png"), vPng.value.sha256);
  const wl = await resolveReportBrandingV2(env, { workspaceId: "wsBiz" });
  ok("entitled MSP white_label profile → mode white_label", wl.mode === "white_label" && wl.attribution === "reduced");
  ok("white-label footer is reduced 'Powered by CyberMeters'", /Powered by CyberMeters/.test(brandingAttribution(wl).footer) && brandingAttribution(wl).reduced === true);

  // ── Entitlement: a NON-entitled account cannot get white_label ───────────
  db.prepare("INSERT INTO msp_branding_profiles (id, owner_user_id, name, logo_r2_key, logo_mime, logo_sha256, mode, is_default) VALUES ('mbp2','ownerStarter','Starter MSP','k','image/png','zz','white_label', 1)").run();
  const notWl = await resolveReportBrandingV2(env, { workspaceId: "wsStarter" });
  ok("non-entitled account: white_label profile ignored (stays co_brand)", notWl.mode !== "white_label");

  // ── MSP profile isolation: ownerBiz's profile must not brand ownerStarter's ws
  ok("MSP profile does not cross to another MSP's workspace", (await resolveReportBrandingV2(env, { workspaceId: "wsStarter" })).mode !== "white_label");
  db.prepare("UPDATE subscriptions SET trial_end='2000-01-01T00:00:00Z' WHERE id='sub-biz'").run();
  ok("expired effective trial loses white label despite saved profile", (await resolveReportBrandingV2(env,{workspaceId:'wsBiz'})).mode !== 'white_label');
  db.prepare("UPDATE subscriptions SET trial_end=?,subscription_status='canceled',status='canceled' WHERE id='sub-biz'").run(trialEnd);
  ok("downgrade affects future descriptor only", (await resolveReportBrandingV2(env,{workspaceId:'wsBiz'})).mode !== 'white_label' && wl.mode === 'white_label');
  db.prepare("UPDATE subscriptions SET subscription_status='trialing',status='active' WHERE id='sub-biz'").run();
  db.prepare("INSERT INTO workspace_branding(workspace_id,display_name) VALUES('wsBizChild','Client without logo')").run();
  db.prepare("UPDATE subscriptions SET subscription_status='canceled',status='canceled' WHERE id='sub-biz'").run();
  const named=await resolveReportBrandingV2(env,{workspaceId:'wsBizChild'});
  ok("client name alone is fully attributed co-brand",named.mode==='co_brand'&&named.display_name==='Client without logo'&&named.attribution==='full');

  // ── Frozen-logo integrity: bytes must match the frozen sha ───────────────
  const key = workspaceLogoKey("wsBizChild", vPng.value.sha256, "png");
  r2store.set(key, png());
  const good = await loadBrandingLogoDataUri(env, { logo_r2_key: key, logo_mime: "image/png", logo_sha256: vPng.value.sha256 });
  ok("matching R2 logo loads as a data URI", typeof good === "string" && good.startsWith("data:image/png;base64,"));
  const tampered = await loadBrandingLogoDataUri(env, { logo_r2_key: key, logo_mime: "image/png", logo_sha256: "deadbeef" });
  ok("sha256 mismatch refuses the logo (→ safe fallback)", tampered === null);
  ok("missing R2 object → null (→ safe fallback)", (await loadBrandingLogoDataUri(env, { logo_r2_key: "absent", logo_mime: "image/png", logo_sha256: "x" })) === null);
  let readOversized=false;
  const huge=await loadBrandingLogoDataUri({cybermeters_reports:{get:async()=>({size:524289,arrayBuffer:async()=>{readOversized=true;return new ArrayBuffer(524289);}})}},{logo_r2_key:'huge',logo_mime:'image/png'});
  ok("oversized R2 logo rejected before buffering",huge===null&&!readOversized);

  // ── Fallback descriptor is always branded ────────────────────────────────
  ok("cyberMetersDescriptor is fully attributed", cyberMetersDescriptor().mode === "cybermeters" && cyberMetersDescriptor().attribution === "full");

  await actualEntryTests();

  console.log(`\nReport branding v2: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("report-branding-v2 validation FAILED"); process.exit(1); }
  console.log("report-branding-v2 validation passed");
}
async function actualEntryTests() {
  const root=fileURLToPath(new URL('../',import.meta.url));
  const require=createRequire(path.join(root,'workers/scan-api/package.json'));
  const {build}=require('esbuild'),{Miniflare,convertV4MiniflareOptions}=require('miniflare');
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'cm-branding-v2-'));
  let mf;
  const eq=(name,actual,expected)=>{assert.deepEqual(actual,expected,name);passed++;console.log('  PASS '+name);};
  try {
    await build({entryPoints:[path.join(root,'workers/scan-api/src/worker.js')],outfile:path.join(scratch,'worker.mjs'),bundle:true,format:'esm',platform:'browser',target:'es2022',external:['cloudflare:*'],logLevel:'silent'});
    mf=new Miniflare(convertV4MiniflareOptions({cf:false,modules:true,resourcePersistencePath:path.join(scratch,'state'),script:fs.readFileSync(path.join(scratch,'worker.mjs'),'utf8'),compatibilityDate:'2026-06-18',compatibilityFlags:['global_fetch_strictly_public'],bindings:{ALLOWED_ORIGIN:'https://app.cybermeters.test',MAINTENANCE_MODE:'off'},d1Databases:{cybermeters_db:'synthetic-branding'},r2Buckets:{cybermeters_reports:'synthetic-brand-logos'},outboundService:async()=>{throw new Error('External network prohibited in branding validator');}}));
    const d1=await mf.getD1Database('cybermeters_db'),r2=await mf.getR2Bucket('cybermeters_reports');
    const sqlite=buildDb(),schema=sqlite.prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END").all();sqlite.close();
    await d1.batch(schema.map(row=>d1.prepare(row.sql)));
    for(const [user,plan] of [['owner','free'],['member','business'],['viewer','business'],['other','business']]){
      await d1.prepare('INSERT INTO users(id,email,plan,email_verified) VALUES(?,?,?,1)').bind(user,user+'@example.test',plan).run();
      await d1.prepare("INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+1 day'))").bind('s-'+user,user,createHash('sha256').update('t-'+user).digest('hex')).run();
    }
    await d1.prepare("INSERT INTO workspaces(id,name,owner_user_id) VALUES('owned','Agency Client','owner'),('foreign','Foreign','other')").run();
    for(const [ws,user,role] of [['owned','owner','owner'],['owned','member','admin'],['owned','viewer','viewer'],['foreign','other','owner']])await d1.prepare('INSERT INTO workspace_members(workspace_id,user_id,role) VALUES(?,?,?)').bind(ws,user,role).run();
    const future=new Date(Date.now()+86400000).toISOString();
    await d1.prepare("INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,subscription_status,trial_end,current_period_end) VALUES('trial','owner','owned','business','active','trialing',?,?)").bind(future,future).run();
    await d1.prepare("INSERT INTO api_tokens(id,user_id,workspace_id,name,token_hash,scope,status) VALUES('tok','owner','owned','synthetic',?,'write','active')").bind(createHash('sha256').update('cm_synthetic').digest('hex')).run();
    const call=async(method,url,user='owner',body,raw)=>{
      // The oversized-body negative control closes its unread local request.
      // Do not reuse that transport connection for the following assertion.
      const result=await mf.dispatchFetch('https://local.invalid/api'+url,{method,headers:{...(raw?{Connection:'close'}:{}),...(user?{Authorization:'Bearer '+(user==='token'?'cm_synthetic':'t-'+user)}:{}),Origin:'https://app.cybermeters.test','Content-Type':'application/json'},...(['POST','PUT'].includes(method)?{body:raw??JSON.stringify(body||{})}:{})});
      return {status:result.status,body:await result.json()};
    };
    const list='/account/branding/profiles',workspace='/workspaces/owned/branding';
    eq('actual entry sees effective trial despite users.plan free',(await call('GET',list)).body.white_label_available,true);
    eq('stale users.plan business cannot create profile',(await call('POST',list,'other',{name:'Stale',mode:'white_label'})).status,403);
    eq('API token cannot create account branding',(await call('POST',list,'token',{name:'Token',mode:'white_label'})).status,403);
    eq('workspace metadata uses billing owner not requesting member plan',(await call('GET',workspace,'member')).body.white_label_available,true);
    eq('viewer metadata is read only',(await call('GET',workspace,'viewer')).body.can_manage,false);
    eq('foreign workspace branding denied',(await call('GET',workspace,'other')).status,403);
    const first=await call('POST',list,'owner',{name:'Agency One',mode:'white_label',accent:'#224466',is_default:true});
    eq('profile create',first.status,201);const firstId=first.body.id;
    const second=await call('POST',list,'owner',{name:'Agency Two',mode:'white_label',accent:'#445566'});eq('second saved profile',second.status,201);const secondId=second.body.id;
    const selected=await call('PUT',list+'/'+secondId,'owner',{is_default:true});eq('atomic default selection',selected.status,200);
    eq('exactly one default after selection',(await d1.prepare("SELECT id FROM msp_branding_profiles WHERE owner_user_id='owner' AND is_default=1").all()).results.map(r=>r.id),[secondId]);
    const descriptor=await call('GET',workspace);eq('workspace receives actual selected profile',[descriptor.body.effective_profile_id,descriptor.body.effective_display_name,descriptor.body.effective_attribution],[secondId,'Agency Two','reduced']);
    eq('foreign profile read refused',(await call('GET',list+'/'+firstId,'other')).status,404);
    eq('foreign profile edit does not touch owner',(await call('PUT',list+'/'+firstId,'other',{name:'Overwrite'})).status,403);
    eq('foreign profile delete scoped',(await call('DELETE',list+'/'+firstId,'other')).body.deleted,false);
    const dataUri='data:image/png;base64,'+Buffer.from(png()).toString('base64');
    const edited=await call('PUT',list+'/'+firstId,'owner',{name:'Updated agency',accent:'#123ABC',logo:dataUri});eq('profile editable without delete/recreate',edited.status,200);
    const readLogo=await call('GET',list+'/'+firstId);eq('saved profile logo authenticated preview',readLogo.body.logo_data_uri,dataUri);
    eq('saved preview never exposes object key',Object.hasOwn(readLogo.body.profile,'logo_r2_key'),false);
    const savedProfile=await d1.prepare('SELECT * FROM msp_branding_profiles WHERE id=?').bind(firstId).first();
    const oldLogo=savedProfile.logo_r2_key;const frozen={mode:'white_label',...savedProfile};
    await call('PUT',list+'/'+firstId,'owner',{logo:null});
    eq('null clears profile logo',(await call('GET',list+'/'+firstId)).body.logo_data_uri,null);
    eq('old profile logo remains for historical reports',await loadBrandingLogoDataUri({cybermeters_reports:r2},frozen),dataUri);
    eq('old immutable object still exists',!!(await r2.head(oldLogo)),true);
    eq('editing profile preserves another default',(await d1.prepare("SELECT id FROM msp_branding_profiles WHERE owner_user_id='owner' AND is_default=1").first()).id,secondId);
    // Trigger a failure in the second statement of the actual D1 batch. A mock
    // Promise.all batch would not prove rollback and is deliberately not used.
    await d1.prepare(`CREATE TRIGGER reject_default BEFORE UPDATE OF is_default ON msp_branding_profiles WHEN OLD.id='${secondId}' AND NEW.is_default=0 BEGIN SELECT RAISE(ABORT,'synthetic atomicity failure'); END`).run();
    const failedCreate=await call('POST',list,'owner',{name:'Must roll back',mode:'white_label',is_default:true});eq('D1 failure rejects create',failedCreate.status,500);
    eq('failed create leaves previous default',(await d1.prepare("SELECT id FROM msp_branding_profiles WHERE owner_user_id='owner' AND is_default=1").first()).id,secondId);
    eq('failed create is rolled back completely',(await d1.prepare("SELECT COUNT(*) n FROM msp_branding_profiles WHERE name='Must roll back'").first()).n,0);
    const failedEdit=await call('PUT',list+'/'+firstId,'owner',{name:'Must not persist',is_default:true});eq('D1 failure rejects edit',failedEdit.status,500);
    eq('failed edit restores name and default',(await d1.prepare('SELECT name,is_default FROM msp_branding_profiles WHERE id=?').bind(firstId).first()),{name:'Updated agency',is_default:0});
    await d1.prepare('DROP TRIGGER reject_default').run();
    const raced=await Promise.all([call('PUT',list+'/'+firstId,'owner',{is_default:true}),call('PUT',list+'/'+secondId,'owner',{is_default:true})]);eq('concurrent default requests succeed',raced.map(r=>r.status),[200,200]);
    eq('concurrent selections retain one default',(await d1.prepare("SELECT COUNT(*) n FROM msp_branding_profiles WHERE owner_user_id='owner' AND is_default=1").first()).n,1);
    eq('client name only supported',(await call('PUT',workspace,'member',{display_name:'Client Display'})).status,200);
    eq('client name persisted without logo',(await call('GET',workspace)).body.logo.display_name,'Client Display');
    eq('viewer cannot rename client',(await call('PUT',workspace,'viewer',{display_name:'Wrong'})).status,403);
    eq('foreign cannot upload client logo',(await call('PUT',workspace+'/logo','other',{logo:dataUri})).status,403);
    eq('client logo upload',(await call('PUT',workspace+'/logo','member',{logo:dataUri,display_name:'Client Report'})).status,200);
    eq('saved client logo preview',(await call('GET',workspace+'/logo')).body.logo_data_uri,dataUri);
    eq('foreign cannot read client logo',(await call('GET',workspace+'/logo','other')).status,403);
    const workspaceFrozen=await d1.prepare("SELECT * FROM workspace_branding WHERE workspace_id='owned'").first();
    eq('client clear pointer',(await call('DELETE',workspace+'/logo')).body.has_logo,false);
    eq('clearing logo preserves client name',(await call('GET',workspace)).body.logo.display_name,'Client Report');
    eq('historical client logo still renders',await loadBrandingLogoDataUri({cybermeters_reports:r2},workspaceFrozen),dataUri);
    eq('oversized upload body rejected',(await call('PUT',workspace+'/logo','owner',null,'x'.repeat(720000))).status,400);
    eq('SVG preview path rejects active format',(await call('PUT',workspace+'/logo','owner',{logo:'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4='})).status,400);
    eq('arbitrary R2 key never accepted',(await call('PUT',workspace+'/logo','owner',{logo_r2_key:'branding/other/private.png'})).status,400);
    await d1.prepare("UPDATE subscriptions SET subscription_status='canceled',status='canceled' WHERE id='trial'").run();
    const downgraded=await call('GET',workspace,'member');eq('billing owner downgrade overrides member stale business flag',[downgraded.body.white_label_available,downgraded.body.effective_mode,downgraded.body.effective_attribution],[false,'co_brand','full']);
    eq('name-only future report displays client after downgrade',downgraded.body.effective_display_name,'Client Report');
    eq('downgrade cannot edit white-label',(await call('PUT',list+'/'+firstId,'owner',{name:'Denied'})).status,403);
    eq('downgrade can read saved profile',(await call('GET',list+'/'+firstId)).status,200);
    eq('downgrade can delete profile',(await call('DELETE',list+'/'+firstId)).body.deleted,true);
    eq('deleted profile frozen logo remains',await loadBrandingLogoDataUri({cybermeters_reports:r2},frozen),dataUri);
    await d1.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='owned'").run();
    eq('soft-deleted workspace rejects branding write',(await call('PUT',workspace,'owner',{display_name:'Revived'})).status,403);
    eq('soft-deleted workspace rejects logo read',(await call('GET',workspace+'/logo')).status,403);
  }finally{await mf?.dispose();fs.rmSync(scratch,{recursive:true,force:true});}
}
main().catch((e) => { console.error("runner crashed:", e); process.exit(1); });
