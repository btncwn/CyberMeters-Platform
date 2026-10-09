// Tenant-scoped report branding. Saved descriptors and content-addressed R2
// objects remain immutable for historical PDFs; edits affect future reports.
import { getEffectivePlan, hasFeatureEntitlement } from '../engines/entitlements.js';
import { getWorkspaceBillingUserId } from '../engines/plan-usage.js';
import { MAX_LOGO_BYTES, validateLogoUpload, workspaceLogoKey, mspLogoKey, resolveReportBrandingV2, loadBrandingLogoDataUri } from '../engines/report-branding-v2.js';
import { createAuditEvent } from '../lib/events.js';
import { createId } from '../lib/util.js';

const HEX = /^#[0-9a-fA-F]{6}$/;
const PROFILE_FIELDS = 'id,name,logo_mime,logo_sha256,accent,mode,is_default,updated_at';
const MAX_BODY_BYTES = Math.ceil(MAX_LOGO_BYTES / 3) * 4 + 16384;
const badInput = () => Object.assign(new Error('Invalid branding input'),{status:400});
async function readBody(request, allowed) {
  const length = Number(request.headers.get('content-length'));
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) throw badInput();
  const reader = request.body?.getReader();
  if (!reader) throw badInput();
  const chunks=[]; let size=0;
  try {
    while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>MAX_BODY_BYTES){await reader.cancel();throw badInput();}chunks.push(value);}
    const bytes=new Uint8Array(size);let offset=0;for(const part of chunks){bytes.set(part,offset);offset+=part.length;}
    const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(k=>!allowed.includes(k)))throw badInput();
    return body;
  } catch { throw badInput(); } finally {reader.releaseLock();}
}
function displayName(value,{required=false}={}) {
  if(value===null&&!required)return null;
  if(typeof value!=='string'||value.trim().length>120||/[\u0000-\u001f\u007f]/.test(value))throw badInput();
  const name=value.trim();if(required&&!name)throw badInput();return name||null;
}
function dataUriToBytes(uri) {
  if(typeof uri!=='string'||uri.length>Math.ceil(MAX_LOGO_BYTES/3)*4+32)return null;
  const match=/^data:image\/(png|jpeg);base64,([A-Za-z0-9+/=]+)$/.exec(uri);
  if(!match)return null;
  try{return Uint8Array.from(atob(match[2]),c=>c.charCodeAt(0));}catch{return null;}
}
async function checkedLogo(value) {
  const bytes=dataUriToBytes(value);if(!bytes)throw badInput();
  const checked=await validateLogoUpload(bytes);if(!checked.ok)throw Object.assign(new Error(checked.error),{status:400});return checked.value;
}
const denied = () => Object.assign(new Error('Current management access required'),{status:403});
const noEntitlement = () => Object.assign(new Error('plan_feature_required'),{status:403,feature:'white_label'});
const profileView = row => row ? Object.fromEntries(PROFILE_FIELDS.split(',').map(key=>[key,row[key]])) : null;

export async function workspaceBrandingRoutes(rctx) {
  const {request,env,url,json,serverError,requireAuth,requireWorkspaceRole}=rctx;
  const wsConfigMatch=url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/branding$/);
  const wsLogoMatch=url.pathname.match(/^\/api\/workspaces\/([^\/]+)\/branding\/logo$/);
  const profListMatch=url.pathname==='/api/account/branding/profiles';
  const profItemMatch=url.pathname.match(/^\/api\/account\/branding\/profiles\/([^\/]+)$/);
  if(!wsConfigMatch&&!wsLogoMatch&&!profListMatch&&!profItemMatch)return null;
  const user=await requireAuth(request,env);
  if(!user)return json({error:'Unauthorized'},401);
  const db=env.cybermeters_db;
  try {
    if(wsConfigMatch||wsLogoMatch){
      const workspaceId=(wsConfigMatch||wsLogoMatch)[1];
      const authorize=async(permission)=>{
        const current=await requireAuth(request,env);
        if(!current||current.id!==user.id)throw denied();
        const access=await requireWorkspaceRole(current,workspaceId,permission,env);
        if(!access)throw denied();return access;
      };
      await authorize('workspace:read');
      const row=()=>db.prepare('SELECT * FROM workspace_branding WHERE workspace_id=?').bind(workspaceId).first();
      if(request.method==='GET'&&wsConfigMatch){
        const branding=await row(),descriptor=await resolveReportBrandingV2(env,{workspaceId});
        const access=await requireWorkspaceRole(user,workspaceId,'workspace:manage',env);
        const owner=await getWorkspaceBillingUserId(workspaceId,null,env);
        const whiteLabel=hasFeatureEntitlement(await getEffectivePlan(owner,env),'white_label');
        return json({can_manage:!!access,white_label_available:whiteLabel,has_logo:!!branding?.logo_sha256,display_name:branding?.display_name||null,
          logo:branding?{mime:branding.logo_mime,width:branding.logo_width,height:branding.logo_height,bytes:branding.logo_bytes,sha256:branding.logo_sha256,display_name:branding.display_name,updated_at:branding.updated_at}:null,
          effective_mode:descriptor.mode,effective_attribution:descriptor.attribution,effective_profile_id:descriptor.profile_id||null,effective_display_name:descriptor.display_name||null,effective_accent:descriptor.accent||null});
      }
      if(request.method==='GET'&&wsLogoMatch){
        const logo_data_uri=await loadBrandingLogoDataUri(env,await row());await authorize('workspace:read');return json({logo_data_uri});
      }
      if(request.method==='PUT'&&wsConfigMatch){
        await authorize('workspace:manage');const body=await readBody(request,['display_name']);
        if(!Object.hasOwn(body,'display_name'))throw badInput();const name=displayName(body.display_name);
        await authorize('workspace:manage');
        await db.prepare(`INSERT INTO workspace_branding(workspace_id,display_name,updated_at,updated_by) VALUES(?,?,datetime('now'),?)
          ON CONFLICT(workspace_id) DO UPDATE SET display_name=excluded.display_name,updated_at=datetime('now'),updated_by=excluded.updated_by`).bind(workspaceId,name,user.id).run();
        return json({ok:true,display_name:name});
      }
      if(request.method==='DELETE'&&wsLogoMatch){
        await authorize('workspace:manage');
        await db.prepare(`UPDATE workspace_branding SET logo_r2_key=NULL,logo_mime=NULL,logo_sha256=NULL,logo_width=NULL,logo_height=NULL,logo_bytes=NULL,updated_at=datetime('now'),updated_by=? WHERE workspace_id=?`).bind(user.id,workspaceId).run();
        await createAuditEvent(env,{workspace_id:workspaceId,user_id:user.id,event_type:'branding_logo_cleared',entity_type:'workspace',entity_id:workspaceId,description:'Workspace report logo cleared'}).catch(()=>{});
        return json({ok:true,has_logo:false});
      }
      if(request.method==='PUT'&&wsLogoMatch){
        await authorize('workspace:manage');const body=await readBody(request,['logo','display_name']);
        const value=await checkedLogo(body.logo),name=Object.hasOwn(body,'display_name')?displayName(body.display_name):null;
        const key=workspaceLogoKey(workspaceId,value.sha256,value.ext);
        await env.cybermeters_reports.put(key,value.bytes,{httpMetadata:{contentType:value.mime}});
        await authorize('workspace:manage');
        await db.prepare(`INSERT INTO workspace_branding(workspace_id,logo_r2_key,logo_mime,logo_sha256,logo_width,logo_height,logo_bytes,display_name,updated_at,updated_by)
          VALUES(?,?,?,?,?,?,?,?,datetime('now'),?) ON CONFLICT(workspace_id) DO UPDATE SET
          logo_r2_key=excluded.logo_r2_key,logo_mime=excluded.logo_mime,logo_sha256=excluded.logo_sha256,logo_width=excluded.logo_width,logo_height=excluded.logo_height,logo_bytes=excluded.logo_bytes,
          display_name=CASE WHEN ? THEN excluded.display_name ELSE workspace_branding.display_name END,updated_at=datetime('now'),updated_by=excluded.updated_by`)
          .bind(workspaceId,key,value.mime,value.sha256,value.width,value.height,value.size,name,user.id,Object.hasOwn(body,'display_name')?1:0).run();
        await createAuditEvent(env,{workspace_id:workspaceId,user_id:user.id,event_type:'branding_logo_set',entity_type:'workspace',entity_id:workspaceId,description:'Workspace report logo set',metadata:{sha256:value.sha256,mime:value.mime}}).catch(()=>{});
        return json({ok:true,has_logo:true,logo:{mime:value.mime,width:value.width,height:value.height,sha256:value.sha256}});
      }
      return json({error:'Method not allowed'},405);
    }
    if(user.api_token_id)return json({error:'Session authentication required'},403);
    const ownerId=user.id;
    const entitled=async()=>hasFeatureEntitlement(await getEffectivePlan(ownerId,env),'white_label');
    const authorize=async(requirePlan=false)=>{
      const current=await requireAuth(request,env);
      if(!current||current.api_token_id||current.id!==ownerId)throw denied();
      if(requirePlan&&!(await entitled()))throw noEntitlement();
    };
    const ownedProfile=async(id)=>{
      const value=await db.prepare('SELECT * FROM msp_branding_profiles WHERE id=? AND owner_user_id=?').bind(id,ownerId).first();
      if(!value)throw Object.assign(new Error('Profile not found'),{status:404});return value;
    };
    if(request.method==='GET'&&profListMatch){
      const rows=await db.prepare(`SELECT ${PROFILE_FIELDS} FROM msp_branding_profiles WHERE owner_user_id=? ORDER BY is_default DESC,updated_at DESC,id DESC`).bind(ownerId).all();
      return json({profiles:rows.results||[],white_label_available:await entitled()});
    }
    if(request.method==='GET'&&profItemMatch){
      const saved=await ownedProfile(profItemMatch[1]),logo_data_uri=await loadBrandingLogoDataUri(env,saved);
      await authorize();return json({profile:profileView(saved),logo_data_uri,white_label_available:await entitled()});
    }
    const saveProfile = async (existingId) => {
      await authorize(true);
      const existing=existingId?await ownedProfile(existingId):null;
      const body=await readBody(request,['name','mode','accent','logo','is_default']);
      if(!Object.keys(body).length)throw badInput();
      const name=Object.hasOwn(body,'name')?displayName(body.name,{required:true}):existing?.name;
      if(!name)throw badInput();
      const mode=Object.hasOwn(body,'mode')?body.mode:existing?.mode||'co_brand';
      if(!['co_brand','white_label'].includes(mode))throw badInput();
      const accent=Object.hasOwn(body,'accent')?body.accent:existing?.accent||null;
      if(accent!==null&&!HEX.test(accent))throw badInput();
      if(Object.hasOwn(body,'is_default')&&typeof body.is_default!=='boolean')throw badInput();
      const isDefault=Object.hasOwn(body,'is_default')?body.is_default:!!existing?.is_default;
      let logoKey=existing?.logo_r2_key||null,logoMime=existing?.logo_mime||null,logoSha=existing?.logo_sha256||null;
      if(Object.hasOwn(body,'logo')){
        if(body.logo===null){logoKey=null;logoMime=null;logoSha=null;}
        else{const value=await checkedLogo(body.logo);logoKey=mspLogoKey(ownerId,value.sha256,value.ext);logoMime=value.mime;logoSha=value.sha256;
          await env.cybermeters_reports.put(logoKey,value.bytes,{httpMetadata:{contentType:value.mime}});}
      }
      await authorize(true);
      const id=existing?.id||'mbp-'+createId();
      const statements=[existing
        ? db.prepare(`UPDATE msp_branding_profiles SET name=CASE WHEN ? THEN ? ELSE name END,
          logo_r2_key=CASE WHEN ? THEN ? ELSE logo_r2_key END,logo_mime=CASE WHEN ? THEN ? ELSE logo_mime END,logo_sha256=CASE WHEN ? THEN ? ELSE logo_sha256 END,
          accent=CASE WHEN ? THEN ? ELSE accent END,mode=CASE WHEN ? THEN ? ELSE mode END,is_default=CASE WHEN ? THEN ? ELSE is_default END,updated_at=datetime('now') WHERE id=? AND owner_user_id=?`)
          .bind(Object.hasOwn(body,'name')?1:0,name,Object.hasOwn(body,'logo')?1:0,logoKey,Object.hasOwn(body,'logo')?1:0,logoMime,Object.hasOwn(body,'logo')?1:0,logoSha,
            Object.hasOwn(body,'accent')?1:0,accent,Object.hasOwn(body,'mode')?1:0,mode,Object.hasOwn(body,'is_default')?1:0,isDefault?1:0,id,ownerId)
        : db.prepare('INSERT INTO msp_branding_profiles(id,owner_user_id,name,logo_r2_key,logo_mime,logo_sha256,accent,mode,is_default) VALUES(?,?,?,?,?,?,?,?,?)').bind(id,ownerId,name,logoKey,logoMime,logoSha,accent,mode,isDefault?1:0)];
      if(body.is_default===true)statements.push(db.prepare(`UPDATE msp_branding_profiles SET is_default=CASE WHEN id=? THEN 1 ELSE 0 END WHERE owner_user_id=? AND EXISTS(SELECT 1 FROM msp_branding_profiles WHERE id=? AND owner_user_id=?)`).bind(id,ownerId,id,ownerId));
      // D1 batches are transactional: a rejected edit/create cannot clear the
      // existing default, and concurrent selections finish with one default.
      await db.batch(statements);
      const saved=await ownedProfile(id);return json({ok:true,id,mode,is_default:!!saved.is_default,profile:profileView(saved)},existing?200:201);
    };
    if(request.method==='POST'&&profListMatch)return await saveProfile(null);
    if(request.method==='PUT'&&profItemMatch)return await saveProfile(profItemMatch[1]);
    if(request.method==='DELETE'&&profItemMatch){
      await authorize();const result=await db.prepare('DELETE FROM msp_branding_profiles WHERE id=? AND owner_user_id=?').bind(profItemMatch[1],ownerId).run();
      return json({ok:true,deleted:(result.meta?.changes||0)>0});
    }
    return json({error:'Method not allowed'},405);
  }catch(error){
    if(error.status){return json({error:error.message,...(error.feature?{feature:error.feature,required_plan:'business'}:{})},error.status);}
    return serverError('branding',error);
  }
}
