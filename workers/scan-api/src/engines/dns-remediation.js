import { canonicalDomain, inZone, createCloudflareDns, DnsActionError, stableJson, boundedDnsJson } from './cloudflare-dns.js';
import { encryptProviderToken, decryptProviderToken, providerKeyAvailable } from '../lib/provider-secrets.js';
import { buildDmarcDnsRecommendedValue, buildTlsRptValue } from './hosted-dmarc.js';
import { parseDmarcRecord, normalizeDnsTxtValue } from './email-analysis.js';
import { RUA_INBOUND_DOMAIN_DEFAULT, normalizeInboundRecipientDomain } from '../lib/dmarc-ingest.js';

export const DNS_ACTIONS = Object.freeze([
  { id: 'spf_publish', remediation_id: 'email.spf.publish', title: 'Publish missing SPF' },
  { id: 'dmarc_reporting', remediation_id: 'email.dmarc.reporting', title: 'Add DMARC reporting' },
  { id: 'tls_rpt', remediation_id: 'email.tls_rpt.enable', title: 'Publish TLS reporting' },
]);
export const DNS_SCOPE_NOTE = 'Explicit changes to this verified domain in your connected Cloudflare zone. DNS publication does not prove mail delivery or close a managed case.';
const ACTIVE = ['applying', 'uncertain', 'rolling_back', 'rollback_uncertain'];
const APPLIED = ['provider_accepted', 'dns_verified'];
const iso = () => new Date().toISOString();
const parse = value => JSON.parse(value);
const err = (code, status = 409, message) => { throw new DnsActionError(code, status, message); };
export function requireKeys(object, allowed) {
  if (!object || typeof object !== 'object' || Array.isArray(object) || Object.keys(object).some(key => !allowed.includes(key))) err('unsupported_input', 422);
}
export function requireRequestId(value) { if (typeof value !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value)) err('invalid_request_id', 400); return value; }
async function digest(value) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join(''); }
export async function loadDnsConnection(c) {
  return c.db.prepare('SELECT * FROM dns_provider_connections WHERE workspace_id=? AND domain_id=?').bind(c.workspaceId, c.domainId).first();
}
export function connectionView(row) { return row ? { id: row.id, zone_id: row.zone_id, zone_name: row.zone_name, connected_at: row.connected_at } : null; }
export function changeView(row, capabilities = {}) {
  const expired = Date.parse(row.expires_at) <= Date.now();
  const verification = parse(row.verification_json);
  return {
    id: row.id, action_id: row.action_id, remediation_id: row.remediation_id, status: row.status, reason: row.reason,
    name: row.record_name, type: 'TXT', before: parse(row.before_json), after: parse(row.desired_json),
    created_at: row.created_at, expires_at: row.expires_at, applied_at: row.applied_at, verified_at: row.verified_at,
    rolled_back_at: row.rolled_back_at, case_id: row.case_id,
    case_status: row.case_id ? (verification.state === 'observed' ? 'awaiting_canonical_verification' : 'unchanged') : null,
    can_apply: capabilities.can_apply === true && row.status === 'preview' && !expired,
    can_verify: capabilities.can_manage === true && [...ACTIVE, ...APPLIED].includes(row.status),
    can_rollback: capabilities.can_manage === true && APPLIED.includes(row.status) && !!row.postimage_json,
    verification,
  };
}
export async function loadDnsChange(c, id) {
  const row = await c.db.prepare('SELECT * FROM dns_provider_changes WHERE workspace_id=? AND domain_id=? AND id=?').bind(c.workspaceId, c.domainId, id).first();
  if (!row) err('change_not_found', 404);
  return row;
}
function secretScope(c, row) { return { workspace_id: c.workspaceId, domain_id: c.domainId, zone_id: row.zone_id, connection_id: row.id }; }
async function provider(c, connection) {
  if (!connection) err('connection_required', 409);
  const token = await decryptProviderToken(connection.token_ciphertext, secretScope(c, connection), c.env.DNS_PROVIDER_KEY);
  return createCloudflareDns(token, c.providerOptions);
}
export async function connectDnsProvider(c, body) {
  requireKeys(body, ['zone_id', 'token']);
  if (!providerKeyAvailable(c.env.DNS_PROVIDER_KEY)) err('key_unavailable', 503);
  if (typeof body.zone_id !== 'string' || !/^[a-f0-9]{32}$/.test(body.zone_id)) err('invalid_zone', 400);
  const api = createCloudflareDns(body.token, c.providerOptions);
  const zone = await api.verifyZone(body.zone_id, c.domain);
  await api.list(zone.id, c.domain); // confirms zone DNS read access, not a claim of token-policy introspection
  await c.authorize(false);
  const existing = await loadDnsConnection(c);
  const busy = await c.db.prepare("SELECT id FROM dns_provider_changes WHERE workspace_id=? AND domain_id=? AND status IN ('applying','rolling_back') LIMIT 1").bind(c.workspaceId, c.domainId).first();
  if (busy) err('action_in_progress');
  // Concurrent first connections must encrypt against the same eventual row ID.
  const id = existing?.id || `dnc_${(await digest(JSON.stringify([c.workspaceId,c.domainId]))).slice(0,40)}`;
  const row = { id, zone_id: zone.id };
  const ciphertext = await encryptProviderToken(body.token, secretScope(c, row), c.env.DNS_PROVIDER_KEY);
  body.token = null;
  const revision = crypto.randomUUID(), now = iso();
  await c.authorize(false);
  await c.db.prepare(`INSERT INTO dns_provider_connections(id,workspace_id,domain_id,zone_id,zone_name,token_ciphertext,credential_revision,connected_by,connected_at)
    SELECT ?,?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM dns_provider_changes WHERE workspace_id=? AND domain_id=? AND status IN ('applying','rolling_back'))
    ON CONFLICT(workspace_id,domain_id) DO UPDATE SET zone_id=excluded.zone_id,zone_name=excluded.zone_name,
    token_ciphertext=excluded.token_ciphertext,credential_revision=excluded.credential_revision,connected_by=excluded.connected_by,connected_at=excluded.connected_at
    WHERE NOT EXISTS(SELECT 1 FROM dns_provider_changes WHERE workspace_id=? AND domain_id=? AND status IN ('applying','rolling_back'))`)
    .bind(id,c.workspaceId,c.domainId,zone.id,zone.name,ciphertext,revision,c.userId,now,c.workspaceId,c.domainId,c.workspaceId,c.domainId).run();
  if ((await loadDnsConnection(c))?.credential_revision !== revision) err('connection_changed');
  return loadDnsConnection(c);
}
export async function disconnectDnsProvider(c) {
  await c.authorize(false);
  const result = await c.db.prepare(`DELETE FROM dns_provider_connections WHERE workspace_id=? AND domain_id=?
    AND NOT EXISTS(SELECT 1 FROM dns_provider_changes WHERE workspace_id=? AND domain_id=? AND status IN ('applying','rolling_back'))`)
    .bind(c.workspaceId,c.domainId,c.workspaceId,c.domainId).run();
  if (result.meta?.changes !== 1 && await loadDnsConnection(c)) err('action_in_progress');
  return { disconnected: true };
}
function ipTerm(value, family) {
  if (typeof value !== 'string' || value.length > 64 || !/^[0-9a-fA-F.:/]+$/.test(value)) err('unsupported_input', 422);
  const parts = value.split('/'), address = parts[0], max = family === 4 ? 32 : 128;
  if (parts.length > 2 || parts[1] !== undefined && (!/^\d{1,3}$/.test(parts[1]) || +parts[1] < 1 || +parts[1] > max)) err('unsupported_input', 422);
  if (family === 4) {
    if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(address) || address.split('.').some(part => +part > 255)) err('unsupported_input', 422);
  } else {
    if (!address.includes(':') || address.includes('.')) err('unsupported_input', 422);
    try { new URL(`http://[${address}]/`); } catch { err('unsupported_input', 422); }
  }
  return value.toLowerCase();
}
export function buildExplicitSpf(inputs) {
  requireKeys(inputs, ['mail_mode', 'no_mail_confirmed', 'senders_confirmed', 'includes', 'ip4', 'ip6', 'all']);
  if (inputs.mail_mode === 'no_mail') {
    if (inputs.no_mail_confirmed !== true || Object.keys(inputs).some(key => !['mail_mode','no_mail_confirmed'].includes(key))) err('unsupported_input', 422);
    return 'v=spf1 -all';
  }
  if (inputs.mail_mode !== 'senders' || inputs.senders_confirmed !== true || !['~all','-all'].includes(inputs.all) || inputs.no_mail_confirmed !== undefined) err('unsupported_input', 422);
  const lists = ['includes','ip4','ip6'].map(key => inputs[key] ?? []);
  if (lists.some(list => !Array.isArray(list) || list.length > 16) || !lists.some(list => list.length)) err('unsupported_input', 422);
  const includes = lists[0].map(name => canonicalDomain(name, { underscore: true }));
  if (includes.length > 10) err('spf_lookup_limit', 422);
  const terms = [...includes.map(name => `include:${name}`), ...lists[1].map(value => `ip4:${ipTerm(value,4)}`), ...lists[2].map(value => `ip6:${ipTerm(value,6)}`)];
  if (new Set(terms).size !== terms.length) err('unsupported_input', 422);
  const value = `v=spf1 ${terms.join(' ')} ${inputs.all}`;
  if (value.length > 2048) err('unsupported_input', 422);
  return value;
}
export async function observeDnsTxt(name, { fetchImpl = fetch, timeoutMs = 6000 } = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`https://cloudflare-dns.com/dns-query?${new URLSearchParams({ name, type: 'TXT' })}`, { headers: { Accept: 'application/dns-json' }, redirect: 'manual', signal: controller.signal });
    if (!response.ok) { await response.body?.cancel(); throw new Error(); }
    const value = await boundedDnsJson(response, 65536);
    if (!value || ![0,3].includes(value.Status) || value.TC !== false || !Array.isArray(value.Question) || value.Question.length !== 1 ||
        value.Question[0].type !== 16 || canonicalDomain(value.Question[0].name, { underscore:true }) !== name ||
        value.Answer != null && !Array.isArray(value.Answer)) throw new Error();
    const answers = value.Answer || [];
    if (answers.length > 100 || value.Status === 3 && answers.length) throw new Error();
    if (answers.some(answer => answer.type !== 16 || canonicalDomain(answer.name, { underscore:true }) !== name || typeof answer.data !== 'string' || answer.data.length > 4096)) throw new Error();
    return { state: 'observed', values: answers.map(answer => normalizeDnsTxtValue(answer.data)), checked_at: iso() };
  } catch { return { state: 'unavailable', values: [], checked_at: iso(), reason: 'dns_unavailable' }; }
  finally { clearTimeout(timer); }
}
// Conservative supported SPF subset. Never flatten provider policy or turn
// lookup failure/truncation into an executable, supposedly validated record.
async function validateSpfIncludes(value, options) {
  let lookups = 0;
  const deadline = Date.now() + 15000;
  async function walk(record, ancestors) {
    const terms = record.trim().split(/\s+/);
    if (terms.shift()?.toLowerCase() !== 'v=spf1') err('unsupported_spf_chain', 422);
    let terminal = false;
    for (const [index, term] of terms.entries()) {
      if (/^[~-]all$/.test(term)) { if (index !== terms.length - 1 || terminal) err('unsupported_spf_chain', 422); terminal = true; continue; }
      if (term.startsWith('ip4:')) { ipTerm(term.slice(4),4); continue; }
      if (term.startsWith('ip6:')) { ipTerm(term.slice(4),6); continue; }
      if (!term.startsWith('include:') && !term.startsWith('redirect=')) err('unsupported_spf_chain', 422);
      const redirect = term.startsWith('redirect=');
      if (redirect && (terminal || index !== terms.length - 1)) err('unsupported_spf_chain', 422);
      const name = canonicalDomain(term.slice(redirect ? 9 : 8), { underscore:true });
      if (++lookups > 10) err('spf_lookup_limit', 422);
      if (ancestors.includes(name)) err('spf_include_loop', 422);
      if (Date.now() >= deadline) err('dns_unavailable', 503);
      const observed = await observeDnsTxt(name, {...options,timeoutMs:Math.min(options?.timeoutMs || 6000,deadline-Date.now())});
      if (observed.state !== 'observed') err('dns_unavailable', 503);
      const records = observed.values.filter(txt => /^v=spf1(?:\s|$)/i.test(txt));
      if (records.length !== 1) err('invalid_spf_include', 422);
      await walk(records[0], [...ancestors,name]);
    }
  }
  await walk(value, []);
}
function validDmarc(value) {
  const parts = value.split(';').map(part => part.trim()).filter(Boolean), names = parts.map(part => part.split('=')[0].trim().toLowerCase());
  if (value.length > 3500 || /[\r\n\x00]/.test(value) || !/^v=DMARC1\s*;/i.test(value) || new Set(names).size !== names.length ||
      parts.some(part => !/^[a-z][a-z0-9_-]*\s*=\s*\S.*$/i.test(part))) return false;
  const parsed = parseDmarcRecord(value,1), tags=parsed.tags;
  return parsed.valid && (!tags.sp || ['none','quarantine','reject'].includes(tags.sp.toLowerCase())) &&
    ['adkim','aspf'].every(key => !tags[key] || ['r','s'].includes(tags[key].toLowerCase()));
}
async function reportingEndpoint(c) {
  const row = await c.db.prepare("SELECT id,address_local FROM dmarc_ingest_endpoints WHERE workspace_id=? AND domain=? AND status='active' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1").bind(c.workspaceId,c.domain).first();
  const inbound = normalizeInboundRecipientDomain(c.env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT);
  if (!row || !/^cmrua_[a-z0-9]{8,}$/.test(row.address_local) || !inbound) err('reporting_endpoint_required',422,'Create a CyberMeters reporting address for this domain first.');
  return { id:row.id, address:`${row.address_local}@${inbound}` };
}
export async function dnsReportingReady(c) { try { await reportingEndpoint(c); return true; } catch { return false; } }
function protocolRecord(action, record) {
  return record.type === 'TXT' && (action === 'spf_publish' ? /^v=spf1(?:\s|$)/i : action === 'dmarc_reporting' ? /^v=DMARC1(?:\s*;|$)/i : /^v=TLSRPTv1(?:\s*;|$)/i).test(normalizeDnsTxtValue(record.content));
}
async function validateCase(c, id, remediationId) {
  if (id == null) return null;
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) err('unsupported_input',422);
  const row = await c.db.prepare("SELECT id,status FROM managed_cases WHERE id=? AND workspace_id=? AND domain=? AND domain_key='email_protection' AND remediation_id=?").bind(id,c.workspaceId,c.domain,remediationId).first();
  if (!row) err('case_not_found',404);
  return row.id;
}
export async function previewDnsChange(c, body) {
  requireKeys(body,['action_id','request_id','inputs','case_id']); requireRequestId(body.request_id);
  const action = DNS_ACTIONS.find(entry => entry.id === body.action_id);
  if (!action) err('unsupported_action',422);
  const inputs = body.inputs ?? {}; requireKeys(inputs, action.id === 'spf_publish' ? ['mail_mode','no_mail_confirmed','senders_confirmed','includes','ip4','ip6','all'] : []);
  const fingerprint = await digest(stableJson({ action_id:action.id,inputs,case_id:body.case_id ?? null,domain_id:c.domainId }));
  const prior = await c.db.prepare('SELECT * FROM dns_provider_changes WHERE workspace_id=? AND request_id=?').bind(c.workspaceId,body.request_id).first();
  if (prior) { if (prior.input_fingerprint !== fingerprint || prior.domain_id !== c.domainId) err('request_conflict'); return prior; }
  const connection = await loadDnsConnection(c), api = await provider(c,connection);
  if (!inZone(c.domain,connection.zone_name)) err('zone_mismatch',422);
  const name = action.id === 'spf_publish' ? c.domain : action.id === 'dmarc_reporting' ? `_dmarc.${c.domain}` : `_smtp._tls.${c.domain}`;
  const before = await api.list(connection.zone_id,name);
  if (before.some(record => record.type === 'CNAME')) err('existing_record_conflict',422);
  const relevant = before.filter(record => protocolRecord(action.id,record));
  let content, endpoint = null, previous = null;
  if (action.id === 'spf_publish') {
    if (relevant.length) err('existing_record_conflict',422,'An SPF record already exists; this action only publishes a missing record.');
    content = buildExplicitSpf(inputs); await validateSpfIncludes(content,c.dnsOptions);
  } else {
    endpoint = await reportingEndpoint(c);
    if (action.id === 'tls_rpt') {
      if (relevant.length) err('existing_record_conflict',422);
      content = buildTlsRptValue(endpoint.address);
    } else {
      if (relevant.length !== 1 || !validDmarc(relevant[0].content)) err('existing_record_conflict',422,'Exactly one valid existing DMARC policy is required.');
      previous = relevant[0];
      content = buildDmarcDnsRecommendedValue(previous.content,`mailto:${endpoint.address}`);
      if (!validDmarc(content)) err('unsupported_input',422);
      if (normalizeDnsTxtValue(previous.content) === content) err('already_configured',409);
    }
  }
  const id = `dch_${crypto.randomUUID()}`, marker = `CyberMeters change ${id}`;
  if (previous?.comment && previous.comment.length > 400) err('existing_record_conflict',422);
  const desired = { name,type:'TXT',content,ttl:previous?.ttl || 300,proxied:false,comment:previous?.comment ? `${previous.comment}\n${marker}` : marker, ...(previous ? {id:previous.id} : {}) };
  const caseId = await validateCase(c,body.case_id,action.remediation_id);
  const now = iso(), expires = new Date(Date.parse(now)+600000).toISOString();
  await c.authorize(false);
  const current = await loadDnsConnection(c);
  if (current?.credential_revision !== connection.credential_revision) err('connection_changed');
  await c.db.prepare(`INSERT INTO dns_provider_changes(id,workspace_id,domain_id,connection_id,credential_revision,zone_id,action_id,remediation_id,
    request_id,input_fingerprint,record_name,before_json,desired_json,reporting_endpoint_id,case_id,created_by,created_at,expires_at,status)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'preview') ON CONFLICT(workspace_id,request_id) DO NOTHING`)
    .bind(id,c.workspaceId,c.domainId,connection.id,connection.credential_revision,connection.zone_id,action.id,action.remediation_id,body.request_id,fingerprint,name,stableJson(before),stableJson(desired),endpoint?.id ?? null,caseId,c.userId,now,expires).run();
  const saved = await c.db.prepare('SELECT * FROM dns_provider_changes WHERE workspace_id=? AND request_id=?').bind(c.workspaceId,body.request_id).first();
  if (saved?.input_fingerprint !== fingerprint || saved.domain_id !== c.domainId) err('request_conflict');
  return saved;
}
async function connectionForChange(c,row,{preview=false}={}) {
  const connection = await loadDnsConnection(c);
  if (!connection || connection.id !== row.connection_id || connection.zone_id !== row.zone_id || preview && connection.credential_revision !== row.credential_revision) err('connection_changed');
  if (!inZone(c.domain,connection.zone_name)) err('zone_mismatch');
  return connection;
}
async function saveState(c,row,status,reason=null,extra={}) {
  await c.db.prepare(`UPDATE dns_provider_changes SET status=?,reason=?,postimage_json=COALESCE(?,postimage_json),provider_record_id=COALESCE(?,provider_record_id),
    applied_at=COALESCE(?,applied_at),rolled_back_at=COALESCE(?,rolled_back_at),
    verification_json=CASE WHEN ?='rolled_back' THEN '{"state":"not_checked","checked_at":null,"reason":"rolled_back"}' ELSE verification_json END,
    verified_at=CASE WHEN ?='rolled_back' THEN NULL ELSE verified_at END WHERE workspace_id=? AND domain_id=? AND id=? AND status=?`)
    .bind(status,reason,extra.postimage ?? null,extra.recordId ?? null,extra.appliedAt ?? null,extra.rolledBackAt ?? null,status,status,c.workspaceId,c.domainId,row.id,row.status).run();
  return loadDnsChange(c,row.id);
}
function expectedRecord(row,records) {
  const desired = parse(row.desired_json);
  const found = records.filter(record => record.name === desired.name && record.type === 'TXT' && record.content === desired.content &&
    record.comment === desired.comment && record.ttl === desired.ttl && record.proxied === false && (!desired.id || record.id === desired.id));
  if (found.length !== 1) return null;
  if (desired.id) {
    const original = parse(row.before_json).find(record => record.id === desired.id);
    const unchanged = record => Object.fromEntries(Object.entries(record).filter(([key]) => !['content','comment','modified_on','comment_modified_on','tags_modified_on'].includes(key)));
    if (!original || stableJson(unchanged(original)) !== stableJson(unchanged(found[0]))) return null;
  }
  const beforeOthers = parse(row.before_json).filter(record => record.id !== desired.id);
  const afterOthers = records.filter(record => record.id !== found[0].id);
  return stableJson(beforeOthers) === stableJson(afterOthers) ? found[0] : null;
}
async function noteCase(c,row,action) {
  if (!row.case_id) return;
  // An action receipt is history, never a manufactured case transition. Existing
  // method-specific canonical verifiers alone may conclude the case.
  await c.db.prepare(`INSERT OR IGNORE INTO managed_case_events(id,case_id,workspace_id,actor_type,actor_id,from_status,to_status,action,detail_json,created_at)
    SELECT ?,id,workspace_id,'system',NULL,status,status,?,?,? FROM managed_cases WHERE id=? AND workspace_id=? AND domain=? AND remediation_id=?`)
    .bind(`mce_${row.id}_${action}`,action,JSON.stringify({change_id:row.id,remediation_id:row.remediation_id,record_name:row.record_name,case_closed:false}),iso(),row.case_id,c.workspaceId,c.domain,row.remediation_id).run();
}
export async function applyDnsChange(c,id,body) {
  requireKeys(body,['request_id','confirm']); requireRequestId(body.request_id); if (body.confirm !== true) err('confirmation_required',400);
  await c.authorize(true);
  let row = await loadDnsChange(c,id);
  if (row.apply_request_id) { if (row.apply_request_id !== body.request_id) err('request_conflict'); return row; }
  if (row.status !== 'preview') err('change_not_applicable');
  if (Date.parse(row.expires_at) <= Date.now()) err('preview_expired');
  const connection = await connectionForChange(c,row,{preview:true}), api = await provider(c,connection);
  const desired = parse(row.desired_json);
  if (row.reporting_endpoint_id && (await reportingEndpoint(c)).id !== row.reporting_endpoint_id) err('reporting_endpoint_changed');
  const current = await api.list(row.zone_id,row.record_name);
  if (stableJson(current) !== row.before_json) return saveState(c,row,'conflict','record_drift');
  if (row.action_id === 'spf_publish') await validateSpfIncludes(desired.content,c.dnsOptions);
  await c.authorize(true);
  await connectionForChange(c,row,{preview:true});
  try {
    const claim = await c.db.prepare("UPDATE dns_provider_changes SET status='applying',apply_request_id=?,operation_by=?,operation_started_at=? WHERE id=? AND workspace_id=? AND domain_id=? AND status='preview' AND expires_at>?")
      .bind(body.request_id,c.userId,iso(),id,c.workspaceId,c.domainId,iso()).run();
    if (claim.meta?.changes !== 1) { const other=await loadDnsChange(c,id); if(other.apply_request_id===body.request_id)return other; err('action_in_progress'); }
  } catch(error) { if(error instanceof DnsActionError)throw error; err('action_in_progress'); }
  row = await loadDnsChange(c,id);
  try {
    await c.authorize(true);
    await connectionForChange(c,row,{preview:true});
    // The final read belongs inside the per-name claim. Otherwise two previews
    // can both observe absence before the first operation releases its claim.
    const latest = await api.list(row.zone_id,row.record_name);
    if (stableJson(latest) !== row.before_json) return saveState(c,row,'conflict','record_drift');
    await c.authorize(true);
    if (row.reporting_endpoint_id && (await reportingEndpoint(c)).id !== row.reporting_endpoint_id) err('reporting_endpoint_changed');
    if (desired.id) await api.update(row.zone_id,desired.id,{content:desired.content,comment:desired.comment});
    else { const {id:unused,...payload}=desired; await api.create(row.zone_id,payload); }
  } catch(error) { return saveState(c,row,error.uncertain ? 'uncertain' : 'unavailable',error.code || 'provider_unavailable'); }
  try {
    const records = await api.list(row.zone_id,row.record_name), found=expectedRecord(row,records);
    if(!found)return saveState(c,row,'uncertain','readback_mismatch');
    await c.authorize(false);
    const saved=await saveState(c,row,'provider_accepted',null,{postimage:stableJson(records),recordId:found.id,appliedAt:iso()});
    await noteCase(c,saved,'dns_provider_accepted');return saved;
  } catch { return saveState(c,row,'uncertain','readback_unavailable'); }
}
export async function verifyDnsChange(c,id,body={}) {
  requireKeys(body,['request_id','confirm']); if(body.request_id)requireRequestId(body.request_id);
  await c.authorize(false); let row=await loadDnsChange(c,id);
  const connection=await connectionForChange(c,row),api=await provider(c,connection);
  if(['applying','rolling_back'].includes(row.status)&&Date.now()-Date.parse(row.operation_started_at)<30000)err('action_in_progress');
  if(['applying','uncertain'].includes(row.status)){
    const records=await api.list(row.zone_id,row.record_name),found=expectedRecord(row,records);
    if(!found)return row;
    await c.authorize(false);
    row=await saveState(c,row,'provider_accepted',null,{postimage:stableJson(records),recordId:found.id,appliedAt:iso()});
    await noteCase(c,row,'dns_provider_accepted');
  }
  if(['rolling_back','rollback_uncertain'].includes(row.status)){
    const records=await api.list(row.zone_id,row.record_name);
    await c.authorize(false);
    if(rollbackMatches(row,records))return saveState(c,row,'rolled_back',null,{rolledBackAt:iso()});
    return row;
  }
  if(!APPLIED.includes(row.status))err('change_not_applicable');
  const current=await api.list(row.zone_id,row.record_name);
  if(stableJson(current)!==row.postimage_json)return saveState(c,row,'conflict','record_drift');
  const observed=await observeDnsTxt(row.record_name,c.dnsOptions),desired=parse(row.desired_json);
  const related=observed.values.filter(content=>protocolRecord(row.action_id,{type:'TXT',content}));
  const matches=observed.state==='observed'&&related.length===1&&related[0]===normalizeDnsTxtValue(desired.content);
  const verification={state:matches?'observed':observed.state==='unavailable'?'unavailable':'pending',checked_at:observed.checked_at,reason:matches?null:observed.reason||'dns_not_yet_matching'};
  await c.authorize(false);
  await c.db.prepare('UPDATE dns_provider_changes SET status=?,verification_json=?,verified_at=? WHERE id=? AND workspace_id=? AND domain_id=? AND status=?')
    .bind(matches?'dns_verified':'provider_accepted',JSON.stringify(verification),matches?iso():null,id,c.workspaceId,c.domainId,row.status).run();
  row=await loadDnsChange(c,id);if(matches)await noteCase(c,row,'dns_observed');return row;
}
function rollbackMatches(row,records){
  const before=parse(row.before_json),desired=parse(row.desired_json);
  if(!desired.id)return stableJson(records)===stableJson(before);
  const original=before.find(record=>record.id===desired.id),restored=records.find(record=>record.id===desired.id);
  if(!restored||!original)return false;
  const withoutTimes=record=>Object.fromEntries(Object.entries(record).filter(([key])=>!['modified_on','comment_modified_on','tags_modified_on'].includes(key)));
  // Restoring an absent comment through Cloudflare uses an empty string.
  const normalized=record=>({...withoutTimes(record),comment:record.comment||''});
  return stableJson(records.filter(record=>record.id!==desired.id))===stableJson(before.filter(record=>record.id!==desired.id))&&stableJson(normalized(restored))===stableJson(normalized(original));
}
export async function rollbackDnsChange(c,id,body){
  requireKeys(body,['request_id','confirm']);requireRequestId(body.request_id);if(body.confirm!==true)err('confirmation_required',400);
  await c.authorize(false);let row=await loadDnsChange(c,id);
  if(row.rollback_request_id){if(row.rollback_request_id!==body.request_id)err('request_conflict');return row;}
  if(!APPLIED.includes(row.status)||!row.postimage_json)err('rollback_unavailable');
  const connection=await connectionForChange(c,row),api=await provider(c,connection),current=await api.list(row.zone_id,row.record_name);
  if(stableJson(current)!==row.postimage_json)return saveState(c,row,'conflict','record_drift');
  await c.authorize(false);
  try{
    const result=await c.db.prepare("UPDATE dns_provider_changes SET status='rolling_back',rollback_request_id=?,operation_by=?,operation_started_at=?,verified_at=NULL,verification_json='{\"state\":\"not_checked\",\"checked_at\":null,\"reason\":\"rollback_pending\"}' WHERE id=? AND workspace_id=? AND domain_id=? AND status=?")
      .bind(body.request_id,c.userId,iso(),id,c.workspaceId,c.domainId,row.status).run();
    if(result.meta?.changes!==1)err('action_in_progress');
  }catch(error){if(error instanceof DnsActionError)throw error;err('action_in_progress');}
  row=await loadDnsChange(c,id);
  try{
    await c.authorize(false);await connectionForChange(c,row);const desired=parse(row.desired_json);
    const latest=await api.list(row.zone_id,row.record_name);
    if(stableJson(latest)!==row.postimage_json)return saveState(c,row,'conflict','record_drift');
    await c.authorize(false);
    if(desired.id){const original=parse(row.before_json).find(record=>record.id===desired.id);await api.update(row.zone_id,desired.id,{content:original.content,comment:original.comment||''});}
    else await api.remove(row.zone_id,row.provider_record_id);
    const records=await api.list(row.zone_id,row.record_name);
    if(!rollbackMatches(row,records))return saveState(c,row,'rollback_uncertain','readback_mismatch');
    await c.authorize(false);
    const saved=await saveState(c,row,'rolled_back',null,{rolledBackAt:iso()});await noteCase(c,saved,'dns_rolled_back');return saved;
  }catch(error){return saveState(c,row,'rollback_uncertain',error.code||'readback_unavailable');}
}
