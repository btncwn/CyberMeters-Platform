import { remoteAccessFingerprint, remoteAccessProgramSource } from './remote-access.js';
import { EXPOSURE_CATALOG_VERSION, EXPOSURE_RULES, RULES_BY_ID, exposurePresentation } from './catalog.js';
import { discoverExposureReferences } from './discovery.js';
import { sha256Text, safeExposureUrl, exposureIdentity, isSafeExposurePath, isRulePathAllowed } from './redaction.js';

function exposureText(response) {
  const b = response?.body;
  return typeof b === 'string' ? b.slice(0, 32768) : b instanceof Uint8Array ? new TextDecoder().decode(b.subarray(0, 32768)) : '';
}
function exposureJson(text) { try { const value = JSON.parse(text); return value && typeof value === 'object' ? value : null; } catch { return null; } }
function exposurePlaceholder(value) {
  return !value || value.length < 8 || /^(?:\*+|x+|null|undefined|true|false|none|redacted|hidden|changeme|password|secret|test|example|sample|dummy)$/i.test(value) || /^(?:your|replace)[_-]/i.test(value) || /(?:\$\{|<[^>]+>|example\.com|placeholder)/i.test(value);
}
function exposureSecrets(text) {
  // Runtime configuration sometimes wraps a secret property as { value: ... }.
  const structured = exposureJson(text);
  if (structured) {
    const queue = [{value: structured, depth: 0}]; let inspected = 0;
    while (queue.length && inspected++ < 500) {
      const {value, depth} = queue.shift(); if (!value || typeof value !== 'object' || depth > 8) continue;
      for (const [key, child] of Object.entries(value).slice(0,100)) {
        if (child && typeof child === 'object') {
          if (typeof child.value === 'string') text += '\n' + key + '=' + child.value;
          queue.push({value:child,depth:depth+1});
        }
      }
    }
  }
  const indicators = [];
  if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\r\n]+[A-Za-z0-9+/=\r\n]{40,}[\s\r\n]+-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(text)) indicators.push('private_key_block');
  const assignments = [...text.matchAll(/["']?([A-Za-z_][A-Za-z0-9_.-]{0,79})["']?\s*[:=]\s*["']?([^\s"'<>;,}]{1,256})/g)].slice(0, 500);
  for (const [,key,value] of assignments) {
    if (exposurePlaceholder(value)) continue;
    const secretName = /(?:password|passwd|client[_-]?secret|secret[_-]?access[_-]?key|private[_-]?key|service[_-]?role[_-]?key|(?:^|[_.-])(?:authToken|access_token|refresh_token|db_pass|app_key))$/i.test(key);
    const expectedPublic = /(?:publishable|anon[_-]?key|public[_-]?key|client[_-]?id|search[_-]?key|measurement[_-]?id)$/i.test(key);
    if (secretName && !expectedPublic && /[A-Za-z]/.test(value) && /[0-9/+=_!@#$%^-]/.test(value)) indicators.push('credential_shaped_assignment');
    if (!expectedPublic && /^(?:sk_live_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})$/.test(value)) indicators.push('provider_secret_shaped_value');
    if (!expectedPublic && /^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:/\s]+:[^@\s]{8,}@/i.test(value)) indicators.push('credential_in_connection_string');
  }
  if (/aws_access_key_id\s*=\s*(?:AKIA|ASIA)[A-Z0-9]{16}/.test(text) && /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}(?:\s|$)/.test(text)) indicators.push('aws_credential_pair');
  // XML/SQL connection strings have their own well-defined password field.
  if (/(?:connectionString|jdbc:|connectionstrings)/i.test(text) && /(?:Password|Pwd)\s*=\s*(?!\*|changeme|password|example|\$\{)[A-Za-z0-9!@#$%^&*_-]{8,}/i.test(text)) indicators.push('credential_in_connection_string');
  return [...new Set(indicators)].sort();
}
function exposureLoginForm(text) {
  return /<form\b/i.test(text) && /<input\b[^>]*type\s*=\s*["']password["']/i.test(text);
}
function exposureDocumentedExample(json) {
  return Boolean(json && !Array.isArray(json) && (Object.keys(json).some(k=>/^(?:example|examples|sample|samples|sampleConfig|exampleConfig|\$schema)$/i.test(k)) || json.schema && (json.title || json.description)));
}
function exposureIsHtml(text) { return /<(?:!doctype|html|head|body|form|pre|code)\b/i.test(text); }
function exposureExample(text) { return /<(?:pre|code)\b/i.test(text) || /(?:^|\n)\s*```/.test(text) || /(?:this is (?:an? )?(?:example|sample)|example configuration|for demonstration only|documentation example)/i.test(text); }
function exposureBlocked(response, text) {
  if ([401,403,407,429].includes(Number(response?.status))) return true;
  return exposureIsHtml(text) && /(?:cf-chl-|cf-turnstile|g-recaptcha|h-captcha|captcha|verify (?:that )?you are human|checking your browser|access denied|request blocked)/i.test(text);
}
function exposureShape(text) {
  const tags = (text.match(/<\/?[a-z][a-z0-9]*/gi) || []).map(s=>s.toLowerCase()).join('|');
  const title = (text.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || '').toLowerCase().replace(/[a-f0-9]{8,}|\d+/g, '#');
  const normalized = text.toLowerCase().replace(/https?:\/\/[^\s<>"']+|\/[a-z0-9_./%-]+/g, '/path').replace(/[a-f0-9]{8,}|\d+/g, '#').replace(/\s+/g,' ').trim();
  const words = new Set(normalized.replace(/<[^>]*>/g,' ').match(/[a-z]{3,}/g) || []);
  return {tags, title, normalized, words};
}
function exposureLooksLikeControl(text, controls) {
  const shape = exposureShape(text);
  for (const c of controls) {
    const other = exposureShape(exposureText(c));
    if (shape.normalized && shape.normalized === other.normalized) return true;
    if (!exposureIsHtml(text) || !shape.tags || shape.tags.split('|').length < 5 || shape.tags !== other.tags || shape.title !== other.title) continue;
    const union = new Set([...shape.words, ...other.words]);
    const intersection = [...shape.words].filter(w=>other.words.has(w)).length;
    if (union.size && intersection / union.size >= 0.72) return true;
  }
  return false;
}
function exposureKnownData(rule, text, json, bytes) {
  const secretIndicators = exposureSecrets(text);
  const yes = (indicators, severity, observation, state = 'finding') => ({indicators, severity, observation, state});
  const configText = !exposureIsHtml(text) && !exposureExample(text);
  switch (rule.id) {
    case 'env-config': {
      const pairs = text.match(/^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*[^\r\n]+$/gm) || [];
      if (configText && pairs.length >= 2 && secretIndicators.length) return yes(['environment_assignment_structure', ...secretIndicators], 'high');
      break;
    }
    case 'application-config': {
      const structure = json && !Array.isArray(json) || /(?:^|\n)\s*(?:services|database|production|spring):\s*(?:\n|\{)/.test(text) || /<configuration[\s>][\s\S]*<\/(?:configuration)>/.test(text) || /(?:server\s*\{|<VirtualHost\b)[\s\S]*(?:listen\s+\d+|ServerName\s+)/.test(text) || /(?:^|\n)(?:spring\.|database\.)[^=]+=/.test(text) || /<\?php[\s\S]*(?:define\s*\(|\$\w+\s*=)/.test(text);
      const internal = /(?:proxy_pass|upstream|ProxyPass)\s+(?:https?:\/\/)?(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(text);
      if (configText && structure && (secretIndicators.length || internal)) return yes(['configuration_structure', ...secretIndicators, ...(internal ? ['private_upstream_configuration'] : [])], secretIndicators.length ? 'high' : 'low');
      break;
    }
    case 'package-auth': {
      const auth = text.match(/(?:^|\n)(?:\/\/[^\s]+:)?_(?:authToken|auth)\s*=\s*([^\r\n]+)/);
      const composer = json && ['github-oauth','gitlab-token','http-basic'].some(k => json[k] && typeof json[k] === 'object' && Object.values(json[k]).some(v => typeof v === 'string' ? !exposurePlaceholder(v) : v && !exposurePlaceholder(String(v.password || ''))));
      const hash = /^(?:[^\s:]{1,64}):(?:\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}|\{SHA\}[A-Za-z0-9+/]{27}=)\s*$/m.test(text);
      if (configText && (auth && !exposurePlaceholder(auth[1].trim()) || composer || hash)) return yes([hash ? 'password_hash_record' : 'package_auth_record'], 'high');
      break;
    }
    case 'git-metadata':
      if (configText && /(?:^|\n)\[core\]\s*\n/.test(text) && /(?:repositoryformatversion|bare)\s*=\s*(?:\d|true|false)/.test(text) || /^ref: refs\/(?:heads|tags)\/[^\s]+\s*$/.test(text) || /^DIRC\u0000\u0000\u0000[\u0002-\u0004][\s\S]{4}/.test(text)) return yes(['git_file_structure', ...secretIndicators], secretIndicators.length ? 'high' : 'medium');
      break;
    case 'svn-metadata':
      if (configText && (/^\d{1,2}\r?\n\r?\ndir\r?\n\d+\r?\nhttps?:\/\//.test(text) || text.startsWith('SQLite format 3\0') && /(?:WCROOT|REPOSITORY)/.test(text) && /(?:NODES|ACTUAL_NODE)/.test(text))) return yes(['svn_working_copy_structure'], 'medium');
      break;
    case 'project-metadata': {
      if (text.startsWith('\0\0\0\x01Bud1') && text.length >= 32) return yes(['ds_store_header'], 'low');
      if (configText && json && !Array.isArray(json)) {
        if (json.name && (json.dependencies || json.require || json.autoload) || Array.isArray(json.packages)) return yes(['package_manifest_structure'], 'info', 'A public package manifest was observed; this does not establish sensitive content.', 'observed');
        if (Array.isArray(json.configurations) && json.configurations.some(c=>c && c.type && c.request) || Array.isArray(json.tasks) && json.tasks.some(t=>t && t.command) || Object.keys(json).some(k=>/^(?:editor\.|files\.|python\.|sqltools\.)/.test(k))) return yes(['editor_project_structure', ...secretIndicators], secretIndicators.length ? 'high' : 'low');
      }
      if (configText && /<project\s+version=["']\d+["'][\s\S]*<component\s+name=["'][^"']+["'][\s\S]*<\/project>/.test(text)) return yes(['ide_project_structure', ...secretIndicators], secretIndicators.length ? 'high' : 'low');
      break;
    }
    case 'database-export': {
      const create = /CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"\w.]+\s*\([\s\S]*?\b(?:int|varchar|text|timestamp|decimal|serial)\b/i.test(text);
      const insert = /INSERT INTO\s+[`"\w.]+(?:\s*\([^)]*\))?\s+VALUES\s*\(/i.test(text);
      if (configText && (create && insert || /(?:MySQL dump|PostgreSQL database dump)/.test(text) && (create || insert))) return yes(['sql_export_structure'], 'high');
      break;
    }
    case 'backup-archive': {
      const b = bytes instanceof Uint8Array ? Array.from(bytes.subarray(0, 512), n=>String.fromCharCode(n)).join('') : text;
      const zip = b.startsWith('PK\x03\x04') && b.length >= 30 && b.charCodeAt(4) <= 63;
      const gzip = b.charCodeAt(0) === 31 && b.charCodeAt(1) === 139 && b.charCodeAt(2) === 8 && b.length >= 18;
      const tar = b.length >= 512 && b.slice(257,262) === 'ustar';
      const tape = b.startsWith('TAPE') && b.length >= 64 && /\x00/.test(b.slice(4,64));
      if (zip || gzip || tar || tape) return yes([zip ? 'zip_header' : gzip ? 'gzip_header' : tar ? 'tar_header' : 'tape_archive_header', 'archive_contents_not_examined'], 'low');
      break;
    }
    case 'directory-listing':
      if (/<(?:title|h1)>\s*Index of [^<]+<\/(?:title|h1)>/i.test(text) && /<(?:table|pre)\b/i.test(text) && /href=["'][^"']+\.(?:zip|sql|bak|tgz|tar\.gz)["']/i.test(text)) return yes(['directory_index_structure', 'backup_filename_link'], 'low');
      break;
    case 'backup-source':
      if (configText && (/<\?php[\s\S]*(?:define\s*\(|\$[a-z_]+\s*=|function\s+[a-z_]+)/i.test(text) || /<%@\s*(?:Page|page)\s+[\s\S]*(?:Language|import)\s*=/i.test(text))) return yes(['server_source_syntax', ...secretIndicators], secretIndicators.length ? 'high' : 'medium');
      break;
    case 'runtime-debug': {
      const php = /PHP Version\s*\d/i.test(text) && /(?:<table|<tr)/i.test(text) && /(?:Loaded Configuration File|SERVER_SOFTWARE|DOCUMENT_ROOT|PHP Extension Build)/.test(text);
      const stack = /(?:Error|Exception|Traceback)/.test(text) && (text.match(/(?:at [^\r\n<>]{1,160}\([^\r\n<>]{1,160}:\d+:\d+\)|File "\/[^"\r\n]+", line \d+|#[0-9]+\s+\/[^\r\n]+)/g)||[]).length >= 2;
      const status = /(?:Server Version:|Apache Server Status)/.test(text) && /(?:Total accesses|Total Accesses|BusyWorkers)/.test(text) && /(?:Server uptime|IdleWorkers|Uptime)/.test(text);
      const debug = json && (Array.isArray(json) ? json : [json]).some(v=>v && typeof v === 'object' && v.__meta && (v.queries || v.exceptions || v.messages));
      const elmah = /Error Log for/i.test(text) && /<table/i.test(text) && /(?:System\.[A-Za-z]+Exception|Exception Type)/.test(text) && /\d{4}-\d{2}-\d{2}/.test(text);
      if (!/(?:this is (?:an? )?(?:example|sample)|for demonstration only|documentation example)/i.test(text) && (php || stack || status || debug || elmah)) return yes([php ? 'php_runtime_table' : stack ? 'runtime_stack_frames' : status ? 'server_workload_fields' : debug ? 'debug_record_structure' : 'error_log_table', ...secretIndicators], secretIndicators.length ? 'high' : 'medium');
      break;
    }
    case 'exposed-log': {
      const access = text.match(/^(?:[\da-f:.]+)\s+\S+\s+\S+\s+\[\d{2}\/[A-Za-z]{3}\/\d{4}:[^\]]+\]\s+"(?:GET|POST|HEAD|PUT)\s+[^\r\n"]+\s+HTTP\/\d(?:\.\d)?"\s+\d{3}\s+\d+/gm) || [];
      const runtime = text.match(/^\[?\d{4}-\d{2}-\d{2}[T ][^\r\n]{0,35}\]?\s+(?:[a-z]+\.)?(?:ERROR|WARN|INFO|DEBUG|CRITICAL)\b[^\r\n]{10,}/gmi) || [];
      if (configText && access.length + runtime.length >= 2) return yes(['multiple_operational_log_records', ...secretIndicators], secretIndicators.length ? 'high' : 'medium');
      break;
    }
    case 'admin-interface':
      if (/<form\b/i.test(text) && /<input\b[^>]*type\s*=\s*["']password["']/i.test(text) && /(?:administrat|admin login|phpmyadmin|jenkins|grafana|tomcat|management console|wordpress)/i.test(text)) return yes(['management_login_form', 'no_auth_bypass_tested'], 'info', rule.risk, 'observed');
      break;
    case 'admin-data': {
      const jenkins = json && Array.isArray(json.jobs) && json.jobs.some(j => j && typeof j.name === 'string' && typeof j.color === 'string') && typeof json.nodeDescription === 'string' && typeof json.numExecutors === 'number';
      const grafana = Array.isArray(json) && json.some(d=>d && d.type === 'dash-db' && typeof d.uid === 'string' && typeof d.title === 'string' && typeof d.url === 'string');
      const jolokia = json && json.status === 200 && json.request?.type === 'version' && json.value?.agent && json.value?.protocol && json.value?.config;
      if (jenkins || grafana || jolokia) return yes([jenkins ? 'jenkins_job_records' : grafana ? 'grafana_dashboard_records' : 'jolokia_runtime_configuration', 'unauthenticated_read', 'no_operation_attempted'], 'medium');
      break;
    }
    case 'prometheus-metrics': {
      const declarations = [...text.matchAll(/^# TYPE ([A-Za-z_:][\w:]*) (?:counter|gauge|histogram|summary|untyped)\s*$/gm)];
      const names = declarations.map(m=>m[1]);
      const numeric = text.split('\n').filter(l=>/^[A-Za-z_:][\w:]*(?:\{[^\r\n]*\})?\s+[-+]?(?:\d+(?:\.\d+)?(?:e[-+]?\d+)?|Inf|NaN)(?:\s+\d+)?$/i.test(l));
      if (configText && names.some(n=>numeric.some(l=>l.startsWith(n))) && names.some(n=>/^(?:process_|http_|node_|jvm_|go_|app_)/.test(n))) return yes(['prometheus_type_and_sample', 'operational_metric'], 'low');
      break;
    }
    case 'actuator-env': {
      const sources = json && Array.isArray(json.propertySources) && json.propertySources.some(p=>p && typeof p.name === 'string' && p.properties && typeof p.properties === 'object');
      const beans = json && json.contexts && Object.values(json.contexts).some(c=>c && c.beans && Object.values(c.beans).some(b=>b && b.prefix && b.properties));
      if (sources || beans) return yes(['runtime_property_structure', ...secretIndicators], secretIndicators.length ? 'high' : 'low');
      break;
    }
    case 'client-secret':
      if (!exposureExample(text) && secretIndicators.length && (/(?:\b(?:const|var|let)\s+|module\.exports|window\.|["']\w+["']\s*:)/.test(text) || /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text))) return yes(['client_content_structure', ...secretIndicators], 'high');
      break;
    case 'source-map': {
      if (json?.version === 3 && Array.isArray(json.sources) && json.sources.every(s=>typeof s === 'string') && typeof json.mappings === 'string' && /^[A-Za-z0-9+/;,]*$/.test(json.mappings) && json.sources.length) {
        const content = Array.isArray(json.sourcesContent) && json.sourcesContent.filter(s=>typeof s === 'string' && s.trim().length > 12);
        if (content?.length) { const secrets = exposureSecrets(content.join('\n')); return yes(['source_map_v3', 'embedded_original_source', ...secrets], secrets.length ? 'high' : 'low'); }
        return yes(['source_map_v3', 'no_embedded_source'], 'info', 'A source map with path metadata was observed; original source content was not present.', 'observed');
      }
      break;
    }
    case 'api-schema':
      if (json && (/^3\.[01]\.\d+$/.test(json.openapi) || json.swagger === '2.0') && json.info && typeof json.info.title === 'string' && json.paths && !Array.isArray(json.paths) && Object.keys(json.paths).some(p=>p.startsWith('/'))) return yes(['api_schema_structure', 'discovery_reference_only'], 'info', rule.risk, 'observed');
      break;
    case 'elasticsearch-indices':
      if (configText && text.split('\n').some(l=>/^(?:green|yellow|red)\s+(?:open|close)\s+\S+\s+\S+\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d.]+[bkmgtp]+\s+[\d.]+[bkmgtp]+\s*$/i.test(l))) return yes(['elasticsearch_index_table', 'unauthenticated_read', 'no_documents_requested'], 'medium');
      break;
    case 'couchdb-databases':
      if (Array.isArray(json) && json.every(v=>typeof v === 'string') && json.includes('_users') && json.includes('_replicator') && json.some(v=>/^[a-z][a-z0-9_$()+/-]*$/.test(v))) return yes(['couchdb_database_list', 'unauthenticated_read', 'no_documents_requested'], 'medium');
      break;
    case 'ignition-health':
      if (json && !Array.isArray(json) && json.can_execute_commands === true && Object.keys(json).length <= 12) return yes(['debug_component_capability_report', 'no_execution_attempted'], 'medium');
      break;
  }
  return null;
}

export function evaluateExposure({rule, response, controls = []} = {}) {
  rule = typeof rule === 'string' ? RULES_BY_ID[rule] : RULES_BY_ID[rule?.id];
  const result = (state, comparable, reason, extra = {}) => ({state, comparable, reason, finding: null, discoveries: {paths: [], hosts: []}, ...extra});
  if (!rule) return result('not_applicable', false, 'unknown_rule');
  const locallyCapped = response?.truncated === true && ['body_limit','wire_limit','decoded_limit'].includes(response?.error);
  if (!response || response.error && !locallyCapped || response.blocked) return result('uncertain', false, 'transport_or_scope_failure');
  const text = exposureText(response); const status = Number(response.status);
  if (exposureBlocked(response, text)) return result('blocked', false, 'authentication_rate_limit_or_challenge');
  if (!['admin-interface','remote-access-portal'].includes(rule.id) && exposureLoginForm(text)) return result('blocked', false, 'authentication_login_form');
  if (rule.id !== 'api-schema' && exposureDocumentedExample(exposureJson(text))) return result('uncertain', false, 'documentation_example_content');
  if (status >= 500 || status < 200 || status >= 300 && status < 400) return result('uncertain', false, 'server_or_redirect_failure');
  // A real, explicitly named login page may be the site's default answer to
  // every path. That is not a file-disclosure soft404; only this narrow rule
  // observes it, and no authentication request is made.
  if (rule.id === 'remote-access-portal') {
    if (response.truncated || !controls.slice(0,2).every(c=>c&&!c.error&&!c.truncated&&[200,404,410].includes(Number(c.status))&&!exposureBlocked(c,exposureText(c))) || controls.length < 2)
      return result('uncertain', false, 'bounded_read_inconclusive');
    if (controls.some(c=>exposureLoginForm(exposureText(c))) && status!==200) return result('uncertain',false,'negative_controls_unavailable');
    if ([404,410].includes(status)) return result('not_found', true, 'explicit_absence');
    if (status !== 200) return result('uncertain', false, 'unexpected_status');
    const portal = remoteAccessFingerprint(text, response.url);
    if (portal) return result('observed', true, 'observation_only', { portal,
      observation:{ evidence:{indicators:['known_remote_access_login']} } });
    if (exposureLoginForm(text)) return result('blocked', false, 'authentication_login_form');
    if (controls.some(c=>exposureLoginForm(exposureText(c)))) return result('uncertain',false,'negative_controls_unavailable');
  }
  const validControls = controls.length >= 2 && controls.slice(0,2).every(c=>c && !c.error && !c.truncated && [200,404,410].includes(Number(c.status)) && !exposureBlocked(c, exposureText(c)) && !exposureLoginForm(exposureText(c)));
  if (!validControls) return result('uncertain', false, 'negative_controls_unavailable');
  if ([404,410].includes(status)) return result('not_found', true, 'explicit_absence');
  if (![200,206].includes(status)) return result('uncertain', false, 'unexpected_status');
  if (exposureLooksLikeControl(text, controls)) return result('uncertain', false, 'soft_404_or_common_response');
  const refs = discoverExposureReferences({origin: response.url, body: text, headers: response.headers || {}});
  const discoveries = {paths: refs.paths.filter(p=>EXPOSURE_RULES.some(r=>isRulePathAllowed(r,p))).slice(0,32), hosts: refs.discoveredHosts.slice(0,32)};
  const detected = exposureKnownData(rule, text, exposureJson(text), response.bytes);
  if (!detected) return response.truncated || status === 206 ? result('uncertain', false, 'bounded_read_inconclusive') : result('not_found', true, 'required_content_not_observed', {discoveries});
  const evidence = { indicators: detected.indicators, catalogVersion: EXPOSURE_CATALOG_VERSION, ruleVersion: rule.version, negativeControls: 2, contentRetained: false, credentialValidityTested: false, operationAttempted: false, partialRead: Boolean(response.truncated || status === 206) };
  const presentation = exposurePresentation(rule.id, detected.indicators);
  const details = { ruleId: rule.id, family: rule.family, severity: detected.severity, title: presentation.title, observation: detected.observation || presentation.observation, evidence, remediation: [...rule.remediation], safeUrl: safeExposureUrl(response.url, EXPOSURE_RULES), identity: exposureIdentity(rule.id, response.url) };
  if (detected.state === 'observed') return result('observed', true, 'observation_only', { observation: details, discoveries });
  return result('finding', true, 'verified_content_indicators', { finding: details, discoveries });
}

// The trusted collector embeds only these reviewed functions and immutable catalog data.
// No response text, discovered string or customer-provided program is interpolated here.
export function exposureEvaluatorProgramSource() {
  return remoteAccessProgramSource() + `const EXPOSURE_CATALOG_VERSION=${JSON.stringify(EXPOSURE_CATALOG_VERSION)};\nconst EXPOSURE_RULES=${JSON.stringify(EXPOSURE_RULES)};\nconst RULES_BY_ID=Object.fromEntries(EXPOSURE_RULES.map(r=>[r.id,r]));\n` + [discoverExposureReferences, exposurePresentation, sha256Text, safeExposureUrl, exposureIdentity, isSafeExposurePath, isRulePathAllowed, exposureText, exposureJson, exposurePlaceholder, exposureSecrets, exposureLoginForm, exposureDocumentedExample, exposureIsHtml, exposureExample, exposureBlocked, exposureShape, exposureLooksLikeControl, exposureKnownData, evaluateExposure].map(fn=>fn.toString()).join('\n');
}
export { isRulePathAllowed, isSafeExposurePath } from './redaction.js';
