import { REMOTE_ACCESS_PATHS, REMOTE_ACCESS_SENTENCES } from './remote-access.js';
// Local, immutable rules. No downloaded templates, executable customer input, or callbacks.
export const EXPOSURE_CATALOG_VERSION = '2026.10.24.2';
export const EXPOSURE_FAMILIES = Object.freeze(['configuration', 'development', 'backups', 'debug', 'administration', 'diagnostics', 'javascript', 'api_references', 'product_misconfiguration']);
const RULE_PRESENTATION = {
  'remote-access-portal': ['Remote-access portal exposed', 'medium', REMOTE_ACCESS_SENTENCES.hidden],
  'env-config': ['Sensitive environment configuration is public', 'high', 'Credential-shaped values are readable without authentication; validity has not been tested.'],
  'application-config': ['Sensitive application configuration is public', 'high', 'Configuration includes secret-shaped values or internal operational settings.'],
  'package-auth': ['Package authentication material is public', 'high', 'An authentication token or password-hash record can be read without authentication.'],
  'git-metadata': ['Repository metadata is public', 'medium', 'Repository configuration, refs or index metadata reveal development structure.'],
  'svn-metadata': ['Subversion working-copy metadata is public', 'medium', 'Working-copy metadata discloses repository or source information.'],
  'project-metadata': ['Development project metadata is public', 'low', 'Project configuration reveals development or deployment settings.'],
  'database-export': ['Database export content is public', 'high', 'Database table definitions or exported records can be read without authentication.'],
  'backup-archive': ['An archive header is publicly readable', 'low', 'A backup/archive container is accessible; its contents and sensitivity were not inspected.'],
  'directory-listing': ['A backup directory can be listed', 'low', 'The listing reveals backup/export filenames; file contents were not read by this check.'],
  'backup-source': ['Server-side source is publicly readable', 'medium', 'Source statements reveal application implementation; this is not code execution.'],
  'runtime-debug': ['Runtime diagnostic details are public', 'medium', 'Runtime paths, configuration or workload details are readable without authentication.'],
  'exposed-log': ['Operational log records are public', 'medium', 'Structured request/error records disclose operating details and may contain personal information.'],
  'admin-interface': ['A management login screen is public', 'info', 'A login entry point was observed; no authentication bypass or operation was tested.'],
  'admin-data': ['Management data is readable without authentication', 'medium', 'A known management response exposes job, dashboard or runtime records without credentials.'],
  'prometheus-metrics': ['Operational metrics are public', 'low', 'Operational metric samples are readable; metrics are not automatically high-risk.'],
  'actuator-env': ['Application runtime configuration is public', 'low', 'Runtime property metadata is readable; masked values are not treated as exposed secrets.'],
  'client-secret': ['Secret-shaped material is present in client content', 'high', 'Private or privileged credential-shaped content is public; its validity was not tested.'],
  'source-map': ['Original source is embedded in a public source map', 'low', 'Original source is readable through a valid source map; exposure alone does not establish a vulnerability.'],
  'api-schema': ['Public API documentation was observed', 'info', 'API documentation supplies discovery candidates and is not itself a vulnerability.'],
  'elasticsearch-indices': ['Search index metadata is public', 'medium', 'Index names, shard and document counts are readable without authentication; document content was not requested.'],
  'couchdb-databases': ['Database names are public', 'medium', 'A CouchDB-compatible database list can be read without credentials; no database documents or write action were requested.'],
  'ignition-health': ['A debug component reports command capability', 'medium', 'The component explicitly reports command capability; no command or exploit was attempted.'],
};
const rule = (id, family, paths, positive, remediation, options = {}) => Object.freeze({
  title: RULE_PRESENTATION[id][0], severity: RULE_PRESENTATION[id][1], risk: RULE_PRESENTATION[id][2],
  id, version: 1, active: true, family, paths: Object.freeze(paths),
  applicability: 'HTTP(S) origin with current explicit scope authorization; GET-only bounded content reads.',
  evidence: Object.freeze({ positive, negative: 'Two random-path controls; format and sensitivity requirements; generic HTML, examples and placeholders do not confirm exposure.', uncertain: 'WAF, CAPTCHA, auth challenge, rate limit, transport error, incomplete body or missing negative controls.' }),
  maxCost: Object.freeze({ requests: 3, redirects: 2, retries: 0, bytes: 32768, timeoutMs: 15000 }),
  remediation: Object.freeze(remediation), ...options,
});
const restrict = ['Remove this file or endpoint from the public web root, or require authentication and restrict network access.', 'Review deployment exclusions and access logs, then repeat this exact check.'];
const rotate = ['Revoke and replace the exposed credential through its owner; this check does not test whether it remains valid.', ...restrict];
export const EXPOSURE_RULES = Object.freeze([
  rule('remote-access-portal', 'administration', REMOTE_ACCESS_PATHS, 'A known portal title and same-origin login form; only an explicit server-version label may support an advisory match.', ['Restrict public portal access to authorised networks and review the server version with its administrator.', 'Apply supported security updates and repeat this exact URL check. Hiding the version or browser login page is not proof that the remote service was removed or updated.'], {
    introducedAt: '2026-10-24',
    version: 2,
    verificationEvidence: 'A later bounded HTTPS check of this exact original URL must state a server version in the curated fixed range. A hidden version, disabled browser login, 404, blocked response or missing evidence cannot prove that the remote service was removed or updated.',
  }),
  rule('env-config', 'configuration', ['/.env', '/.env.local', '/.env.production', '/.env.prod', '/.env.dev', '/.env.stage', '/.env.bak', '/.env.old', '/.env.backup', '/.env.save', '/.env.example', '/.env_sample', '/api/.env', '/config/.env', '/sendgrid.env', '/.aws/credentials'], 'Multiple dotenv/INI assignments and at least one non-placeholder credential-shaped value.', rotate),
  rule('application-config', 'configuration', ['/config.json', '/appsettings.json', '/appsettings.Production.json', '/config.yml', '/config.yaml', '/application.yml', '/application.properties', '/database.yml', '/docker-compose.yml', '/docker-compose.prod.yml', '/web.config', '/nginx.conf', '/apache.conf', '/wp-config.php.bak'], 'Structured application/server configuration plus a credential or private operational configuration indicator.', ['If credential-shaped values were exposed, revoke and replace them through their owner; validity has not been tested.', ...restrict]),
  rule('package-auth', 'configuration', ['/.npmrc', '/.yarnrc', '/auth.json', '/.composer-auth.json', '/.composer/auth.json', '/.htpasswd'], 'Package-manager auth assignment/JSON or a complete supported password-hash record.', rotate),
  rule('git-metadata', 'development', ['/.git/config', '/.git/HEAD', '/.git/index'], 'Git configuration plus repository directives; HEAD ref syntax; or index signature with supported version.', restrict),
  rule('svn-metadata', 'development', ['/.svn/entries', '/.svn/wc.db'], 'SVN entries format with repository metadata or SQLite header plus SVN schema names.', restrict),
  rule('project-metadata', 'development', ['/.vscode/settings.json', '/.vscode/launch.json', '/.vscode/tasks.json', '/.idea/workspace.xml', '/.idea/deployment.xml', '/.DS_Store', '/package.json', '/composer.json', '/composer.lock'], 'Parseable development metadata with actual settings/build/source information; public package manifests stay observations.', restrict),
  rule('database-export', 'backups', ['/backup.sql', '/database.sql', '/db.sql', '/dump.sql', '/mysql.sql', '/data.sql', '/db_backup.sql', '/backups/database.sql', '/wp-content/uploads/dump.sql'], 'Database export header plus SQL table definition/data grammar, or multiple consistent SQL statements.', restrict),
  rule('backup-archive', 'backups', ['/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip', '/database.bak', '/backup.bak', '/backup.tar', '/backups/backup.zip'], 'Archive/container signature plus header structure. Claim is limited to an accessible archive header; contents are unexamined.', restrict),
  rule('directory-listing', 'backups', ['/backup/', '/backups/', '/old/', '/archive/', '/exports/', '/php/backup/'], 'Directory index title, listing structure and links to backup/export files.', restrict),
  rule('backup-source', 'backups', ['/index.php.bak', '/index.php~', '/config.php.old', '/wp-config.php~', '/web.config.bak'], 'Server-side source syntax plus configuration/source statements, with secret-shaped values reported separately.', restrict),
  rule('runtime-debug', 'debug', ['/phpinfo.php', '/info.php', '/php_info.php', '/_profiler/phpinfo', '/server-status', '/_debugbar/open', '/elmah.axd', '/elmah'], 'Runtime table, multiple stack frames with internal source paths, real debug records, or server workload fields.', restrict),
  rule('exposed-log', 'debug', ['/access.log', '/error.log', '/debug.log', '/development.log', '/log/access.log', '/logs/access.log', '/logs/development.log', '/storage/logs/laravel.log'], 'Multiple complete timestamped HTTP/server log records with operational content.', restrict),
  rule('admin-interface', 'administration', ['/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/', '/manager/html', '/grafana/login', '/jenkins/login', '/login', '/dashboard/'], 'Password login form and administration/product context. Login screen is an observation, never auth bypass.', ['Confirm that this management entry point is intended to be public; require strong authentication and restrict it where practical.'], { observationOnly: true }),
  rule('admin-data', 'administration', ['/jenkins/api/json', '/api/json', '/api/search', '/jolokia/version'], 'Known management response schema with jobs/dashboard/runtime data available without credentials; no operation attempted.', restrict),
  rule('prometheus-metrics', 'diagnostics', ['/metrics', '/actuator/prometheus', '/prometheus/metrics'], 'Prometheus TYPE/HELP declarations plus matching numeric samples for operational metrics.', ['Limit public access to operational metrics if they are not intentionally public.', 'Review labels for secrets and personal data, then repeat this check.']),
  rule('actuator-env', 'diagnostics', ['/actuator/env', '/env', '/actuator/configprops'], 'Structured Spring property sources or configuration beans; masked values are distinguished from exposed credentials.', restrict),
  rule('client-secret', 'javascript', ['/', '/env.js', '/env-config.js', '/__ENV.js', '/config.js', '/config/env.js', '/config/runtime-env.js', '/env.production.js', '/env.development.js'], 'JavaScript/JSON/configuration context and private key or specific secret-valued assignment. Publishable/anonymous/client keys alone are not findings.', rotate),
  rule('source-map', 'javascript', ['/main.js.map', '/app.js.map', '/bundle.js.map'], 'Source Map v3 with sources, mappings and non-empty sourcesContent. Metadata-only maps stay observations.', ['Remove source maps with embedded original source from public deployments unless intentional.', 'Review embedded source for secrets and rotate any exposed credentials, then repeat this check.']),
  rule('api-schema', 'api_references', ['/openapi.json', '/swagger.json', '/api-docs', '/v3/api-docs', '/swagger/v1/swagger.json', '/api/openapi.json'], 'Parseable OpenAPI/Swagger version and paths object; supplies safe read-only endpoint candidates, not a vulnerability.', ['Confirm that published API documentation and its endpoint references are intended to be public.'], { observationOnly: true }),
  rule('elasticsearch-indices', 'product_misconfiguration', ['/_cat/indices'], 'Elasticsearch index table with health, state, index, shard and document-count columns. No CVE inferred.', restrict),
  rule('couchdb-databases', 'product_misconfiguration', ['/_all_dbs'], 'JSON database list including CouchDB system database names and a non-system database. No write tested.', restrict),
  rule('ignition-health', 'product_misconfiguration', ['/_ignition/health-check'], 'Ignition JSON explicitly reports can_execute_commands true. This is a configuration report, not proof of code execution.', ['Disable debug mode and restrict the Ignition debug component on public deployments.', 'Upgrade and configure the observed framework as recommended by its maintainer, then repeat this check.']),
]);
export const RULES_BY_ID = Object.freeze(Object.fromEntries(EXPOSURE_RULES.map(r => [r.id, r])));

export function exposurePresentation(ruleId, indicators = []) {
  const r = RULES_BY_ID[ruleId]; if (!r) return null;
  const secret = indicators.some(i => ['private_key_block','credential_shaped_assignment','provider_secret_shaped_value','credential_in_connection_string','aws_credential_pair','package_auth_record','password_hash_record'].includes(i));
  let severity = secret ? 'high' : r.severity, observation = r.risk, title = r.title, observationOnly = Boolean(r.observationOnly);
  if (ruleId === 'application-config' && !secret) { severity = 'low'; observation = 'Configuration exposes private upstream routing; no credential-shaped value was observed.'; }
  if (indicators.includes('package_manifest_structure')) { severity = 'info'; observationOnly = true; title = 'Public package manifest observed'; observation = 'A public package manifest was observed; this does not establish sensitive content.'; }
  if (indicators.includes('no_embedded_source')) { severity = 'info'; observationOnly = true; title = 'Source map metadata observed'; observation = 'A source map with path metadata was observed; original source content was not present.'; }
  if (secret && ['actuator-env','source-map','project-metadata','runtime-debug','exposed-log','backup-source','git-metadata'].includes(ruleId)) observation = 'The observed structured content includes a credential-shaped value or private key. Credential validity was not tested.';
  return {title, observation, risk: observation, severity, observationOnly};
}

export const EXPOSURE_INDICATORS = Object.freeze([
  'known_remote_access_login',
  'private_key_block','credential_shaped_assignment','provider_secret_shaped_value','credential_in_connection_string','aws_credential_pair',
  'environment_assignment_structure','configuration_structure','private_upstream_configuration','password_hash_record','package_auth_record',
  'git_file_structure','svn_working_copy_structure','ds_store_header','package_manifest_structure','editor_project_structure','ide_project_structure',
  'sql_export_structure','zip_header','gzip_header','tar_header','tape_archive_header','archive_contents_not_examined','directory_index_structure','backup_filename_link',
  'server_source_syntax','php_runtime_table','runtime_stack_frames','server_workload_fields','debug_record_structure','error_log_table',
  'multiple_operational_log_records','management_login_form','no_auth_bypass_tested','jenkins_job_records','grafana_dashboard_records','jolokia_runtime_configuration',
  'unauthenticated_read','no_operation_attempted','prometheus_type_and_sample','operational_metric','runtime_property_structure','client_content_structure',
  'source_map_v3','embedded_original_source','no_embedded_source','api_schema_structure','discovery_reference_only','elasticsearch_index_table','no_documents_requested',
  'couchdb_database_list','debug_component_capability_report','no_execution_attempted',
]);
