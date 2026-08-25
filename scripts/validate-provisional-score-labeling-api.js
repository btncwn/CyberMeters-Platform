#!/usr/bin/env node

// Real route contract for GET /api/workspaces/:id/domains. Uses an in-memory
// SQLite/D1 adapter plus stored report fixtures; no network or production access.
import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const { workspacesCoreRoutes } = await import(pathToFileURL(path.join(
  root,
  'workers/scan-api/src/routes/workspaces-core.js',
)).href)

let passed = 0
let failed = 0
function ok(name, condition, detail = '') {
  if (condition) {
    passed += 1
    console.log(`PASS ${name}`)
  } else {
    failed += 1
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ''}`)
  }
}
function eq(name, actual, expected) {
  ok(name, Object.is(actual, expected), `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
}

const db = new DatabaseSync(':memory:')
db.exec(`
  CREATE TABLE workspaces (
    id TEXT PRIMARY KEY, name TEXT, created_at TEXT, deleted_at TEXT
  );
  CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
  CREATE TABLE workspace_domains (
    workspace_id TEXT, domain_id TEXT,
    verification_status TEXT, verification_method TEXT,
    verification_token TEXT, verified_at TEXT,
    verification_initiated_at TEXT
  );
  CREATE TABLE scans (
    id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, domain TEXT,
    status TEXT, score INTEGER, rating TEXT, scan_quality TEXT, created_at TEXT
  );
`)
db.exec(`
  INSERT INTO workspaces VALUES
    ('ws-founder','Founder workspace','2026-08-01 00:00:00',NULL),
    ('ws-foreign','Foreign workspace','2026-08-01 00:00:00',NULL),
    ('ws-deleted','Deleted workspace','2026-08-01 00:00:00','2026-08-12 00:00:00');
  INSERT INTO domains VALUES
    ('d-blackbull','blackbullbarbers.co.uk'),
    ('d-cyber','cybermeters.com'),
    ('d-sheshire','sheshire.co.uk'),
    ('d-established','established.example'),
    ('d-empty','not-established.example');
  INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES
    ('ws-founder','d-blackbull','verified'),
    ('ws-founder','d-cyber','verified'),
    ('ws-founder','d-sheshire','verified'),
    ('ws-founder','d-established','verified'),
    ('ws-founder','d-empty','verified'),
    ('ws-foreign','d-blackbull','verified'),
    ('ws-deleted','d-blackbull','verified');
  INSERT INTO scans VALUES
    ('scan-blackbull','ws-founder','d-blackbull','blackbullbarbers.co.uk','completed',100,'excellent','partial','2026-08-12 12:00:00'),
    ('scan-cyber','ws-founder','d-cyber','cybermeters.com','completed',85,'good','degraded','2026-08-12 12:01:00'),
    ('scan-sheshire','ws-founder','d-sheshire','sheshire.co.uk','completed',85,'good','partial','2026-08-12 12:02:00'),
    ('scan-established','ws-founder','d-established','established.example','completed',82,'good','complete','2026-08-12 12:03:00'),
    ('scan-foreign-newer','ws-foreign','d-blackbull','blackbullbarbers.co.uk','completed',1,'critical','complete','2026-08-12 13:00:00');
`)

const d1 = {
  prepare(sql) {
    const statement = db.prepare(sql)
    const bound = (values) => ({
      first: async () => statement.get(...values) ?? null,
      all: async () => ({ results: statement.all(...values) }),
      run: async () => ({ meta: statement.run(...values) }),
    })
    return { ...bound([]), bind: (...values) => bound(values) }
  },
}

const modules = {
  ssl: { https_available: true },
  cve_intelligence: {
    cve_coverage: 'complete',
    incomplete: false,
    technologies_checked: [],
    lookup_statuses: {},
    results: {},
  },
  known_exploited_vulnerabilities: { matches: [] },
  email_security_intelligence: { domain: 'example.test' },
}
const signalNames = [
  'dns',
  'certificate_transparency',
  'website_security',
  'email_protection',
  'attack_surface',
  'technology_visibility',
  'vulnerability_intelligence',
  'registration_data',
]
const monitoringHealthy = {
  signals: Object.fromEntries(signalNames.map((signal) => [
    signal,
    { state: 'monitoring_healthy', message: `${signal} complete` },
  ])),
}
const reports = new Map([
  ['scan-blackbull', { modules, monitoring_states: monitoringHealthy }],
  ['scan-cyber', { modules, monitoring_states: monitoringHealthy }],
  ['scan-sheshire', { modules, monitoring_states: monitoringHealthy }],
  ['scan-established', { modules, monitoring_states: monitoringHealthy }],
  ['scan-foreign-newer', { modules, monitoring_states: monitoringHealthy }],
])
let reportReads = 0
const env = {
  cybermeters_db: d1,
  cybermeters_reports: {
    async get(key) {
      reportReads += 1
      const scanId = key.match(/^reports\/(.+)\.json$/)?.[1]
      const report = reports.get(scanId)
      return report ? { json: async () => structuredClone(report) } : null
    },
  },
}

function context(workspaceId, { deny = false } = {}) {
  return {
    request: new Request(`https://api.example.test/api/workspaces/${workspaceId}/domains`),
    env,
    ctx: {},
    url: new URL(`https://api.example.test/api/workspaces/${workspaceId}/domains`),
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: (error) => Response.json({ error: String(error) }, { status: 500 }),
    requireAuth: async () => ({ id: 'founder' }),
    requireWorkspaceRole: async (_user, id) => deny || id === 'ws-deleted'
      ? null
      : { role: 'owner' },
    DELETION_PURGE_WINDOW_DAYS: 30,
  }
}

const response = await workspacesCoreRoutes(context('ws-founder'))
eq('authorised workspace-domain route returns 200', response.status, 200)
const body = await response.json()
eq('response stays scoped to the requested workspace', body.workspace_id, 'ws-founder')
eq('all five linked domains are returned', body.domains?.length, 5)
const byName = new Map(body.domains.map((row) => [row.domain, row]))

for (const [hostname, score] of [
  ['blackbullbarbers.co.uk', 100],
  ['cybermeters.com', 85],
  ['sheshire.co.uk', 85],
]) {
  const row = byName.get(hostname)
  eq(`${hostname}: legacy numeric score is preserved`, row?.latest_score, score)
  eq(`${hostname}: canonical numeric score is preserved`, row?.latest_assessment?.display_score, score)
  eq(`${hostname}: canonical state is provisional`, row?.latest_assessment?.state, 'provisional')
  eq(`${hostname}: explicit provisional flag is true`, row?.latest_assessment?.provisional, true)
  eq(`${hostname}: methodology identity is explicit`, row?.latest_assessment?.methodology_version, '2026-08-24.1')
}

const established = byName.get('established.example')
eq('established evidence keeps its numeric score', established?.latest_assessment?.display_score, 82)
eq('established evidence is explicitly established', established?.latest_assessment?.state, 'established')
eq('established evidence is not provisional', established?.latest_assessment?.provisional, false)
eq('established evidence keeps its canonical band', established?.latest_assessment?.display_rating, 'good')

const empty = byName.get('not-established.example')
eq('not-established domain has no fabricated legacy number', empty?.latest_score, null)
eq('not-established domain has no canonical number', empty?.latest_assessment?.display_score, null)
eq('not-established domain has the explicit state', empty?.latest_assessment?.state, 'not_established')
eq('not-established reason is preserved', empty?.latest_assessment?.message, 'Current posture not yet established.')

eq('newer foreign workspace score is never selected', byName.get('blackbullbarbers.co.uk')?.latest_score, 100)
ok('Phase-5 evidence reads are bounded to rows with scans', reportReads === 4, `reads ${reportReads}`)

const beforeDeniedReads = reportReads
const denied = await workspacesCoreRoutes(context('ws-deleted'))
eq('soft-deleted workspace is non-enumerating forbidden', denied.status, 403)
eq('soft-deleted workspace performs no report reads', reportReads, beforeDeniedReads)

console.log(`\nprovisional-score-labeling API: ${passed}/${passed + failed} passed`)
if (failed) {
  console.error('provisional-score-labeling API validation FAILED')
  process.exit(1)
}
console.log('provisional-score-labeling API validation passed')
