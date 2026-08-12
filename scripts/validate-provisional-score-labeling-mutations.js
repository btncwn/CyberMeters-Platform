#!/usr/bin/env node

// Strict fresh-process mutation proof for canonical provisional score labeling.
// Each mutant changes real production bytes, must fail the focused validator by
// exactly the frozen right-reason set, and is restored before the next mutant.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const validator = path.join(root, 'scripts', 'validate-provisional-score-labeling.js')
const files = {
  assessment: 'workers/scan-api/src/engines/assessment-presentation.js',
  phase5: 'workers/scan-api/src/engines/phase5-evidence.js',
  workspaces: 'workers/scan-api/src/routes/workspaces-core.js',
  frontendContract: 'frontend/src/lib/canonical-score-presentation.js',
  page: 'frontend/src/pages/WorkspaceDetailPage.jsx',
  scoring: 'workers/scan-api/src/engines/scoring.js',
}

const EXPECTED_MUTANTS = 15
const EXPECTED_INVALID_CONTROLS = 2
const EXPECTED_ASSERTIONS = 57
const SUMMARY_PREFIX = 'provisional-score-labeling:'

const A = Object.freeze({
  blackState: 'Blackbull-like partial 100: state is explicitly provisional',
  blackFlag: 'Blackbull-like partial 100: provisional flag is true',
  cyberState: 'CyberMeters-like degraded 85: state is explicitly provisional',
  cyberFlag: 'CyberMeters-like degraded 85: provisional flag is true',
  sheshireState: 'Sheshire-like partial 85: state is explicitly provisional',
  sheshireFlag: 'Sheshire-like partial 85: provisional flag is true',
  monitoringState: 'complete execution plus incomplete monitoring remains provisional',
  establishedState: 'complete evidence owns the established state',
  missingValue: 'missing score remains null, never zero',
  malformedNaNValue: 'malformed NaN never becomes zero',
  malformedStringValue: 'malformed 85 never becomes zero',
  malformedObjectValue: 'malformed [object Object] never becomes zero',
  malformedUndefinedValue: 'malformed undefined never becomes zero',
  frontendProvisionalValue: 'frontend contract preserves canonical provisional 100',
  frontendProvisionalState: 'frontend contract visibly classifies canonical provisional state',
  frontendEstablishedValue: 'frontend contract preserves canonical established value',
  frontendEstablishedState: 'frontend contract does not force established evidence provisional',
  missingStateClosed: 'frontend contract fails missing state closed',
  missingStateNumber: 'frontend contract never fabricates a number for missing state',
  missingFlagClosed: 'frontend contract fails missing provisional flag closed',
  missingFlagNumber: 'frontend contract never fabricates a number for missing provisional flag',
  inconsistentClosed: 'frontend contract fails inconsistent established flags closed',
  inconsistentNumber: 'frontend contract never fabricates a number for inconsistent established flags',
  apiAssessment: 'workspace domain API exposes the additive canonical latest_assessment contract',
  apiLegacy: 'legacy latest_score compatibility field remains present',
  monitoringWiring: 'phase5 list projection carries frozen monitoring evidence into the canonical resolver',
  tenant: 'workspace-domain scan selection is bound to the authorised workspace',
  readOnly: 'workspace-domain GET remains read-only',
  pageCanonical: 'WorkspaceDetailPage passes backend canonical state to the shared score renderer',
  sharedContract: 'shared renderer delegates to the explicit-state frontend contract',
  overall: 'workspace overall Cyber Score remains backend-owned with no domain-row fallback',
  algorithm: 'Cyber Metrics Score algorithm and methodology identity remain unchanged',
})

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex')
function git(args, encoding = 'utf8') {
  const child = spawnSync('git', args, { cwd: root, encoding })
  if (child.error || child.signal !== null || child.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${child.error?.message || child.signal || child.stderr || child.status}`)
  }
  return child.stdout
}
function worktreeFingerprint() {
  const status = git(['status', '--porcelain=v1', '--untracked-files=all'])
  const diff = git(['diff', '--binary', '--no-ext-diff', 'HEAD', '--', '.'])
  const raw = git(['ls-files', '--others', '--exclude-standard', '-z'], 'buffer')
  const untracked = raw.toString('utf8').split('\0').filter(Boolean).sort()
    .filter((relative) => fs.statSync(path.join(root, relative)).isFile())
    .map((relative) => `${relative}\0${sha256(fs.readFileSync(path.join(root, relative)))}`)
    .join('\n')
  return { status, diff, untracked, hash: sha256(`${status}\0${diff}\0${untracked}`) }
}
function replaceExactlyOnce(source, anchor, replacement, label) {
  const first = source.indexOf(anchor)
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor must exist exactly once`)
  }
  const mutated = source.slice(0, first) + replacement + source.slice(first + anchor.length)
  if (mutated === source) throw new Error(`${label}: mutation is a no-op`)
  return mutated
}
function runValidator() {
  return spawnSync(process.execPath, [validator], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
  })
}
function failNames(output) {
  return output.split('\n')
    .filter((line) => line.startsWith('FAIL '))
    .map((line) => line.slice(5).split(' — ')[0].trim())
    .sort()
}
function summary(output) {
  const line = output.split('\n').find((candidate) => candidate.startsWith(SUMMARY_PREFIX))
  const match = line?.match(/(\d+) passed, (\d+) failed \((\d+) total\)/)
  return match
    ? { pass: Number(match[1]), fail: Number(match[2]), total: Number(match[3]) }
    : null
}

const mutants = [
  {
    name: 'backend removes provisional flag', file: 'assessment',
    anchor: '    provisional:    !complete,', replacement: '    provisional:    false,',
    expected: [A.blackFlag, A.cyberFlag, A.sheshireFlag, A.frontendProvisionalValue, A.frontendProvisionalState],
  },
  {
    name: 'score 100 is forced established', file: 'assessment',
    anchor: '  const state = !hasScore\n    ? ASSESSMENT_PRESENTATION_STATES.NOT_ESTABLISHED',
    replacement: '  const state = score === 100 && hasScore\n    ? ASSESSMENT_PRESENTATION_STATES.ESTABLISHED\n    : !hasScore\n      ? ASSESSMENT_PRESENTATION_STATES.NOT_ESTABLISHED',
    expected: [A.blackState, A.monitoringState, A.frontendProvisionalValue, A.frontendProvisionalState],
  },
  {
    name: 'incomplete evidence is treated established', file: 'assessment',
    anchor: '      : ASSESSMENT_PRESENTATION_STATES.PROVISIONAL;',
    replacement: '      : ASSESSMENT_PRESENTATION_STATES.ESTABLISHED;',
    expected: [A.blackState, A.cyberState, A.sheshireState, A.monitoringState, A.frontendProvisionalValue, A.frontendProvisionalState],
  },
  {
    name: 'established evidence is forced provisional', file: 'assessment',
    anchor: '      ? ASSESSMENT_PRESENTATION_STATES.ESTABLISHED\n      : ASSESSMENT_PRESENTATION_STATES.PROVISIONAL;',
    replacement: '      ? ASSESSMENT_PRESENTATION_STATES.PROVISIONAL\n      : ASSESSMENT_PRESENTATION_STATES.PROVISIONAL;',
    expected: [A.establishedState, A.frontendEstablishedValue, A.frontendEstablishedState],
  },
  {
    name: 'frontend ignores canonical state', file: 'frontendContract',
    anchor: '  const state = assessment?.state', replacement: "  const state = 'provisional'",
    expected: [A.frontendEstablishedValue, A.frontendEstablishedState, A.missingStateClosed, A.missingStateNumber, A.inconsistentClosed, A.inconsistentNumber, A.sharedContract],
  },
  {
    name: 'frontend locally infers provisionality from score', file: 'frontendContract',
    anchor: "  const provisional = state === 'provisional' && score != null &&\n    assessment?.provisional === true && assessment?.authoritative === false",
    replacement: '  const provisional = score != null',
    expected: [A.frontendEstablishedState, A.missingStateClosed, A.missingStateNumber, A.missingFlagClosed, A.missingFlagNumber, A.inconsistentClosed, A.inconsistentNumber, A.sharedContract],
  },
  {
    name: 'missing score becomes zero', file: 'assessment',
    anchor: '    display_score:  hasScore ? score : null,', replacement: '    display_score:  hasScore ? score : 0,',
    expected: [A.missingValue, A.malformedNaNValue, A.malformedStringValue, A.malformedObjectValue, A.malformedUndefinedValue],
  },
  {
    name: 'workspace overall dash falls back to a domain number', file: 'page',
    anchor: "value={noCurrentMonitoring ? '—' : (postureScore != null ? postureScore : '—')}",
    replacement: "value={noCurrentMonitoring ? '—' : (postureScore != null ? postureScore : (domains[0]?.latest_score ?? '—'))}",
    expected: [A.overall],
  },
  {
    name: 'legacy API compatibility score field disappears', file: 'workspaces',
    anchor: '              latest_score: customerScan?.score ?? null,',
    replacement: '              removed_latest_score: customerScan?.score ?? null,',
    expected: [A.apiLegacy],
  },
  {
    name: 'unrelated risk score indicator is altered', file: 'scoring',
    anchor: '    score += f.score_impact;', replacement: '    score -= f.score_impact;',
    expected: [A.algorithm],
  },
  {
    name: 'historical evidence is rewritten on read', file: 'workspaces',
    anchor: '          const domains = (result.results ?? []).map((row, index) => {',
    replacement: '          await env.cybermeters_db.prepare("UPDATE scans SET score = 0").run();\n          const domains = (result.results ?? []).map((row, index) => {',
    expected: [A.readOnly],
  },
  {
    name: 'cross-workspace score state is accepted', file: 'workspaces',
    anchor: '                   AND (workspace_id = wd.workspace_id OR workspace_id IS NULL)',
    replacement: '                   AND workspace_id IS NOT NULL',
    expected: [A.tenant],
  },
  {
    name: 'canonical API presentation field disappears', file: 'workspaces',
    anchor: '              latest_assessment: latestAssessment,',
    replacement: '              removed_latest_assessment: latestAssessment,',
    expected: [A.apiAssessment],
  },
  {
    name: 'monitoring evidence is dropped before canonical projection', file: 'phase5',
    anchor: '      monitoringStates: outcome.monitoring_states,',
    replacement: '      monitoringStates: undefined,',
    expected: [A.monitoringWiring],
  },
  {
    name: 'WorkspaceDetail locally reconstructs established state from legacy score', file: 'page',
    anchor: '<CanonicalScore assessment={d.latest_assessment} />',
    replacement: "<CanonicalScore assessment={{ state: 'established', display_score: d.latest_score, provisional: false, authoritative: true }} />",
    expected: [A.pageCanonical],
  },
]

const originals = new Map(Object.entries(files).map(([key, relative]) => [
  key,
  { relative, path: path.join(root, relative), bytes: fs.readFileSync(path.join(root, relative)) },
]))
const beforeTree = worktreeFingerprint()
let killed = 0
let controlsRejected = 0
let suiteFailures = 0

function restoreAll() {
  for (const entry of originals.values()) fs.writeFileSync(entry.path, entry.bytes)
}

try {
  if (mutants.length !== EXPECTED_MUTANTS) throw new Error(`mutant count ${mutants.length}, want ${EXPECTED_MUTANTS}`)
  const baseline = runValidator()
  const baselineOutput = `${baseline.stdout || ''}\n${baseline.stderr || ''}`
  const baselineSummary = summary(baselineOutput)
  if (baseline.error || baseline.signal !== null || baseline.status !== 0 ||
      !baselineSummary || baselineSummary.pass !== EXPECTED_ASSERTIONS ||
      baselineSummary.fail !== 0 || baselineSummary.total !== EXPECTED_ASSERTIONS) {
    throw new Error(`baseline is not ${EXPECTED_ASSERTIONS}/${EXPECTED_ASSERTIONS} green\n${baselineOutput}`)
  }
  console.log(`PASS baseline validator green (${EXPECTED_ASSERTIONS}/${EXPECTED_ASSERTIONS})`)

  for (const mutant of mutants) {
    const original = originals.get(mutant.file)
    const source = original.bytes.toString('utf8')
    const mutated = replaceExactlyOnce(source, mutant.anchor, mutant.replacement, mutant.name)
    fs.writeFileSync(original.path, mutated)
    try {
      const child = runValidator()
      const output = `${child.stdout || ''}\n${child.stderr || ''}`
      const got = failNames(output)
      const want = [...mutant.expected].sort()
      const totals = summary(output)
      const problems = []
      if (child.error) problems.push(`spawn error ${child.error.message}`)
      if (child.signal !== null) problems.push(`signal ${child.signal}`)
      if (child.status !== 1) problems.push(`exit ${child.status}, want 1`)
      if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module/.test(output)) problems.push('load/syntax failure is not a kill')
      if (!totals || totals.total !== EXPECTED_ASSERTIONS || totals.fail !== want.length ||
          totals.pass !== EXPECTED_ASSERTIONS - want.length) problems.push(`summary mismatch ${JSON.stringify(totals)}`)
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        problems.push(`FAIL set mismatch got [${got.join(' | ')}] want [${want.join(' | ')}]`)
      }
      if (problems.length) {
        suiteFailures += 1
        console.error(`FAIL mutant "${mutant.name}" escaped or died for the wrong reason`)
        for (const problem of problems) console.error(`  - ${problem}`)
        console.error(output.trim())
      } else {
        killed += 1
        console.log(`PASS mutant "${mutant.name}" killed exactly by: ${want.join(' | ')}`)
      }
    } finally {
      fs.writeFileSync(original.path, original.bytes)
    }
  }

  // No-op controls never reach a child process and therefore cannot be counted.
  try {
    const source = originals.get('assessment').bytes.toString('utf8')
    replaceExactlyOnce(source, '    state,', '    state,', 'no-op control')
    suiteFailures += 1
    console.error('FAIL no-op control was accepted')
  } catch (error) {
    if (/no-op/.test(error.message)) {
      controlsRejected += 1
      console.log('PASS no-op mutation control rejected before execution')
    } else throw error
  }

  // A parse failure is invalid evidence, even though the child exits non-zero.
  const invalidTarget = originals.get('frontendContract')
  fs.writeFileSync(invalidTarget.path, `${invalidTarget.bytes.toString('utf8')}\nexport const broken = {\n`)
  try {
    const child = runValidator()
    const output = `${child.stdout || ''}\n${child.stderr || ''}`
    if (child.status !== 0 && /SyntaxError/.test(output) && !summary(output)) {
      controlsRejected += 1
      console.log('PASS syntax/load failure control rejected as an invalid kill')
    } else {
      suiteFailures += 1
      console.error('FAIL syntax/load failure control was not classified invalid')
    }
  } finally {
    fs.writeFileSync(invalidTarget.path, invalidTarget.bytes)
  }
} catch (error) {
  suiteFailures += 1
  console.error(`FAIL mutation suite setup/baseline — ${error.message}`)
} finally {
  restoreAll()
}

for (const entry of originals.values()) {
  if (!fs.readFileSync(entry.path).equals(entry.bytes)) {
    suiteFailures += 1
    console.error(`FAIL source bytes not restored: ${entry.relative}`)
  }
}
const afterTree = worktreeFingerprint()
if (afterTree.hash !== beforeTree.hash || afterTree.status !== beforeTree.status ||
    afterTree.diff !== beforeTree.diff || afterTree.untracked !== beforeTree.untracked) {
  suiteFailures += 1
  console.error(`FAIL worktree fingerprint changed: before=${beforeTree.hash} after=${afterTree.hash}`)
} else {
  console.log(`PASS worktree fingerprint restored exactly (${afterTree.hash})`)
}

if (killed !== EXPECTED_MUTANTS || controlsRejected !== EXPECTED_INVALID_CONTROLS || suiteFailures) {
  console.error(`provisional-score-labeling mutations FAILED: ${killed}/${EXPECTED_MUTANTS} exact kills, ${controlsRejected}/${EXPECTED_INVALID_CONTROLS} invalid controls rejected, suite failures=${suiteFailures}`)
  process.exit(1)
}
console.log(`provisional-score-labeling mutations passed: ${killed}/${EXPECTED_MUTANTS} exact right-reason kills; ${controlsRejected}/${EXPECTED_INVALID_CONTROLS} invalid controls rejected; bytes restored exactly`)
