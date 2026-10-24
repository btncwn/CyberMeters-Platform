// Existing accuracy corpus, ordinary homepage requests through the REAL tech
// module. No path enumeration, payload, credential, account or production scan.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { runTechModule } from '../../workers/scan-api/src/engines/tech-scan.js';
import { dnsQuery } from '../../workers/scan-api/src/engines/dns.js';
import { PHP_RUNTIME_TABLE_VERSION } from '../../workers/scan-api/src/engines/php-runtime.js';

const output = process.argv[process.argv.indexOf('--output') + 1];
if (!output || !process.argv.includes('--output')) throw new Error('--output required');
const corpus = fs.readFileSync(new URL('./free-scan-corpus.txt', import.meta.url), 'utf8');
const hosts = corpus.split(/\r?\n/).map(line => line.trim().split(/\s+/)[0]).filter(host => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host));
const records = new Array(hosts.length);
let cursor = 0;
async function worker() {
  for (;;) {
    const i = cursor++;
    if (i >= hosts.length) return;
    const record = { corpus_id: `entry-${String(i + 1).padStart(3, '0')}`, classification: 'unknown' };
    try {
      const tech = await runTechModule(hosts[i], { dnsResolver: dnsQuery, signal: AbortSignal.timeout(15000) });
      const observation = tech.php_runtime;
      record.status = tech.status_code ?? null;
      record.reason = tech.incomplete_reason || tech.error || observation?.state || 'unavailable';
      if (observation) {
        record.state = observation.state;
        record.table_version = observation.table_version;
        if (observation.reported_version) record.reported_version = observation.reported_version;
        record.classification = observation.state === 'outdated' ? 'review_required'
          : observation.state === 'fixed' || observation.state === 'absent' ? 'not_detected' : 'unknown';
        // Public header evidence is kept locally for independent manual triage;
        // checked-in acceptance retains only bounded parsed numbers/hashes.
        record.header_sha256 = createHash('sha256').update(JSON.stringify([tech.server, tech.x_powered_by])).digest('hex');
      }
    } catch { record.reason = 'transport_unavailable'; }
    records[i] = record;
    if (records.filter(Boolean).length % 10 === 0) console.log(`Corpus ${records.filter(Boolean).length}/${hosts.length}`);
  }
}
await Promise.all([worker(), worker(), worker()]);
const report = { schema: 'php-runtime-corpus-v1', observed_at: new Date().toISOString(),
  corpus_sha256: createHash('sha256').update(corpus).digest('hex'), table_version: PHP_RUNTIME_TABLE_VERSION,
  scope: 'Existing accuracy corpus, existing bounded HTTPS homepage technology observation only. No exploit testing or production scan.',
  counts: { total: hosts.length, tp: 0, fp: 0, unknown: records.filter(r => r.classification === 'unknown').length,
    not_detected: records.filter(r => r.classification === 'not_detected').length, review_required: records.filter(r => r.classification === 'review_required').length },
  limitation: 'Positive reported-release observations require independent header/version triage. No true vulnerable/exploitable installation is assumed; controlled fixtures carry detection truth.', records };
fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report.counts));
