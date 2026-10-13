import { readFileSync, writeFileSync } from 'node:fs';

const source = new URL('../workers/network-probe/src/tls-collector-runtime.js', import.meta.url);
const target = new URL('../workers/network-probe/src/tls-collector-program.generated.js', import.meta.url);
const contents = `// Generated from tls-collector-runtime.js; run node scripts/build-tls-collector.js.\nexport const TLS_COLLECTOR_PROGRAM = ${JSON.stringify(readFileSync(source,'utf8'))};\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(target,'utf8') !== contents) {
    console.error('TLS collector program is stale');
    process.exitCode = 1;
  }
} else writeFileSync(target, contents);
