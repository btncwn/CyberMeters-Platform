// C-60a: lab measurement only; use the production bounded collector transport.
import { runProductionCorpus } from './production-collector-corpus.mjs';
const args=process.argv.slice(2);
await runProductionCorpus('remote-access',args.includes('--output')?args:[...args,'--output','/tmp/remote-access-corpus.json']);
