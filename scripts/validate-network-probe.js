#!/usr/bin/env node
// Offline Worker dry-build + actual loopback TLS fixtures. No provider resources
// or public targets are used. Run after the scan-api's pinned dependencies exist.
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const scratch=mkdtempSync(join(tmpdir(),'cm-network-probe-validation-'));
let status=1;
try{
 const config=join(scratch,'wrangler.toml');const output=join(scratch,'bundle');
 writeFileSync(config,`name="cybermeters-network-probe-validation"\nmain=${JSON.stringify(resolve(root,'workers/network-probe/src/index.js'))}\ncompatibility_date="2026-10-09"\ncompatibility_flags=["enable_request_signal"]\nworkers_dev=false\npreview_urls=false\n[[containers]]\nclass_name="NetworkProbeContainer"\nscheduling_policy="durable_object"\n[[durable_objects.bindings]]\nname="PROBE_CONTAINERS"\nclass_name="NetworkProbeContainer"\n[exports.NetworkProbeContainer]\ntype="durable-object"\nstorage="sqlite"\n`);
 const env={...process.env,XDG_CONFIG_HOME:join(scratch,'config'),WRANGLER_SEND_METRICS:'false'};
 const built=spawnSync(process.execPath,[join(root,'workers/scan-api/node_modules/wrangler/bin/wrangler.js'),'versions','upload','--dry-run','--config',config,'--outdir',output],{cwd:root,env,stdio:'inherit',timeout:60000});
 if(built.status===0){const tested=spawnSync(process.execPath,['--test','workers/network-probe/test/collector.test.js'],{cwd:root,env:{...env,NETWORK_PROBE_BUNDLE:join(output,'index.js'),NETWORK_PROBE_TEMP_ROOT:scratch},stdio:'inherit',timeout:60000});status=tested.status??1;}
 else status=built.status??1;
}finally{rmSync(scratch,{recursive:true,force:true});}
process.exitCode=status;
