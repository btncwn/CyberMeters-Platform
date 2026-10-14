// Run inside the final TLS image with --network none and a loopback fixture.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const iterations=Number(process.argv[2]??3);
if(!Number.isInteger(iterations)||iterations<1||iterations>10||
   process.env.CM_TLS_TEST_RUNTIME_ROOT!=='/opt/cybermeters' ||
   !process.env.CM_TLS_TEST_CERTIFICATE || !process.env.CM_TLS_TEST_KEY ||
   !process.env.CM_TLS_TEST_FIXTURE_BINARY)throw new Error('bounded final-runtime fixture required');
const test=fileURLToPath(new URL('../workers/network-probe/tls-engine/test-parent-active.js',import.meta.url));
const read=name=>{try{return readFileSync(join('/sys/fs/cgroup',name),'utf8').trim();}catch{return null;}};
const numeric=name=>{const value=read(name);return value&&/^\d+$/.test(value)?Number(value):null;};
const cpu=()=>{const match=/^usage_usec\s+(\d+)$/m.exec(read('cpu.stat')??'');return match?Number(match[1]):null;};
const beforeCpu=cpu(),beforeMemory=numeric('memory.current');
if(beforeCpu===null||beforeMemory===null||!read('cpu.max')||!read('memory.max'))throw new Error('cgroup v2 required');
const started=process.hrtime.bigint(),durations=[],totals={checks:0,connections:0,bytes_sent:0,bytes_received:0};
for(let i=0;i<iterations;i++){
  const began=process.hrtime.bigint();
  const run=spawnSync(process.execPath,[test],{env:{...process.env,CM_TLS_TEST_PROFILE:'1'},
    encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
  if(run.status!==0)throw new Error(`special profile iteration ${i+1}: ${String(run.stderr||run.error||'').slice(-500)}`);
  const line=run.stdout.split('\n').find(value=>value.startsWith('TLS special parent profile: '));
  if(!line)throw new Error('missing parent accounting');
  const rows=JSON.parse(line.slice('TLS special parent profile: '.length));
  if(rows.length!==3||rows.map(row=>row.control).join(',')!=='heartbleed,ccs,robot')throw new Error('incomplete controls');
  for(const row of rows){
    if(row.state!=='rejected'||!Number.isSafeInteger(row.connections)||!Number.isSafeInteger(row.bytes_sent)||
       !Number.isSafeInteger(row.bytes_received))throw new Error('invalid control result');
    totals.checks++;totals.connections+=row.connections;
    totals.bytes_sent+=row.bytes_sent;totals.bytes_received+=row.bytes_received;
  }
  durations.push(Number(process.hrtime.bigint()-began)/1e6);
}
durations.sort((a,b)=>a-b);
const round=value=>Math.round(value*100)/100;
console.log(JSON.stringify({kind:'tls-special-final-runtime-profile-v1',iterations,target_scope:'isolated_loopback_only',
  cgroup_limits:{cpu_max:read('cpu.max'),memory_max:read('memory.max')},
  duration_ms:{wall:round(Number(process.hrtime.bigint()-started)/1e6),min:round(durations[0]),
    median:round(durations[Math.floor(durations.length/2)]),p95:round(durations[Math.ceil(durations.length*.95)-1]),
    max:round(durations.at(-1))},cpu_usage_usec:cpu()-beforeCpu,
  memory_current_before_bytes:beforeMemory,memory_current_after_bytes:numeric('memory.current'),
  memory_peak_bytes:numeric('memory.peak'),totals}));
