#!/usr/bin/env node
// Reintroduce each false-healthy resolver decision in a fresh process. Restore
// the source bytes after every run, including a failed or interrupted test.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const source=fileURLToPath(new URL('../workers/scan-api/src/engines/cyber-mot-domains.js',import.meta.url));
const validator=fileURLToPath(new URL('./test-target-outcomes.js',import.meta.url));
const original=readFileSync(source,'utf8');
const mutants=[
  {name:'UNAVAILABLE_READS_HEALTHY',from:'d.domain_key === "attack_surface" && unavailableHosts.length > 0',
    to:'d.domain_key === "attack_surface" && false && unavailableHosts.length > 0',
    failures:['T2_UNAVAILABLE_HOST_NEVER_HEALTHY','T2_EDGE_ORIGIN_WORDING']},
  {name:'NON_RESOLVING_READS_HEALTHY',from:'.some((asset) => asset?.probe_status === "not_applicable")) {',
    to:'.some((asset) => false && asset?.probe_status === "not_applicable")) {',
    failures:['T2_NON_RESOLVING_HOST_NEVER_HEALTHY']},
];
let failed=false;
try{
  for(const mutant of mutants){
    if(original.split(mutant.from).length!==2)throw new Error(`${mutant.name}: expected one anchor`);
    writeFileSync(source,original.replace(mutant.from,mutant.to));
    let code=0,output='';
    try{output=execFileSync(process.execPath,[validator],{encoding:'utf8'});}
    catch(error){code=error.status??1;output=String(error.stdout||'')+String(error.stderr||'');}
    const failures=output.split('\n').filter(line=>line.startsWith('FAIL ')).map(line=>line.slice(5));
    const passed=code!==0&&/Target outcome honesty: \d+\/\d+ assertions passed/.test(output)&&
      JSON.stringify(failures)===JSON.stringify(mutant.failures);
    console.log(`${passed?'PASS':'FAIL'} ${mutant.name}${passed?'':` ${JSON.stringify(failures)}`}`);
    failed ||= !passed;
    writeFileSync(source,original);
  }
}finally{
  writeFileSync(source,original);
}
if(readFileSync(source,'utf8')!==original)throw new Error('source was not restored');
if(failed)process.exitCode=1;
