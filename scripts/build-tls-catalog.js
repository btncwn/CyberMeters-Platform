import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const source=new URL('../workers/network-probe/tls-engine/compiled-catalog.generated.json',import.meta.url);
const target=new URL('../shared/tls/cipher-catalog.generated.js',import.meta.url);
const bytes=readFileSync(source);
const catalog=JSON.parse(bytes);
if(catalog.schema!=='tls-compiled-catalog-v1'||!Array.isArray(catalog.entries)||catalog.entries.length<100||
  catalog.engines?.legacy?.version!=='1.0.2u'||catalog.engines?.modern?.version!=='3.5.9')throw new Error('TLS compiled catalogue is incomplete');
const protocols=new Set(['ssl2','ssl3','tls1','tls1_1','tls1_2','tls1_3']);
const seen=new Set();
for(const item of catalog.entries){
  if(!protocols.has(item.protocol)||!['legacy','modern'].includes(item.engine)||
    typeof item.name!=='string'||!/^[A-Za-z0-9_-]{1,96}$/.test(item.name)||
    typeof item.executable!=='boolean'||typeof item.reason!=='string')throw new Error('Invalid compiled cipher entry');
  const key=`${item.protocol}|${item.name}`;
  if(seen.has(key))throw new Error(`Duplicate compiled cipher: ${key}`);
  seen.add(key);
}
for(const protocol of protocols)if(!catalog.entries.some(item=>item.protocol===protocol&&item.executable))
  throw new Error(`No executable ciphers for ${protocol}`);
const digest=createHash('sha256').update(bytes).digest('hex');
const rows=catalog.entries.map(({protocol,engine,name,id,bits,executable,reason})=>({protocol,engine,name,id,bits,executable,reason}));
const output=`// Generated from the pinned native TLS engine catalogue. Run node scripts/build-tls-catalog.js.\n`+
  `export const TLS_CIPHER_CATALOG_SHA256 = '${digest}';\n`+
  `export const TLS_CIPHER_CATALOG = Object.freeze(${JSON.stringify(rows)});\n`;
if(process.argv.includes('--check')){
  if(readFileSync(target,'utf8')!==output)throw new Error('TLS cipher catalogue is stale');
}else writeFileSync(target,output);
