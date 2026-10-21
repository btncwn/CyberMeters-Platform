import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { seal, open, inventory, validateManifest } from './ops/cloudflare-recovery.mjs';
const key=randomBytes(32),bytes=Buffer.from('synthetic recovery fixture');
const encrypted=seal(bytes,key);
assert.deepEqual(open(encrypted,key),bytes);
assert.notDeepEqual(seal(bytes,key),encrypted);
for(const modified of [encrypted.subarray(0,-1),Buffer.from(encrypted)]){
 modified[12]^=1;assert.throws(()=>open(modified,key));
}
assert.throws(()=>open(encrypted,randomBytes(32)));
assert.throws(()=>open(Buffer.alloc(10),key));
assert.equal(inventory([{key:'b',size:2,etag:'b'},{key:'a',size:1,etag:'a'}]),inventory([{key:'a',size:1,etag:'a'},{key:'b',size:2,etag:'b'}]));
const m={schema:1,run:'20261021T090000Z-1234abcd',account:'e0241806b7f2f8408c75f5e938be3271',source_db:'fd6792cb-441a-44a7-8ca2-9a0b411ec706',source_bucket:'cybermeters-reports',members:[{kind:'d1',slot:'members/'+'a'.repeat(64),sha256:'b'.repeat(64),size:1}]};
validateManifest(m);
for(const x of [{...m,account:'other'}, {...m,run:'../prod'}, {...m,members:[]}, {...m,members:[...m.members,...m.members]}, {...m,members:[{...m.members[0],size:101*1024*1024}]}, {...m,members:[{...m.members[0],slot:'../../prod'}]}])assert.throws(()=>validateManifest(x));
console.log('Cloudflare recovery: crypto, inventory and manifest checks passed; synthetic bytes only.');
