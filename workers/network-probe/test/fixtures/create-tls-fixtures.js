import {mkdtempSync,writeFileSync,readFileSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

// Keys exist only in a private temporary directory. All connections in the
// consuming tests remain on loopback; this CA is never used by the collector.
export function createTlsFixtures() {
  const directory=mkdtempSync(join(process.env.NETWORK_PROBE_TEMP_ROOT || tmpdir(),'cm-tls-fixtures-'));
  const write=(name,value)=>writeFileSync(join(directory,name),value,{mode:0o600});
  const cleanup=()=>rmSync(directory,{recursive:true,force:true});
  const openssl=args=>{
    const result=spawnSync('openssl',args,{cwd:directory,encoding:'utf8',stdio:['ignore','ignore','pipe'],timeout:15000});
    if(result.error || result.status!==0)throw new Error(`OpenSSL fixture setup failed (${args[0]}): ${result.error?.message || result.stderr?.slice(-500) || result.status}`);
  };
  try {
    openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','7300','-subj','/CN=CyberMeters LOCAL TEST CA']);
    write('index','');write('serial','01\n');mkdirSync(join(directory,'newcerts'),{mode:0o700});
    write('ca.cnf','[ca]\ndefault_ca=local\n[local]\nunique_subject=no\ndatabase=index\nserial=serial\nnew_certs_dir=newcerts\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n');
    const certificates=[
      ['valid','owned.example.com','250101000000Z','400101000000Z'],
      ['expired','owned.example.com','200101000000Z','210101000000Z'],
      ['wrong','other.example.com','250101000000Z','400101000000Z'],
    ];
    for(const [name,hostname,start,end] of certificates){
      openssl(['req','-new','-newkey','rsa:2048','-nodes','-keyout',`${name}.key`,'-out',`${name}.csr`,'-subj',`/CN=${hostname}`]);
      write('extensions.cnf',`[server]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${hostname}\n`);
      openssl(['ca','-batch','-config','ca.cnf','-in',`${name}.csr`,'-out',`${name}.pem`,'-startdate',start,'-enddate',end,'-extfile','extensions.cnf','-extensions','server','-notext']);
    }
    return {read:name=>readFileSync(join(directory,name),'utf8'),cleanup};
  }catch(error){cleanup();throw error;}
}
