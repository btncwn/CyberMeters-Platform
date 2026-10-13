// Content never leaves the evaluator. These helpers deal only with safe endpoint metadata.
export function sha256Text(value) {
  const data = new TextEncoder().encode(String(value));
  const size = Math.ceil((data.length + 9) / 64) * 64;
  const bytes = new Uint8Array(size); bytes.set(data); bytes[data.length] = 128;
  const view = new DataView(bytes.buffer); view.setUint32(size - 4, data.length * 8);
  const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const rotr = (x,n) => (x >>> n) | (x << (32-n)); const w = new Int32Array(64);
  for (let offset=0; offset<size; offset+=64) {
    for (let i=0;i<16;i++) w[i]=view.getInt32(offset+i*4);
    for (let i=16;i<64;i++) { const x=w[i-15],y=w[i-2]; w[i]=(w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>>10)))|0; }
    let [a,b,c,d,e,f,g,z]=h;
    for (let i=0;i<64;i++) { const t1=(z+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i])|0; const t2=((rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c)))|0; z=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0; }
    [a,b,c,d,e,f,g,z].forEach((x,i)=>{h[i]=(h[i]+x)|0;});
  }
  return h.map(x=>(x>>>0).toString(16).padStart(8,'0')).join('');
}
export function isSafeExposurePath(path) {
  if (typeof path !== 'string' || path.length > 512 || !path.startsWith('/') || path.startsWith('//') || /[^A-Za-z0-9_./~-]/.test(path) || path.includes('..')) return false;
  // GET is not proof of safety. Reject operation verbs even in filename components.
  if (/(?:^|[/_.-])(?:logout|signout|delete|remove|drop|truncate|restart|reboot|shutdown|stop|start|execute|exec|run|trigger|create|generate|reset|flush|purge|import|restore|install|update|enable|disable|kill|action)(?:$|[/_.-])/i.test(path)) return false;
  // Do not retain token-bearing URLs or personal-address shaped paths.
  if (/(?:token|password|secret|session|authkey)[_-]?[A-Za-z0-9]{8,}/i.test(path) || /[A-Za-z0-9_-]{48,}/.test(path)) return false;
  return path.split('/').every(s => s.length <= 80);
}
export function isRulePathAllowed(rule, path) {
  if (!rule || !isSafeExposurePath(path)) return false;
  if (rule.paths.includes(path)) return true;
  const patterns = {
    'env-config': /\/(?:\.env(?:\.[a-z0-9_.-]+)?|[a-z0-9_.-]+\.env)$/i,
    'application-config': /\/(?:config|appsettings|application|database|docker-compose|web|nginx|apache)[a-z0-9_.-]*\.(?:json|ya?ml|properties|conf|config)(?:\.(?:bak|old|backup|save))?$/i,
    'database-export': /\/[a-z0-9_.-]+\.sql$/i,
    'backup-archive': /\/[a-z0-9_.-]+\.(?:zip|tgz|tar|tar\.gz|bak)$/i,
    'backup-source': /\/[a-z0-9_.-]+\.(?:php|aspx|jsp|config|py|rb)(?:\.(?:bak|old|backup|save)|~)$/i,
    'client-secret': /\/[a-z0-9_.-]+\.(?:m?js|json)$/i,
    'source-map': /\/[a-z0-9_.-]+\.(?:m?js|css)\.map$/i,
    'api-schema': /\/[a-z0-9_.-]*(?:openapi|swagger|api-docs)[a-z0-9_.-]*(?:\.json)?$/i,
    'exposed-log': /\/[a-z0-9_.-]+\.log$/i,
    'admin-interface': /\/(?:admin|administrator|dashboard|console|login)\/?$/i,
  };
  return Boolean(patterns[rule.id]?.test(path));
}
export function safeExposureUrl(value, rules = []) {
  try {
    const u = new URL(value); if (!['http:', 'https:'].includes(u.protocol)) return '[invalid-url]';
    const fixed = new Set(rules.flatMap(r => r.paths));
    const path = fixed.has(u.pathname) ? u.pathname : '/[redacted-path]';
    // Host is a verified asset identifier; all userinfo, query and fragment are removed.
    return u.origin + path;
  } catch { return '[invalid-url]'; }
}
export function exposureIdentity(ruleId, value) {
  try { const u = new URL(value); return 'exposure:' + sha256Text(ruleId + '\n' + u.origin.toLowerCase() + u.pathname); }
  catch { return 'exposure:' + sha256Text(ruleId + '\ninvalid'); }
}
