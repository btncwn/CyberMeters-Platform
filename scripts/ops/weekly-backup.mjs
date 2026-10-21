// Weekly off-site D1 export + R2 inventory. Never writes plaintext recovery data.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { seal, open, inventory } from './cloudflare-recovery.mjs';

const ACCOUNT = 'e0241806b7f2f8408c75f5e938be3271';
const DATABASE = 'fd6792cb-441a-44a7-8ca2-9a0b411ec706';
const BUCKET = 'cybermeters-reports';
const MAX_PLAIN = 50 * 1024 * 1024;
const MAX_CIPHER = 10 * 1024 * 1024;
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');

export function encodeBackup(data, key) {
  if (data?.schema !== 1 || data.database !== DATABASE || data.bucket !== BUCKET ||
      typeof data.sql !== 'string' || !Array.isArray(data.objects) || data.objects.length > 1000) throw Error('Invalid weekly payload');
  const plain = Buffer.from(JSON.stringify(data));
  if (plain.length > MAX_PLAIN) throw Error('Weekly plaintext bound exceeded');
  const encrypted = seal(gzipSync(plain), key);
  if (encrypted.length > MAX_CIPHER) throw Error('Weekly encrypted artifact exceeds 10 MiB free-allocation bound');
  return encrypted;
}
export function verifyBackup(bytes, key, receipt) {
  if (bytes.length > MAX_CIPHER || digest(bytes) !== receipt?.sha256 || bytes.length !== receipt?.bytes) throw Error('Weekly artifact readback mismatch');
  const data = JSON.parse(gunzipSync(open(bytes, key), { maxOutputLength: MAX_PLAIN }));
  if (data.schema !== 1 || data.database !== DATABASE || data.bucket !== BUCKET ||
      data.run !== receipt.run || !Array.isArray(data.objects) || data.objects.length > 1000) throw Error('Weekly payload identity mismatch');
  // Exercise the captured SQL locally; this never connects to a remote database.
  const db = new DatabaseSync(':memory:');
  try {
    db.exec(data.sql);
    if (db.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') throw Error('Captured SQL integrity failed');
    if (db.prepare('PRAGMA foreign_key_check').all().length) throw Error('Captured SQL foreign-key check failed');
    return { run: data.run, objects: data.objects.length, captured_at: data.captured_at };
  } finally { db.close(); }
}

export function weeklyApi(token, fetchImpl = fetch) {
  if (!token) throw Error('CLOUDFLARE_BACKUP_TOKEN is required');
  const base = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/`;
  async function request(path, body) {
    const response = await fetchImpl(base + path, {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(60000),
    });
    if (!response.ok) throw Error(`Backup API failed: HTTP ${response.status}`);
    const parsed = await response.json();
    if (parsed.success !== true) throw Error('Backup API did not confirm success');
    return parsed;
  }
  async function list() {
    let cursor = '', rows = [];
    do {
      const page = await request(`r2/buckets/${BUCKET}/objects?per_page=1000${cursor ? '&cursor=' + encodeURIComponent(cursor) : ''}`);
      rows.push(...page.result);
      if (rows.length > 1000) throw Error('Weekly inventory exceeds 1000 objects');
      cursor = page.result_info?.is_truncated ? page.result_info.cursor : '';
      if (page.result_info?.is_truncated && !cursor) throw Error('Missing inventory cursor');
    } while (cursor);
    return rows.map(({ key, etag, size }) => ({ key, etag, size }));
  }
  return {
    async capture(run, key) {
      if (!/^\d+-\d+$/.test(run)) throw Error('Expected immutable workflow run/attempt identity');
      const objects = await list();
      let result = (await request(`d1/database/${DATABASE}/export`, { output_format: 'polling' })).result;
      for (let n = 0; result.status !== 'complete'; n++) {
        if (n >= 60 || result.status === 'error' || !result.at_bookmark) throw Error('D1 export did not complete');
        await new Promise(done => setTimeout(done, 1000));
        result = (await request(`d1/database/${DATABASE}/export`, { output_format: 'polling', current_bookmark: result.at_bookmark })).result;
      }
      const url = new URL(result.result.signed_url);
      if (url.protocol !== 'https:' || !url.hostname.endsWith('.r2.cloudflarestorage.com')) throw Error('Unexpected export download origin');
      // A signed storage URL must never receive the account API credential.
      const response = await fetchImpl(url, { redirect: 'error', signal: AbortSignal.timeout(60000) });
      if (!response.ok || Number(response.headers.get('content-length')) > MAX_PLAIN) throw Error('Export download failed or oversized');
      const reader = response.body.getReader();
      const chunks = []; let size = 0;
      try {
        while (true) {
          const part = await reader.read(); if (part.done) break;
          size += part.value.byteLength;
          if (size > MAX_PLAIN) { await reader.cancel(); throw Error('Export download exceeds limit'); }
          chunks.push(Buffer.from(part.value));
        }
      } finally { reader.releaseLock(); }
      const sql = Buffer.concat(chunks).toString('utf8');
      if (inventory(objects) !== inventory(await list())) throw Error('R2 inventory changed during capture');
      const captured_at = new Date().toISOString();
      const bytes = encodeBackup({ schema: 1, database: DATABASE, bucket: BUCKET, run, captured_at, sql, objects }, key);
      const receipt = { schema: 1, run, captured_at, sha256: digest(bytes), bytes: bytes.length };
      verifyBackup(bytes, key, receipt);
      return { bytes, receipt };
    },
    async record(receipt, bytes, key) {
      const proof = verifyBackup(bytes, key, receipt);
      const correlation = `github-weekly:${proof.run}`;
      const id = 'opev_' + digest(Buffer.from(correlation)).slice(0, 32);
      await request(`d1/database/${DATABASE}/query`, {
        sql: "INSERT OR IGNORE INTO operational_events (id,event_type,correlation_id,status,attempts) VALUES (?,'weekly_backup_completed',?,'ok',1)",
        params: [id, correlation],
      });
      const read = await request(`d1/database/${DATABASE}/query`, {
        sql: "SELECT created_at FROM operational_events WHERE id=? AND event_type='weekly_backup_completed' AND status='ok'", params: [id],
      });
      const created_at = read.result?.[0]?.results?.[0]?.created_at;
      if (!created_at) throw Error('Weekly success event was not read back');
      return { ...proof, last_success_at: created_at, event_id: id };
    },
  };
}

async function main() {
  const [action, directory, receiptDirectory] = process.argv.slice(2);
  const encodedKey = process.env.CM_WEEKLY_BACKUP_KEY || '';
  if (!/^[A-Za-z0-9+/]{43}=$/.test(encodedKey)) throw Error('CM_WEEKLY_BACKUP_KEY must be a base64-encoded 32-byte key');
  const key = Buffer.from(encodedKey, 'base64');
  if (key.length !== 32 || !directory) throw Error('Invalid backup key or directory');
  const client = weeklyApi(process.env.CLOUDFLARE_BACKUP_TOKEN);
  if (action === 'capture') {
    const run = `${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`;
    const { bytes, receipt } = await client.capture(run, key);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    writeFileSync(resolve(directory, 'weekly-backup.bin'), bytes, { mode: 0o600 });
    writeFileSync(resolve(directory, 'receipt.json'), JSON.stringify(receipt), { mode: 0o600 });
    console.log(JSON.stringify({ run, encrypted_bytes: bytes.length, captured_at: receipt.captured_at }));
  } else if (action === 'record' && receiptDirectory) {
    const receipt = JSON.parse(readFileSync(resolve(receiptDirectory, 'receipt.json')));
    if (receipt.run !== `${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`) throw Error('Receipt belongs to another workflow attempt');
    console.log(JSON.stringify(await client.record(receipt, readFileSync(resolve(directory, 'weekly-backup.bin')), key)));
  } else throw Error('Usage: weekly-backup.mjs capture DIR | record DOWNLOADED_DIR ORIGINAL_DIR');
}
if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) main().catch(() => {
  // Export URLs, API bodies, SQL, object names and credentials stay out of logs.
  console.error('Weekly backup failed; no new verified-success timestamp claimed.'); process.exitCode = 1;
});
