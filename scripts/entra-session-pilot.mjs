#!/usr/bin/env node
// Human-operated own-account acceptance. Not a customer API or a credential
// store. This pilot is restricted to the test identity approved in the chat.
import fs from 'node:fs';
import path from 'node:path';
import { Writable } from 'node:stream';
import readline from 'node:readline/promises';
import { createEntraSessionClient, EntraSessionError } from '../workers/scan-api/src/engines/entra-sessions.js';

const TEST_UPN = 'cm-identity-test@ttrnn47gmail.onmicrosoft.com';
const usage = 'node scripts/entra-session-pilot.mjs --tenant TENANT_ID --client APPLICATION_ID [--apply --receipt /absolute/private/path.json]';
const args = process.argv.slice(2), options = {};
if (args.includes('--help')) { console.log(usage); process.exit(0); }
for (let i = 0; i < args.length; i++) {
  const key = args[i];
  if (key === '--apply' && !options.apply) options.apply = true;
  else if (['--tenant','--client','--receipt'].includes(key) && args[i + 1] && !options[key.slice(2)]) options[key.slice(2)] = args[++i];
  else { console.error(usage); process.exit(2); }
}
if (!/^[0-9a-f-]{36}$/i.test(options.tenant || '') || !/^[0-9a-f-]{36}$/i.test(options.client || '') ||
    (options.apply && (!path.isAbsolute(options.receipt || '') || fs.existsSync(options.receipt))) ||
    (!options.apply && options.receipt)) {
  console.error('Check the IDs. An apply requires a new absolute receipt path; never replace an existing receipt.');
  console.error(usage); process.exit(2);
}
if (!process.stdin.isTTY || !process.stderr.isTTY) { console.error('Human-operated terminal required. Do not pipe credentials into this command.'); process.exit(2); }

let muted = false;
const output = new Writable({ write(chunk, encoding, done) { if (!muted) process.stderr.write(chunk, encoding); done(); } });
const prompt = readline.createInterface({ input: process.stdin, output, terminal: true });
let receiptFd, attempt = null;
function saveReceipt(value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  fs.writeSync(receiptFd, bytes, 0, bytes.length, 0);
  fs.ftruncateSync(receiptFd, bytes.length); fs.fsyncSync(receiptFd);
}
try {
  console.log('Target: ' + TEST_UPN);
  console.log(options.apply ? 'A preview is shown first. One session-revocation request needs your exact confirmation.' : 'PREVIEW ONLY. No session or password will be changed.');
  process.stderr.write('Entra application client secret (hidden; never saved): ');
  muted = true;
  let clientSecret = await prompt.question('');
  muted = false; process.stderr.write('\n');
  const client = createEntraSessionClient({ tenantId: options.tenant, clientId: options.client, clientSecret });
  clientSecret = null;
  const preview = await client.preview(TEST_UPN);
  console.log(JSON.stringify(preview, null, 2));
  if (options.apply) {
    console.log('This requests revocation of this test user’s Entra refresh tokens and sign-in sessions. Existing access tokens or sessions owned by other applications may remain valid. The password is unchanged.');
    const answer = await prompt.question('Type REVOKE ' + TEST_UPN + ' to send one request: ');
    if (answer !== 'REVOKE ' + TEST_UPN) { console.log('Cancelled. No revocation sent.'); process.exitCode = 2; }
    else {
      // Durable write-ahead receipt. If interrupted afterwards, treat it as an
      // uncertain attempt and inspect it; do not rerun with another receipt.
      receiptFd = fs.openSync(options.receipt, 'wx', 0o600);
      attempt = { version: 1, target: TEST_UPN, preview, status: 'attempt_reserved', logoutVerified: false, reservedAt: new Date().toISOString() };
      saveReceipt(attempt);
      const result = await client.revoke(preview, { confirmedUpn: TEST_UPN, authorize: async () => true });
      attempt = { ...attempt, ...result };
      saveReceipt(attempt);
      console.log(JSON.stringify(result, null, 2));
      console.log('Receipt: ' + options.receipt);
      console.log('Do not rerun. Next verify the previously signed-in test session separately.');
    }
  }
} catch (error) {
  muted = false;
  const code = error instanceof EntraSessionError ? error.code : 'pilot_failed';
  if (attempt) {
    attempt = { ...attempt, status: 'not_confirmed', reason: code, uncertain: !(error instanceof EntraSessionError) || error.uncertain, logoutVerified: false };
    try { saveReceipt(attempt); } catch { /* The durable attempt_reserved receipt remains evidence of uncertainty. */ }
  }
  console.error('Not completed: ' + code + '. No logout verification is claimed.');
  if (attempt) console.error('An attempt receipt exists. Inspect it before any further action; do not rerun automatically.');
  process.exitCode = 1;
} finally {
  muted = false; prompt.close();
  if (receiptFd !== undefined) fs.closeSync(receiptFd);
}
