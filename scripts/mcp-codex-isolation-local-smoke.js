#!/usr/bin/env node
// Safe, read-only Codex CLI isolation preflight. Does not contact an MCP server,
// launch OAuth, open a browser, or run a model. Any future local OAuth probe must
// first prove that only its disposable MCP server appears in this preflight.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function listIsolatedMcpServers({ cwd, home }) {
  return new Promise((resolve, reject) => {
    const child = spawn('codex', ['mcp', 'list', '--json'], {
      cwd,
      env: {
        PATH: process.env.PATH ?? '/opt/homebrew/bin:/usr/bin:/bin',
        HOME: home,
        CODEX_HOME: home,
        TMPDIR: home,
        LANG: 'C',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let finished = false;
    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(alarm);
      if (error) reject(error);
      else resolve(value);
    };
    const alarm = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new Error('Codex MCP config listing timed out'));
    }, 10000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (part) => { stdout = (stdout + part).slice(-8000); });
    child.stderr.on('data', (part) => { stderr = (stderr + part).slice(-1000); });
    child.once('error', (error) => finish(error));
    child.once('close', (code) => {
      if (code !== 0) finish(new Error(`Codex MCP config listing failed: ${stderr}`));
      else finish(null, JSON.parse(stdout));
    });
  });
}

async function main() {
  const temp = await mkdtemp(join(tmpdir(), 'cybermeters-codex-isolation-'));
  try {
    const home = join(temp, 'codex-home');
    await mkdir(home);
    await writeFile(join(home, 'config.toml'),
      'mcp_oauth_credentials_store = "file"\n' +
      'cli_auth_credentials_store = "ephemeral"\n' +
      'check_for_update_on_startup = false\n' +
      '[mcp_servers.cybermeters_isolation_canary]\n' +
      'url = "http://127.0.0.1:1/mcp"\n');
    const entries = await listIsolatedMcpServers({ cwd: temp, home });
    assert.ok(Array.isArray(entries));
    assert.deepEqual(entries.map(({ name }) => name), ['cybermeters_isolation_canary'],
      'Codex loaded an MCP server outside its disposable home');
    process.stdout.write('PASS: Codex CLI sees only its disposable MCP config (no connection attempted)\n');
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`FAIL: ${error.stack ?? error}\n`);
  process.exitCode = 1;
});
