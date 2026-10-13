// Standalone Node program copied into the private probe container at build time.
// Only this parent process owns DNS and TCP. The compiled TLS engines exchange
// framed bytes over stdio and cannot choose or resolve another destination.
import { resolve4, resolve6 } from 'node:dns/promises';
import { connect, isIP } from 'node:net';
import { spawn } from 'node:child_process';

const FRAME = Object.freeze({ CONNECT: 1, SEND: 2, RESULT: 3, CLOSE: 4, CONNECTED: 1, RECEIVED: 2, CLOSED: 4, ABORT: 5 });
const MAX_FRAME = 262144;
const MAX_LINE = 4096;
const MAX_STARTTLS_BYTES = 8192;
const CONNECT_TIMEOUT_MS = 4000;
const DNS_TIMEOUT_MS = 4000;
const CHECK_TIMEOUT_MS = 12000;
const MAX_WIRE_OVERREAD = 65536;
const CONNECTION_BINARY = Object.freeze({
  legacy: '/opt/cybermeters/tls-baseline-legacy',
  modern: '/opt/cybermeters/tls-baseline-modern',
});
const activeControls = new Set(['heartbleed', 'robot', 'ccs']);
const productControl = Object.freeze({ protocol:'handshake',cipher:'handshake',key_exchange:'handshake',certificate:'certificate',ocsp:'certificate',compression:'compression',secure_renegotiation:'renegotiation',fallback_scsv:'fallback',extended_master_secret:'handshake',session_resumption:'resumption',early_data:'resumption',sni_alpn:'handshake',heartbleed:'heartbleed',robot:'robot',ccs:'ccs' });

function ipKey(value) {
  if (isIP(value) === 4) return value;
  if (isIP(value) === 6) return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  return null;
}
function publicAddress(value) {
  if (isIP(value) === 4) {
    const [a, b, c] = value.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113));
  }
  if (isIP(value) === 6) {
    const normalized = ipKey(value);
    const halves = normalized.split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const words = (halves.length === 2 ? [...left,...Array(8-left.length-right.length).fill('0'),...right] : left).map(x => parseInt(x, 16));
    if (words.length !== 8 || words.some(x => !Number.isInteger(x))) return false;
    return (words[0] & 0xe000) === 0x2000 &&
      !(words[0] === 0x2001 && (words[1] < 0x200 || words[1] === 0xdb8)) &&
      words[0] !== 0x2002 && !(words[0] === 0x3fff && words[1] < 0x1000);
  }
  return false;
}
function limited(promise, ms, signal) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); }),
    new Promise((_, reject) => {
      if (signal?.aborted) reject(new Error('aborted'));
      else signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    }),
  ]).finally(() => clearTimeout(timer));
}
async function recheckDns(endpoint, signal) {
  const expected = ipKey(endpoint.address);
  const authorized = new Set(endpoint.dns_addresses.map(ipKey));
  if (!expected || !publicAddress(endpoint.address) || !authorized.has(expected)) throw new Error('scope_invalid');
  const [a, aaaa] = await limited(Promise.allSettled([resolve4(endpoint.hostname), resolve6(endpoint.hostname)]), DNS_TIMEOUT_MS, signal);
  const answers = [...(a.status === 'fulfilled' ? a.value : []), ...(aaaa.status === 'fulfilled' ? aaaa.value : [])];
  if (!answers.some(value => ipKey(value) === expected)) throw new Error('dns_authority_changed');
  return expected;
}
function frame(type, payload = Buffer.alloc(0)) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const out = Buffer.allocUnsafe(5 + data.length);
  out[0] = type;
  out.writeUInt32BE(data.length, 1);
  data.copy(out, 5);
  return out;
}
function parseFrames(state, chunk) {
  state.pending = Buffer.concat([state.pending, chunk]);
  if (state.pending.length > MAX_FRAME + 5 + 16384) throw new Error('engine_frame_overflow');
  const frames = [];
  while (state.pending.length >= 5) {
    const size = state.pending.readUInt32BE(1);
    if (size > MAX_FRAME) throw new Error('engine_frame_limit');
    if (state.pending.length < 5 + size) break;
    frames.push({ type: state.pending[0], payload: state.pending.subarray(5, 5 + size) });
    state.pending = state.pending.subarray(5 + size);
  }
  return frames;
}
function socketLineReader(socket, budget, signal) {
  let pending = Buffer.alloc(0);
  let answer = null;
  const onData = chunk => {
    budget.bytes_received += chunk.length;
    if (budget.bytes_sent + budget.bytes_received > budget.max_bytes + MAX_WIRE_OVERREAD) { answer?.reject(new Error('byte_budget')); socket.destroy(); return; }
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > MAX_STARTTLS_BYTES) { answer?.reject(new Error('starttls_response_limit')); socket.destroy(); return; }
    const pos = pending.indexOf('\n');
    if (pos >= 0 && answer) {
      const line = pending.subarray(0, pos + 1).toString('ascii');
      pending = pending.subarray(pos + 1);
      const current = answer; answer = null; current.resolve(line);
    }
  };
  socket.on('data', onData);
  return {
    async line() {
      const pos = pending.indexOf('\n');
      if (pos >= 0) { const line = pending.subarray(0, pos + 1).toString('ascii'); pending = pending.subarray(pos + 1); return line; }
      return limited(new Promise((resolve, reject) => { answer = { resolve, reject }; }), 3000, signal);
    },
    detach() { socket.off('data', onData); if (pending.length) throw new Error('starttls_unexpected_bytes'); },
  };
}
async function starttls(socket, application, budget, signal) {
  if (!['smtp','imap','pop3'].includes(application)) return;
  const reader = socketLineReader(socket, budget, signal);
  let lines = 0;
  const next = async () => { if (++lines > 20) throw new Error('starttls_line_limit'); const line = await reader.line(); if (line.length > MAX_LINE || /[^\x09\x0a\x0d\x20-\x7e]/.test(line)) throw new Error('starttls_non_ascii'); return line; };
  const send = line => { const data = Buffer.from(line, 'ascii'); budget.bytes_sent += data.length; if (budget.bytes_sent + budget.bytes_received > budget.max_bytes) throw new Error('byte_budget'); socket.write(data); };
  try {
    if (application === 'smtp') {
      let greeting = await next(); while (/^220-/.test(greeting)) greeting = await next();
      if (!/^220[ \r]/.test(greeting)) throw new Error('starttls_greeting');
      send('EHLO scanner.cybermeters.com\r\n');
      let hasStarttls = false, line;
      do { line = await next(); if (/^250[- ]STARTTLS\r?\n$/i.test(line)) hasStarttls = true; } while (/^250-/.test(line));
      if (!/^250[ \r]/.test(line) || !hasStarttls) throw new Error('starttls_unavailable');
      send('STARTTLS\r\n'); if (!/^220[ \r]/.test(await next())) throw new Error('starttls_rejected');
    } else if (application === 'imap') {
      if (!/^\* OK[ \r]/i.test(await next())) throw new Error('starttls_greeting');
      send('a001 CAPABILITY\r\n'); let hasStarttls = false, line;
      do { line = await next(); if (/^\* CAPABILITY\b.*\bSTARTTLS\b/i.test(line)) hasStarttls = true; } while (!/^a001 (OK|NO|BAD)\b/i.test(line));
      if (!/^a001 OK\b/i.test(line) || !hasStarttls) throw new Error('starttls_unavailable');
      send('a002 STARTTLS\r\n'); if (!/^a002 OK\b/i.test(await next())) throw new Error('starttls_rejected');
    } else {
      if (!/^\+OK[ \r]/i.test(await next())) throw new Error('starttls_greeting');
      send('STLS\r\n'); if (!/^\+OK[ \r]/i.test(await next())) throw new Error('starttls_rejected');
    }
    reader.detach();
  } catch (error) { reader.detach(); throw error; }
}
function engineCommand(input, check, maxConnections) {
  const binary = activeControls.has(check.control) || check.control === 'compression' ? CONNECTION_BINARY.legacy
    : check.protocol === 'tls1_3' ? CONNECTION_BINARY.modern
    : check.control === 'cipher' || ['ssl2','ssl3','tls1','tls1_1'].includes(check.protocol) ? CONNECTION_BINARY.legacy : CONNECTION_BINARY.modern;
  const args = ['--control',productControl[check.control],'--protocol',check.protocol,'--max-connections',String(maxConnections),
    '--hostname',input.endpoint.sni,'--alpn',input.endpoint.application_protocol === 'https' ? 'h2-http1' : 'none',
    '--trust-bundle','/opt/cybermeters/trust/ca-bundle.pem','--timeout-ms',String(Math.min(CHECK_TIMEOUT_MS, 25000))];
  if (check.cipher_id !== null) args.push('--cipher',check.cipher_id);
  return { binary, args };
}

export async function runTlsEngineCheck(input, check, budget, signal) {
  const { binary, args } = engineCommand(input, check, budget.max_connections - budget.connections);
  const child = spawn(binary, args, { stdio: ['pipe','pipe','ignore'], env: { PATH: '/usr/bin:/bin' }, shell: false });
  const parser = { pending: Buffer.alloc(0) };
  let phase = 'idle', socket = null, result = null, childError = null, lastClosed = false;
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, killed) => resolve({ code, killed })); });
  const write = (type, payload) => { if (child.stdin.destroyed) throw new Error('engine_stdin_closed'); child.stdin.write(frame(type, payload)); };
  const abort = () => { try { write(FRAME.ABORT); } catch {} socket?.destroy(); child.kill('SIGKILL'); };
  signal?.addEventListener('abort', abort, { once: true });
  const onClosed = reason => {
    if (phase !== 'connected' && phase !== 'closing') return;
    phase = 'idle'; lastClosed = true; socket?.removeAllListeners('data'); socket = null;
    try { write(FRAME.CLOSED, Buffer.from(reason)); } catch {}
  };
  const onFrame = async ({ type, payload }) => {
    if (type === FRAME.CONNECT) {
      if (payload.length !== 0 || phase !== 'idle' || budget.connections >= budget.max_connections) throw new Error('engine_connect_invalid');
      phase = 'connecting'; lastClosed = false;
      await recheckDns(input.endpoint, signal);
      budget.connections++;
      const family = isIP(input.endpoint.address);
      socket = connect({ host: input.endpoint.address, port: input.endpoint.port, family, allowHalfOpen: false });
      socket.setNoDelay(true);
      socket.setTimeout(CONNECT_TIMEOUT_MS);
      try {
        await limited(new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); }), CONNECT_TIMEOUT_MS, signal);
        if (ipKey(socket.remoteAddress) !== ipKey(input.endpoint.address)) throw new Error('peer_mismatch');
        await starttls(socket, input.endpoint.application_protocol, budget, signal);
      } catch {
        socket.destroy(); socket = null; phase = 'idle'; write(FRAME.CLOSED, Buffer.from('connect_failed')); return;
      }
      phase = 'connected';
      socket.on('data', chunk => {
        budget.bytes_received += chunk.length;
        if (budget.bytes_sent + budget.bytes_received > budget.max_bytes + MAX_WIRE_OVERREAD) { socket?.destroy(); onClosed('budget'); return; }
        for (let at = 0; at < chunk.length; at += 16384) write(FRAME.RECEIVED, chunk.subarray(at, at + 16384));
      });
      socket.once('timeout', () => { socket?.destroy(); onClosed('timeout'); });
      socket.once('end', () => onClosed('eof'));
      socket.once('error', () => onClosed('eof'));
      write(FRAME.CONNECTED);
    } else if (type === FRAME.SEND) {
      if (phase !== 'connected' || payload.length < 1 || payload.length > 16384) throw new Error('engine_send_invalid');
      if (budget.bytes_sent + budget.bytes_received + payload.length > budget.max_bytes) { socket?.destroy(); onClosed('budget'); return; }
      budget.bytes_sent += payload.length; socket.write(payload);
    } else if (type === FRAME.CLOSE) {
      // Peer EOF and child CLOSE can cross in the pipes. CLOSED was already
      // delivered, so the child will consume that barrier; allow one late CLOSE.
      if (payload.length === 0 && phase === 'idle' && lastClosed) { lastClosed = false; return; }
      if (payload.length !== 0 || phase !== 'connected') throw new Error('engine_close_invalid');
      phase = 'closing'; socket.destroy(); onClosed('eof');
    } else if (type === FRAME.RESULT) {
      if (result !== null || payload.length < 1 || payload.length > 262144 || phase !== 'idle') throw new Error('engine_result_invalid');
      result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
    } else throw new Error('engine_frame_invalid');
  };
  const timeout = setTimeout(abort, CHECK_TIMEOUT_MS);
  try {
    for await (const chunk of child.stdout) {
      for (const f of parseFrames(parser, chunk)) await onFrame(f);
      if (result !== null) break;
    }
    const status = await done;
    if (status.code !== 0 || !result || parser.pending.length || signal?.aborted) throw new Error('engine_incomplete');
    return result;
  } catch (error) { childError = error; abort(); throw error; }
  finally { clearTimeout(timeout); signal?.removeEventListener('abort', abort); socket?.destroy(); if (childError) child.kill('SIGKILL'); }
}

export async function __runTlsCollector(input) {
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.max(1, Date.parse(input.deadline_at) - Date.now()));
  const budget = { max_connections: input.max_connections, max_bytes: input.max_bytes, connections: 0, bytes_sent: 0, bytes_received: 0 };
  const results = [];
  try {
    for (const check of input.checks) {
      const before = { connections: budget.connections, bytes_sent: budget.bytes_sent, bytes_received: budget.bytes_received };
      const checkStarted = Date.now();
      if (controller.signal.aborted || budget.connections >= budget.max_connections || budget.bytes_sent + budget.bytes_received >= budget.max_bytes) {
        results.push({ check, engine_result: null, reason: 'budget_exhausted', observed_at: new Date().toISOString(), physical_telemetry: { connections: 0, bytes_sent: 0, bytes_received: 0, duration_ms: 0 } }); continue;
      }
      let engineResult = null, reason = null;
      try { engineResult = await runTlsEngineCheck(input, check, budget, controller.signal); }
      catch (error) { reason = controller.signal.aborted ? 'deadline_exhausted'
        : error?.message === 'dns_authority_changed' || error?.message === 'scope_invalid'
          ? 'dns_authority_changed' : 'engine_unavailable'; }
      results.push({ check, engine_result: engineResult, reason, observed_at: new Date().toISOString(),
        physical_telemetry: { connections: budget.connections - before.connections, bytes_sent: budget.bytes_sent - before.bytes_sent,
          bytes_received: budget.bytes_received - before.bytes_received, duration_ms: Date.now() - checkStarted } });
    }
  } finally { clearTimeout(timeout); }
  return { schema_version: 'tls-collector-raw-v1', request_id: input.request_id, started_at: new Date(started).toISOString(),
    finished_at: new Date().toISOString(), results, telemetry: { connections: budget.connections, bytes_sent: budget.bytes_sent,
      bytes_received: budget.bytes_received, duration_ms: Date.now() - started } };
}
