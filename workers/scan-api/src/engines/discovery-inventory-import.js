import { normalizeHostname, createCandidateCollector, exceedsUtf8Bytes } from './hostname-candidates.js';

export const DISCOVERY_IMPORT_SOURCE = 'customer_import';
export const DISCOVERY_IMPORT_LIMITS = Object.freeze({ maxInputBytes: 262144, maxEntries: 5000, maxCandidates: 200 });

// Parses caller-supplied text only. The caller must authenticate the upload and
// supply an authorized root. A listed name is a candidate, never scan consent.
// Supported formats: one FQDN per line, CSV with a hostname/domain/name column,
// and the ordinary owner/TTL/IN/type subset of a DNS master file. Includes and
// generated records are deliberately unsupported; no file or network is read.
export function importDiscoveryInventory(text, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const format = opts.format ?? 'list';
  const root = normalizeHostname(opts.domain);
  const collector = createCandidateCollector({ domain: root, observedAt: opts.observedAt,
    maxCandidates: DISCOVERY_IMPORT_LIMITS.maxCandidates, maxInputBytes: DISCOVERY_IMPORT_LIMITS.maxInputBytes });
  const reasons = new Set();
  let examined = 0;
  const reject = reason => { collector.reject(); reasons.add(reason); };
  const result = () => ({ ...collector.result(), import_format: format,
    entries_examined: examined, rejected_reasons: [...reasons].sort() });
  if (!root) { reject('invalid_domain'); return result(); }
  if (!['list', 'csv', 'zone'].includes(format)) { reject('unsupported_format'); return result(); }
  if (typeof text !== 'string') { reject('invalid_input'); return result(); }
  if (exceedsUtf8Bytes(text, DISCOVERY_IMPORT_LIMITS.maxInputBytes)) {
    collector.truncate(); reasons.add('input_byte_limit'); return result();
  }
  const admit = hostname => {
    if (examined >= DISCOVERY_IMPORT_LIMITS.maxEntries) { collector.truncate(); return; }
    examined++;
    collector.add(hostname, DISCOVERY_IMPORT_SOURCE);
  };
  text = text.replace(/^\uFEFF/, '');
  if (format === 'list') {
    for (const line of text.split(/\r?\n/)) {
      const value = line.trim();
      if (value && !value.startsWith('#')) admit(value);
    }
  } else if (format === 'csv') {
    const rows = csvRows(text);
    if (!rows) { reject('malformed_csv'); return result(); }
    const header = rows.shift()?.map(value => value.trim().toLowerCase()) || [];
    const columns = header.flatMap((name, index) => ['hostname', 'domain', 'name'].includes(name) ? [index] : []);
    if (columns.length !== 1) { reject('ambiguous_csv_header'); return result(); }
    for (const row of rows) {
      if (row.every(value => !value.trim())) continue;
      if (row.length !== header.length) { reject('invalid_csv_row'); continue; }
      admit(row[columns[0]]);
    }
  } else {
    const records = zoneRecords(text);
    if (!records) { reject('malformed_zone'); return result(); }
    let origin = root, previousOwner = null;
    for (const record of records) {
      const fields = record.text.match(/"(?:\\.|[^"\\])*"|[^\s]+/g) || [];
      if (!fields.length) continue;
      const directive = fields[0].toUpperCase();
      if (directive === '$ORIGIN') {
        const next = fields.length === 2 ? absoluteOwner(fields[1], origin) : null;
        if (!next || next.startsWith('*.')) { reject('invalid_origin'); origin = null; previousOwner = null; }
        else { origin = next; previousOwner = null; }
        continue;
      }
      if (directive === '$TTL') {
        if (fields.length !== 2 || !ttl(fields[1])) reject('invalid_ttl');
        continue;
      }
      if (directive.startsWith('$')) { reject('unsupported_zone_directive'); previousOwner = null; continue; }
      let owner;
      if (record.inherited) owner = previousOwner;
      else { owner = absoluteOwner(fields.shift(), origin); previousOwner = owner; }
      if (!owner) { reject('invalid_zone_owner'); continue; }
      // Class and TTL can appear in either order, once each.
      let seenClass = false, seenTtl = false;
      for (let i = 0; i < 2 && fields.length; i++) {
        if (!seenClass && fields[0].toUpperCase() === 'IN') { fields.shift(); seenClass = true; }
        else if (!seenTtl && ttl(fields[0])) { fields.shift(); seenTtl = true; }
        else break;
      }
      const type = fields.shift()?.toUpperCase();
      if (!ZONE_TYPES.has(type) || !fields.length) { reject('unsupported_zone_record'); continue; }
      // Owner names only: DNS targets and TXT text need their own source parsers.
      admit(owner);
    }
  }
  return result();
}

const ZONE_TYPES = new Set(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'SOA', 'CAA', 'PTR',
  'HTTPS', 'SVCB', 'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'TLSA', 'SSHFP', 'NAPTR']);
const ttl = value => typeof value === 'string' && /^(?:\d+[wdhms]?)+$/i.test(value);

function absoluteOwner(value, origin) {
  if (typeof value !== 'string' || !origin) return null;
  if (value === '@') return origin;
  if (value === '*') return `*.${origin}`;
  const wildcard = value.startsWith('*.');
  const raw = wildcard ? value.slice(2) : value;
  const name = normalizeHostname(raw.endsWith('.') ? raw : `${raw}.${origin}`);
  return name ? (wildcard ? `*.${name}` : name) : null;
}

// Strict small CSV reader: quoted fields, escaped double quotes and CRLF work;
// a malformed quotation rejects the whole document, never a repaired prefix.
function csvRows(text) {
  const rows = [], row = [];
  let field = '', quoted = false, closed = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else { quoted = false; closed = true; }
      } else field += c;
      continue;
    }
    if (c === '"') {
      if (field.length || closed) return null;
      quoted = true; continue;
    }
    if (c === ',' || c === '\n' || c === '\r') {
      row.push(field); field = ''; closed = false;
      if (c !== ',') {
        rows.push(row.splice(0));
        if (c === '\r' && text[i + 1] === '\n') i++;
      }
      continue;
    }
    if (closed) return null;
    field += c;
  }
  if (quoted) return null;
  if (field || row.length || closed) { row.push(field); rows.push(row); }
  return rows;
}

// Preserve leading whitespace (inherited owner), while ignoring semicolon
// comments and balanced multiline parentheses outside quoted RDATA.
function zoneRecords(text) {
  const records = [];
  let current = '', quoted = false, escaped = false, comment = false, depth = 0;
  const flush = () => {
    if (current.trim()) records.push({ text: current.trim(), inherited: /^\s/.test(current) });
    current = '';
  };
  for (const c of text.replace(/\r\n?/g, '\n')) {
    if (comment) {
      if (c !== '\n') continue;
      comment = false;
    }
    if (escaped) { current += c; escaped = false; continue; }
    if (c === '\\') { current += c; escaped = true; continue; }
    if (c === '"') { quoted = !quoted; current += c; continue; }
    if (!quoted && c === ';') { comment = true; continue; }
    if (!quoted && c === '(') { depth++; current += ' '; continue; }
    if (!quoted && c === ')') { if (!depth) return null; depth--; current += ' '; continue; }
    if (c === '\n' && !quoted) {
      if (depth) current += ' ';
      else flush();
    } else current += c;
  }
  if (quoted || escaped || depth) return null;
  flush();
  return records;
}
