#!/usr/bin/env node
//
// PR-5.5 Gate 4 — MIME peak-memory structure and audited parser exits.
//
// This validator intentionally does NOT claim to measure Cloudflare isolate
// memory in Node. It proves the retained-buffer envelope from source structure,
// kills the two required unsafe mutations, and drives malformed stream outcomes
// through the real inbound handler's Gate 3B required-audit contract.
//
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const inboundPath = path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "email",
  "inbound.js",
);
const inboundSource = fs.readFileSync(inboundPath, "utf8");
const {
  RUA_ATTACHMENT_MAX_BYTES,
  RUA_ENCODED_ATTACHMENT_MAX_BYTES,
  RUA_MAX_MIME_PARTS,
  RUA_MIME_BUFFER_MAX_BYTES,
  RUA_MIME_ENTITY_MAX_BYTES,
  RUA_MIME_HEADER_MAX_BYTES,
  RUA_PARSER_MAX_RETAINED_BYTES,
  RUA_RAW_EMAIL_MAX_BYTES,
  _base64ToBytes,
  handleInboundEmail,
  parseMimeMessageStream,
} = await import(pathToFileURL(inboundPath).href);

let pass = 0;
let fail = 0;
const ok = (name, condition) => {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.log(`FAIL ${name}`);
  }
};

function namedEnvelopeHolds(source) {
  return /const RUA_RAW_EMAIL_MAX_BYTES\s+=/.test(source) &&
    /const RUA_MIME_HEADER_MAX_BYTES\s+=/.test(source) &&
    /const RUA_MAX_MIME_PARTS\s+=/.test(source) &&
    /const RUA_ENCODED_ATTACHMENT_MAX_BYTES\s+=/.test(source) &&
    /const RUA_ATTACHMENT_MAX_BYTES\s+=/.test(source) &&
    /const RUA_MIME_BUFFER_MAX_BYTES\s+=/.test(source) &&
    /message\.rawSize > RUA_RAW_EMAIL_MAX_BYTES/.test(source) &&
    /rootHeaderBuffer\.length \+ text\.length > RUA_MIME_HEADER_MAX_BYTES/.test(source) &&
    /state\.entityCount > RUA_MAX_MIME_PARTS/.test(source) &&
    /leafLength > RUA_ENCODED_ATTACHMENT_MAX_BYTES/.test(source) &&
    /decodedLength > maxDecodedBytes/.test(source);
}

function noWholeBodyMaterialisation(source) {
  const parserStart = source.indexOf("// ── bounded streaming MIME parsing");
  const parserEnd = source.indexOf("// Public mailbox domains", parserStart);
  const parser = parserStart >= 0 && parserEnd > parserStart
    ? source.slice(parserStart, parserEnd)
    : source;
  return !/(?:body|rawLatin1|rawText)\s*\.split\s*\(\s*["'`]--/.test(source) &&
    !/\.split\s*\(\s*["'`]--["'`]\s*\+\s*boundary/.test(source) &&
    !/readStreamCapped/.test(source) &&
    !/chunks\.push\(value\)[\s\S]{0,300}new Uint8Array\(total\)/.test(parser);
}

function onePartBufferInvariant(source) {
  return /class StreamingMultipartParser/.test(source) &&
    /this\.buffer\.length \+ text\.length > RUA_MIME_BUFFER_MAX_BYTES/.test(source) &&
    /this\.searchFrom = Math\.max\(0, this\.buffer\.length - this\.marker\.length - 4\)/.test(
      source,
    ) &&
    /if \(state\.parts\.length\)/.test(source) &&
    /throw new Error\("multiple_tlsrpt_attachments"\)/.test(source) &&
    /throw new Error\("multiple_dmarc_attachments"\)/.test(source) &&
    /throw new Error\("unsupported_nested_multipart"\)/.test(source) &&
    !/_parseMultipartBody/.test(source);
}

function decodePreflightOrder(source) {
  const start = source.indexOf("function _base64ToBytes(");
  const end = source.indexOf("\nfunction _readU16", start);
  if (start < 0 || end < 0) return false;
  const body = source.slice(start, end);
  const encodedGuard = body.indexOf("end - start > maxEncodedBytes");
  const decodedGuard = body.indexOf("decodedLength > maxDecodedBytes");
  const allocation = body.indexOf("new Uint8Array(decodedLength)");
  const decode = body.indexOf("atob(");
  return encodedGuard >= 0 && decodedGuard > encodedGuard &&
    allocation > decodedGuard && decode > allocation;
}

function auditedExitContract(source) {
  const reasons = [
    "stream_read_error",
    "truncated_mime",
    "unterminated_multipart",
    "header_too_large",
    "multiple_tlsrpt_attachments",
    "invalid_base64",
  ];
  return reasons.every((reason) => source.includes(`case "${reason}"`)) &&
    /parsedMessage = await parseMimeMessageStream\([\s\S]*?catch \(error\) \{\s*await drop\(endpoint, error\?\.message \|\| "parse_error", recipient\);\s*return;/.test(
      source,
    ) &&
    /event_type: "dmarc_inbound_email_dropped"[\s\S]*?required: true/.test(source);
}

ok("named raw/header/part/encoded/decoded limits are wired",
  namedEnvelopeHolds(inboundSource));
ok("no whole-body boundary split or full raw-message chunk join remains",
  noWholeBodyMaterialisation(inboundSource));
ok("one bounded MIME entity and one report candidate are the structural maximum",
  onePartBufferInvariant(inboundSource));
ok("encoded and decoded base64 preflights precede allocation and decoding",
  decodePreflightOrder(inboundSource));
ok("all required parser exits use the Gate 3B audited terminal contract",
  auditedExitContract(inboundSource));

ok("raw envelope is lower than the former 25 MiB ceiling",
  RUA_RAW_EMAIL_MAX_BYTES === 4 * 1024 * 1024);
ok("header, part and encoded limits are concrete named bounds",
  RUA_MIME_HEADER_MAX_BYTES === 64 * 1024 &&
    RUA_MAX_MIME_PARTS === 25 &&
    RUA_ENCODED_ATTACHMENT_MAX_BYTES === 3 * 1024 * 1024);
ok("maximum retained MIME buffer is algebraically bounded",
  RUA_MIME_BUFFER_MAX_BYTES > RUA_MIME_ENTITY_MAX_BYTES &&
    RUA_MIME_BUFFER_MAX_BYTES <
      RUA_MIME_ENTITY_MAX_BYTES + 64 * 1024);
ok("conservative retained-buffer envelope is derived only from named caps",
  RUA_PARSER_MAX_RETAINED_BYTES > RUA_RAW_EMAIL_MAX_BYTES &&
    RUA_PARSER_MAX_RETAINED_BYTES < 20 * 1024 * 1024);
ok("decoded attachment ceiling remains 2 MiB",
  RUA_ATTACHMENT_MAX_BYTES === 2 * 1024 * 1024);

// Required mutation 1: restoring whole-body split must turn this validator red.
const splitMutation = `${inboundSource}\nfunction unsafeGate4Mutation(body, boundary) {\n` +
  `  return body.split("--" + boundary);\n}\n`;
ok("whole-body split mutation changes source", splitMutation !== inboundSource);
ok("whole-body split mutation is killed", !noWholeBodyMaterialisation(splitMutation));

// Required mutation 2: decoding before the length preflight must turn red.
const decodeMutation = inboundSource.replace(
  '  if (typeof input !== "string" || start < 0 || end < start ||',
  '  atob(input);\n  if (typeof input !== "string" || start < 0 || end < start ||',
);
ok("decode-before-length-check mutation changes source",
  decodeMutation !== inboundSource);
ok("decode-before-length-check mutation is killed",
  !decodePreflightOrder(decodeMutation));

// A tiny runtime control proves decoded length rejection uses the same public
// helper. The structural order above, not Node memory behaviour, is the proof.
let decodedLimitReason = null;
try { _base64ToBytes("QUJD", 2, 16); }
catch (error) { decodedLimitReason = error?.message; }
ok("decoded-size overflow fails before returning bytes",
  decodedLimitReason === "attachment_too_large");

function makeDb() {
  const endpoint = {
    id: "ep_gate4",
    workspace_id: "ws_gate4",
    domain: "victim.example",
    domain_id: "domain_gate4",
    address_local: "cmrua_gate4abcd",
    status: "active",
    is_active: 1,
  };
  const audits = [];
  return {
    endpoint,
    audits,
    prepare(sql) {
      let args = [];
      const kind = /FROM dmarc_ingest_endpoints/.test(sql)
        ? "endpoint"
        : /INSERT INTO audit_events/.test(sql)
          ? "audit"
          : /FROM notification_events/.test(sql)
            ? "notification_lookup"
            : "other";
      return {
        bind(...values) {
          args = values;
          return this;
        },
        async first() {
          if (kind === "endpoint") return endpoint;
          return null;
        },
        async run() {
          if (kind === "audit") {
            audits.push({
              event_type: args[4],
              metadata: args[8] ? JSON.parse(args[8]) : null,
            });
          }
          return { meta: { changes: 1 } };
        },
        async all() {
          return { results: [] };
        },
      };
    },
    async batch(statements) {
      return Promise.all(statements.map((statement) => statement.run()));
    },
  };
}

function streamFromText(text, chunkBytes = 1024) {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
        controller.enqueue(bytes.subarray(offset, offset + chunkBytes));
      }
      controller.close();
    },
  });
}

function messageWithRaw(raw, rawSize = null) {
  return {
    to: "cmrua_gate4abcd@reports.cybermeters.com",
    from: "attacker@example.net",
    rawSize,
    raw,
  };
}

async function invokeMalformed(message) {
  const db = makeDb();
  let thrown = null;
  try {
    await handleInboundEmail(message, {
      cybermeters_db: db,
      RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
      APP_VERSION: "gate4-validator",
      FRONTEND_URL: "https://app.cybermeters.com",
      RESEND_API_KEY: "",
    }, {}, {
      rateLimitScopeId: async () => "scope_gate4",
      consumeApiRateLimit: async () => false,
    });
  } catch (error) {
    thrown = error;
  }
  const terminal = db.audits.find((event) =>
    event.event_type === "dmarc_inbound_email_dropped");
  return { db, thrown, reason: terminal?.metadata?.reason || null };
}

async function expectAudited(name, message, reason) {
  const result = await invokeMalformed(message);
  ok(`${name} does not escape as an unhandled parser error`, result.thrown == null);
  ok(`${name} records the explicit required terminal audit`,
    result.reason === reason);
}

// Conceptual hostile envelope: it is not materialised in this Node process.
// The raw-size preflight must reject a declared 25 MiB multipart/base64 message
// before acquiring or reading its stream.
let rawAccessed = false;
const hostileEnvelope = {
  to: "cmrua_gate4abcd@reports.cybermeters.com",
  from: "attacker@example.net",
  rawSize: 25 * 1024 * 1024,
  get raw() {
    rawAccessed = true;
    throw new Error("raw stream must not be acquired");
  },
};
await expectAudited(
  "declared 25 MiB multi-boundary/base64 envelope",
  hostileEnvelope,
  "email_too_large",
);
ok("25 MiB envelope is rejected before raw stream acquisition", !rawAccessed);

const streamError = new ReadableStream({
  pull(controller) {
    controller.error(new Error("injected stream failure"));
  },
});
await expectAudited(
  "stream read failure",
  messageWithRaw(streamError, 100),
  "stream_read_error",
);

await expectAudited(
  "truncated MIME part without a header/body separator",
  messageWithRaw(streamFromText(
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
    "--b\r\nContent-Type: application/tlsrpt+json\r\n--b--\r\n",
  ), 120),
  "truncated_mime",
);

await expectAudited(
  "unterminated multipart boundary",
  messageWithRaw(streamFromText(
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
    "--b\r\nContent-Type: application/tlsrpt+json\r\n\r\n{}\r\n",
  ), 120),
  "unterminated_multipart",
);

await expectAudited(
  "oversized root MIME header",
  messageWithRaw(streamFromText(
    `X-Attacker: ${"a".repeat(RUA_MIME_HEADER_MAX_BYTES + 1)}`,
  ), RUA_MIME_HEADER_MAX_BYTES + 20),
  "header_too_large",
);

const tlsPart = (body) =>
  "--b\r\nContent-Type: application/tlsrpt+json; name=\"r.json\"\r\n" +
  "Content-Disposition: attachment; filename=\"r.json\"\r\n" +
  "Content-Transfer-Encoding: base64\r\n\r\n" +
  `${body}\r\n`;
await expectAudited(
  "oversized attachment MIME header",
  messageWithRaw(streamFromText(
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
    `--b\r\nX-Attacker: ${"a".repeat(RUA_MIME_HEADER_MAX_BYTES + 1)}` +
    "\r\n\r\nignored\r\n--b--\r\n",
  ), RUA_MIME_HEADER_MAX_BYTES + 200),
  "header_too_large",
);

await expectAudited(
  "ambiguous multiple TLS-RPT attachments",
  messageWithRaw(streamFromText(
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
    tlsPart("e30=") + tlsPart("e30=") + "--b--\r\n",
  ), 500),
  "multiple_tlsrpt_attachments",
);

await expectAudited(
  "invalid base64 attachment",
  messageWithRaw(streamFromText(
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
    tlsPart("%%%=") + "--b--\r\n",
  ), 300),
  "invalid_base64",
);

const invalidDmarcXml = btoa("<feedback></feedback>");
await expectAudited(
  "strict DMARC XML schema failure",
  messageWithRaw(streamFromText(
    "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
    "--b\r\nContent-Type: application/xml; name=\"r.xml\"\r\n" +
    "Content-Disposition: attachment; filename=\"r.xml\"\r\n" +
    "Content-Transfer-Encoding: base64\r\n\r\n" +
    `${invalidDmarcXml}\r\n--b--\r\n`,
  ), 400),
  "parse_error",
);

const tooManyParts = [
  "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
  ...Array.from({ length: RUA_MAX_MIME_PARTS + 1 }, (_, index) =>
    `--b\r\nContent-Type: text/plain\r\n\r\npart-${index}\r\n`),
  "--b--\r\n",
].join("");
await expectAudited(
  "part-count overflow",
  messageWithRaw(streamFromText(tooManyParts, 37), tooManyParts.length),
  "mime_complexity_exceeded",
);

// Direct stream parser sanity: a small valid multipart retains one candidate
// and reports a maximum buffer below the named structural ceiling.
const validMime = "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
  tlsPart("e30=") + "--b--\r\n";
const parsed = await parseMimeMessageStream(streamFromText(validMime, 17));
ok("stream parser retains exactly one decoded candidate", parsed.parts.length === 1);
ok("reported retained MIME buffer stays below its named ceiling",
  parsed.stats.max_buffered_bytes <= RUA_MIME_BUFFER_MAX_BYTES);

const splitBoundaryPrefix = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b";
const splitBoundarySuffix =
  "\r\nContent-Type: application/tlsrpt+json; name=\"r.json\"\r\n" +
  "Content-Disposition: attachment; filename=\"r.json\"\r\n" +
  "Content-Transfer-Encoding: base64\r\n\r\ne30=\r\n--b--\r\n";
const boundarySplitStream = new ReadableStream({
  start(controller) {
    controller.enqueue(new TextEncoder().encode(splitBoundaryPrefix));
    controller.enqueue(new TextEncoder().encode(splitBoundarySuffix));
    controller.close();
  },
});
const splitBoundaryParsed = await parseMimeMessageStream(boundarySplitStream);
ok("MIME delimiter split immediately after its marker is processed incrementally",
  splitBoundaryParsed.parts.length === 1);

console.log(`\nEmail parser hardening: ${pass}/${pass + fail} passed`);
if (fail) {
  console.error("email-parser-hardening validation FAILED");
  process.exit(1);
}
console.log("email-parser-hardening validation passed");
