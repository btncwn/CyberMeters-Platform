// AWS Signature Version 4 request signing (Web Crypto only, no SDK).
//
// Used for read-only calls to a customer's AWS account through a role the
// customer created for CyberMeters. Only what those calls need is supported:
// GET or POST, query string or form/JSON body, and an optional session token.
// Reference: the AWS SigV4 signing process (canonical request, string to sign,
// derived signing key); checked against the published examples in
// scripts/validate-aws-sigv4.js.

const encoder = new TextEncoder();

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(data) {
  return hex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? encoder.encode(data) : data));
}

async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", typeof key === "string" ? encoder.encode(key) : key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, encoder.encode(data));
}

// RFC 3986 unreserved characters stay; everything else is percent-encoded.
export function awsUriEncode(value, { encodeSlash = true } = {}) {
  let out = "";
  for (const byte of encoder.encode(String(value))) {
    const c = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-._~]/.test(c) || (!encodeSlash && c === "/")) out += c;
    else out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

function canonicalQuery(searchParams) {
  return [...searchParams.entries()]
    .map(([k, v]) => [awsUriEncode(k), awsUriEncode(v)])
    .sort(([ak, av], [bk, bv]) => (ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

/** "20150830T123600Z" for a Date. */
export function amzDate(date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

/**
 * Sign a request. Returns the headers to send (including Authorization).
 *   method, url, region, service, body (string, may be ""),
 *   credentials { accessKeyId, secretAccessKey, sessionToken? },
 *   headers (extra headers to sign, lower-case names), date (Date)
 */
export async function signAwsRequest({ method, url, region, service, body = "", credentials, headers = {}, date = new Date() }) {
  if (!credentials?.accessKeyId || !credentials?.secretAccessKey) throw new Error("AWS credentials are required");
  const u = new URL(url);
  const stamp = amzDate(date);
  const day = stamp.slice(0, 8);
  const payloadHash = await sha256Hex(body);

  const toSign = { ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)])), host: u.host, "x-amz-date": stamp };
  if (credentials.sessionToken) toSign["x-amz-security-token"] = credentials.sessionToken;
  const names = Object.keys(toSign).sort();
  const canonicalHeaders = names.map((n) => `${n}:${toSign[n].trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const path = u.pathname === "" ? "/" : awsUriEncode(decodeURIComponent(u.pathname), { encodeSlash: false });

  const canonicalRequest = [method.toUpperCase(), path, canonicalQuery(u.searchParams), canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${day}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", stamp, scope, await sha256Hex(canonicalRequest)].join("\n");

  let key = await hmac(`AWS4${credentials.secretAccessKey}`, day);
  key = await hmac(key, region);
  key = await hmac(key, service);
  key = await hmac(key, "aws4_request");
  const signature = hex(await hmac(key, stringToSign));

  const out = { ...toSign };
  delete out.host;
  out.authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: out, canonicalRequest, stringToSign, signature };
}
