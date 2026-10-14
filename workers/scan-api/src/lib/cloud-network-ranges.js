// Address and range parsing for the provider network lookup, plus the
// provider catalogue. No data import: the build script uses this module too.

export const NETWORK_PROVIDERS = Object.freeze({
  aws: Object.freeze({ label: "Amazon Web Services", kind: "cloud" }),
  azure: Object.freeze({ label: "Microsoft Azure", kind: "cloud" }),
  gcp: Object.freeze({ label: "Google Cloud", kind: "cloud" }),
  cloudflare: Object.freeze({ label: "Cloudflare", kind: "edge" }),
});

// Ranges a provider operates in FRONT of other servers (content delivery,
// proxies): the address is the edge, not the server.
const EDGE_SERVICES = Object.freeze({ aws: new Set(["CLOUDFRONT", "GLOBALACCELERATOR"]) });

export function networkKind(provider, service) {
  if (EDGE_SERVICES[provider]?.has(String(service || ""))) return "edge";
  return NETWORK_PROVIDERS[provider]?.kind ?? "cloud";
}



const V4_BITS = 32;
const V6_BITS = 128;

function parseIpv4(text) {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

function parseIpv6(text) {
  if (!/^[0-9a-f:.]+$/i.test(text) || text.length > 45) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const words = (half) => {
    if (half === "") return [];
    const parts = half.split(":");
    const out = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (i === parts.length - 1 && part.includes(".")) {
        const v4 = parseIpv4(part);
        if (v4 == null) return null;
        out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
        out.push(parseInt(part, 16));
      }
    }
    return out;
  };
  const head = words(halves[0]);
  const tail = halves.length === 2 ? words(halves[1]) : [];
  if (head == null || tail == null) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...new Array(Math.max(0, missing)).fill(0), ...tail];
  let value = 0n;
  for (const word of all) value = (value << 16n) | BigInt(word);
  return value;
}

/** Parse an IP address. Returns { version, value } or null. */
export function parseIpAddress(input) {
  const text = String(input ?? "").trim().toLowerCase();
  if (!text || text.length > 45) return null;
  if (text.includes(":")) {
    const value = parseIpv6(text);
    return value == null ? null : { version: 6, value };
  }
  const value = parseIpv4(text);
  return value == null ? null : { version: 4, value };
}

function maskFor(version, bits) {
  const width = BigInt(version === 4 ? V4_BITS : V6_BITS);
  const all = (1n << width) - 1n;
  return bits === 0 ? 0n : (all >> (width - BigInt(bits))) << (width - BigInt(bits));
}

/** Parse "network/bits". Returns { version, bits, network } with host bits cleared, or null. */
export function parseCidr(input) {
  const [addr, bitsText, extra] = String(input ?? "").trim().split("/");
  if (extra !== undefined || !/^[0-9]{1,3}$/.test(bitsText || "")) return null;
  const ip = parseIpAddress(addr);
  if (!ip) return null;
  const bits = Number(bitsText);
  if (bits > (ip.version === 4 ? V4_BITS : V6_BITS)) return null;
  return { version: ip.version, bits, network: ip.value & maskFor(ip.version, bits) };
}

function formatIpv4(value) {
  return [24n, 16n, 8n, 0n].map((s) => String((value >> s) & 0xffn)).join(".");
}

function formatIpv6(value) {
  const words = [];
  for (let s = 112n; s >= 0n; s -= 16n) words.push(Number((value >> s) & 0xffffn));
  // Compress the longest run of zero words (length >= 2), leftmost on ties.
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = words.map((w) => w.toString(16));
  if (best < 0) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

/** Canonical "network/bits" text for a CIDR, or null when it does not parse. */
export function canonicalCidr(input) {
  const c = parseCidr(input);
  if (!c) return null;
  return `${c.version === 4 ? formatIpv4(c.network) : formatIpv6(c.network)}/${c.bits}`;
}

export { maskFor };
