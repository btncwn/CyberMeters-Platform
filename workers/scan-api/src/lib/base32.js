// ── Base32 codec ──
// RFC 4648 base32 encode/decode (used by TOTP). Extracted verbatim from index.js
// (monolith decomposition, Phase 1b). Behavior-preserving — no logic change.
const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf) {
  const bytes = new Uint8Array(buf);
  let bits = 0, value = 0, output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_CHARS[(value << (5 - bits)) & 0x1f];
  return output;
}

export function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[=\s]/g, "");
  let bits = 0, value = 0;
  const output = [];
  for (const char of clean) {
    const idx = BASE32_CHARS.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base32 character: ${char}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
