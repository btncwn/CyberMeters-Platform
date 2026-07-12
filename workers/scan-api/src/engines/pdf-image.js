// ── PDF raster-image preparation ──────────────────────────────────────────────
// Turns a data: URI logo into a PDF Image-XObject descriptor the raw-PDF builder
// can embed. Two paths, both self-contained (Workers-native streams, no deps):
//
//   • JPEG  → embedded verbatim via /DCTDecode (PDF understands JPEG natively).
//   • PNG   → inflated (DecompressionStream), de-filtered, alpha flattened over
//             the header band colour, re-deflated (CompressionStream) and embedded
//             as an 8-bit /DeviceRGB image with /FlateDecode.
//
// Anything else (SVG, WebP, 16-bit, interlaced, CMYK JPEG) returns null so the
// caller falls back to the text wordmark. Never throws.
//
// Returns { width, height, colorSpace, bitsPerComponent, filter, bytes } or null.

const MAX_PIXELS = 4_000_000; // guard against pathological logos

function dataUriToBytes(uri) {
  const m = /^data:(image\/[a-z.+-]+);base64,([A-Za-z0-9+/=]+)$/.exec(String(uri || ""));
  if (!m) return null;
  try {
    const bin = atob(m[2]);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return { mime: m[1], bytes: out };
  } catch { return null; }
}

function hexToRgb(hex) {
  const h = String(hex || "#00876A").replace("#", "");
  return [parseInt(h.slice(0, 2), 16) || 0, parseInt(h.slice(2, 4), 16) || 0, parseInt(h.slice(4, 6), 16) || 0];
}

async function inflate(u8) {
  const s = new Response(u8).body.pipeThrough(new DecompressionStream("deflate"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}
async function deflate(u8) {
  const s = new Response(u8).body.pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

// ── JPEG: read dimensions + component count from the first SOF marker ─────────
function parseJpeg(u8) {
  if (u8[0] !== 0xff || u8[1] !== 0xd8) return null; // SOI
  let i = 2;
  while (i + 9 < u8.length) {
    if (u8[i] !== 0xff) { i++; continue; }
    let marker = u8[i + 1];
    while (marker === 0xff && i + 1 < u8.length) { i++; marker = u8[i + 1]; } // skip fill
    // Standalone markers with no length payload.
    if (marker === 0xd8 || marker === 0xd9 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
    const len = (u8[i + 2] << 8) | u8[i + 3];
    // SOF0..SOF15 carry the frame header, excluding DHT(C4)/JPG(C8)/DAC(CC).
    const isSof = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
    if (isSof) {
      const height = (u8[i + 5] << 8) | u8[i + 6];
      const width = (u8[i + 7] << 8) | u8[i + 8];
      const components = u8[i + 9];
      return { width, height, components };
    }
    i += 2 + len;
  }
  return null;
}

async function prepareJpeg(bytes) {
  const sof = parseJpeg(bytes);
  if (!sof || !sof.width || !sof.height) return null;
  if (sof.width * sof.height > MAX_PIXELS) return null;
  const colorSpace = sof.components === 1 ? "DeviceGray" : sof.components === 3 ? "DeviceRGB" : null;
  if (!colorSpace) return null; // CMYK/YCCK — skip, fall back to text
  return { width: sof.width, height: sof.height, colorSpace, bitsPerComponent: 8, filter: "DCTDecode", bytes };
}

// ── PNG: full decode to flattened RGB ────────────────────────────────────────
function paeth(a, b, c) {
  const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

async function preparePng(bytes, bgHex) {
  // Signature
  const sig = [137, 80, 78, 71, 13, 10, 26, 10];
  for (let i = 0; i < 8; i++) if (bytes[i] !== sig[i]) return null;

  let width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
  let palette = null, trns = null;
  const idat = [];
  let p = 8;
  const u32 = (o) => ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
  while (p + 8 <= bytes.length) {
    const len = u32(p);
    const type = String.fromCharCode(bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]);
    const dataStart = p + 8;
    if (type === "IHDR") {
      width = u32(dataStart); height = u32(dataStart + 4);
      bitDepth = bytes[dataStart + 8]; colorType = bytes[dataStart + 9];
      interlace = bytes[dataStart + 12];
    } else if (type === "PLTE") {
      palette = bytes.subarray(dataStart, dataStart + len);
    } else if (type === "tRNS") {
      trns = bytes.subarray(dataStart, dataStart + len);
    } else if (type === "IDAT") {
      idat.push(bytes.subarray(dataStart, dataStart + len));
    } else if (type === "IEND") {
      break;
    }
    p = dataStart + len + 4; // skip data + CRC
  }

  if (!width || !height || bitDepth !== 8 || interlace !== 0) return null;
  if (width * height > MAX_PIXELS) return null;
  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[colorType];
  if (!channels) return null;
  if (colorType === 3 && !palette) return null;

  // Concatenate + inflate IDAT (zlib).
  let idatLen = 0; for (const c of idat) idatLen += c.length;
  const comp = new Uint8Array(idatLen);
  { let o = 0; for (const c of idat) { comp.set(c, o); o += c.length; } }
  let raw;
  try { raw = await inflate(comp); } catch { return null; }

  const stride = width * channels;
  if (raw.length < (stride + 1) * height) return null;

  // De-filter into a channel buffer.
  const chan = new Uint8Array(stride * height);
  const bpp = channels;
  for (let y = 0; y < height; y++) {
    const filt = raw[y * (stride + 1)];
    const rowIn = y * (stride + 1) + 1;
    const rowOut = y * stride;
    const prevOut = rowOut - stride;
    for (let x = 0; x < stride; x++) {
      const rawByte = raw[rowIn + x];
      const a = x >= bpp ? chan[rowOut + x - bpp] : 0;
      const b = y > 0 ? chan[prevOut + x] : 0;
      const c = x >= bpp && y > 0 ? chan[prevOut + x - bpp] : 0;
      let val;
      switch (filt) {
        case 0: val = rawByte; break;
        case 1: val = rawByte + a; break;
        case 2: val = rawByte + b; break;
        case 3: val = rawByte + ((a + b) >> 1); break;
        case 4: val = rawByte + paeth(a, b, c); break;
        default: return null;
      }
      chan[rowOut + x] = val & 0xff;
    }
  }

  // Flatten to RGB, compositing any alpha over the header band colour.
  const [br, bg, bb] = hexToRgb(bgHex);
  const rgb = new Uint8Array(width * height * 3);
  for (let i = 0, o = 0; i < width * height; i++) {
    let r, g, b, alpha = 255;
    const s = i * channels;
    if (colorType === 2) { r = chan[s]; g = chan[s + 1]; b = chan[s + 2]; }
    else if (colorType === 6) { r = chan[s]; g = chan[s + 1]; b = chan[s + 2]; alpha = chan[s + 3]; }
    else if (colorType === 0) { r = g = b = chan[s]; }
    else if (colorType === 4) { r = g = b = chan[s]; alpha = chan[s + 1]; }
    else { // palette (3)
      const idx = chan[s];
      r = palette[idx * 3]; g = palette[idx * 3 + 1]; b = palette[idx * 3 + 2];
      alpha = trns && idx < trns.length ? trns[idx] : 255;
    }
    if (alpha !== 255) {
      const af = alpha / 255;
      r = Math.round(r * af + br * (1 - af));
      g = Math.round(g * af + bg * (1 - af));
      b = Math.round(b * af + bb * (1 - af));
    }
    rgb[o++] = r; rgb[o++] = g; rgb[o++] = b;
  }

  let packed;
  try { packed = await deflate(rgb); } catch { return null; }
  return { width, height, colorSpace: "DeviceRGB", bitsPerComponent: 8, filter: "FlateDecode", bytes: packed };
}

// Public: prepare a logo data URI for PDF embedding, or null to fall back to text.
export async function prepareLogoXObject(dataUri, bgHex = "#00876A") {
  try {
    const parsed = dataUriToBytes(dataUri);
    if (!parsed) return null;
    if (parsed.mime === "image/jpeg" || parsed.mime === "image/jpg") return await prepareJpeg(parsed.bytes);
    if (parsed.mime === "image/png") return await preparePng(parsed.bytes, bgHex);
    return null; // svg/webp → text wordmark
  } catch {
    return null;
  }
}
