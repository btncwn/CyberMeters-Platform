// ── Brand IDN / Unicode homograph analysis ──────────────────────────────────
//
// Pure, Worker-compatible detection core for Item 8 PR-A. This module does no
// DNS, CT, persistence, alerting or case work. It keeps four distinct facts
// separate:
//   1. the submitted hostname,
//   2. its validated IDNA A-label/U-label round-trip,
//   3. visual-confusable similarity to the protected brand, and
//   4. script composition (mixed-script / whole-script-confusable).
//
// `tr46` is already the repository-pinned IDNA authority. Reusing it avoids a
// second punycode/UTS #46 implementation with different validity semantics.
// The confusable map is intentionally bounded to common Latin-lookalike
// characters used in domain impersonation. A non-ASCII label is never treated
// as suspicious merely because it is internationalised: it must contain a
// mapped visual confusable and meet the skeleton-distance gate.
import tr46 from "tr46";

export const BRAND_IDN_PROFILE = Object.freeze({
  library: "tr46",
  library_version: "6.0.0",
  checkBidi: true,
  checkHyphens: true,
  checkJoiners: true,
  useSTD3ASCIIRules: true,
  verifyDNSLength: true,
  transitionalProcessing: false,
  ignoreInvalidPunycode: false,
});

const TR46_OPTIONS = Object.freeze({
  checkBidi: BRAND_IDN_PROFILE.checkBidi,
  checkHyphens: BRAND_IDN_PROFILE.checkHyphens,
  checkJoiners: BRAND_IDN_PROFILE.checkJoiners,
  useSTD3ASCIIRules: BRAND_IDN_PROFILE.useSTD3ASCIIRules,
  verifyDNSLength: BRAND_IDN_PROFILE.verifyDNSLength,
  transitionalProcessing: BRAND_IDN_PROFILE.transitionalProcessing,
  ignoreInvalidPunycode: BRAND_IDN_PROFILE.ignoreInvalidPunycode,
});

// Unicode Technical Standard #39-inspired, deliberately bounded skeleton map.
// Keys are lower-case because skeleton inputs are NFC-normalised + lower-cased.
// Characters are escaped so source review can identify exact code points.
const CONFUSABLE_MAP = new Map([
  // Cyrillic
  ["\u0430", "a"], // а
  ["\u0432", "b"], // в
  ["\u0441", "c"], // с
  ["\u0501", "d"], // ԁ
  ["\u0435", "e"], // е
  ["\u04bb", "h"], // һ
  ["\u0456", "i"], // і
  ["\u0458", "j"], // ј
  ["\u043a", "k"], // к
  ["\u04cf", "l"], // ӏ
  ["\u043c", "m"], // м
  ["\u043e", "o"], // о
  ["\u0440", "p"], // р
  ["\u051b", "q"], // ԛ
  ["\u0455", "s"], // ѕ
  ["\u0442", "t"], // т
  ["\u0445", "x"], // х
  ["\u0443", "y"], // у
  ["\u051d", "w"], // ԝ
  // Greek
  ["\u03b1", "a"], // α
  ["\u03b2", "b"], // β
  ["\u03b5", "e"], // ε
  ["\u03b9", "i"], // ι
  ["\u03ba", "k"], // κ
  ["\u03bc", "m"], // μ
  ["\u03bd", "v"], // ν
  ["\u03bf", "o"], // ο
  ["\u03c1", "p"], // ρ
  ["\u03c4", "t"], // τ
  ["\u03c5", "y"], // υ
  ["\u03c7", "x"], // χ
  // Armenian (high-confidence Latin lookalikes only)
  ["\u057d", "u"], // ս
  ["\u0585", "o"], // օ
]);

const SCRIPT_PATTERNS = [
  ["Latin", /\p{Script=Latin}/u],
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Hebrew", /\p{Script=Hebrew}/u],
  ["Arabic", /\p{Script=Arabic}/u],
  ["Georgian", /\p{Script=Georgian}/u],
  ["Devanagari", /\p{Script=Devanagari}/u],
  ["Han", /\p{Script=Han}/u],
  ["Hiragana", /\p{Script=Hiragana}/u],
  ["Katakana", /\p{Script=Katakana}/u],
  ["Hangul", /\p{Script=Hangul}/u],
];

function normalizeHostnameInput(value) {
  return String(value || "")
    .trim()
    .replace(/^\*\./, "")
    .replace(/\.$/, "")
    .normalize("NFC")
    .toLowerCase();
}

function normalizeBrandInput(value) {
  return String(value || "").trim().normalize("NFC").toLowerCase();
}

export function decodeIdnHostname(value) {
  const submitted = normalizeHostnameInput(value);
  const fail = (error) => ({
    ok: false,
    submitted,
    alabel: null,
    unicode: null,
    punycode_decoded: false,
    error,
    idna_profile: BRAND_IDN_PROFILE,
  });
  if (!submitted || submitted.includes("..") || submitted.startsWith(".")) {
    return fail("invalid_hostname");
  }

  try {
    const converted = tr46.toUnicode(submitted, TR46_OPTIONS);
    if (!converted?.domain || converted.error === true) return fail("invalid_idna_name");
    const unicode = converted.domain.normalize("NFC").toLowerCase();
    const alabel = tr46.toASCII(unicode, TR46_OPTIONS);
    if (!alabel) return fail("invalid_idna_name");
    const submittedAlabel = tr46.toASCII(submitted, TR46_OPTIONS);
    if (!submittedAlabel || submittedAlabel.toLowerCase() !== alabel.toLowerCase()) {
      return fail("idna_round_trip_failed");
    }
    return {
      ok: true,
      submitted,
      alabel: alabel.toLowerCase(),
      unicode,
      punycode_decoded: /(^|\.)xn--/i.test(submitted) && unicode !== submitted,
      error: null,
      idna_profile: BRAND_IDN_PROFILE,
    };
  } catch {
    return fail("idna_conversion_error");
  }
}

export function encodeIdnHostname(value) {
  const submitted = normalizeHostnameInput(value);
  if (!submitted) return { ok: false, submitted, alabel: null, error: "invalid_hostname" };
  try {
    const alabel = tr46.toASCII(submitted, TR46_OPTIONS);
    if (!alabel) return { ok: false, submitted, alabel: null, error: "invalid_idna_name" };
    const decoded = decodeIdnHostname(alabel);
    if (!decoded.ok) return { ok: false, submitted, alabel: null, error: decoded.error };
    return { ok: true, submitted, alabel: decoded.alabel, unicode: decoded.unicode, error: null };
  } catch {
    return { ok: false, submitted, alabel: null, error: "idna_conversion_error" };
  }
}

export function confusableSkeleton(value) {
  const normalized = normalizeBrandInput(value);
  let skeleton = "";
  let confusableCount = 0;
  for (const char of normalized) {
    const mapped = CONFUSABLE_MAP.get(char);
    if (mapped) {
      skeleton += mapped;
      confusableCount++;
    } else {
      // Retain, rather than delete, an unmapped international character. That
      // prevents a legitimate non-Latin label from matching by omission.
      skeleton += char;
    }
  }
  return { normalized, skeleton, confusable_count: confusableCount };
}

export function detectUnicodeScripts(value) {
  const scripts = new Set();
  for (const char of normalizeBrandInput(value)) {
    if (!/\p{L}/u.test(char)) continue;
    const match = SCRIPT_PATTERNS.find(([, pattern]) => pattern.test(char));
    scripts.add(match?.[0] || "Other");
  }
  return [...scripts].sort();
}

export function levenshteinDistance(left, right) {
  const a = Array.from(String(left || ""));
  const b = Array.from(String(right || ""));
  const previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diagonal = previous[0];
    previous[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const above = previous[j];
      previous[j] = Math.min(
        previous[j] + 1,
        previous[j - 1] + 1,
        diagonal + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return previous[b.length];
}

function skeletonSimilarity(left, right) {
  if (!left || !right) return null;
  const distance = levenshteinDistance(left, right);
  const longest = Math.max(Array.from(left).length, Array.from(right).length);
  return {
    distance,
    score: Math.max(0, Math.round((1 - distance / longest) * 100)),
  };
}

/**
 * Analyse every hostname label and return the strongest IDN homograph match.
 * Exact skeleton equality is accepted for brands of any supported length.
 * A one-edit skeleton near-match is accepted only for brands with >=5 skeleton
 * characters and >=80 similarity, limiting short-brand false positives.
 */
export function analyzeIdnHomograph(candidateDomain, brandName) {
  const decoded = decodeIdnHostname(candidateDomain);
  const brand = confusableSkeleton(brandName);
  const empty = {
    is_homograph: false,
    similarity_score: null,
    skeleton_distance: null,
    matched_label: null,
    candidate_unicode: decoded.unicode,
    candidate_alabel: decoded.alabel,
    punycode_decoded: decoded.punycode_decoded,
    scripts: [],
    mixed_script: false,
    whole_script_confusable: false,
    confusable_count: 0,
    reason_codes: [],
    error: decoded.error,
  };
  if (!decoded.ok || !brand.skeleton) return empty;

  let best = null;
  for (const label of decoded.unicode.split(".")) {
    if (!label || !/[^\x00-\x7f]/.test(label)) continue;
    const candidate = confusableSkeleton(label);
    if (candidate.confusable_count === 0) continue;
    const similarity = skeletonSimilarity(candidate.skeleton, brand.skeleton);
    if (!similarity) continue;
    const brandLength = Array.from(brand.skeleton).length;
    const withinGate = similarity.distance === 0 ||
      (brandLength >= 5 && similarity.distance === 1 && similarity.score >= 80);
    if (!withinGate) continue;
    const scripts = detectUnicodeScripts(label);
    const next = {
      label,
      similarity,
      scripts,
      mixed_script: scripts.length > 1,
      whole_script_confusable: scripts.length === 1 && scripts[0] !== "Latin",
      confusable_count: candidate.confusable_count,
    };
    if (!best || next.similarity.score > best.similarity.score ||
        (next.similarity.score === best.similarity.score &&
         next.confusable_count > best.confusable_count)) {
      best = next;
    }
  }
  if (!best) return { ...empty, error: null };

  const reasonCodes = ["idn_visual_confusable", "confusable_skeleton_match"];
  if (decoded.punycode_decoded) reasonCodes.push("punycode_decoded");
  if (best.mixed_script) reasonCodes.push("mixed_script");
  if (best.whole_script_confusable) reasonCodes.push("whole_script_confusable");
  return {
    ...empty,
    is_homograph: true,
    similarity_score: best.similarity.score,
    skeleton_distance: best.similarity.distance,
    matched_label: best.label,
    scripts: best.scripts,
    mixed_script: best.mixed_script,
    whole_script_confusable: best.whole_script_confusable,
    confusable_count: best.confusable_count,
    reason_codes: reasonCodes,
    error: null,
  };
}
