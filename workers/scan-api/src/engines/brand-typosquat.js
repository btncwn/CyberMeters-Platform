// ── Brand + typosquat detection module ──
// Brand-part extraction, high/med-risk brand keyword sets, homoglyph/typo variant
// generation with risk scoring, and the typosquat scan roll-up. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). MED_RISK_BRAND_KEYWORDS, TYPOSQUAT_HOMOGLYPHS,
// _typosquatRisk and MAX_BRAND_CANDIDATES are module-internal.

/**
 * extractBrandParts(domain)
 * Returns { brand, tld } for a registered domain.
 * Strips www., takes the first label as brand, the rest as TLD.
 *   "tesla.com"              → { brand:"tesla",             tld:"com" }
 *   "blackbullbarbers.co.uk" → { brand:"blackbullbarbers",  tld:"co.uk" }
 */
export function extractBrandParts(domain) {
  const clean  = domain.replace(/^www\./i, '').toLowerCase();
  const labels = clean.split('.');
  return { brand: labels[0], tld: labels.slice(1).join('.') };
}

// Keywords that lift candidate risk to 'high' (impersonation-focused)
export const HIGH_RISK_BRAND_KEYWORDS = [
  'login', 'secure', 'account', 'verify', 'auth', 'portal', 'admin', 'support',
];
// Keywords that lift candidate risk to 'medium'
const MED_RISK_BRAND_KEYWORDS = [
  'help', 'service', 'online', 'my', 'app', 'customer', 'access', 'billing',
];

// Visual character substitutions commonly used in phishing / lookalike domains
const TYPOSQUAT_HOMOGLYPHS = {
  a: ['4'],
  e: ['3'],
  i: ['1', 'l'],
  l: ['1', 'i'],
  o: ['0'],
  s: ['5', 'z'],
  t: ['7'],
  g: ['9'],
  b: ['6'],
  n: ['m'],
  m: ['n'],
};

/** Score a candidate SLD and return { risk_level, risk_reasons, _score }. */
function _typosquatRisk(sld, variantType) {
  let score = 0;
  const reasons = [];
  const s = sld.toLowerCase();

  for (const kw of HIGH_RISK_BRAND_KEYWORDS) {
    if (s.includes(kw)) { score += 3; reasons.push(`contains '${kw}'`); }
  }
  for (const kw of MED_RISK_BRAND_KEYWORDS) {
    if (s.includes(kw) && !reasons.some(r => r.includes(`'${kw}'`))) {
      score += 1; reasons.push(`contains '${kw}'`);
    }
  }

  if (['omission', 'duplication', 'transposition'].includes(variantType)) {
    score += 2; reasons.push('single-character typo variant');
  } else if (variantType === 'substitution') {
    score += 2; reasons.push('homoglyph character substitution');
  }

  const risk_level = score >= 7 ? 'critical' : score >= 5 ? 'high' : score >= 2 ? 'medium' : 'low';
  return { risk_level, risk_reasons: reasons, _score: score };
}

/** Maximum candidates returned by generateTyposquatCandidates. */
const MAX_BRAND_CANDIDATES = 40;

/**
 * generateTyposquatCandidates(brand, tld)
 * Pure function. Generates lookalike domain candidates via:
 *   1. Homoglyph substitution  (l→1, o→0, …)
 *   2. Omission                (drop one character)
 *   3. Duplication             (double one character)
 *   4. Transposition           (swap adjacent characters)
 *   5. Hyphen keyword append   (brand-login.tld)
 *   6. Prefix keyword prepend  (login-brand.tld)
 * Returns up to MAX_BRAND_CANDIDATES items sorted by descending risk score.
 */
export function generateTyposquatCandidates(brand, tld) {
  if (!brand || brand.length < 3) return [];

  const seen  = new Set();
  const items = [];

  function add(sld, variantType) {
    const candidate_domain = `${sld}.${tld}`;
    if (seen.has(candidate_domain)) return;
    if (sld === brand) return;
    if (sld.length < 2) return;
    seen.add(candidate_domain);
    const { risk_level, risk_reasons, _score } = _typosquatRisk(sld, variantType);
    items.push({ candidate_domain, variant_type: variantType, risk_level, risk_reasons, _score });
  }

  // 1. Homoglyph substitution
  for (let i = 0; i < brand.length; i++) {
    for (const sub of (TYPOSQUAT_HOMOGLYPHS[brand[i]] || [])) {
      add(brand.slice(0, i) + sub + brand.slice(i + 1), 'substitution');
    }
  }

  // 2. Omission
  for (let i = 0; i < brand.length; i++) {
    add(brand.slice(0, i) + brand.slice(i + 1), 'omission');
  }

  // 3. Duplication
  for (let i = 0; i < brand.length; i++) {
    add(brand.slice(0, i) + brand[i] + brand[i] + brand.slice(i + 1), 'duplication');
  }

  // 4. Transposition
  for (let i = 0; i < brand.length - 1; i++) {
    const arr = brand.split('');
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    add(arr.join(''), 'transposition');
  }

  // 5. Keyboard-adjacent substitutions (qwerty layout)
  const KEYBOARD_ADJACENT = {
    a: 'sqzw', b: 'vghn', c: 'xdfv', d: 'serfcx', e: 'wsdr',
    f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', i: 'ujko', j: 'huikmn',
    k: 'jiolm', l: 'kop', m: 'njk', n: 'bhjm', o: 'iklp',
    p: 'ol', q: 'wa', r: 'edft', s: 'awedxz', t: 'rfgy',
    u: 'yhji', v: 'cfgb', w: 'qase', x: 'zsdc', y: 'tghu', z: 'asx',
  };
  for (let i = 0; i < brand.length; i++) {
    for (const adj of (KEYBOARD_ADJACENT[brand[i]] || '')) {
      add(brand.slice(0, i) + adj + brand.slice(i + 1), 'keyboard_adjacent');
    }
  }

  // 6 & 7. Keyword variants (high-risk first, then medium-risk)
  for (const kw of [...HIGH_RISK_BRAND_KEYWORDS, ...MED_RISK_BRAND_KEYWORDS]) {
    add(`${brand}-${kw}`, 'hyphen_keyword');
    add(`${kw}-${brand}`, 'prefix_keyword');
  }

  // Sort by risk score desc, then alphabetically for determinism
  items.sort(
    (a, b) => b._score - a._score || a.candidate_domain.localeCompare(b.candidate_domain)
  );

  // Strip internal scoring field before returning.
  // Sprint 9D: all scan-time candidates are unvalidated (DNS probe deferred to /refresh).
  return items.slice(0, MAX_BRAND_CANDIDATES).map(({ _score, ...rest }) => ({
    ...rest,
    confidence:         40,
    validation_quality: "weak",
  }));
}

/**
 * runTyposquatModule(domain)
 * Phase 7i: pure computation, zero network I/O.
 *
 * Generates typosquat candidates for the brand name extracted from `domain`.
 * DNS/HTTPS validation is intentionally deferred to the dedicated
 * POST /api/workspaces/:id/brand-monitoring/refresh endpoint, which carries
 * its own 50-subrequest budget.  Inline DNS checks here would exceed the
 * budget already consumed by scan Phases 1–6 (~47 subrequests).
 */
export function runTyposquatModule(domain) {
  try {
    const { brand, tld } = extractBrandParts(domain);
    const candidates = generateTyposquatCandidates(brand, tld);

    return {
      brand,
      total_candidates_generated: candidates.length,
      candidates_validated:       false,
      domains:                    candidates,
      risk_summary: {
        critical: candidates.filter(c => c.risk_level === 'critical').length,
        high:     candidates.filter(c => c.risk_level === 'high').length,
        medium:   candidates.filter(c => c.risk_level === 'medium').length,
        low:      candidates.filter(c => c.risk_level === 'low').length,
      },
      source: 'typosquat_analysis',
      error:  null,
    };
  } catch (err) {
    return {
      brand:                      null,
      total_candidates_generated: 0,
      candidates_validated:       false,
      domains:                    [],
      risk_summary:               { high: 0, medium: 0, low: 0 },
      source:                     'typosquat_analysis',
      error:                      String(err),
    };
  }
}
