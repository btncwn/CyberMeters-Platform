#!/usr/bin/env node
//
// Item 8 PR-A — Brand IDN/homograph detection core.
// Pins IDNA round-trip, NFC handling, mixed/whole-script analysis, bounded
// confusable skeleton matching, negative controls, and ASCII compatibility.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (file) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", file)).href;
const idn = await import(eng("idn-homograph.js"));
const brand = await import(eng("brand-protection.js"));

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

// Canonical audit fixture: Cyrillic small a + "pple".
const cyrillicApple = idn.analyzeIdnHomograph("xn--pple-43d.com", "apple");
ok("punycode Cyrillic apple is detected", cyrillicApple.is_homograph);
eq("punycode round-trip exposes the Unicode hostname", cyrillicApple.candidate_unicode, "\u0430pple.com");
eq("exact skeleton match scores 100", cyrillicApple.similarity_score, 100);
ok("mixed Latin/Cyrillic script is explicit", cyrillicApple.mixed_script);
ok("punycode decode is explicit evidence", cyrillicApple.reason_codes.includes("punycode_decoded"));

// Unicode input follows the same path and canonicalises to the same A-label.
const directUnicode = idn.analyzeIdnHomograph("\u0430pple.com", "apple");
ok("direct Unicode input is detected", directUnicode.is_homograph);
eq("Unicode and punycode inputs share one canonical A-label",
  directUnicode.candidate_alabel, cyrillicApple.candidate_alabel);
const decomposed = idn.encodeIdnHostname("cafe\u0301.example");
const composed = idn.encodeIdnHostname("caf\u00e9.example");
ok("decomposed and composed Unicode hostnames both encode", decomposed.ok && composed.ok);
eq("NFC-equivalent Unicode hostnames share one canonical A-label",
  decomposed.alabel, composed.alabel);

// Greek omicron, a common whole-label substitution.
const greekEncoded = idn.encodeIdnHostname("g\u03bfogle.com");
ok("Greek-omicron fixture encodes", greekEncoded.ok);
const greekGoogle = idn.analyzeIdnHomograph(greekEncoded.alabel, "google");
ok("Greek omicron Google lookalike is detected", greekGoogle.is_homograph);
ok("Greek/Latin mix is explicit", greekGoogle.mixed_script);

// Whole-script Cyrillic "apple" (а р р ӏ е) has no Latin letters.
const wholeScriptEncoded = idn.encodeIdnHostname("\u0430\u0440\u0440\u04cf\u0435.com");
ok("whole-script fixture encodes", wholeScriptEncoded.ok);
const wholeScript = idn.analyzeIdnHomograph(wholeScriptEncoded.alabel, "apple");
ok("whole-script confusable is detected", wholeScript.is_homograph);
ok("whole-script flag is explicit", wholeScript.whole_script_confusable);
eq("whole-script set is Cyrillic only", wholeScript.scripts, ["Cyrillic"]);

// Nested credential host: the protected-looking label need not be the first
// hostname label. Discovery/persistence wiring lands in PR-B.
const nested = idn.analyzeIdnHomograph(`login.${cyrillicApple.candidate_alabel}`, "apple");
ok("nested IDN base is detected by label", nested.is_homograph);
eq("nested match identifies the confusable label", nested.matched_label, "\u0430pple");

// One-edit skeleton support is bounded to brands >=5 characters.
const oneEdit = idn.analyzeIdnHomograph("\u0430ppl3.com", "apple");
ok("confusable plus one edit remains detectable for a five-character brand", oneEdit.is_homograph);
eq("one-edit skeleton distance is explicit", oneEdit.skeleton_distance, 1);
const shortOneEdit = idn.analyzeIdnHomograph("\u0430cm3.com", "acme");
ok("short-brand one-edit near match is refused", !shortOneEdit.is_homograph);
eq("two-character brands generate no speculative IDN candidates",
  idn.generateIdnHomographCandidates("ai", "com"), []);
const shortExact = idn.analyzeIdnHomograph("\u0430i.com", "ai");
ok("short-brand core accepts only an exact mapped skeleton", shortExact.is_homograph &&
  shortExact.skeleton_distance === 0);

// False-positive controls: internationalisation alone is never a verdict.
const legitimate = idn.analyzeIdnHomograph("xn--bcher-kva.de", "apple");
ok("legitimate unrelated IDN is not a homograph", !legitimate.is_homograph);
const unrelated = idn.analyzeIdnHomograph("xn--e1afmkfd.xn--p1ai", "apple");
ok("unrelated all-IDN hostname is not a homograph", !unrelated.is_homograph);
const malformed = idn.analyzeIdnHomograph("xn--.com", "apple");
ok("malformed A-label fails closed", !malformed.is_homograph && Boolean(malformed.error));
const malformedJoiner = idn.analyzeIdnHomograph("a\u200dpple.com", "apple");
ok("disallowed joiner hostname fails closed", !malformedJoiner.is_homograph &&
  Boolean(malformedJoiner.error));

// NFC is deterministic and unmapped characters are retained, never deleted.
const retained = idn.confusableSkeleton("b\u00fccher");
eq("unmapped international character is retained", retained.skeleton, "b\u00fccher");
eq("unmapped international character is not counted as confusable", retained.confusable_count, 0);

// Backward compatibility: the existing ASCII Levenshtein contract is unchanged.
eq("ASCII exact match remains 100", brand.brandSimilarityScore("apple.com", "apple"), 100);
eq("ASCII one-character substitution remains 80", brand.brandSimilarityScore("appl3.com", "apple"), 80);
eq("unrelated ASCII remains 0", brand.brandSimilarityScore("zebra.com", "apple"), 0);
eq("IDN skeleton path lifts the canonical fixture to 100",
  brand.brandSimilarityScore("xn--pple-43d.com", "apple"), 100);

console.log(`\nBrand IDN/homograph PR-A: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand IDN/homograph PR-A validation passed");
