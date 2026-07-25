#!/usr/bin/env node
// Item 7 P1 deterministic protocol fixtures.
//
// Pure fixture DNS only: no production fetch, persistence, API, lifecycle,
// customer surface, or runScanEngine caller is introduced in P1.
import {
  DMARCBIS_MAX_REPORT_URIS,
  parseDmarcbisAuthorizationRecordSet,
  parseDmarcbisPolicyRecord,
  parseDmarcbisPolicyRecordSet,
  parseDmarcbisReportingUri,
} from "../workers/scan-api/src/engines/dmarcbis-parser.js";
import {
  canonicalizeDmarcbisDomain,
  constructExternalRuaAuthorizationName,
  validateDnsNameLength,
} from "../workers/scan-api/src/engines/dmarcbis-idna.js";
import {
  planDmarcbisTreeWalk,
  resolveDmarcbisExternalRuaAuthorizations,
  resolveDmarcbisPolicy,
} from "../workers/scan-api/src/engines/dmarcbis-resolver.js";

let pass = 0;
let fail = 0;
const failures = [];
const ok = (name, condition, detail = "") => {
  if (condition) {
    pass += 1;
    console.log(`ok - ${name}`);
  } else {
    fail += 1;
    const message = `${name}${detail ? `: ${detail}` : ""}`;
    failures.push(message);
    console.error(`not ok - ${message}`);
  }
};
const eq = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

const TXT = (...values) => ({
  outcome: "success",
  txt_records: values.map((value) =>
    Array.isArray(value) ? { chunks: value } : { chunks: [value] }),
});
const NODATA = Object.freeze({ outcome: "nodata", txt_records: [] });
const NXDOMAIN = Object.freeze({ outcome: "nxdomain", txt_records: [] });
const TIMEOUT = Object.freeze({ outcome: "timeout" });
const SERVFAIL = Object.freeze({ outcome: "servfail" });

function fixtureDns(zone = {}, { fallback = NODATA } = {}) {
  const questions = [];
  const query = async (question) => {
    questions.push({ ...question });
    const resolverKey = `${question.resolver}|${question.type}|${question.name}`.toLowerCase();
    const genericKey = `${question.type}|${question.name}`.toLowerCase();
    const value = zone[resolverKey] ?? zone[genericKey] ?? fallback;
    if (value instanceof Error) throw value;
    return typeof value === "function" ? value(question, questions) : value;
  };
  query.questions = questions;
  return query;
}

function zoneEntry(zone, name, type, value, resolver = null) {
  const key = resolver
    ? `${resolver}|${type}|${name}`.toLowerCase()
    : `${type}|${name}`.toLowerCase();
  zone[key] = value;
}

function policyZone(domain, record, extra = {}) {
  const zone = {};
  zoneEntry(zone, `_dmarc.${domain}`, "TXT", TXT(record));
  const labels = domain.split(".");
  for (let index = 1; index < labels.length; index += 1) {
    zoneEntry(zone, `_dmarc.${labels.slice(index).join(".")}`, "TXT", NODATA);
  }
  Object.assign(zone, extra);
  return zone;
}

function runtimeGrade(result) {
  return result.policy_completeness === "complete" ? "L3" : "L1";
}

// ── IDNA and constructed-name fixtures ──────────────────────────────────────
{
  const unicode = canonicalizeDmarcbisDomain("BÜCHER.example.");
  ok("IDNA valid Unicode name", unicode.ok);
  eq("IDNA uses the expected lower-case A-label", unicode.alabel, "xn--bcher-kva.example");
  eq("IDNA preserves the submitted form", unicode.submitted, "BÜCHER.example.");
  eq("IDNA records the root trailing dot", unicode.had_trailing_dot, true);
  eq("non-transitional sharp-s vector", canonicalizeDmarcbisDomain("faß.de").alabel, "xn--fa-hia.de");
  ok("IDNA rejects an empty label", !canonicalizeDmarcbisDomain("a..example").ok);
  ok("IDNA rejects an IP literal", !canonicalizeDmarcbisDomain("192.0.2.1").ok);
  ok("IDNA rejects invalid punycode", !canonicalizeDmarcbisDomain("xn--a.example").ok);
  ok("IDNA rejects an invalid joiner context", !canonicalizeDmarcbisDomain("a\u200db.example").ok);
  ok("DNS length rejects a 64-octet label", !validateDnsNameLength(`${"a".repeat(64)}.test`).ok);
  const validSource = `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.test`;
  const tooLongConstructed = constructExternalRuaAuthorizationName(
    validSource,
    `${"d".repeat(50)}.external.test`,
  );
  ok("RFC 9990 constructed-name overflow is rejected without truncation", !tooLongConstructed.ok);
}

// ── Parser and multiplicity fixtures ────────────────────────────────────────
{
  const chunks = parseDmarcbisPolicyRecord({ chunks: ["v=DM", "ARC1; p=reject"] });
  eq("TXT chunks concatenate in order", chunks.value, "v=DMARC1; p=reject");
  ok("concatenated current version is recognized", chunks.is_current_version);

  const wrongCase = parseDmarcbisPolicyRecord("v=dmarc1; p=reject");
  ok("wrong-case DMARC version is not current", !wrongCase.is_current_version);
  const laterVersion = parseDmarcbisPolicyRecord("p=reject; v=DMARC1");
  ok("version appearing later is not current", !laterVersion.is_current_version);
  const caseInsensitiveGrammar = parseDmarcbisPolicyRecord("V = DMARC1; P = REJECT");
  ok("ABNF tag names remain case-insensitive", caseInsensitiveGrammar.is_current_version);
  eq("ABNF policy token is normalized", caseInsensitiveGrammar.p.normalized, "reject");
  const separatorWsp = parseDmarcbisPolicyRecord("v=DMARC1\t;\t p=reject");
  ok("RFC WSP around a semicolon is accepted", separatorWsp.valid_for_discovery);
  eq("tab-separated policy remains reject", separatorWsp.p.normalized, "reject");
  const ignoredRemainder = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=reject; syntactically-broken",
  );
  ok("RFC 9989 §4.8 ignores a malformed remainder tag", ignoredRemainder.valid_for_discovery);
  eq("ignored remainder syntax does not replace a valid policy",
    ignoredRemainder.p.normalized, "reject");
  ok("ignored remainder syntax remains diagnostic", ignoredRemainder.ignored_syntax_errors);

  const duplicate = parseDmarcbisPolicyRecordSet(["v=DMARC1; p=none; p=reject"]);
  eq("duplicate tag is a fatal single candidate", duplicate.raw_state, "single_invalid_duplicate_tag");
  eq("duplicate tag never becomes a selected record", duplicate.selected, null);

  const unknown = parseDmarcbisPolicyRecord("v=DMARC1; p=reject; xfoo=bar");
  ok("unknown tag is retained", unknown.unknown_tags.some((tag) => tag.name === "xfoo"));
  ok("unknown tag alone does not invalidate policy", unknown.valid_for_discovery);

  eq(
    "two valid policy candidates are discarded together",
    parseDmarcbisPolicyRecordSet([
      "v=DMARC1; p=none",
      "v=DMARC1; p=reject",
    ]).raw_state,
    "multiple",
  );
  eq(
    "one valid plus malformed current candidate is still multiple",
    parseDmarcbisPolicyRecordSet([
      "v=DMARC1; p=reject",
      "v=DMARC1; p=invalid",
    ]).raw_state,
    "multiple_mixed",
  );
  eq(
    "unrelated TXT does not create policy multiplicity",
    parseDmarcbisPolicyRecordSet([
      "google-site-verification=abc",
      "v=DMARC1; p=reject",
    ]).raw_state,
    "single_valid_with_non_dmarc_txt",
  );
  eq(
    "multiple invalid current candidates remain multiple and unselected",
    parseDmarcbisPolicyRecordSet([
      "v=DMARC1; p=invalid",
      "v=DMARC1; sp=invalid",
    ]).raw_state,
    "multiple_invalid",
  );

  const pct = parseDmarcbisPolicyRecord("v=DMARC1; p=reject; pct=25");
  eq("legacy pct raw value is preserved", pct.legacy_pct.raw, "25");
  eq("legacy pct numeric diagnostic is preserved", pct.legacy_pct.numeric, 25);
  eq("legacy pct is never applied", pct.legacy_pct.applied_to_effective_policy, false);

  const fallback = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=invalid; rua=mailto:dmarc@example.test",
  );
  eq("invalid policy plus a syntactically valid rua selects RFC fallback", fallback.policy_mode, "invalid_policy_fallback_none");
  ok("RFC fallback record remains a policy source", fallback.valid_for_discovery);
  const noFallback = parseDmarcbisPolicyRecord("v=DMARC1; p=invalid");
  eq("invalid policy without a valid rua performs no DMARC processing", noFallback.policy_mode, "no_processing_invalid_policy");
  ok("invalid policy without rua is not a policy source", !noFallback.valid_for_discovery);
  const invalidSpWithValidPAndRua = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=reject; sp=invalid; rua=mailto:dmarc@example.test",
  );
  eq("RFC 9989 §4.10.1 invalid sp is not rescued by valid p",
    invalidSpWithValidPAndRua.policy_mode, "invalid_policy_fallback_none");
  ok("RFC 9989 §4.10.1 invalid sp plus valid rua remains a fallback source",
    invalidSpWithValidPAndRua.valid_for_discovery);
  const invalidNpWithValidPNoRua = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=reject; np=invalid",
  );
  eq("RFC 9989 §4.10.1 invalid np is not ignored in favor of valid p",
    invalidNpWithValidPNoRua.policy_mode, "no_processing_invalid_policy");
  ok("RFC 9989 §4.10.1 invalid np without rua is not a policy source",
    !invalidNpWithValidPNoRua.valid_for_discovery);
  const defaults = parseDmarcbisPolicyRecord("v=DMARC1");
  eq("missing p defaults to none", defaults.p.normalized, "none");
  eq("missing t defaults to n", defaults.t.normalized, "n");
  eq("missing psd defaults to u", defaults.psd.normalized, "u");
  const invalidDefaults = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=reject; t=invalid; psd=invalid",
  );
  eq("invalid t falls back to its defined default", invalidDefaults.t.normalized, "n");
  eq("invalid psd falls back to its defined default", invalidDefaults.psd.normalized, "u");
  const failureTags = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=none; ruf=mailto:forensic@example.test; fo=1:d",
  );
  eq("RFC 9991 ruf is parsed and preserved", failureTags.ruf[0].destination_host, "example.test");
  eq("failure-report option is parsed and preserved", failureTags.fo.normalized, ["1", "d"]);

  const obsolete = parseDmarcbisReportingUri("mailto:dmarc@example.test!10m");
  eq("obsolete URI size suffix is preserved", obsolete.obsolete_size, "10m");
  ok("obsolete size suffix does not prevent URI syntax recognition", obsolete.syntax_valid);
  const unsupported = parseDmarcbisReportingUri("https://reports.example.test/dmarc");
  eq("unsupported scheme is operationally unassessed", unsupported.uri_parse_status, "unsupported_scheme");
  eq("unsupported scheme does not guess a destination host", unsupported.destination_host, null);
  ok("malformed URI is not coerced", !parseDmarcbisReportingUri("not a uri").syntax_valid);
  const longUri = parseDmarcbisReportingUri(`mailto:${"a".repeat(2040)}@example.test`);
  ok("over-bound URI is diagnosed without RFC-invalidity", longUri.syntax_valid && longUri.over_product_limit);

  const oversized = parseDmarcbisPolicyRecordSet([
    `v=DMARC1; p=reject; x=${"a".repeat(65 * 1024)}`,
  ]);
  eq("oversized RR is incomplete rather than prefix-parsed", oversized.raw_state, "incomplete_oversized");
  eq("oversized RR has no selected policy", oversized.selected, null);
  const truncated = parseDmarcbisPolicyRecordSet([
    { chunks: ["v=DMARC1; p=reject"], truncated: true },
  ]);
  eq("unresolved truncation is incomplete", truncated.raw_state, "incomplete_oversized");
  const aggregateOversized = parseDmarcbisPolicyRecordSet(
    Array.from({ length: 5 }, (_, index) =>
      `v=DMARC1; p=reject; x${index}=${"a".repeat(54 * 1024)}`),
  );
  eq("aggregate DMARC DNS evidence over 256 KiB is incomplete",
    aggregateOversized.raw_state, "incomplete_oversized");
  eq("aggregate evidence overflow selects no record", aggregateOversized.selected, null);

  const authMultiple = parseDmarcbisAuthorizationRecordSet([
    "v=DMARC1",
    "v=DMARC1;",
  ]);
  ok("RFC 9990 at-least-one rule authorizes multiple valid records", authMultiple.authorized);
  eq("RFC 9990 multiplicity remains multiple_valid", authMultiple.record_state, "multiple_valid");
  const authMixed = parseDmarcbisAuthorizationRecordSet([
    "v=DMARC1",
    "v=DMARC1; rua",
  ]);
  ok("RFC 9990 valid plus malformed remains authorized", authMixed.authorized);
  eq("RFC 9990 mixed state is preserved", authMixed.record_state, "mixed");
  const unrelatedAuth = parseDmarcbisAuthorizationRecordSet([
    "google-site-verification=abc",
  ]);
  eq("unrelated TXT is zero RFC 9990 authorization records",
    unrelatedAuth.record_state, "absent");
  eq("unrelated TXT cannot authorize external reporting", unrelatedAuth.authorized, false);

  const aggregateAuth = parseDmarcbisAuthorizationRecordSet(
    ["xa", "xb", "xc", "xd", "xe"].map(
      (tag) => `v=DMARC1; ${tag}=${"a".repeat(60 * 1024)}`,
    ),
  );
  eq("oversized aggregate authorization evidence is incomplete",
    aggregateAuth.record_state, "incomplete_oversized");
  eq("incomplete authorization evidence cannot authorize", aggregateAuth.authorized, false);
  eq("authorization parser exposes aggregate incompleteness", aggregateAuth.complete, false);
}

// ── Tree-walk, precedence, existence, and t fixtures ────────────────────────
{
  const deep = planDmarcbisTreeWalk("a.b.c.d.e.f.g.h.i.j.mail.example.com");
  eq("deep-label walk has the RFC maximum", deep.questions.length, 8);
  eq("deep-label walk exact first", deep.questions[0].name, "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com");
  eq("deep-label walk jumps directly to seven labels", deep.questions[1].name, "_dmarc.g.h.i.j.mail.example.com");
  eq("deep-label walk finishes at the final label", deep.questions[7].name, "_dmarc.com");

  const exactDns = fixtureDns(policyZone(
    "example.test",
    "v=DMARC1; p=reject; psd=n",
  ));
  const exact = await resolveDmarcbisPolicy({ authorDomain: "example.test", dns: exactDns });
  eq("exact record supplies exact policy", exact.effective_requested_policy, "reject");
  eq("exact record policy kind", exact.policy_source_kind, "exact");
  eq("psd=n exact record defines organisation", exact.organisational_domain, "example.test");
  eq("canonical parser version is explicit", exact.parser_version, "rfc9989-parser-v1");
  eq("canonical IDNA dependency version is explicit", exact.idna_profile.library_version, "6.0.0");
  eq("complete exact derivation is runtime L3", runtimeGrade(exact), "L3");
  eq("policy observation never claims receiver enforcement", exact.receiver_enforcement_observed, false);

  const exactSubdomainZone = {};
  zoneEntry(exactSubdomainZone, "_dmarc.mail.example.test", "TXT",
    TXT("v=DMARC1; p=reject"));
  zoneEntry(exactSubdomainZone, "_dmarc.example.test", "TXT",
    TXT("v=DMARC1; p=none; sp=quarantine; psd=n"));
  const exactSubdomain = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(exactSubdomainZone),
  });
  eq("exact subdomain record wins policy precedence", exactSubdomain.effective_requested_policy, "reject");
  eq("exact subdomain source remains exact", exactSubdomain.policy_source_kind, "exact");
  eq("exact policy does not force the author to be the organisational domain",
    exactSubdomain.organisational_domain, "example.test");

  const childZone = {};
  zoneEntry(childZone, "_dmarc.mail.example.test", "TXT", NODATA);
  zoneEntry(childZone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=none; sp=reject; np=quarantine; psd=n"));
  zoneEntry(childZone, "mail.example.test", "A", NODATA);
  const inheritedSp = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(childZone),
  });
  eq("NODATA proves an existing child", inheritedSp.domain_existence, "exists");
  eq("existing child inherits sp", inheritedSp.effective_policy_tag, "sp");
  eq("existing child effective policy", inheritedSp.effective_requested_policy, "reject");
  eq("existing child source is organisational", inheritedSp.policy_source_kind, "organisational");

  const nxZone = { ...childZone };
  zoneEntry(nxZone, "mail.example.test", "A", NXDOMAIN);
  const inheritedNp = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(nxZone),
  });
  eq("NXDOMAIN proves a nonexistent child", inheritedNp.domain_existence, "nonexistent");
  eq("nonexistent child inherits np", inheritedNp.effective_policy_tag, "np");
  eq("nonexistent child effective policy", inheritedNp.effective_requested_policy, "quarantine");

  const inheritedPZone = {};
  zoneEntry(inheritedPZone, "_dmarc.mail.example.test", "TXT", NODATA);
  zoneEntry(inheritedPZone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=quarantine; psd=n"));
  const inheritedP = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(inheritedPZone),
  });
  eq("absence of sp/np inherits p without existence lookup", inheritedP.effective_policy_tag, "p");
  eq("p inheritance does not issue existence question", inheritedP.limits.existence_questions, 0);

  const inheritedSpOnlyZone = {};
  zoneEntry(inheritedSpOnlyZone, "_dmarc.mail.example.test", "TXT", NODATA);
  zoneEntry(
    inheritedSpOnlyZone,
    "_dmarc.example.test",
    "TXT",
    TXT("v=DMARC1; p=none; sp=reject; psd=n"),
  );
  zoneEntry(inheritedSpOnlyZone, "mail.example.test", "A", TIMEOUT);
  const inheritedSpOnlyDns = fixtureDns(inheritedSpOnlyZone);
  const inheritedSpOnly = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: inheritedSpOnlyDns,
  });
  eq("sp-only inheritance does not depend on existence", inheritedSpOnly.effective_policy_tag, "sp");
  eq("sp-only inheritance spends no existence question",
    inheritedSpOnly.limits.existence_questions, 0);
  ok("sp-only inheritance never launches the irrelevant timeout",
    !inheritedSpOnlyDns.questions.some((question) =>
      question.purpose === "author_domain_existence"));

  const standardWalkZone = {};
  zoneEntry(standardWalkZone, "_dmarc.a.mail.example.test", "TXT", NODATA);
  zoneEntry(standardWalkZone, "_dmarc.mail.example.test", "TXT",
    TXT("v=DMARC1; p=reject"));
  zoneEntry(standardWalkZone, "_dmarc.example.test", "TXT",
    TXT("v=DMARC1; p=quarantine"));
  zoneEntry(standardWalkZone, "_dmarc.test", "TXT", NODATA);
  const standardWalk = await resolveDmarcbisPolicy({
    authorDomain: "a.mail.example.test",
    dns: fixtureDns(standardWalkZone),
  });
  eq("fewest-label valid record defines organisation without explicit psd",
    standardWalk.organisational_domain, "example.test");
  eq("intermediate subdomain record does not override organisational policy source",
    standardWalk.policy_source_domain, "example.test");

  const tReject = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone("example.test", "v=DMARC1; p=reject; t=y; psd=n")),
  });
  eq("RFC 9989 §4.7 reject+t=y is one level below", tReject.effective_requested_policy, "quarantine");
  eq("t=y records the direct-clause adjustment", tReject.testing_adjustment, "one_level_below");
  const tQuarantine = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone("example.test", "v=DMARC1; p=quarantine; t=y; psd=n")),
  });
  eq("RFC 9989 §4.7 quarantine+t=y becomes none", tQuarantine.effective_requested_policy, "none");
  const tNone = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone("example.test", "v=DMARC1; p=none; t=y; psd=n")),
  });
  eq("RFC 9989 §4.7 t has no effect on none", tNone.effective_requested_policy, "none");
  eq("t none reports no-effect adjustment", tNone.testing_adjustment, "no_effect_on_none");
  const tDefault = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone("example.test", "v=DMARC1; p=reject; psd=n")),
  });
  eq("absent t defaults to n", tDefault.t.normalized, "n");
  eq("absent t leaves requested policy unchanged", tDefault.effective_requested_policy, "reject");

  const psdYZone = {};
  zoneEntry(psdYZone, "_dmarc.mail.example.test", "TXT", NODATA);
  zoneEntry(psdYZone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=reject; psd=y"));
  const psdY = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(psdYZone),
  });
  eq("psd=y identifies the domain one label below", psdY.organisational_domain, "mail.example.test");
  eq("psd=y parent is PSD policy source", psdY.policy_source_kind, "psd");
  eq("psd=y stops logical evaluation", psdY.tree_walk.stop_reason, "psd_y");

  const noPolicy = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns({}),
  });
  eq("complete zero-record walk has no policy", noPolicy.effective_requested_policy, null);
  eq("complete zero-record walk is not p=none", noPolicy.policy_source_kind, "none");
  eq("complete no-policy result remains complete", noPolicy.policy_completeness, "complete");

  const fallbackResult = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone(
      "example.test",
      "v=DMARC1; p=invalid; rua=mailto:dmarc@example.test; psd=n",
    )),
  });
  eq("invalid policy plus valid rua derives fallback none", fallbackResult.effective_requested_policy, "none");
  eq("fallback provenance is explicit", fallbackResult.inheritance_reason, "invalid_policy_fallback_none");

  const noFallbackResult = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone("example.test", "v=DMARC1; p=invalid; psd=n")),
  });
  eq("invalid policy without valid rua derives no policy", noFallbackResult.effective_requested_policy, null);
  eq("invalid policy remains malformed, not missing", noFallbackResult.observation_state, "present_invalid");

  const malformedParentZone = {};
  zoneEntry(
    malformedParentZone,
    "_dmarc.mail.example.test",
    "TXT",
    TXT("v=DMARC1; p=invalid"),
  );
  zoneEntry(malformedParentZone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=reject; psd=n"));
  const malformedParent = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(malformedParentZone),
  });
  eq("malformed exact record remains an exact defect", malformedParent.observation_state, "present_invalid");
  eq("malformed exact record does not hide usable inheritance", malformedParent.effective_requested_policy, "reject");

  const malformedExactPsdZone = {};
  zoneEntry(
    malformedExactPsdZone,
    "_dmarc.mail.example.test",
    "TXT",
    TXT("v=DMARC1; p=invalid; psd=n"),
  );
  zoneEntry(
    malformedExactPsdZone,
    "_dmarc.example.test",
    "TXT",
    TXT("v=DMARC1; p=reject; psd=n"),
  );
  const malformedExactPsd = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(malformedExactPsdZone),
  });
  eq("unusable exact psd tag cannot stop the required parent walk",
    malformedExactPsd.policy_source_domain, "example.test");
  eq("parent policy applies after an unusable exact psd candidate",
    malformedExactPsd.effective_requested_policy, "reject");

  const multipleParentZone = {};
  zoneEntry(
    multipleParentZone,
    "_dmarc.mail.example.test",
    "TXT",
    TXT("v=DMARC1; p=none", "v=DMARC1; p=reject"),
  );
  zoneEntry(multipleParentZone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=quarantine; psd=n"));
  const multipleParent = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(multipleParentZone),
  });
  eq("multiple exact records are never selected", multipleParent.observation_state, "multiple");
  eq("multiple exact records may coexist with inherited policy", multipleParent.effective_requested_policy, "quarantine");

  const timeoutZone = {};
  zoneEntry(timeoutZone, "_dmarc.mail.example.test", "TXT", NODATA);
  zoneEntry(timeoutZone, "_dmarc.example.test", "TXT", TIMEOUT);
  const timeout = await resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: fixtureDns(timeoutZone),
  });
  eq("required timeout is unavailable, not absent", timeout.policy_completeness, "unavailable");
  eq("required timeout never defaults to none", timeout.effective_requested_policy, null);
  eq("required timeout degrades monitoring", timeout.monitoring_state, "monitoring_degraded");
  eq("definitive exact absence remains an empty raw array even when a parent times out", timeout.raw_records, []);

  const servfailZone = {};
  zoneEntry(servfailZone, "_dmarc.example.test", "TXT", SERVFAIL);
  const servfail = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(servfailZone),
  });
  eq("SERVFAIL never becomes a zero-record observation", servfail.observation_state, "unavailable");
  eq("SERVFAIL raw-record state is unknown, not empty", servfail.raw_records, null);

  const malformedDnsResponse = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns({
      "txt|_dmarc.example.test": {},
    }),
  });
  eq("shape-less provider response is unavailable, not NODATA",
    malformedDnsResponse.provider_state, "malformed_response");
  eq("shape-less provider response cannot produce absence",
    malformedDnsResponse.raw_records, null);

  const truncatedDnsResponse = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns({
      "txt|_dmarc.example.test": {
        outcome: "success",
        truncated: true,
        txt_records: [{ chunks: ["v=DMARC1; p=reject; psd=n"] }],
      },
    }),
  });
  eq("unresolved DNS truncation overrides nominal success",
    truncatedDnsResponse.provider_state, "truncated_unresolved");
  eq("unresolved DNS truncation cannot produce a policy",
    truncatedDnsResponse.effective_requested_policy, null);
  eq("unresolved DNS truncation keeps raw records unknown",
    truncatedDnsResponse.raw_records, null);

  const disagreeZone = policyZone("example.test", "v=DMARC1; p=reject; psd=n");
  zoneEntry(
    disagreeZone,
    "_dmarc.example.test",
    "TXT",
    TXT("v=DMARC1; p=none; psd=n"),
    "secondary",
  );
  const disagreement = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(disagreeZone),
  });
  eq("decisive resolver disagreement is explicit", disagreement.corroboration_state, "resolver_disagreement");
  eq("decisive resolver disagreement withholds policy", disagreement.effective_requested_policy, null);
  eq("decisive resolver disagreement degrades monitoring", disagreement.monitoring_state, "monitoring_degraded");

  const pctResult = await resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone("example.test", "v=DMARC1; p=reject; pct=25; psd=n")),
  });
  eq("legacy pct cannot reduce reject semantics", pctResult.effective_requested_policy, "reject");
  eq("legacy pct remains non-operative in resolver output", pctResult.legacy_pct.applied_to_effective_policy, false);

  const deepDomain = "a.b.c.d.e.f.g.h.i.j.example.test";
  const deepZone = {};
  for (const question of planDmarcbisTreeWalk(deepDomain).questions) {
    zoneEntry(deepZone, question.name, "TXT", NODATA);
  }
  zoneEntry(deepZone, "_dmarc.example.test", "TXT",
    TXT("v=DMARC1; p=none; sp=reject; np=quarantine; psd=n"));
  zoneEntry(deepZone, deepDomain, "A", NODATA);
  const deepDns = fixtureDns(deepZone);
  const deepCore = await resolveDmarcbisPolicy({
    authorDomain: deepDomain,
    dns: deepDns,
  });
  eq("deep core issues at most eight primary tree questions",
    deepCore.limits.issued_tree_questions, 8);
  eq("deep inherited core issues one existence question",
    deepCore.limits.existence_questions, 1);
  eq("deep inherited core issues one decisive corroboration question",
    deepCore.limits.corroboration_questions, 1);
  eq("deep core total logical questions fit the approved maximum", deepDns.questions.length, 10);
}

// ── External RUA authorisation fixtures ─────────────────────────────────────
async function sourceWithRua(ruaValue) {
  return resolveDmarcbisPolicy({
    authorDomain: "example.test",
    dns: fixtureDns(policyZone(
      "example.test",
      `v=DMARC1; p=reject; psd=n; rua=${ruaValue}`,
    )),
  });
}

function destinationOrg(zone, host, org, policy = "v=DMARC1; p=none; psd=n") {
  zoneEntry(zone, `_dmarc.${host}`, "TXT", host === org ? TXT(policy) : NODATA);
  if (host !== org) zoneEntry(zone, `_dmarc.${org}`, "TXT", TXT(policy));
}

{
  const noRua = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: { rua_destinations: [] },
    dns: fixtureDns({}),
  });
  eq("complete zero rua destinations is not applicable", noRua.rua_authorisation_completeness, "not_applicable");
  eq("zero destinations never becomes all-authorized", noRua.all_destinations_authorized, null);
  const unknownRua = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: { rua_destinations: null },
    dns: fixtureDns({}),
  });
  eq("unavailable rua set remains incomplete", unknownRua.rua_authorisation_completeness, "incomplete");
  eq("unavailable rua set remains null rather than empty", unknownRua.destinations, null);

  const samePolicy = await sourceWithRua("mailto:dmarc@mail.example.test");
  const sameZone = {};
  destinationOrg(sameZone, "mail.example.test", "example.test");
  const sameDns = fixtureDns(sameZone);
  const same = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: samePolicy,
    dns: sameDns,
  });
  eq("same-org rua needs no external authorization", same.destinations[0].authorization_status, "not_required_same_organisational_domain");
  ok("same-org rua issues no RFC 9990 authorization query",
    !sameDns.questions.some((question) => question.purpose === "external_rua_authorization"));

  const externalPolicy = await sourceWithRua("mailto:dmarc@reports.external.test");
  const authName = "example.test._report._dmarc.reports.external.test";
  const authorizedZone = {};
  destinationOrg(authorizedZone, "reports.external.test", "external.test");
  zoneEntry(authorizedZone, authName, "TXT", TXT("v=DMARC1"));
  const authorized = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(authorizedZone),
  });
  eq("external rua with valid record is authorized", authorized.destinations[0].authorization_status, "authorized");
  eq("authorized rua remains under Item 5 trust gate", authorized.destinations[0].trusted_ingestion_status, "observational_item5_gate_required");
  eq("authorized rua does not prove receiver enforcement", authorized.receiver_enforcement_observed, false);

  const multipleAuthZone = { ...authorizedZone };
  zoneEntry(multipleAuthZone, authName, "TXT", TXT("v=DMARC1", "v=DMARC1; x=one"));
  const multipleAuth = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(multipleAuthZone),
  });
  eq("multiple valid authorization records authorize", multipleAuth.destinations[0].authorization_status, "authorized");
  eq("multiple valid authorization state is preserved", multipleAuth.destinations[0].authorization_record_state, "multiple_valid");

  const mixedAuthZone = { ...authorizedZone };
  zoneEntry(mixedAuthZone, authName, "TXT", TXT("v=DMARC1", "v=DMARC1; rua"));
  const mixedAuth = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(mixedAuthZone),
  });
  eq("mixed valid/malformed authorization still authorizes", mixedAuth.destinations[0].authorization_status, "authorized");
  eq("mixed authorization state is preserved", mixedAuth.destinations[0].authorization_record_state, "mixed");

  const mixedAuthDisagreementZone = { ...mixedAuthZone };
  zoneEntry(
    mixedAuthDisagreementZone,
    authName,
    "TXT",
    TXT("v=DMARC1"),
    "secondary",
  );
  const mixedAuthDisagreement = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(mixedAuthDisagreementZone),
  });
  eq("authorization corroboration compares every current candidate",
    mixedAuthDisagreement.destinations[0].authorization_status, "unavailable");
  eq("authorization candidate disagreement is explicit",
    mixedAuthDisagreement.destinations[0].authorization_record_state,
    "resolver_disagreement");

  const oversizedAuthZone = { ...authorizedZone };
  zoneEntry(
    oversizedAuthZone,
    authName,
    "TXT",
    TXT(...["xa", "xb", "xc", "xd", "xe"].map(
      (tag) => `v=DMARC1; ${tag}=${"a".repeat(60 * 1024)}`,
    )),
  );
  const oversizedAuth = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(oversizedAuthZone),
  });
  eq("oversized authorization evidence is unavailable, not unauthorized",
    oversizedAuth.destinations[0].authorization_status, "unavailable");
  eq("oversized authorization evidence remains incomplete",
    oversizedAuth.destinations[0].lookup_completeness, "incomplete");

  const unauthorizedZone = {};
  destinationOrg(unauthorizedZone, "reports.external.test", "external.test");
  zoneEntry(unauthorizedZone, authName, "TXT", NODATA);
  const unauthorized = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(unauthorizedZone),
  });
  eq("definitive zero valid authorization records is unauthorized", unauthorized.destinations[0].authorization_status, "unauthorized");
  eq("definitive unauthorized result is complete", unauthorized.rua_authorisation_completeness, "complete");

  const malformedAuthZone = { ...unauthorizedZone };
  zoneEntry(malformedAuthZone, authName, "TXT", TXT("v=DMARC1; rua"));
  const malformedAuth = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(malformedAuthZone),
  });
  eq("malformed-only authorization set has no positive determination", malformedAuth.destinations[0].authorization_status, "malformed");

  const unavailableZone = { ...unauthorizedZone };
  zoneEntry(unavailableZone, authName, "TXT", TIMEOUT, "primary");
  zoneEntry(unavailableZone, authName, "TXT", TIMEOUT, "secondary");
  const unavailable = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(unavailableZone),
  });
  eq("authorization timeout is unavailable, not unauthorized", unavailable.destinations[0].authorization_status, "unavailable");
  eq("authorization timeout makes aggregate completeness incomplete", unavailable.rua_authorisation_completeness, "incomplete");

  const authDisagreeZone = { ...authorizedZone };
  zoneEntry(authDisagreeZone, authName, "TXT", TXT("v=DMARC1; x=other"), "secondary");
  const authDisagreement = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(authDisagreeZone),
  });
  eq("authorization resolver disagreement withholds result", authDisagreement.destinations[0].authorization_record_state, "resolver_disagreement");
  eq("authorization resolver disagreement is unavailable", authDisagreement.destinations[0].authorization_status, "unavailable");

  const budgetDns = fixtureDns(authorizedZone);
  const budgeted = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: budgetDns,
    reserveHost: () => false,
  });
  eq("full-host reservation refusal is explicit", budgeted.destinations[0].authorization_status, "not_assessed_budget");
  eq("budget refusal prohibits all-authorized claim", budgeted.all_destinations_authorized, null);
  eq("budget refusal issues no destination DNS question", budgetDns.questions.length, 0);

  const twoHostPolicy = await sourceWithRua(
    "mailto:first@reports.external.test,mailto:second@reports.second.test",
  );
  const oneHostDns = fixtureDns(authorizedZone);
  let reservation = 0;
  const oneHostOnly = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: twoHostPolicy,
    dns: oneHostDns,
    reserveHost: () => ++reservation === 1,
  });
  eq("first fully admitted host is assessed", oneHostOnly.destinations[0].authorization_status, "authorized");
  eq("next host is refused before any partial work", oneHostOnly.destinations[1].authorization_status, "not_assessed_budget");
  ok("refused second host issues no destination question",
    !oneHostDns.questions.some((question) => question.name.includes("reports.second.test")));

  const sameOverrideZone = { ...authorizedZone };
  zoneEntry(
    sameOverrideZone,
    authName,
    "TXT",
    TXT("v=DMARC1; rua=mailto:replacement@reports.external.test"),
  );
  const sameOverride = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(sameOverrideZone),
  });
  eq("same-host override is selected", sameOverride.destinations[0].override_status, "same_host_override");
  eq("same-host override retains destination host", sameOverride.destinations[0].authorized_destination, "mailto:replacement@reports.external.test");

  const secondHopZone = { ...authorizedZone };
  zoneEntry(
    secondHopZone,
    authName,
    "TXT",
    TXT("v=DMARC1; rua=mailto:replacement@second.example"),
  );
  const secondHop = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(secondHopZone),
  });
  eq("different-host override prohibits both destinations", secondHop.destinations[0].destination_usability, "prohibited_second_hop");
  eq("different-host override selects no destination", secondHop.destinations[0].authorized_destination, null);

  const conflictZone = { ...authorizedZone };
  zoneEntry(
    conflictZone,
    authName,
    "TXT",
    TXT(
      "v=DMARC1; rua=mailto:first@reports.external.test",
      "v=DMARC1; rua=mailto:second@reports.external.test",
    ),
  );
  const conflict = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: externalPolicy,
    dns: fixtureDns(conflictZone),
  });
  eq("conflicting same-host overrides are not arbitrarily selected", conflict.destinations[0].override_status, "conflicting_same_host");
  eq("conflicting same-host overrides select no destination", conflict.destinations[0].authorized_destination, null);

  const unsupportedPolicy = await sourceWithRua(
    "https://reports.external.test/dmarc,mailto:dmarc@reports.external.test",
  );
  const unsupportedResult = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: unsupportedPolicy,
    dns: fixtureDns(authorizedZone),
  });
  eq("multiple rua entries remain ordered", unsupportedResult.destinations.length, 2);
  eq("unsupported destination remains unassessed", unsupportedResult.destinations[0].authorization_status, "not_assessed_unsupported_scheme");
  eq("one unassessed destination makes aggregate incomplete", unsupportedResult.rua_authorisation_completeness, "incomplete");
  eq("mixed completeness prohibits all-authorized claim", unsupportedResult.all_destinations_authorized, null);

  const repeatedHostPolicy = await sourceWithRua(
    "mailto:first@reports.external.test,mailto:second@reports.external.test",
  );
  const repeatedHostDns = fixtureDns(authorizedZone);
  const repeatedHost = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: repeatedHostPolicy,
    dns: repeatedHostDns,
  });
  eq("first same-host URI retains its own authorized destination",
    repeatedHost.destinations[0].authorized_destination,
    "mailto:first@reports.external.test");
  eq("reused same-host assessment retains the second URI destination",
    repeatedHost.destinations[1].authorized_destination,
    "mailto:second@reports.external.test");
  ok("same-host reuse issues only one authorization pair",
    repeatedHostDns.questions.filter((question) =>
      question.purpose?.startsWith("external_rua_authorization")).length === 2);

  const manyUris = Array.from(
    { length: DMARCBIS_MAX_REPORT_URIS + 1 },
    (_, index) => `mailto:r${index}@h${index % 2}.external.test`,
  ).join(",");
  const manyPolicy = await sourceWithRua(manyUris);
  const many = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: manyPolicy,
    dns: fixtureDns({}),
  });
  eq("URI overflow retains every bounded parsed entry", many.destinations.length, DMARCBIS_MAX_REPORT_URIS + 1);
  eq("URI overflow is explicitly unassessed", many.destinations.at(-1).assessment_reason, "uri_count_limit");
  eq("URI overflow prohibits all-authorized claim", many.all_destinations_authorized, null);

  const sixHostsPolicy = await sourceWithRua(
    Array.from({ length: 6 }, (_, index) => `mailto:r@host${index}.external.test`).join(","),
  );
  const sixHosts = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: sixHostsPolicy,
    dns: fixtureDns({}),
  });
  eq("sixth unique external host is retained but unassessed", sixHosts.destinations[5].assessment_reason, "external_host_limit");
  eq("destination host overflow prohibits all-authorized claim", sixHosts.all_destinations_authorized, null);

  const deepDestination = "a.b.c.d.e.f.g.h.i.external.test";
  const deepExternalRecord = parseDmarcbisPolicyRecord(
    `v=DMARC1; p=reject; rua=mailto:dmarc@${deepDestination}`,
  );
  const deepExternalPolicy = {
    policy_source_domain: "example.test",
    organisational_domain: "example.test",
    rua_destinations: deepExternalRecord.rua,
  };
  const deepExternalZone = {};
  for (const question of planDmarcbisTreeWalk(deepDestination).questions) {
    zoneEntry(deepExternalZone, question.name, "TXT", NODATA);
  }
  zoneEntry(deepExternalZone, "_dmarc.external.test", "TXT",
    TXT("v=DMARC1; p=none; psd=n"));
  const deepAuthName = `example.test._report._dmarc.${deepDestination}`;
  zoneEntry(deepExternalZone, deepAuthName, "TXT", TXT("v=DMARC1"));
  const deepExternalDns = fixtureDns(deepExternalZone);
  const deepExternal = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: deepExternalPolicy,
    dns: deepExternalDns,
  });
  eq("deep external destination remains authorized", deepExternal.destinations[0].authorization_status, "authorized");
  eq("deep external host consumes no more than its full 11-question reservation",
    deepExternalDns.questions.length, 11);

  const longPolicySource =
    `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(40)}`;
  const longNameRecord = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=reject; rua=mailto:dmarc@reports.external.test",
  );
  const longNameZone = {};
  destinationOrg(longNameZone, "reports.external.test", "external.test");
  const longNameDns = fixtureDns(longNameZone);
  const longName = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence: {
      policy_source_domain: longPolicySource,
      organisational_domain: longPolicySource,
      rua_destinations: longNameRecord.rua,
    },
    dns: longNameDns,
  });
  eq("overlong constructed authorization name has no positive determination",
    longName.destinations[0].authorization_record_state, "name_too_long");
  ok("overlong constructed name is never truncated into a DNS question",
    !longNameDns.questions.some((question) => question.purpose === "external_rua_authorization"));
}

// P1 boundary: no production caller until P2.
{
  const fs = await import("node:fs");
  const scanEngine = fs.readFileSync(
    new URL("../workers/scan-api/src/engines/scan-engine.js", import.meta.url),
    "utf8",
  );
  ok("P1 canonical resolver has no production runScanEngine caller",
    !scanEngine.includes("dmarcbis-resolver"));
  ok("P1 does not modify the legacy production DMARC decision before P2",
    scanEngine.includes("runEmailModule"));
}

console.log(`\nDMARCbis P1 fixtures: ${pass} passed, ${fail} failed`);
if (fail) {
  console.error(failures.map((failure) => ` - ${failure}`).join("\n"));
  process.exit(1);
}
