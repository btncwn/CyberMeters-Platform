// DMARCbis DNS-name canonicalisation.
//
// Pure protocol support: no DNS, persistence, API, lifecycle, or presentation
// caller is wired in P1. RFC 9990 §4 requires an A-label policy source in the
// external-authorisation query name. The approved Worker-compatible UTS #46
// implementation is pinned exactly in package.json.
import tr46 from "tr46";

export const DMARCBIS_IDNA_PROFILE = Object.freeze({
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

function isIpLiteral(value) {
  if (value.startsWith("[") || value.endsWith("]") || value.includes(":")) return true;
  if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value)) return false;
  return value.split(".").every((part) => Number(part) <= 255);
}

export function dnsNameLength(name) {
  const labels = String(name || "").split(".");
  return {
    labels,
    label_octets: labels.map((label) => new TextEncoder().encode(label).byteLength),
    presentation_octets: new TextEncoder().encode(String(name || "")).byteLength,
  };
}

export function validateDnsNameLength(name) {
  const { labels, label_octets: labelOctets, presentation_octets: presentationOctets } =
    dnsNameLength(name);
  if (labels.length === 0 || labels.some((label) => label.length === 0)) {
    return { ok: false, error: "empty_label" };
  }
  const overlongIndex = labelOctets.findIndex((length) => length > 63);
  if (overlongIndex !== -1) {
    return {
      ok: false,
      error: "label_too_long",
      label_index: overlongIndex,
      label_octets: labelOctets[overlongIndex],
    };
  }
  // A fully qualified name can occupy at most 255 wire octets. The textual
  // representation without the root dot therefore occupies at most 253.
  if (presentationOctets > 253) {
    return { ok: false, error: "name_too_long", name_octets: presentationOctets };
  }
  return { ok: true, name_octets: presentationOctets, label_octets: labelOctets };
}

export function canonicalizeDmarcbisDomain(input) {
  const raw = input == null ? "" : String(input);
  const submitted = raw.trim();
  const hadTrailingDot = submitted.endsWith(".");
  const withoutRoot = hadTrailingDot ? submitted.slice(0, -1) : submitted;

  const fail = (error, detail = null) => ({
    ok: false,
    raw,
    submitted,
    had_trailing_dot: hadTrailingDot,
    alabel: null,
    error,
    detail,
    idna_profile: DMARCBIS_IDNA_PROFILE,
  });

  if (!withoutRoot) return fail("empty_name");
  if (withoutRoot.includes("..") || withoutRoot.startsWith(".") || withoutRoot.endsWith(".")) {
    return fail("empty_label");
  }
  if (isIpLiteral(withoutRoot)) return fail("ip_literal_not_allowed");

  let alabel;
  try {
    alabel = tr46.toASCII(withoutRoot, {
      checkBidi: DMARCBIS_IDNA_PROFILE.checkBidi,
      checkHyphens: DMARCBIS_IDNA_PROFILE.checkHyphens,
      checkJoiners: DMARCBIS_IDNA_PROFILE.checkJoiners,
      useSTD3ASCIIRules: DMARCBIS_IDNA_PROFILE.useSTD3ASCIIRules,
      verifyDNSLength: DMARCBIS_IDNA_PROFILE.verifyDNSLength,
      transitionalProcessing: DMARCBIS_IDNA_PROFILE.transitionalProcessing,
      ignoreInvalidPunycode: DMARCBIS_IDNA_PROFILE.ignoreInvalidPunycode,
    });
  } catch (error) {
    return fail("idna_conversion_error", String(error?.message || error));
  }

  if (!alabel) return fail("invalid_idna_name");
  alabel = alabel.toLowerCase();
  const length = validateDnsNameLength(alabel);
  if (!length.ok) return fail(length.error, length);

  return {
    ok: true,
    raw,
    submitted,
    had_trailing_dot: hadTrailingDot,
    alabel,
    error: null,
    detail: null,
    length,
    idna_profile: DMARCBIS_IDNA_PROFILE,
  };
}

function constructName(parts) {
  const name = parts.filter(Boolean).join(".").toLowerCase();
  const length = validateDnsNameLength(name);
  return length.ok
    ? { ok: true, name, length, error: null }
    : { ok: false, name: null, length, error: length.error };
}

export function constructDmarcPolicyName(domain) {
  const canonical = typeof domain === "object" && domain?.alabel
    ? domain
    : canonicalizeDmarcbisDomain(domain);
  if (!canonical.ok) {
    return { ok: false, name: null, error: canonical.error, domain: canonical };
  }
  return {
    ...constructName(["_dmarc", canonical.alabel]),
    domain: canonical,
  };
}

export function constructExternalRuaAuthorizationName(policySourceDomain, destinationHost) {
  const policySource = typeof policySourceDomain === "object" && policySourceDomain?.alabel
    ? policySourceDomain
    : canonicalizeDmarcbisDomain(policySourceDomain);
  const destination = typeof destinationHost === "object" && destinationHost?.alabel
    ? destinationHost
    : canonicalizeDmarcbisDomain(destinationHost);

  if (!policySource.ok) {
    return {
      ok: false,
      name: null,
      error: policySource.error,
      policy_source: policySource,
      destination,
    };
  }
  if (!destination.ok) {
    return {
      ok: false,
      name: null,
      error: destination.error,
      policy_source: policySource,
      destination,
    };
  }

  return {
    ...constructName([
      policySource.alabel,
      "_report",
      "_dmarc",
      destination.alabel,
    ]),
    policy_source: policySource,
    destination,
  };
}
