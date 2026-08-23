#!/usr/bin/env node
//
// P1.2-E — HISTORICAL READ-COMPATIBILITY. Node 24+.
//
// THE CLASS. Before P1.1, ssl-scan.js set `http_redirect_validated` from TRANSPORT
// observation, so an origin answering 5xx on the plain-HTTP hop — never serving,
// never revealing whether it redirects — still "validated" the redirect decision and
// published a scored `ssl_no_http_redirect` defect. Those conclusions are frozen in
// stored snapshots and were read at face value by every snapshot consumer.
//
// STORED BYTES ARE NEVER REWRITTEN. This is a pure READ projection: the immutable
// snapshot and its checksum are untouched; only the customer view is corrected.
//
// THE DISCRIMINATOR IS THE EVIDENCE SHAPE, NOT A VERSION. #424 proved what a moving
// boundary costs — comparing stored rows against a constant that moves on every mint
// re-classifies honest history as legacy. The recorded chain states outright whether
// the hop that "validated" the redirect was serviceable, so this asks the evidence.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const {
  projectWebsiteRedirectSnapshotForCustomer, projectPhase5SnapshotForCustomer,
  LEGACY_WEBSITE_REDIRECT_REASON, LEGACY_WEBSITE_REDIRECT_FINDING,
} = await import(eng("phase5-evidence.js"));
const { projectLegacyWebsiteDomainState, LEGACY_TLS_DOMAIN_RESOLVER_VERSIONS,
        LEGACY_UNPROVEN_TLS_SLUG, LEGACY_IDENTITY_PROJECTION } = await import(eng("finding-identity.js"));
const { CYBER_MOT_RESOLVER_VERSION, FIRST_HONEST_RESOLVER_VERSION } = await import(eng("cyber-mot-domains.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const snapshot = () => Object.freeze({
  observed_findings: [{ finding_id: LEGACY_WEBSITE_REDIRECT_FINDING, severity: "medium" },
                      { finding_id: "header_missing_csp", severity: "low" }],
  domains: [{ domain_key: "website_security", state: "issue_detected", coverage: "complete",
              finding_ids: [LEGACY_WEBSITE_REDIRECT_FINDING], finding_count: 1 },
            { domain_key: "email_protection", state: "assessed_healthy", coverage: "complete" }],
  overall: { cyber_metrics_score: 85, score_band: "good" },
});
const chain = (state, origin_status, validated = true) => ({ ssl: { http_redirect_chain: {
  http_redirect_validated: validated, hop_observations: [{ state, origin_status }] } } });
const website = (s) => s.domains.find((d) => d.domain_key === "website_security");
const findingIds = (s) => s.observed_findings.map((f) => f.finding_id);

// ── GATE 1 — the affected class is projected, not read at face value ────────
{
  const out = projectWebsiteRedirectSnapshotForCustomer(snapshot(), chain("origin_response", 503));
  eq("P12E_AFFECTED_DOMAIN_IS_EVIDENCE_INSUFFICIENT", website(out).state, "evidence_insufficient");
  ok("P12E_AFFECTED_FINDING_IS_WITHHELD", !findingIds(out).includes(LEGACY_WEBSITE_REDIRECT_FINDING));
  ok("P12E_UNRELATED_FINDING_SURVIVES", findingIds(out).includes("header_missing_csp"));
  eq("P12E_AFFECTED_SCORE_IS_WITHHELD", out.overall.cyber_metrics_score, null);
  eq("P12E_PROJECTION_IS_DECLARED", out.customer_projection.website_redirect_reason,
     LEGACY_WEBSITE_REDIRECT_REASON);
  ok("P12E_UNAFFECTED_DOMAIN_UNTOUCHED",
     out.domains.find((d) => d.domain_key === "email_protection").state === "assessed_healthy");
  const edge = projectWebsiteRedirectSnapshotForCustomer(snapshot(), chain("cloudflare_edge_error", null));
  eq("P12E_EDGE_ERROR_HOP_ALSO_PROJECTED", website(edge).state, "evidence_insufficient");
}

// ── GATE 2 — STORED BYTES ARE NEVER REWRITTEN ───────────────────────────────
{
  const stored = snapshot();
  const before = JSON.stringify(stored);
  const out = projectWebsiteRedirectSnapshotForCustomer(stored, chain("origin_response", 503));
  eq("P12E_INPUT_SNAPSHOT_IS_BYTE_IDENTICAL_AFTER_PROJECTION", JSON.stringify(stored), before);
  ok("P12E_PROJECTION_RETURNS_A_NEW_OBJECT", out !== stored);
  ok("P12E_STORED_DOMAIN_ARRAY_NOT_MUTATED", website(stored).state === "issue_detected");
}

// ── GATE 3 — POSITIVE CONTROLS: honest history is left alone ────────────────
// The #424 lesson is binding here: a projection that masks honest rows is the same
// defect in the opposite direction.
{
  for (const [label, mods] of [
    ["serviceable_200", chain("origin_response", 200)],
    ["serviceable_404", chain("origin_response", 404)],
    ["serviceable_301", chain("origin_response", 301)],
  ]) {
    const out = projectWebsiteRedirectSnapshotForCustomer(snapshot(), mods);
    eq(`P12E_POSITIVE_${label.toUpperCase()}_STATE_UNCHANGED`, website(out).state, "issue_detected");
    ok(`P12E_POSITIVE_${label.toUpperCase()}_FINDING_KEPT`,
       findingIds(out).includes(LEGACY_WEBSITE_REDIRECT_FINDING));
    eq(`P12E_POSITIVE_${label.toUpperCase()}_SCORE_KEPT`, out.overall.cyber_metrics_score, 85);
  }
}

// ── GATE 4 — FAIL NEUTRAL when the shape cannot be evaluated ────────────────
// report-snapshot.js falls back to `{}` when the R2 source read fails. Masking on
// absent evidence would tell a customer their honest conclusion was unfounded, on no
// evidence at all.
{
  for (const [label, mods] of [
    ["modules_absent", {}],
    ["no_chain", { ssl: {} }],
    ["validated_false", chain("origin_response", 503, false)],
    ["unreadable_hop_state", chain(undefined, 503)],
    // UNKNOWN serviceability, not merely unreadable. Under the P1.1 admission
    // contract an out-of-range status is a MALFORMED OBSERVATION and classifies
    // null — neither serviceable nor proven non-serviceable. Unknown must leave
    // history alone: only a POSITIVE reading of "this could not have grounded a
    // defect" may withhold a customer's historical conclusion.
    ["unknown_serviceability_out_of_range", chain("origin_response", 600)],
    ["unknown_serviceability_fractional", chain("origin_response", 200.5)],
    ["null_modules", null],
  ]) {
    const out = projectWebsiteRedirectSnapshotForCustomer(snapshot(), mods);
    eq(`P12E_NEUTRAL_${label.toUpperCase()}_STATE_UNCHANGED`, website(out).state, "issue_detected");
    ok(`P12E_NEUTRAL_${label.toUpperCase()}_FINDING_KEPT`,
       findingIds(out).includes(LEGACY_WEBSITE_REDIRECT_FINDING));
  }
  ok("P12E_NEUTRAL_NON_OBJECT_SNAPSHOT_RETURNED_AS_IS",
     projectWebsiteRedirectSnapshotForCustomer(null, chain("origin_response", 503)) === null);
}

// ── GATE 5 — the class must actually be present ─────────────────────────────
{
  const clean = { ...snapshot(), observed_findings: [{ finding_id: "header_missing_csp" }] };
  const out = projectWebsiteRedirectSnapshotForCustomer(clean, chain("origin_response", 503));
  eq("P12E_NO_REDIRECT_FINDING_MEANS_NO_PROJECTION", website(out).state, "issue_detected");
}

// ── GATE 6 — the composite chain carries it ─────────────────────────────────
{
  const out = projectPhase5SnapshotForCustomer(snapshot(), chain("origin_response", 503));
  eq("P12E_COMPOSITE_CHAIN_APPLIES_THE_PROJECTION", website(out).state, "evidence_insufficient");
}

// ── GATE 7 — the CLOSED historical enumeration must stay closed ─────────────
// `LEGACY_TLS_DOMAIN_RESOLVER_VERSIONS` (finding-identity.js:21-27) is bounded ON
// PURPOSE to versions predating the identity layer — its own comment says "New/future
// versions are intentionally excluded". Extending it is the INVERTED failure of this
// episode: not a moving boundary that masks history, but a widened enumeration that
// masks LIVE rows. A current-version row must never be projected as legacy.
{
  // The row must satisfy EVERY precondition at finding-identity.js:195-203, or the
  // "still projected" control would pass for the wrong reason (guard rejected the
  // shape) rather than because the version is enumerated.
  const legacyRow = (version) => ({
    domain_key: "website_security",
    state: "issue_detected",
    highest_severity: "critical",
    finding_count: 1,
    finding_ids_json: JSON.stringify([LEGACY_UNPROVEN_TLS_SLUG]),
    resolver_version: version,
    coverage: "complete",
  });
  const projected = (v) => projectLegacyWebsiteDomainState(legacyRow(v));
  // Positive control — a genuinely enumerated legacy version IS still projected, so
  // this gate cannot pass by the projection being switched off entirely.
  ok("P12E_ENUM_GENUINELY_LEGACY_VERSION_STILL_PROJECTED",
     projected("2026-07-16.1").legacy_identity_projection === LEGACY_IDENTITY_PROJECTION,
     JSON.stringify(projected("2026-07-16.1").legacy_identity_projection));
  // The inverted case: the CURRENT resolver must never be treated as legacy.
  ok("P12E_ENUM_CURRENT_VERSION_IS_NOT_MASKED_AS_LEGACY",
     projected(CYBER_MOT_RESOLVER_VERSION).legacy_identity_projection === undefined,
     `current=${CYBER_MOT_RESOLVER_VERSION}`);
  ok("P12E_ENUM_FIRST_HONEST_VERSION_IS_NOT_MASKED_AS_LEGACY",
     projected(FIRST_HONEST_RESOLVER_VERSION).legacy_identity_projection === undefined,
     `floor=${FIRST_HONEST_RESOLVER_VERSION}`);
  eq("P12E_ENUM_REMAINS_CLOSED_AT_FOUR_ENTRIES", LEGACY_TLS_DOMAIN_RESOLVER_VERSIONS.length, 4);
  ok("P12E_ENUM_DOES_NOT_CONTAIN_THE_CURRENT_VERSION",
     !LEGACY_TLS_DOMAIN_RESOLVER_VERSIONS.includes(CYBER_MOT_RESOLVER_VERSION));
}

console.log(`\nP1.2-E historical read-compatibility: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("P1.2-E validation FAILED"); process.exit(1); }
console.log("P1.2-E validation passed");
