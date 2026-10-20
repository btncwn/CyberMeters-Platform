// ── Free DMARC checker (public /tools/dmarc-checker) ─────────────────────────
//
// Reuses the canonical RFC 9989 (DMARCbis) core: the DNS tree walk, the
// organisational-domain derivation, p/sp/np/t inheritance and the external
// report-destination authorisation phase (dmarcbis-production.js), and the
// customer wording of dmarcbis-presentation.js. This module only projects that
// evidence into the public result and writes the suggested next record. It
// never parses DMARC itself and never upgrades an incomplete lookup into a
// missing record.
import { buildDmarcPolicyPresentation } from "../dmarcbis-presentation.js";
import {
  attachDmarcbisExternalResult,
  runDmarcbisCore,
  runDmarcbisExternalRuaPhase,
} from "../dmarcbis-production.js";

export const DMARC_TOOL_SCHEMA = "free-tool-dmarc.v1";

const LADDER = Object.freeze([
  { policy: "none", label: "Monitor", detail: "p=none: receivers report but take no action on failing mail." },
  { policy: "quarantine", label: "Quarantine", detail: "p=quarantine: failing mail is treated as suspicious, usually sent to spam." },
  { policy: "reject", label: "Reject", detail: "p=reject: failing mail is refused." },
]);
const RANK = Object.freeze({ none: 0, quarantine: 1, reject: 2 });

const POLICY_MEANING = Object.freeze({
  none: "No action: receivers send reports but deliver failing mail as normal.",
  quarantine: "Quarantine: receivers are asked to treat failing mail as suspicious, usually the spam folder.",
  reject: "Reject: receivers are asked to refuse failing mail.",
});
const ALIGNMENT_MEANING = Object.freeze({
  r: "relaxed: a subdomain counts as a match (mail.example.com aligns with example.com).",
  s: "strict: only the exact same domain counts as a match.",
});

// The record is rebuilt in this order; unknown and legacy tags are dropped.
const TAG_ORDER = Object.freeze(["v", "p", "sp", "np", "psd", "adkim", "aspf", "rua", "ruf", "fo"]);

function tagValue(record, name) {
  const tag = record?.[name];
  if (!tag || typeof tag !== "object") return null;
  return tag.present === true && tag.validity === "valid" ? String(tag.raw) : null;
}

function rawTagMap(record) {
  const map = new Map();
  for (const tag of record?.tags || []) {
    if (tag.known && !tag.duplicate && !map.has(tag.name)) map.set(tag.name, String(tag.raw_value ?? "").trim());
  }
  return map;
}

function buildRecord(map) {
  const parts = [];
  for (const name of TAG_ORDER) {
    if (name === "v") { parts.push("v=DMARC1"); continue; }
    if (map.has(name) && map.get(name)) parts.push(`${name}=${map.get(name)}`);
  }
  return parts.join("; ");
}

function explainTags(record) {
  if (!record) return [];
  const out = [];
  const p = record.p?.normalized ?? null;
  const add = (tag, value, meaning, defaulted = false) => out.push({ tag, value, meaning, defaulted });
  if (p) add("p", p, POLICY_MEANING[p] || "Not a recognised policy value.", record.p.defaulted === true);
  const sp = tagValue(record, "sp");
  add("sp", sp ?? "(not set)", sp
    ? `Subdomains: ${POLICY_MEANING[sp] || sp}`
    : "Not set, so subdomains use the p policy.", !sp);
  const np = tagValue(record, "np");
  add("np", np ?? "(not set)", np
    ? `Subdomains that do not exist in DNS: ${POLICY_MEANING[np] || np} (RFC 9989).`
    : "Not set, so subdomains that do not exist use sp, or p when sp is not set (RFC 9989).", !np);
  const adkim = record.adkim?.normalized || "r";
  add("adkim", adkim, `DKIM alignment ${ALIGNMENT_MEANING[adkim] || adkim}`, record.adkim?.defaulted === true);
  const aspf = record.aspf?.normalized || "r";
  add("aspf", aspf, `SPF alignment ${ALIGNMENT_MEANING[aspf] || aspf}`, record.aspf?.defaulted === true);
  const t = record.t?.normalized;
  if (t === "y") add("t", "y", "Testing mode (RFC 9989): receivers are asked to apply one step less than the policy says.");
  if (record.legacy_pct?.observed) {
    add("pct", String(record.legacy_pct.raw), "Removed by RFC 9989. Older receivers may still apply the policy to only this percentage of failing mail; current ones ignore it.");
  }
  const fo = record.fo?.present ? (Array.isArray(record.fo.normalized) ? record.fo.normalized.join(":") : String(record.fo.raw)) : null;
  if (fo) add("fo", fo, "Failure-report options: when receivers that send failure reports should send one.");
  return out;
}

// Aggregate-report destinations carry the canonical presentation's label and
// message (dmarcbis-presentation.js); failure-report destinations are listed
// but their authorisation is not assessed.
function destinationRows(evidence, presentation, list) {
  const destinations = Array.isArray(evidence?.external_rua_authorisation?.destinations) && list === "rua"
    ? evidence.external_rua_authorisation.destinations
    : (evidence?.[`${list}_destinations`] || []);
  const presented = list === "rua" ? (presentation?.external_rua?.destinations || []) : [];
  return destinations.map((destination, index) => ({
    uri: destination.normalized_uri || destination.raw || null,
    host: destination.destination_host || null,
    status: list === "rua" ? (destination.authorization_status || "unavailable") : "not_assessed",
    label: list === "rua" ? (presented[index]?.status_label || "Authorisation not determined") : "Authorisation not checked for failure reports",
    message: list === "rua" ? (presented[index]?.message || null) : null,
    authorization_query_name: destination.authorization_query_name || null,
  }));
}

const WHY_IT_MATTERS = "DMARC tells receiving mail servers what to do with email that claims to be from your domain but fails authentication. Without an enforced policy, anyone can send invoices, payment changes or password-reset emails that appear to come from you, and your customers' mail servers will deliver them. Several large mailbox providers now require DMARC from bulk senders, so it also affects whether your own mail arrives.";

const NOT_CHECKED = Object.freeze([
  { label: "Whether receivers apply your policy", reason: "Each receiver decides; DNS shows only what you request." },
  { label: "Whether your real senders pass", reason: "That needs aggregate reports from receivers over days or weeks, not a single DNS check." },
  { label: "DKIM keys", reason: "DKIM selectors cannot be listed from DNS, so this tool does not guess them." },
  { label: "Whether report mailboxes exist or are read", reason: "Only the receiving side of those addresses can see that." },
]);

function nextRecordPlan(evidence, presentation, destinations) {
  const record = evidence.source_record;
  const author = evidence.author_domain;
  const org = evidence.organisational_domain || author;
  const name = `_dmarc.${author}`;
  const cautions = [];

  if (["absent"].includes(evidence.observation_state) && evidence.policy_source_kind === "none") {
    return {
      title: "Publish a DMARC record",
      explanation: "Start in monitoring mode: it changes no delivery, and the reports show every service that sends as you. Create the report mailbox first, or point rua at a reporting service you use.",
      record: { type: "TXT", name: `_dmarc.${org}`, value: `v=DMARC1; p=none; rua=mailto:dmarc-reports@${org}` },
      cautions: ["Replace dmarc-reports@ with a mailbox that exists. Reports arrive daily as XML attachments."],
    };
  }
  if (evidence.policy_source_kind === "organisational" || evidence.policy_source_kind === "psd") {
    const policy = evidence.effective_requested_policy;
    return {
      title: policy && RANK[policy] >= 1 ? "No change needed for this subdomain" : `Strengthen the policy at ${evidence.policy_source_domain}`,
      explanation: `${presentation.policy.inheritance_message || `${author} has no record of its own and inherits the organisational policy.`} Changes belong in the record at _dmarc.${evidence.policy_source_domain}.`,
      record: null,
      cautions,
    };
  }
  if (evidence.observation_state === "multiple") {
    return {
      title: "Keep exactly one DMARC record",
      explanation: `${name} publishes more than one DMARC record, so receivers ignore all of them. Delete every one except the record you want to keep.`,
      record: null,
      cautions,
    };
  }
  if (!record) return null;

  const map = rawTagMap(record);
  const changes = [];
  const declared = record.p?.normalized;
  if (record.validity === "invalid" || record.policy_mode !== "normal") {
    for (const tag of ["p", "sp", "np", "adkim", "aspf"]) {
      if (record[tag]?.validity === "invalid") { map.delete(tag); changes.push(`Removed the invalid ${tag}= value.`); }
    }
    if (!map.has("p")) { map.set("p", "none"); changes.push("Set p=none so the record is valid."); }
  }
  if (map.has("pct") || record.legacy_pct?.observed) {
    changes.push("Removed pct=: RFC 9989 dropped it, and a value below 100 makes older receivers enforce only part of the policy.");
  }
  if (record.t?.normalized === "y") {
    changes.push("Removed t=y so receivers apply the policy as written.");
  }
  const current = map.get("p") || declared || "none";
  const invalid = record.validity === "invalid" || record.policy_mode !== "normal";
  let title = invalid ? "Replace the record with a valid one" : "Update the record";
  // The policy only moves up once reports exist to show it is safe: without
  // rua= nobody can see which senders would fail. Reporting comes first.
  const hasReports = map.has("rua");
  if (!hasReports && !invalid && (current === "none" || current === "quarantine")) {
    title = `Turn on reports first, keep p=${current}`;
    cautions.push(`Keep p=${current} for now. Once a few weeks of aggregate reports show every service that sends as you passing SPF or DKIM in alignment, move to ${current === "none" ? "p=quarantine" : "p=reject"}.`);
  } else if (current === "none" && !invalid) {
    map.set("p", "quarantine");
    title = "Move from monitoring to quarantine";
    changes.push("Changed p=none to p=quarantine.");
    cautions.push("Only do this once your aggregate reports show every service that sends as you passing SPF or DKIM in alignment; otherwise their mail goes to spam.");
  } else if (current === "quarantine") {
    map.set("p", "reject");
    title = "Move from quarantine to reject";
    changes.push("Changed p=quarantine to p=reject.");
    cautions.push("Keep watching the aggregate reports for a few weeks at quarantine first: anything still failing will be refused at reject.");
  } else if (current === "reject") {
    const sp = map.get("sp");
    if (sp && RANK[sp] < RANK.reject && !map.has("np")) {
      map.set("np", "reject");
      title = "Close the gap for subdomains that do not exist";
      changes.push("Added np=reject: no mail should come from a subdomain that does not exist, so it can be refused even while sp stays weaker (RFC 9989).");
    }
  }
  if (!map.has("rua")) {
    map.set("rua", `mailto:dmarc-reports@${org}`);
    changes.push(`Added rua= so you receive aggregate reports (replace dmarc-reports@${org} with a mailbox that exists).`);
  }
  map.delete("pct");
  map.delete("t");

  const unauthorized = destinations.filter((destination) => destination.status === "unauthorized");
  if (unauthorized.length > 0) {
    cautions.push(...unauthorized.map((destination) => (
      `Reports to ${destination.uri} are not authorised by ${destination.host}, so receivers following the standard will not send them there. The report receiver must publish a TXT record at ${destination.authorization_query_name || `${author}._report._dmarc.${destination.host}`} with the value v=DMARC1.`
    )));
  }

  if (changes.length === 0) {
    return {
      title: "No change needed",
      explanation: "The record already asks receivers to reject failing mail and asks for reports. Keep watching the reports for new services that send as you.",
      record: null,
      cautions,
    };
  }
  return {
    title,
    explanation: changes.join(" "),
    record: { type: "TXT", name, value: buildRecord(map) },
    replaces: record.value ? [record.value] : [],
    cautions,
  };
}

/** Pure projection: canonical DMARCbis evidence → public result. Exported for tests. */
export function buildDmarcToolResult(evidence, { domain, checkedAt }) {
  const presentation = buildDmarcPolicyPresentation({ status: "current", evidence });
  const base = { schema: DMARC_TOOL_SCHEMA, tool: "dmarc", domain, checked_at: checkedAt };
  const complete = evidence?.policy_completeness === "complete"
    && !["unavailable", "resolver_disagreement", "incomplete_oversized"].includes(evidence?.observation_state);

  if (!complete) {
    return {
      ...base,
      verdict: {
        level: "unknown",
        headline: "Could not check DMARC",
        summary: presentation.observation?.message || "A required DNS lookup was unavailable. This is not a missing-record result.",
      },
      record: null,
      tags: [],
      ladder: { steps: LADDER, current: null },
      reporting: { rua: [], ruf: [] },
      checked: [{ label: "DMARC record lookup", state: "unknown", detail: presentation.observation?.message || null }],
      not_checked: NOT_CHECKED,
      why_it_matters: WHY_IT_MATTERS,
      next_step: { title: "Try again shortly", explanation: "Nothing was concluded about this domain.", record: null },
    };
  }

  const record = evidence.source_record || null;
  const effective = evidence.effective_requested_policy || null;
  const rua = destinationRows(evidence, presentation, "rua");
  const ruf = destinationRows(evidence, presentation, "ruf");
  const checked = [];
  const inherited = ["organisational", "psd"].includes(evidence.policy_source_kind);
  const noPolicy = evidence.policy_source_kind === "none";

  checked.push({
    label: "DMARC record",
    state: noPolicy || evidence.observation_state === "multiple" || evidence.record_validity === "invalid" ? "fail" : "pass",
    detail: inherited ? presentation.policy.inheritance_message : presentation.observation.message,
  });
  if (record?.diagnostics?.length) {
    checked.push({
      label: "Record syntax",
      state: record.validity === "invalid" ? "fail" : "warn",
      detail: record.diagnostics.map((d) => d.code === "invalid_tag_value" ? `${d.tag}=${d.raw} is not a valid value.` : d.code === "duplicate_tag" ? `Tag repeated: ${(d.tags || []).join(", ")}.` : d.code).join(" "),
    });
  }
  if (effective) {
    checked.push({
      label: "Policy",
      state: effective === "none" ? "warn" : "pass",
      detail: [presentation.policy.message, presentation.policy.testing_message].filter(Boolean).join(" "),
    });
  }
  const sp = tagValue(record, "sp");
  const declared = record?.p?.normalized;
  if (sp && declared && RANK[sp] < RANK[declared]) {
    checked.push({ label: "Subdomain policy", state: "warn", detail: `sp=${sp} is weaker than p=${declared}, so forged mail from a subdomain gets less protection than the main domain.` });
  }
  if (presentation.legacy_pct?.message) {
    checked.push({ label: "Legacy pct tag", state: Number(record?.legacy_pct?.numeric) < 100 ? "warn" : "info", detail: presentation.legacy_pct.message });
  }
  if (!noPolicy) {
    checked.push({
      label: "Aggregate reports (rua)",
      state: rua.length > 0 ? "pass" : "warn",
      detail: rua.length > 0 ? `Reports are requested to ${rua.length} destination${rua.length === 1 ? "" : "s"}.` : "No rua= is set, so you get no reports on who sends as you or what fails.",
    });
    const external = rua.filter((destination) => !String(destination.status).startsWith("not_required"));
    if (external.length > 0) {
      const bad = external.filter((destination) => destination.status === "unauthorized" || destination.status === "malformed");
      const unknown = external.filter((destination) => !["authorized", "unauthorized", "malformed"].includes(destination.status));
      checked.push({
        label: "Report destinations outside your domain",
        state: bad.length ? "fail" : unknown.length ? "unknown" : "pass",
        detail: bad.length
          ? `${bad.length} destination${bad.length === 1 ? " has" : "s have"} not authorised your reports, so standard receivers will not send them.`
          : unknown.length
            ? "Authorisation for at least one external destination could not be checked."
            : "Every external destination publishes a valid authorisation record. This does not prove reports are sent or read.",
      });
    }
    checked.push({
      label: "Failure reports (ruf)",
      state: "info",
      detail: ruf.length > 0 ? "Requested. Many receivers do not send failure reports, for privacy reasons." : "Not requested. That is common; aggregate reports carry what most domains need.",
    });
  }

  const unauthorizedCount = rua.filter((destination) => destination.status === "unauthorized").length;
  let verdict;
  if (noPolicy) {
    verdict = { level: "risk", headline: "No DMARC policy", summary: "Receivers have no instruction for mail that fails authentication, so forged mail claiming to be from this domain is delivered normally." };
  } else if (evidence.observation_state === "multiple") {
    verdict = { level: "risk", headline: "More than one DMARC record", summary: "With several records at the same name receivers use none of them, so the domain has no working policy." };
  } else if (evidence.record_validity === "invalid" || !effective) {
    verdict = { level: "risk", headline: "DMARC record cannot be used", summary: presentation.observation.message };
  } else if (effective === "none") {
    verdict = rua.length > 0
      ? { level: "attention", headline: "Monitoring only (p=none)", summary: "Reports are requested, but failing mail is still delivered. The next step is quarantine once the reports show your real senders passing." }
      : { level: "attention", headline: "No protection yet (p=none, no reports)", summary: "Failing mail is still delivered, and no reports are requested, so you cannot see who sends as you. The next step is to add rua= and read the reports before tightening the policy." };
  } else if (unauthorizedCount > 0 || rua.length === 0) {
    verdict = { level: "attention", headline: `p=${effective} is published, but reporting needs attention`, summary: rua.length === 0 ? "Receivers are asked to act on failing mail, but no reports are requested, so you cannot see new senders or problems." : "Receivers are asked to act on failing mail, but some report destinations will not receive reports." };
  } else {
    verdict = {
      level: "good",
      headline: effective === "reject" ? "Policy asks receivers to reject failing mail" : "Policy asks receivers to quarantine failing mail",
      summary: effective === "reject"
        ? "The strongest DMARC policy is published and reports are requested. Each receiver still decides whether to apply it."
        : "Receivers are asked to treat failing mail as suspicious. Reject is the last step on the ladder.",
    };
  }

  return {
    ...base,
    verdict,
    record: {
      dns_name: `_dmarc.${evidence.policy_source_domain || evidence.author_domain}`,
      values: inherited ? (record?.value ? [record.value] : []) : (evidence.raw_records || []).map((r) => r.value).filter(Boolean),
      source_kind: evidence.policy_source_kind,
      source_domain: evidence.policy_source_domain,
      inherited,
      organisational_domain: evidence.organisational_domain,
    },
    tags: explainTags(record),
    ladder: { steps: LADDER, current: effective, declared: declared || null },
    reporting: { rua, ruf },
    checked,
    not_checked: [
      ...NOT_CHECKED,
      ...(evidence.corroboration_state === "unavailable" ? [{ label: "Second resolver confirmation", reason: "A second DNS resolver did not answer, so this result rests on one resolver." }] : []),
    ],
    why_it_matters: WHY_IT_MATTERS,
    next_step: nextRecordPlan(evidence, presentation, rua),
    methodology: "RFC 9989 (DMARCbis) DNS tree walk; external report authorisation per RFC 9990.",
  };
}

/** runDmarcCheck — bounded DMARCbis core + external report phase. */
// `providers` ({ primaryProvider, secondaryProvider }) is for deterministic tests.
export async function runDmarcCheck(domain, { accounting = null, signal = null, cache = null, now = () => new Date(), providers = {} } = {}) {
  const checkedAt = now().toISOString();
  const core = await runDmarcbisCore(domain, { accounting, signal, cache, ...providers });
  const external = await runDmarcbisExternalRuaPhase(core, { accounting, signal, cache, ...providers });
  return buildDmarcToolResult(attachDmarcbisExternalResult(core, external), { domain, checkedAt });
}
