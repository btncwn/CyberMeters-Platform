// ── Free SPF checker (public /tools/spf-checker) ─────────────────────────────
//
// Reuses the canonical RFC 7208 resolver (spf-resolver.js) with its include
// trace; this module only turns that evidence into the public result: a verdict,
// the include tree, what was and was not checked, and a corrected record the
// visitor can paste. It never re-implements SPF evaluation: the lookup count,
// void count, cycle and dangling-include errors are the resolver's.
//
// DNS only (DoH). Bounded by the resolver's own limits (10 DNS-mechanism
// lookups, 2 void lookups, cycle guard) plus the caller's subrequest counter
// and deadline.
import { normalizeDnsTxtValue, parseSpfRecord } from "../email-analysis.js";
import { makeDohSpfLookup, resolveSpfAuthorization, SPF_RESOLUTION_STATUS } from "../spf-resolver.js";

export const SPF_TOOL_SCHEMA = "free-tool-spf.v1";
const LOOKUP_LIMIT = 10;
const VOID_LIMIT = 2;
const TREE_MAX_NODES = 60;

const ALL_MEANINGS = Object.freeze({
  "+": {
    label: "+all: every server on the internet may send as this domain",
    detail: "+all passes SPF for any sender, so SPF gives no protection at all and a forger passes it.",
    severity: "fail",
  },
  "?": {
    label: "?all: neutral, no statement about other senders",
    detail: "?all tells receivers nothing about senders not listed, so a forger is not marked as failing SPF.",
    severity: "warn",
  },
  "~": {
    label: "~all: other senders soft-fail",
    detail: "~all marks unlisted senders as a soft failure. With an enforced DMARC policy this is the usual choice: DMARC decides what happens to the message.",
    severity: "pass",
  },
  "-": {
    label: "-all: other senders fail",
    detail: "-all tells receivers that only the listed senders are authorised. Some receivers reject on SPF failure alone, before DKIM or DMARC are considered.",
    severity: "pass",
  },
});

const STOP_REASONS = Object.freeze({
  dns_lookup_limit_exceeded: "SPF allows at most 10 DNS lookups. Evaluation stopped at the 11th, as a receiving server's does, and SPF returns a permanent error.",
  void_lookup_limit_exceeded: "More than two lookups returned no answer. RFC 7208 makes that a permanent error.",
  included_domain_no_spf: "This include points at a domain with no SPF record. RFC 7208 makes that a permanent error for the whole record.",
  redirect_domain_no_spf: "The redirect points at a domain with no SPF record. RFC 7208 makes that a permanent error.",
  include_cycle_detected: "This include leads back to a record already being evaluated, so it can never finish.",
  redirect_cycle_detected: "This redirect leads back to a record already being evaluated, so it can never finish.",
  multiple_spf_records: "More than one SPF record is published here. SPF requires exactly one.",
  included_record_invalid: "The included record is not a valid SPF record.",
  malformed_ip_literal: "An ip4 or ip6 value could not be read as an address range.",
  include_without_domain: "An include has no domain after it.",
  temporary_dns_error: "A DNS lookup timed out or failed here, so this part could not be checked.",
});

function compactTree(node, budget) {
  if (!node || budget.left <= 0) return null;
  budget.left -= 1;
  const children = [];
  for (const child of node.children || []) {
    const compact = compactTree(child, budget);
    if (compact) children.push(compact);
  }
  return {
    domain: node.domain,
    via: node.via,
    record: node.record ? normalizeDnsTxtValue(node.record) : null,
    status: node.status,
    // An include's own lookup is charged to its parent, so add it back: this is
    // what removing the include would save.
    lookups: node.via === "root" ? node.lookups : node.lookups + (node.status === "evaluated" ? 1 : 0),
    void_lookups: node.void_lookups,
    stopped: node.stopped,
    stopped_reason: node.stopped ? (STOP_REASONS[node.stopped] || null) : null,
    children,
  };
}

function findNodes(node, predicate, out = []) {
  if (!node) return out;
  if (predicate(node)) out.push(node);
  for (const child of node.children || []) findNodes(child, predicate, out);
  return out;
}

function tokensOf(record) {
  return normalizeDnsTxtValue(record).split(/\s+/).filter(Boolean).slice(1);
}

function mechanismName(token) {
  const body = /^[+\-~?]/.test(token) ? token.slice(1) : token;
  if (body.toLowerCase().startsWith("redirect=")) return "redirect";
  if (body.toLowerCase().startsWith("exp=")) return "exp";
  return body.split(/[:/]/)[0].toLowerCase();
}

function includeTarget(token) {
  const body = /^[+\-~?]/.test(token) ? token.slice(1) : token;
  const match = body.match(/^include:(.+)$/i);
  return match ? match[1].toLowerCase().replace(/\.$/, "") : null;
}

// Build the corrected record from the published one, one documented change at a
// time. Returns null when the record cannot be corrected mechanically (over the
// lookup limit: which services to drop is the owner's decision).
function correctedRecord({ records, allQualifier, danglingIncludes, overLimit }) {
  if (records.length === 0 || overLimit) return null;
  const changes = [];
  const seen = new Set();
  const kept = [];
  let redirect = null;
  let all = null;
  for (const record of records) {
    for (const token of tokensOf(record)) {
      const name = mechanismName(token);
      if (name === "all") { all = all ?? token; continue; }
      if (name === "redirect") { redirect = redirect ?? token; continue; }
      if (name === "ptr") { if (!changes.includes("ptr")) changes.push("ptr"); continue; }
      const target = includeTarget(token);
      if (target && danglingIncludes.has(target)) { changes.push(`dangling:${target}`); continue; }
      const key = token.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      kept.push(token);
    }
  }
  if (records.length > 1) changes.unshift("merged");
  let finalAll = all;
  if (allQualifier === "+" || allQualifier === "?") {
    finalAll = "~all";
    changes.push(`all:${allQualifier}`);
  }
  if (!finalAll && !redirect) {
    finalAll = "~all";
    changes.push("all:missing");
  }
  if (finalAll && redirect) {
    // With an all mechanism present the redirect is never used (RFC 7208 §6.1).
    redirect = null;
    changes.push("redirect:unused");
  }
  if (changes.length === 0) return null;
  const value = ["v=spf1", ...kept, ...(redirect ? [redirect] : []), ...(finalAll ? [finalAll] : [])].join(" ");
  return { value, changes };
}

const CHANGE_TEXT = Object.freeze({
  merged: "Combined the separate SPF records into one, keeping every sender they listed.",
  ptr: "Removed ptr: it is deprecated (RFC 7208 §5.5), slow, and many receivers ignore it.",
  "all:+": "Replaced +all with ~all so unlisted senders are no longer passed.",
  "all:?": "Replaced ?all with ~all so unlisted senders are marked as failing.",
  "all:missing": "Added ~all: without it, unlisted senders get a neutral result.",
  "redirect:unused": "Dropped the redirect: with an all mechanism present it is never used.",
});

function changeText(change) {
  if (CHANGE_TEXT[change]) return CHANGE_TEXT[change];
  if (change.startsWith("dangling:")) {
    return `Removed include:${change.slice(9)}: that domain publishes no SPF record, which makes the whole record a permanent error. If you still use that service, ask them for their current SPF include.`;
  }
  return change;
}

/** Pure projection: resolver evidence → public result. Exported for tests. */
export function buildSpfToolResult({ domain, checkedAt, rootLookup, records, resolution, mxPresent }) {
  const checked = [];
  const notChecked = [
    { label: "Which services really send your email", reason: "DNS shows who you authorise, not who sends. Aggregate DMARC reports show the senders receivers actually saw." },
    { label: "Whether receivers act on SPF", reason: "Each receiving server decides what to do with an SPF failure; that is not visible from outside." },
    { label: "Mechanisms that depend on the sender", reason: "exists, ptr and macros (%{…}) are evaluated per message, so their result cannot be known in advance." },
  ];
  const issues = [];
  const base = { schema: SPF_TOOL_SCHEMA, tool: "spf", domain, checked_at: checkedAt };

  if (rootLookup === "temperror" || !resolution || resolution.resolution_status === SPF_RESOLUTION_STATUS.TEMPERROR) {
    return {
      ...base,
      verdict: {
        level: "unknown",
        headline: "Could not check SPF",
        summary: "A DNS lookup needed for this check timed out or failed. This is not a missing or broken record; try again in a few minutes.",
      },
      records,
      tree: resolution?.include_tree ? compactTree(resolution.include_tree, { left: TREE_MAX_NODES }) : null,
      lookups: { used: resolution?.lookup_count ?? null, limit: LOOKUP_LIMIT },
      void_lookups: { used: resolution?.void_lookup_count ?? null, limit: VOID_LIMIT },
      all: null,
      issues,
      checked: [{ label: "SPF record lookup", state: "unknown", detail: "The DNS answer could not be obtained." }],
      not_checked: notChecked,
      why_it_matters: WHY_IT_MATTERS,
      next_step: { title: "Try again shortly", explanation: "Nothing was concluded about this domain.", record: null },
    };
  }

  if (records.length === 0) {
    checked.push({ label: "SPF record published", state: "fail", detail: `No TXT record starting with v=spf1 was observed at ${domain}.` });
    const options = [
      {
        label: "If this domain never sends email",
        record: { type: "TXT", name: domain, value: "v=spf1 -all" },
        explanation: "Says no server may send as this domain, so forged mail fails SPF.",
      },
      {
        label: "If this domain sends email",
        record: { type: "TXT", name: domain, value: "v=spf1 include:<your email provider's SPF domain> ~all" },
        explanation: "Replace the placeholder with the include your email provider documents, and add one include per other service that sends as you (newsletters, invoicing, your website's contact form).",
      },
    ];
    return {
      ...base,
      verdict: {
        level: "risk",
        headline: "No SPF record",
        summary: mxPresent
          ? "This domain receives email but publishes no SPF record, so receivers cannot tell which servers may send as it."
          : "No SPF record is published. If the domain sends no email, a one-line record still stops others using it to send forged mail.",
      },
      records,
      tree: null,
      lookups: { used: 0, limit: LOOKUP_LIMIT },
      void_lookups: { used: 0, limit: VOID_LIMIT },
      all: null,
      issues: [{ code: "missing", severity: "fail", title: "No SPF record", detail: "Receivers get no SPF result for mail claiming to be from this domain." }],
      checked,
      not_checked: notChecked,
      why_it_matters: WHY_IT_MATTERS,
      next_step: {
        title: "Publish one SPF record",
        explanation: "Add one of these as a TXT record at the domain itself (the host field is often written @).",
        record: null,
        options,
      },
    };
  }

  const tree = resolution.include_tree ? compactTree(resolution.include_tree, { left: TREE_MAX_NODES }) : null;
  const parsed = parseSpfRecord(records[0], records.length);
  const allMechanism = parsed.mechanisms.find((m) => m.mechanism === "all") || null;
  const allQualifier = allMechanism ? allMechanism.qualifier : null;
  const hasRedirect = parsed.mechanisms.some((m) => m.mechanism === "redirect");
  const stop = resolution.resolution_status === SPF_RESOLUTION_STATUS.PERMERROR
    ? (findNodes(resolution.include_tree, (node) => node.stopped)[0]?.stopped || "multiple_spf_records")
    : null;
  const lookupsUsed = resolution.lookup_count ?? 0;
  const overLimit = stop === "dns_lookup_limit_exceeded";
  const danglingIncludes = new Set(
    findNodes(resolution.include_tree, (node) => node.status === "no_spf_record" && node.via === "include")
      .map((node) => node.domain),
  );

  if (records.length > 1) {
    issues.push({ code: "multiple_records", severity: "fail", title: `${records.length} SPF records published`, detail: STOP_REASONS.multiple_spf_records + " Receivers return a permanent error and SPF fails for every message." });
  }
  checked.push({
    label: "One SPF record",
    state: records.length === 1 ? "pass" : "fail",
    detail: records.length === 1 ? `Exactly one v=spf1 record was observed at ${domain}.` : `${records.length} v=spf1 records were observed at ${domain}.`,
  });

  if (records.length === 1) {
    checked.push({
      label: "DNS lookups",
      state: overLimit ? "fail" : lookupsUsed >= 8 ? "warn" : "pass",
      detail: overLimit
        ? "More than 10 DNS lookups are needed. Receivers stop at the limit and SPF returns a permanent error."
        : `${lookupsUsed} of 10 DNS lookups used${lookupsUsed >= 8 ? " — close to the limit; one more include from a provider could break SPF." : "."}`,
    });
    if (overLimit) issues.push({ code: "lookup_limit", severity: "fail", title: "Over the 10-lookup limit", detail: STOP_REASONS.dns_lookup_limit_exceeded });
    else if (lookupsUsed >= 8) issues.push({ code: "lookup_near_limit", severity: "warn", title: "Close to the 10-lookup limit", detail: "Providers change their own includes without notice; a record this close to the limit can break with no change on your side." });

    const voidUsed = resolution.void_lookup_count ?? 0;
    checked.push({
      label: "Void lookups",
      state: stop === "void_lookup_limit_exceeded" ? "fail" : voidUsed > 0 ? "warn" : "pass",
      detail: `${voidUsed} of 2 allowed lookups returned no answer.`,
    });
    if (stop === "void_lookup_limit_exceeded") issues.push({ code: "void_limit", severity: "fail", title: "Too many lookups with no answer", detail: STOP_REASONS.void_lookup_limit_exceeded });

    for (const target of danglingIncludes) {
      issues.push({ code: "dangling_include", severity: "fail", title: `include:${target} has no SPF record`, detail: STOP_REASONS.included_domain_no_spf });
    }
    checked.push({
      label: "Every include resolves",
      state: danglingIncludes.size > 0 ? "fail" : stop === "include_cycle_detected" ? "fail" : overLimit ? "unknown" : "pass",
      detail: danglingIncludes.size > 0
        ? `${danglingIncludes.size} include${danglingIncludes.size === 1 ? "" : "s"} point at a domain with no SPF record.`
        : overLimit ? "Evaluation stopped at the lookup limit, so includes after that point were not checked." : "Every include that was reached published an SPF record.",
    });
    if (stop === "include_cycle_detected" || stop === "redirect_cycle_detected") {
      issues.push({ code: "cycle", severity: "fail", title: "Include loop", detail: STOP_REASONS[stop] });
    }
    if (stop && !["dns_lookup_limit_exceeded", "void_lookup_limit_exceeded", "included_domain_no_spf", "include_cycle_detected", "redirect_cycle_detected"].includes(stop)) {
      issues.push({ code: "permerror", severity: "fail", title: "SPF permanent error", detail: STOP_REASONS[stop] || "The record cannot be evaluated." });
    }
  }

  const allInfo = allQualifier ? ALL_MEANINGS[allQualifier] : null;
  if (allInfo) {
    checked.push({ label: "Policy for other senders", state: allInfo.severity, detail: `${allInfo.label}. ${allInfo.detail}` });
    if (allQualifier === "+") issues.push({ code: "plus_all", severity: "fail", title: "+all lets anyone send", detail: allInfo.detail });
    if (allQualifier === "?") issues.push({ code: "neutral_all", severity: "warn", title: "?all gives no protection", detail: allInfo.detail });
  } else if (!hasRedirect) {
    checked.push({ label: "Policy for other senders", state: "warn", detail: "The record has no all mechanism, so senders not listed get a neutral result." });
    issues.push({ code: "missing_all", severity: "warn", title: "No all mechanism", detail: "Without ~all or -all at the end, the record does not say what to do with other senders." });
  } else {
    checked.push({ label: "Policy for other senders", state: "info", detail: "The record ends in a redirect; the other domain's record decides." });
  }

  if (parsed.mechanisms.some((m) => m.mechanism === "ptr")) {
    issues.push({ code: "ptr", severity: "warn", title: "ptr is deprecated", detail: CHANGE_TEXT.ptr });
  }
  if ((resolution.unresolved_mechanisms || []).some((m) => !String(m.mechanism).toLowerCase().includes("ptr"))) {
    issues.push({ code: "not_static", severity: "info", title: "Part of the record depends on the message", detail: "exists or a macro is used. Those parts are evaluated per message, so the authorised set shown here is incomplete." });
  }

  const fails = issues.filter((issue) => issue.severity === "fail");
  const warns = issues.filter((issue) => issue.severity === "warn");
  const verdict = fails.length > 0
    ? { level: "risk", headline: fails[0].title, summary: fails.length > 1 ? `${fails.length} problems make SPF fail or give no protection. The first is shown above; all are listed below.` : fails[0].detail }
    : warns.length > 0
      ? { level: "attention", headline: "SPF works, with something to fix", summary: warns[0].detail }
      : { level: "good", headline: "SPF record looks right", summary: `One valid record, ${lookupsUsed} of 10 lookups, and a clear policy for other senders.` };

  const corrected = correctedRecord({ records, allQualifier, danglingIncludes, overLimit });
  let nextStep;
  if (overLimit) {
    const heavy = (tree?.children || [])
      .filter((child) => child.via === "include")
      .sort((a, b) => b.lookups - a.lookups)
      .slice(0, 3)
      .map((child) => `include:${child.domain} (${child.lookups} lookup${child.lookups === 1 ? "" : "s"})`);
    nextStep = {
      title: "Bring the record under 10 lookups",
      explanation: `Remove includes for services that no longer send as you${heavy.length ? `; the largest are ${heavy.join(", ")}` : ""}. Replacing an include with that provider's IP ranges also cuts lookups, but the ranges then need watching when the provider changes them, so it is not done automatically here.`,
      record: null,
    };
  } else if (corrected) {
    nextStep = {
      title: records.length > 1 ? "Replace the SPF records with this one" : "Replace the SPF record with this one",
      explanation: corrected.changes.map(changeText).join(" "),
      record: { type: "TXT", name: domain, value: corrected.value },
      replaces: records,
    };
  } else {
    nextStep = {
      title: "No change needed",
      explanation: "Keep the record as it is. When you add a new service that sends email as you, add its include and check the lookup count again.",
      record: null,
    };
  }

  return {
    ...base,
    verdict,
    records,
    tree,
    lookups: { used: lookupsUsed, limit: LOOKUP_LIMIT, stopped_at_limit: overLimit },
    void_lookups: { used: resolution.void_lookup_count ?? 0, limit: VOID_LIMIT },
    all: allInfo ? { qualifier: allQualifier, label: allInfo.label, detail: allInfo.detail } : null,
    resolution_status: resolution.resolution_status,
    issues,
    checked,
    not_checked: notChecked,
    why_it_matters: WHY_IT_MATTERS,
    next_step: nextStep,
  };
}

const WHY_IT_MATTERS = "SPF lists the servers allowed to send email as your domain. Without a working record, invoices and password resets you send are more likely to land in spam, and anyone can send mail that claims to come from you to your customers and suppliers. A broken record is worse than it looks: one error makes SPF fail for every message.";

/**
 * runSpfCheck — DNS-only SPF evaluation for the public tool.
 * `dnsQuery(name, type)` is the accounted DoH helper supplied by the caller.
 */
export async function runSpfCheck(domain, { dnsQuery, now = () => new Date() } = {}) {
  const lookup = makeDohSpfLookup(dnsQuery, normalizeDnsTxtValue);
  const checkedAt = now().toISOString();
  const [root, mx] = await Promise.all([lookup(domain, "TXT"), lookup(domain, "MX")]);
  if (root.status === "temperror") {
    return buildSpfToolResult({ domain, checkedAt, rootLookup: "temperror", records: [], resolution: null, mxPresent: false });
  }
  const records = (root.values || [])
    .map((value) => String(value).trim())
    .filter((value) => /^v=spf1(\s|$)/i.test(value));
  const resolution = await resolveSpfAuthorization({
    domain,
    rootRecord: records[0] ?? null,
    recordCount: records.length,
    lookup,
    nowIso: checkedAt,
    trace: true,
  });
  return buildSpfToolResult({
    domain,
    checkedAt,
    rootLookup: "ok",
    records,
    resolution,
    mxPresent: mx.status === "ok" && (mx.values || []).length > 0,
  });
}
