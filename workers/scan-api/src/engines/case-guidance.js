// ── What a case asks of the customer, and what the last re-check found ──────
// Backend-owned wording for the case page, so the screen decides nothing:
//   remediation   the canonical remediation (registry; never invented): the
//                 problem in plain words, why it matters, what to do, effort
//                 and who usually does it;
//   recheck       how CyberMeters re-checks the fix and what counts as fixed;
//   last_recheck  the latest re-check — fixed, still present or still waiting —
//                 when it ran and what each affected host answered;
//   closure       how the case ended, kept apart: verified by CyberMeters,
//                 closed by the customer without a re-check, risk accepted, or
//                 marked not a real problem.
// Pure; reads the case row and its append-only events.
import { getRemediationById, resolveRemediation } from "./remediation-registry.js";

export const CASE_GUIDANCE_VERSION = "case-guidance-v1";

const OWNER_LABELS = Object.freeze({
  customer: "You can do this yourself",
  customer_it: "Your IT, DNS or hosting administrator",
  email_provider: "Your email provider",
  registrar: "Your domain registrar",
  cybermeters: "CyberMeters",
  external_body: "An external body",
});

const RECHECK_METHOD_LABELS = Object.freeze({
  rescan: "The next complete scan re-checks the affected host itself.",
  dns_recheck: "CyberMeters re-queries DNS after your change.",
  https_recheck: "CyberMeters requests the HTTPS endpoint again and reads its answer.",
  certificate_recheck: "CyberMeters reads the certificate the live site presents again.",
  receiver_reports: "Later DMARC aggregate reports from receiving mail providers confirm it.",
  manual_attestation: "CyberMeters cannot observe this fix from outside. Your confirmation is recorded as yours and never shown as verified.",
  external: "An independent body confirms it, not a CyberMeters scan.",
  unsupported: "There is no way to check this fix from outside today.",
});

// A live TLS control re-runs the control itself, which for a protocol or cipher
// condition does not involve reading the certificate.
const TLS_CONTROL_RECHECK_LABEL = "CyberMeters repeats the same TLS check on the same endpoint.";

// The re-check of a management-page exposure (engines/exposure-recheck.js).
const HOST_RECHECK_RULE = "A timeout, a refused or blocked connection, or a filter's 401, 403 or 429 never closes the case: none of them shows the tool is gone. It closes when the host answers without the tool, or when the name is confirmed removed (three checks at least a day apart, then checked again). If you limited access to trusted addresses, CyberMeters cannot see that from outside; removing the public name, or having it answer without the tool, lets CyberMeters verify the fix.";

const WAITING_REASONS = Object.freeze({
  scan_partial: "The latest scan did not complete, so the fix was not re-checked. The next complete scan checks again.",
  no_completeness_evidence: "The latest scan did not record whether the check that found this ran, so the fix was not re-checked.",
  module_incomplete: "The check that found this did not complete in the latest scan, so the fix was not re-checked.",
  module_did_not_run: "The check that found this did not run in the latest scan, so the fix was not re-checked.",
  unknown_detecting_module: "This case does not record which check found it, so a scan cannot re-check it.",
  affected_hosts_unknown: "This case does not record which host to re-check. It is re-checked once a scan names the host again.",
  affected_host_not_rechecked: "The affected host was not re-checked in the latest scan.",
  affected_host_timed_out: "The affected host did not answer in time. Silence is not proof the problem is gone: an outage, or a block on CyberMeters alone, looks the same.",
  affected_host_no_answer: "The affected host refused or dropped the connection. A blocked connection is not proof the problem is gone: a block on CyberMeters alone looks the same.",
  affected_host_access_restricted: "The affected host answered with 401, 403 or 429, which filters often send to scanners only. That is not proof the problem is gone.",
  affected_host_no_origin: "No server answered behind the affected host's edge provider. That is not proof the problem is gone.",
  affected_host_server_error: "The affected host answered with a server error, so the page could not be checked.",
  affected_host_name_not_resolving: "The affected name no longer resolves. The case closes once the removal is confirmed (three checks at least a day apart) and checked again.",
  removal_not_confirmed: "The name was not seen, but its removal is not confirmed yet (three checks at least a day apart).",
  later_reobservation_required: "The removal is confirmed; the next scan checks it once more before the case closes.",
  no_current_lifecycle_observation: "The latest scan did not observe the affected name, so the fix was not re-checked.",
  lifecycle_evidence_incomplete: "The latest scan's evidence for the affected name was incomplete, so the fix was not re-checked.",
  active_source_contract_not_met: "The affected name still answered in DNS or on the web, so it was not treated as removed.",
  scan_not_complete: "The latest scan did not complete, so the fix was not re-checked.",
});

function short(value, max = 300) {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, max) : null;
}

function parse(value) {
  if (value && typeof value === "object") return value;
  try { return value ? JSON.parse(value) : null; } catch { return null; }
}

function where(host) {
  const parts = [];
  if (host.protocol && Number.isInteger(host.port)) parts.push(`${String(host.protocol).toUpperCase()} port ${host.port}`);
  if (Number.isInteger(host.status)) parts.push(`HTTP ${host.status}`);
  return parts.length ? ` (${parts.join(", ")})` : "";
}

export function hostRecheckLabel(host) {
  const name = short(host?.hostname, 255) || "The affected host";
  switch (host?.outcome) {
    case "answered_without_tool":
      return host.ended_at?.host && host.ended_at.host !== host.hostname
        ? `${name} sent visitors to ${host.ended_at.host}, where the tool was not found${where(host)}.`
        : `${name} answered without the tool${where(host)}.`;
    case "confirmed_removed": return `${name} no longer exists in DNS; its removal was confirmed and checked again.`;
    case "still_present": return `${name} still answers with the tool${where(host)}.`;
    case "timed_out": return `${name} did not answer in time.`;
    case "no_answer": return `${name} refused or dropped the connection.`;
    case "access_restricted": return `${name} answered${where(host)}, as filters often do for scanners.`;
    case "no_origin": return `No server answered behind ${name}'s edge provider.`;
    case "server_error": return `${name} answered with a server error${where(host)}.`;
    case "name_not_resolving": return `${name} no longer resolves; its removal is not confirmed yet.`;
    default: return `${name} was not re-checked in this scan.`;
  }
}

function remediationFor(row) {
  const byId = row?.remediation_id ? getRemediationById(row.remediation_id) : null;
  const entry = byId || (() => {
    const findingType = row?.source_finding_type || row?.finding_id;
    if (!findingType) return null;
    const resolved = resolveRemediation({ finding_type: findingType });
    return resolved?.status === "resolved" ? resolved : null;
  })();
  return entry || null;
}

function recheckHostsOf(detail) {
  const hosts = detail?.recheck?.hosts || detail?.verification_evidence?.observation?.recheck?.hosts;
  return Array.isArray(hosts) ? hosts.slice(0, 10) : [];
}

// A reopen CyberMeters made is itself an observation: a scan saw the problem
// again. It supersedes an earlier "fixed", so a reopened case never shows one.
function isSystemReopen(event) {
  return event?.actor_type === "system" && (event?.to_status === "reopened" || event?.action === "reopened");
}

function lastRecheck(events) {
  const ordered = (Array.isArray(events) ? events : []).filter((event) =>
    ["verified_resolved", "verification_failed", "verification_deferred"].includes(event?.action) || isSystemReopen(event));
  const event = ordered[ordered.length - 1];
  if (!event) return null;
  const detail = parse(event.detail_json ?? event.detail);
  if (isSystemReopen(event)) {
    return {
      outcome: "still_present",
      label: "Seen again — the case was reopened",
      at: event.created_at || null,
      scan_id: detail?.scan_id ?? null,
      reason: null,
      hosts: [],
    };
  }
  const outcome = event.action === "verified_resolved" ? "fixed" : event.action === "verification_failed" ? "still_present" : "waiting";
  const hosts = recheckHostsOf(detail).map((host) => ({ hostname: host.hostname ?? null, outcome: host.outcome ?? null, label: hostRecheckLabel(host) }));
  return {
    outcome,
    label: { fixed: "Fixed — verified by CyberMeters", still_present: "Still present", waiting: "Not confirmed yet" }[outcome],
    at: detail?.verification_evidence?.observed_at || event.created_at || null,
    scan_id: detail?.scan_id ?? null,
    reason: outcome === "waiting" ? (WAITING_REASONS[detail?.reason] || "The fix has not been re-checked yet.") : null,
    hosts,
  };
}

function closureFor(row, phase, support, events, recheck) {
  const verifiedEvent = [...(Array.isArray(events) ? events : [])].reverse().find((event) => event?.action === "verified_resolved");
  const verifiedAt = parse(verifiedEvent?.detail_json ?? verifiedEvent?.detail)?.verification_evidence?.observed_at
    || row?.verified_at || row?.resolved_at || null;
  // "Verified" means CyberMeters saw it only where CyberMeters re-checks it.
  const verifiedByUs = support === "automated";
  switch (phase) {
    case "verified":
    case "monitoring":
      if (verifiedByUs) {
        return { kind: "verified", label: "Verified fixed by CyberMeters", at: verifiedAt, hosts: recheck?.outcome === "fixed" ? recheck.hosts : [] };
      }
      return support === "external"
        ? { kind: "confirmed_externally", label: "Confirmed by an independent third party, not by a CyberMeters scan", at: row?.verified_at || null }
        : { kind: "attested", label: "Confirmed by your team — CyberMeters cannot verify this from outside", at: row?.verified_at || null };
    case "closed_no_action":
      return row?.verified_at && verifiedByUs
        ? { kind: "verified_then_closed", label: "Verified fixed by CyberMeters, then closed by your team", at: row.closed_at || null }
        : { kind: "closed_by_customer", label: "Closed by your team without a CyberMeters re-check", at: row?.closed_at || null };
    case "accepted_risk":
      return { kind: "risk_accepted", label: row?.risk_accepted_until ? `Risk accepted by your team until ${String(row.risk_accepted_until).slice(0, 10)}` : "Risk accepted by your team", at: row?.accepted_at || null };
    case "false_positive":
      return { kind: "false_positive", label: "Marked by your team as not a real problem", at: row?.closed_at || null };
    case "rejected":
      return { kind: "rejected", label: "Rejected by your team", at: row?.closed_at || null };
    case "superseded":
      return { kind: "superseded", label: "Replaced by another case", at: row?.closed_at || null };
    default:
      return null;
  }
}

function day(value) {
  const ms = Date.parse(String(value || "").replace(" ", "T"));
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : null;
}

// The same finding's earlier and later cases: a closed case is never reopened in
// place, so a finding seen again opens a new case and both point at each other.
function continuityFor(row, events) {
  const previous = parse(row?.evidence_json)?.previous_case;
  const list = Array.isArray(events) ? events : [];
  const seenAgain = [...list].reverse().find((event) => event?.action === "seen_again");
  const nextId = parse(seenAgain?.detail_json ?? seenAgain?.detail)?.new_case_id;
  const stillSeen = [...list].reverse().find((event) => event?.action === "seen_again_marked_not_a_problem");
  const continuity = {
    previous_case: previous?.id
      ? {
        case_id: String(previous.id),
        label: previous.status === "false_positive"
          ? `An earlier case for this finding on other hosts was marked by your team as not a real problem${day(previous.closed_at) ? ` on ${day(previous.closed_at)}` : ""}.`
          : `This was seen again after an earlier case was closed${day(previous.closed_at) ? ` on ${day(previous.closed_at)}` : ""}. That case keeps its history.`,
      }
      : null,
    next_case: nextId
      ? { case_id: String(nextId), label: `Seen again${day(seenAgain.created_at) ? ` on ${day(seenAgain.created_at)}` : ""} after this case was closed; a new case was opened.` }
      : null,
    still_seen: stillSeen
      ? { label: `Still seen on the same hosts${day(stillSeen.created_at) ? ` on ${day(stillSeen.created_at)}` : ""}. It stays marked as not a real problem.` }
      : null,
  };
  return continuity.previous_case || continuity.next_case || continuity.still_seen ? continuity : null;
}

/**
 * Guidance for one case. `row` is the managed_cases row; `phase` its canonical
 * phase; `events` its append-only history (detail_json as stored).
 */
// The case's title for customer screens, at read time (founder, 22 Oct 2026:
// Operations rows read "header missing strict transport security
// (sheshire.co.uk:header_missing_strict_transport_security)"). The canonical
// remediation's customer title when the registry knows the finding; otherwise
// the stored title without a trailing "(host:raw_key)" and without underscores,
// so an unmapped finding stays explicit but never shows a machine key. The
// stored title is history and is never rewritten.
const RAW_KEY_SUFFIX = /\s*\([^()]*\b[a-z0-9]+_[a-z0-9_]+\b[^()]*\)\s*$/;
export function caseDisplayTitleFor(row) {
  try {
    const registered = short(remediationFor(row)?.customer_title, 160);
    if (registered) return registered;
  } catch { /* fall through to the stored title */ }
  const stored = typeof row?.title === "string" ? row.title.replace(RAW_KEY_SUFFIX, "").replace(/_/g, " ").trim() : "";
  return stored ? stored.charAt(0).toUpperCase() + stored.slice(1) : null;
}

export function caseGuidance(row, { phase = null, support = null, events = [], hostRecheck = false } = {}) {
  const entry = remediationFor(row);
  const method = entry?.verification_method || null;
  const recheck = lastRecheck(events);
  return {
    version: CASE_GUIDANCE_VERSION,
    remediation: entry
      ? {
        title: short(entry.customer_title, 160),
        explanation: short(entry.technical_explanation, 600),
        business_impact: short(entry.business_impact, 600),
        recommended_action: short(entry.recommended_action, 600),
        effort: entry.effort || null,
        owner_label: OWNER_LABELS[entry.owner_type] || null,
      }
      : null,
    recheck: method
      ? {
        method,
        label: entry?.supporting_evidence_types?.includes("tls_endpoint_measurement")
          ? TLS_CONTROL_RECHECK_LABEL
          : RECHECK_METHOD_LABELS[method] || null,
        fixed_when: short(entry?.verification_evidence_requirements, 400),
        rule: hostRecheck ? HOST_RECHECK_RULE : null,
      }
      : null,
    last_recheck: recheck,
    closure: closureFor(row, phase, support, events, recheck),
    continuity: continuityFor(row, events),
  };
}
