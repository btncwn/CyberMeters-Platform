// ── M6 Phase B1: Related Changes — deterministic correlation rules ──
//
// The rule DECIDES. There is no statistics, no probability, no baseline and no AI here
// (that is B2/B3). A cluster is produced only when a REGISTERED rule pairs >=2
// INDEPENDENT signal families for the SAME registrable domain, in a consistent
// materialising direction, within the bounded window the adapter already applied.
// (design note §4, §5, §6, §9.)
//
// Honesty rules encoded here:
//   • >=2 INDEPENDENT signal FAMILIES — not >=2 events (§4.3). Same eTLD+1 + same
//     window alone is only a CANDIDATE, never a shipped cluster (§4 last line).
//   • Provenance guard for Shadow IT (§5): a shadow-it observation corroborates ONLY
//     if its provenance is not already represented by another producer in the cluster.
//     A cloud_asset shadow-it row is NOT independent when the cluster already has an
//     asset event; only genuinely independent provenance (vendor, saas_portal) counts.
//   • Consistent direction (§4.5): resolutions/improvements are dropped upstream; a
//     cluster is materialising evidence only.
//   • Derived outputs are NEVER inputs: CE Readiness, Website Security summaries and
//     aggregate scores are outputs and never enter here (the adapter never reads them).
//   • BRAND ships NO rule in v1. Brand is one signal family (§4.3) whose evidence is
//     about LOOKALIKE domains — a different registrable domain than the protected
//     host/cert/email signals — so it cannot meaningfully reach >=2 independent
//     families at the registrable-domain join, and manufacturing a cross-pairing would
//     be a fabricated correlation. Per §6 ("the number is an output of the bar"), no
//     brand rule qualifies. Brand events are still collected (B2-ready); the validator
//     asserts brand-alone NEVER forms a cluster.

import { SIGNAL_FAMILY } from "./related-changes-adapter.js";

const F = SIGNAL_FAMILY;

// Direction severity for the cluster's headline direction (highest wins).
const DIRECTION_RANK = { degraded: 3, changed: 2, appeared: 1 };
const MATERIALISING = new Set(["appeared", "changed", "degraded"]);

// Shadow-IT provenance → the producer family it duplicates. '__independent__' provenance
// (vendor relationship, SaaS portal) is never a duplicate of another producer.
const SHADOW_SOURCE_TO_FAMILY = Object.freeze({
  cloud_asset: F.ASSET,
  identity_provider: F.IDENTITY,
  email_sender: F.EMAIL_SENDER,
  vendor: "__independent__",
  saas_portal: "__independent__",
});

// A requirement is a family string or an OR-group (array of family strings). A rule
// matches when EVERY requirement is satisfiable by a distinct available family, and the
// total distinct families selected is >= 2.
export const RELATED_CHANGE_RULES = Object.freeze([
  {
    id: "new_host_with_cert",
    title: "New host with a new or changed certificate",
    summary: "A new host appeared and a certificate was issued or changed for the same registrable domain in the same period.",
    requires: [F.ASSET, F.CERT],
  },
  {
    id: "new_host_with_identity",
    title: "New host with a login or identity surface",
    summary: "A new host appeared and a login or identity-provider surface was observed on the same registrable domain in the same period.",
    requires: [F.ASSET, F.IDENTITY],
  },
  {
    id: "identity_with_cert",
    title: "Login or admin surface with a certificate change",
    summary: "A login or admin surface and a certificate change were observed on the same registrable domain in the same period.",
    requires: [F.IDENTITY, F.CERT],
  },
  {
    id: "email_config_with_host_or_cert",
    title: "Email-authentication change with a new host or certificate",
    summary: "Email authentication (SPF, DMARC or DKIM) changed and a new host or certificate appeared on the same registrable domain in the same period.",
    requires: [F.EMAIL_CONFIG, [F.ASSET, F.CERT]],
  },
  {
    id: "new_sender_with_email_config",
    title: "New sending source with an email-authentication change",
    summary: "A new sending source appeared and email authentication (SPF or DMARC) changed on the same root domain in the same period.",
    requires: [F.EMAIL_SENDER, F.EMAIL_CONFIG],
  },
  {
    id: "shadow_it_with_host_or_cert",
    title: "Unapproved technology with a new host or certificate",
    summary: "Unapproved technology (from independent provenance) and a new host or certificate were observed on the same registrable domain in the same period.",
    requires: [F.SHADOW_IT, [F.ASSET, F.CERT]],
  },
]);

const RULE_BY_ID = new Map(RELATED_CHANGE_RULES.map((r) => [r.id, r]));
export function getRule(id) {
  return RULE_BY_ID.get(id) || null;
}

// Is a shadow-it event independent corroboration given the OTHER families present?
function shadowIsIndependent(shadowEvent, otherFamilies) {
  const types = Array.isArray(shadowEvent.source_type) ? shadowEvent.source_type : [];
  for (const t of types) {
    const dup = SHADOW_SOURCE_TO_FAMILY[t];
    if (dup === "__independent__") return true;         // vendor / saas_portal — never a duplicate
    if (dup === undefined) return true;                 // unknown provenance is treated as its own producer
    if (!otherFamilies.has(dup)) return true;           // maps to a family NOT already in the cluster
  }
  return false;                                         // every provenance duplicates a producer already present
}

// Which families are present-and-independent for a domain's event set? Non-shadow
// families are present if they have >=1 materialising event. Shadow-IT is present only
// if at least one of its events passes the provenance guard against the other families.
function independentFamilies(byFamily) {
  const present = new Set();
  for (const fam of Object.keys(byFamily)) {
    if (fam !== F.SHADOW_IT && byFamily[fam].length > 0) present.add(fam);
  }
  const shadowEvents = byFamily[F.SHADOW_IT] || [];
  if (shadowEvents.some((e) => shadowIsIndependent(e, present))) present.add(F.SHADOW_IT);
  return present;
}

// Try to satisfy a rule's requirements with distinct available families. Greedy is
// correct here because OR-groups are small and families are distinct; returns the set
// of chosen families or null if unsatisfiable.
function satisfyRule(rule, available) {
  const chosen = new Set();
  for (const req of rule.requires) {
    const options = Array.isArray(req) ? req : [req];
    const pick = options.find((f) => available.has(f) && !chosen.has(f));
    if (!pick) return null;
    chosen.add(pick);
  }
  return chosen.size >= 2 ? chosen : null;
}

function headlineDirection(events) {
  let best = "appeared";
  let bestRank = 0;
  for (const e of events) {
    const r = DIRECTION_RANK[e.direction] || 0;
    if (r > bestRank) { bestRank = r; best = e.direction; }
  }
  return best;
}

/**
 * correlateChangeEvents — group canonical events by registrable domain and emit one
 * cluster per matched rule. Pure; deterministic; no DB, no clock, no randomness.
 *
 * @param {Array} events  canonical events from collectChangeEvents()
 * @param {object} [opts]
 * @param {string} [opts.completeness='complete']  the scan's evidence completeness
 * @returns {Array<{rule_id,rule_title,rule_summary,registrable_domain,direction,
 *   families:string[],signal_family_count,independent_producer_count,completeness,
 *   events:Array}>}
 */
export function correlateChangeEvents(events, opts = {}) {
  const completeness = opts.completeness === "partial" ? "partial" : "complete";

  // §4.5: correlate only materialising signals.
  const material = (events || []).filter((e) => MATERIALISING.has(e.direction) && e.registrable_domain);

  // Group by registrable domain.
  const byDomain = new Map();
  for (const e of material) {
    if (!byDomain.has(e.registrable_domain)) byDomain.set(e.registrable_domain, []);
    byDomain.get(e.registrable_domain).push(e);
  }

  const clusters = [];
  for (const [registrable, domainEvents] of byDomain) {
    // Bucket by producer family (the adapter's canonical family tag).
    const normFamily = {};
    for (const e of domainEvents) {
      (normFamily[e.producer_family] ||= []).push(e);
    }

    const available = independentFamilies(normFamily);
    if (available.size < 2) continue; // same domain + window alone is only a CANDIDATE

    for (const rule of RELATED_CHANGE_RULES) {
      const chosen = satisfyRule(rule, available);
      if (!chosen) continue;

      // Contributing events: those in the chosen families. For shadow-it, only the
      // events that individually pass the provenance guard against the other chosen
      // families (so a non-independent shadow row is never cited as evidence).
      const otherChosen = new Set([...chosen].filter((f) => f !== F.SHADOW_IT));
      const contributing = [];
      for (const fam of chosen) {
        const famEvents = normFamily[fam] || [];
        if (fam === F.SHADOW_IT) {
          for (const e of famEvents) if (shadowIsIndependent(e, otherChosen)) contributing.push(e);
        } else {
          for (const e of famEvents) contributing.push(e);
        }
      }
      if (contributing.length < 2) continue;

      const producerSet = new Set(contributing.map((e) => `${e.producer_family}:${e.source_table}`));
      clusters.push({
        rule_id: rule.id,
        rule_title: rule.title,
        rule_summary: rule.summary,
        registrable_domain: registrable,
        direction: headlineDirection(contributing),
        families: [...chosen].sort(),
        signal_family_count: chosen.size,
        independent_producer_count: producerSet.size,
        completeness,
        events: contributing,
      });
    }
  }

  // Deterministic ordering (no clock/random): by domain then rule id.
  clusters.sort((a, b) =>
    a.registrable_domain < b.registrable_domain ? -1 :
    a.registrable_domain > b.registrable_domain ? 1 :
    a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0
  );
  return clusters;
}
