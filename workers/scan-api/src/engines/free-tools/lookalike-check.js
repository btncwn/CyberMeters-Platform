// ── Free lookalike domain checker (public /tools/lookalike-domain-checker) ──
//
// The candidate names come from the canonical Brand Protection generator
// (brand-typosquat.js generateTyposquatCandidates: typos, look-alike
// characters, keyword and TLD variants, IDN homographs), so the free tool and
// Brand Protection consider the same variants. Each candidate gets DNS
// questions only:
//   NS          — is the name delegated in DNS (it usually means registered)
//   A and AAAA  — does it point at a server (only for names that exist)
//   MX          — does it accept email (only for names that exist)
//
// Honesty rules (founder, 20 Oct 2026): this reports what DNS shows —
// registered, resolves, accepts email — and never calls a domain malicious,
// a phish or an attack. Registered can be a parked page, a reseller or the
// visitor's own defensive registration. A failed lookup is "could not check",
// never "not registered".
import { extractBrandParts, generateTyposquatCandidates, MAX_BRAND_CANDIDATES } from "../brand-typosquat.js";

export const LOOKALIKE_TOOL_SCHEMA = "free-tool-lookalike.v1";

// The per-check subrequest budget is 120 (FREE_TOOL_POLICY.subrequestLimit).
// One NS question per candidate (44 at most), then A, AAAA and MX for at most
// this many names that exist: 44 + 3 × 24 = 116.
export const LOOKALIKE_DETAIL_LIMIT = 24;
// The most names one check considers, from the Brand Protection generator;
// the tool page states this number rather than its own estimate.
export const LOOKALIKE_MAX_CANDIDATES = MAX_BRAND_CANDIDATES;
const CONCURRENCY = 6;

const VARIANT_LABEL = Object.freeze({
  homoglyph_idn: "Look-alike letters from another alphabet",
  substitution: "A letter swapped for a look-alike character",
  omission: "One letter missing",
  duplication: "One letter doubled",
  transposition: "Two letters swapped",
  keyboard_adjacent: "A neighbouring key typed",
  hyphen_keyword: "Your name with a word added",
  prefix_keyword: "A word added before your name",
  tld_variation: "Your name on a different ending",
});

const NOT_CHECKED = Object.freeze([
  { label: "Who owns each name", reason: "DNS does not say who registered a domain. A registered lookalike may be yours, a reseller's or simply parked." },
  { label: "What a website on it shows", reason: "No page is opened. Brand Protection in CyberMeters checks that and keeps watching." },
  { label: "Every possible variant", reason: "We check the most likely typos, look-alike letters, keyword and ending variants, not every possible name." },
  { label: "Names registered after this check", reason: "This is one check, once." },
]);

const WHY_IT_MATTERS = "People type and read domain names quickly. A name one letter away from yours, or the same name on a different ending, can be used to send email that looks like it came from you or to host a copy of your site. Knowing which ones exist lets you decide whether to register them yourself, ask the registrar about them, or warn your customers and staff.";

const answers = (response, type) => (Array.isArray(response?.Answer) ? response.Answer : []).filter((a) => a.type === type);

async function ask(dnsQuery, name, type) {
  try {
    const response = await dnsQuery(name, type);
    if (response?.Status === 3) return { ok: true, exists: false, records: [] };
    if (response?.Status !== 0) return { ok: false };
    const code = { NS: 2, A: 1, AAAA: 28, MX: 15 }[type];
    return { ok: true, exists: true, records: answers(response, code).map((a) => String(a.data || "").replace(/\.$/, "")) };
  } catch (error) {
    if (error?.code === "scan_subrequest_budget_exhausted" || error?.subrequestLimit === true) return { ok: false, budget: true };
    return { ok: false };
  }
}

async function inBatches(items, worker) {
  const out = new Array(items.length);
  for (let i = 0; i < items.length; i += CONCURRENCY) {
    const slice = items.slice(i, i + CONCURRENCY);
    const done = await Promise.all(slice.map((item, j) => worker(item, i + j)));
    done.forEach((value, j) => { out[i + j] = value; });
  }
  return out;
}

/** Candidate names for a registrable domain, from the Brand Protection generator. */
export function lookalikeCandidates(registrable) {
  const { brand, tld } = extractBrandParts(registrable);
  return generateTyposquatCandidates(brand, tld).map((c) => ({
    domain: c.candidate_domain,
    variant: c.variant_type,
    variant_label: VARIANT_LABEL[c.variant_type] || "A close variant",
  }));
}

function rowState(row) {
  if (row.status === "unknown") return "unknown";
  if (row.status === "not_found") return "pass";
  return row.mx ? "fail" : "warn";
}

/** The public result from per-candidate DNS observations. Pure: no network. */
export function buildLookalikeToolResult(domain, registrable, rows, { now = Date.now() } = {}) {
  const base = { schema: LOOKALIKE_TOOL_SCHEMA, tool: "lookalike", domain, checked_at: new Date(now).toISOString(), registrable_domain: registrable };
  const registered = rows.filter((row) => row.status === "registered");
  const unknown = rows.filter((row) => row.status === "unknown");
  const withMail = registered.filter((row) => row.mx === true);
  const resolving = registered.filter((row) => row.resolves === true);

  if (rows.length === 0 || unknown.length > rows.length / 2) {
    return {
      ...base,
      verdict: { level: "unknown", headline: "Could not check lookalike domains", summary: rows.length === 0 ? "No variants could be made from this name." : "Too many DNS lookups failed to give a fair answer. Nothing was concluded; please try again." },
      candidates_checked: rows.length,
      lookalikes: [],
      checked: [{ label: "DNS lookups for close variants", state: "unknown", detail: `${unknown.length} of ${rows.length} lookups did not answer.` }],
      not_checked: NOT_CHECKED,
      why_it_matters: WHY_IT_MATTERS,
      next_step: { title: "Try again shortly", explanation: "Nothing was concluded about these names.", record: null },
    };
  }

  // Names that accept email first, then names that point at a server.
  const order = (row) => (row.mx ? 0 : row.resolves ? 1 : 2);
  const lookalikes = registered
    .sort((a, b) => order(a) - order(b) || a.domain.localeCompare(b.domain))
    .map((row) => ({ ...row, state: rowState(row) }));

  // Registered is a fact, not a threat: the most this tool says is "needs
  // attention", because many lookalikes belong to the business itself.
  const level = registered.length === 0 ? "good" : "attention";
  const verdict = registered.length === 0
    ? { level, headline: "None of the close variants we checked are registered", summary: `We checked ${rows.length} close variants of ${registrable} and found none in DNS.` }
    : {
      level,
      headline: `${registered.length} lookalike domain${registered.length === 1 ? " is" : "s are"} registered`,
      summary: [
        `${registered.length} of ${rows.length} close variants of ${registrable} exist in DNS`,
        resolving.length ? `${resolving.length} point${resolving.length === 1 ? "s" : ""} at a server` : null,
        withMail.length ? `${withMail.length} can receive email` : null,
      ].filter(Boolean).join("; ") + ". Being registered does not mean a name is being misused; check whether each one is yours.",
    };

  const checked = [
    { label: "Close variants checked", state: "info", detail: `${rows.length} names: typos, look-alike letters, keyword and ending variants.` },
    ...(unknown.length ? [{ label: "Lookups that did not answer", state: "unknown", detail: `${unknown.length} names could not be checked; they are not counted either way.` }] : []),
    ...(registered.some((row) => row.detail_checked === false) ? [{ label: "Server and email checks", state: "unknown", detail: `Checked for the first ${LOOKALIKE_DETAIL_LIMIT} registered names only.` }] : []),
  ];

  return {
    ...base,
    verdict,
    candidates_checked: rows.length,
    lookalikes,
    checked,
    not_checked: NOT_CHECKED,
    why_it_matters: WHY_IT_MATTERS,
    next_step: registered.length === 0
      ? { title: "No change needed", explanation: "Re-check now and then, or let CyberMeters Brand Protection watch for new registrations.", record: null }
      : {
        title: "Check whether each one is yours",
        explanation: "For each registered name, look up its owner with the registrar or a WHOIS service. If it is yours, keep it renewed. If it is not and it receives email or shows a copy of your site, tell your staff and customers, and report it to the registrar's abuse contact.",
        record: null,
        cautions: withMail.length ? ["A lookalike that receives email can also be set up to send it. Make sure your own domain publishes SPF, DKIM and a DMARC policy, so receivers can tell your mail from look-alike mail."] : [],
      },
  };
}

/** Run the check. deps.dnsQuery(name, type) → DoH JSON; a throw counts as no answer. */
export async function runLookalikeCheck(domain, { dnsQuery, registrable = domain, now } = {}) {
  const candidates = lookalikeCandidates(registrable);
  let budgetLeft = true;
  const nsAnswers = await inBatches(candidates, async (candidate) => {
    if (!budgetLeft) return { ok: false };
    const answer = await ask(dnsQuery, candidate.domain, "NS");
    if (answer.budget) budgetLeft = false;
    return answer;
  });
  const existing = candidates.map((c, i) => ({ c, ns: nsAnswers[i] })).filter(({ ns }) => ns.ok && ns.exists);
  const detailed = new Set(existing.slice(0, LOOKALIKE_DETAIL_LIMIT).map(({ c }) => c.domain));
  const details = new Map(await inBatches([...detailed], async (name) => {
    if (!budgetLeft) return [name, null];
    const [a, aaaa, mx] = await Promise.all([ask(dnsQuery, name, "A"), ask(dnsQuery, name, "AAAA"), ask(dnsQuery, name, "MX")]);
    if (a.budget || aaaa.budget || mx.budget) budgetLeft = false;
    return [name, { a, aaaa, mx }];
  }));

  const rows = candidates.map((candidate, i) => {
    const ns = nsAnswers[i];
    const row = { domain: candidate.domain, variant: candidate.variant, variant_label: candidate.variant_label };
    if (!ns.ok) return { ...row, status: "unknown" };
    if (!ns.exists) return { ...row, status: "not_found" };
    const detail = details.get(candidate.domain);
    if (!detail) return { ...row, status: "registered", delegated: ns.records.length > 0, resolves: null, mx: null, detail_checked: false };
    const resolves = (detail.a.ok && detail.a.records.length > 0) || (detail.aaaa.ok && detail.aaaa.records.length > 0)
      ? true : (detail.a.ok && detail.aaaa.ok ? false : null);
    const mx = detail.mx.ok ? detail.mx.records.some((value) => !/^0\s+\.?$/.test(value)) : null;
    return { ...row, status: "registered", delegated: ns.records.length > 0, resolves, mx, detail_checked: true };
  });
  return buildLookalikeToolResult(domain, registrable, rows, { now: now ? now() : Date.now() });
}
