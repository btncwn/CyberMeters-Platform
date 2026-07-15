// ── New Scan: domain-ownership verification state ────────────────────────────
// Pure state logic for the New Scan page, kept out of the component so the rules
// below are testable without a DOM.
//
// The defect this fixes: New Scan validated the domain with a REGEX and then said
// "Valid domain — ready to scan". That sentence asserts ownership; the regex only
// proves syntax. So the page promised a scan it could not start, the customer
// clicked, and the backend refused with a raw machine code (the UI rendered
// `domain_verification_required` verbatim under "Something went wrong") — while the
// green "ready to scan" tick sat directly above the failure.
//
// Nothing here is a second verification mechanism. The backend already owns all of
// it: POST /api/domains/:id/verification mints the token and returns the exact DNS
// instruction; POST /api/domains/:id/verify performs the check. This module only
// decides what the customer is looking at.

// ── States ───────────────────────────────────────────────────────────────────
//   idle            — nothing typed, or the domain is not syntactically valid
//   ready           — syntax is valid. NOT a claim that the domain is scannable:
//                     ownership is unknown until the backend says so.
//   starting        — the scan request is in flight
//   needs_setup     — the backend refused: this workspace has not proven ownership
//   instructions    — a token exists; the exact TXT record is on screen
//   checking        — the DNS check is in flight
//   check_failed    — the record was not found (yet). Instructions MUST persist.
//   verified        — ownership proven; the scan may start
//   scanning        — the scan was accepted
export const SCAN_STATES = Object.freeze([
  'idle', 'resolving', 'valid_unverified', 'initiating_verification', 'instructions',
  'checking', 'check_failed', 'verified', 'starting', 'scanning',
]);

// States where ownership is not proven but the domain IS actionable. Every one of
// these MUST render a visible verification CTA — see requiresVerificationCta.
//
// This list exists because of a production deadlock: the verification panel was
// only reachable from the createScan error path, while Start Scan was disabled
// until verified. The customer could not submit, so the 403 never fired, so the
// panel never appeared: a valid domain with no way forward and no explanation.
// A state that needs verification but shows no CTA is a dead end by definition.
const CTA_STATES = new Set([
  'valid_unverified', 'initiating_verification', 'instructions', 'checking', 'check_failed',
]);

// True when the page owes the customer a route to verification.
export function requiresVerificationCta(state) {
  return CTA_STATES.has(state);
}

// The deadlock invariant, stated positively: no state may need verification and
// simultaneously offer nothing. Asserted over EVERY state in the test suite.
export function isDeadEnd(state) {
  const needsVerification = !canStartScan(state) && state !== 'idle' && state !== 'starting' && state !== 'scanning' && state !== 'resolving';
  return needsVerification && !requiresVerificationCta(state);
}

// Ownership is a backend fact. The page may never infer it from a regex, a previous
// visit, or the absence of an error — only these states mean "proven".
const VERIFIED_STATES = new Set(['verified', 'scanning']);

// Start Scan is enabled ONLY once ownership is proven. Syntax is not permission.
export function canStartScan(state) {
  return state === 'verified';
}

// The syntax check. Named so it cannot be mistaken for an ownership check — the old
// `valid` flag was true for any well-formed string and drove copy that implied more.
export function isValidDomainSyntax(value) {
  return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(String(value || '').trim());
}

// What the field says under the input. It may describe the FORMAT and nothing more
// until the backend has confirmed ownership.
export function domainHintFor(state, value) {
  if (!String(value || '').trim()) return null;
  if (!isValidDomainSyntax(value)) return { tone: 'error', text: 'Enter a domain like example.com' };
  if (VERIFIED_STATES.has(state)) return { tone: 'success', text: 'Domain ownership verified — ready to scan' };
  if (state === 'resolving') return { tone: 'neutral', text: 'Checking domain ownership…' };
  // Deliberately not "ready to scan": we do not know that yet. The verification CTA
  // below tells the customer what to do about it.
  return { tone: 'neutral', text: 'Valid domain format. Verify ownership to enable scanning.' };
}

// ── Customer-safe copy ───────────────────────────────────────────────────────
// The API client preserves the server's `error` string verbatim as the Error
// message (other flows switch on it), so `e.message` here can be a machine code.
// Never render it. Any code we do not have copy for degrades to a neutral sentence
// rather than leaking an identifier.
const SAFE_MESSAGES = Object.freeze({
  domain_verification_required: 'Verify ownership of this domain before scanning.',
  plan_limit_exceeded: 'You have reached your plan limit.',
  rate_limit_exceeded: 'You have reached the hourly scan limit.',
});

export function safeErrorMessage(err) {
  const code = err?.code || err?.error || '';
  if (SAFE_MESSAGES[code]) return SAFE_MESSAGES[code];
  const message = String(err?.message || '').trim();
  // A machine code looks like snake_case with no spaces. If the "message" is one,
  // it is an identifier that leaked into a customer-facing field.
  if (!message || /^[a-z0-9]+(_[a-z0-9]+)+$/.test(message)) {
    return 'We could not start this scan. Please try again or contact support.';
  }
  return message;
}

export function isVerificationRequired(err) {
  return (err?.code || err?.error) === 'domain_verification_required';
}

// ── DNS instruction ──────────────────────────────────────────────────────────
// Built ONLY from the backend's response. The host/value are never reconstructed
// here — a client-built token would be a second source of truth and could disagree
// with what the server stored, sending the customer to publish a record that can
// never verify.
export const DNS_TTL_GUIDANCE = 'Leave TTL on Auto (or 300 seconds). DNS changes usually apply within minutes, but can take up to 48 hours.';

export function dnsInstructionFrom(response) {
  const dns = response?.dns;
  if (!dns?.host || !dns?.value) return null;
  return {
    record_type: dns.record_type || 'TXT',
    host: dns.host,
    value: dns.value,
    ttl: DNS_TTL_GUIDANCE,
    provider_path: 'Cloudflare: DNS → Records → Add record → TXT',
  };
}

// The check reported "not found". That is a waiting state, not a dead end: the
// record may simply not have propagated. The instruction MUST stay on screen —
// clearing it would strand the customer with no way to complete the task.
export function checkFailureMessage(err) {
  const code = err?.code || err?.error || '';
  if (code === 'verification_failed' || code === 'dns_record_not_found') {
    return 'We could not find that TXT record yet. DNS can take a few minutes to propagate — check the record below and try again.';
  }
  return 'We could not check the DNS record just now. The record details below are still valid — please try again shortly.';
}


// The backend returns a per-method breakdown on a failed check:
//   { success:false, verification_status:'failed',
//     checks:{ dns_txt:{result:'found'|'not_found', error}, html_file:{...} } }
// at HTTP 200 — so it is a normal response, not an exception.
//
// Distinguish the outcomes rather than showing one shrug for all of them: "record
// not published yet" and "record present but wrong value" need different actions
// from the customer, and a lookup error is neither of those.
export function verifyFailureNote(res) {
  const dns = res?.checks?.dns_txt;
  if (dns?.error) {
    return 'We could not complete the DNS lookup just now. Your record below is unaffected — please try again shortly.';
  }
  if (dns?.result === 'not_found') {
    // The server re-checks hourly for 48h, so this is a wait, not a failure.
    return 'That TXT record is not visible yet. DNS can take a few minutes to propagate — check the record below matches exactly, then try again. We also re-check automatically every hour for 48 hours.';
  }
  if (dns?.result === 'found') {
    // Present but not accepted => the published value is not the expected one.
    return 'A TXT record was found at that host, but its value does not match the one below. Check for a stray quote, space, or an older record still present, then try again.';
  }
  // Unknown shape — never echo it. Fall back to the safe generic.
  return checkFailureMessage(res || {});
}

// Instructions survive every non-success outcome. Losing them on an error is how a
// customer ends up unable to finish, with no way back to the token.
export function shouldKeepInstructions(state) {
  return state === 'instructions' || state === 'checking' || state === 'check_failed';
}
