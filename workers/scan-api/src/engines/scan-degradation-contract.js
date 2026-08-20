// ── D1 Option D — structured scan-degradation contract ───────────────────────
//
// Authority: FOUNDER-DECISION-006-D1-OPTION-D (transport seq 50) via
// WORKORDER-D1-OPTION-D-IMPLEMENTATION-001 (seq 51) and its seq-126 amendment.
//
// THE SEMANTIC BOUNDARY, fixed and non-negotiable:
//
//     degraded != complete
//     degraded != healthy
//     degraded != score / band / BRS / timeline / verification / resolution permission
//
// `degraded` means: a declared evidence SOURCE was lost, some valid evidence
// survived, and both facts are represented explicitly. It is strictly weaker than
// `complete` and never weaker than `partial` — every protection applied to
// `partial` applies to `degraded` as well.
//
// WHY A SEPARATE CARRIER. The per-provider `modules.subdomains.sources` shape is a
// live compatibility invariant asserted by deep equality in
// `scripts/validate-shared-ct-provider-cache.js` (per-source success shape is
// exactly `{ count, error }`). Degradation facts are therefore carried in a
// SIBLING `degradations[]` array — never by widening `sources`. Satisfying the
// invariant through product compatibility is required; weakening that test is
// explicitly forbidden.
//
// FAIL-CLOSED BY CONSTRUCTION. Anything this module cannot fully validate returns
// null, and a null degradation can never produce `degraded` — the caller stays on
// the legacy `partial` path. Unrecognised status, unrecognised claim effect, a
// missing/unknown contract version, absent fallback evidence or a non-publishable
// fallback all fail back to `partial` conservatism.

export const SCAN_DEGRADATION_CONTRACT_VERSION = "scan-degradation/1";

// Exactly the seq-51 minimum field set. Order is fixed so serialized records are
// stable across report and snapshot surfaces.
export const SCAN_DEGRADATION_FIELDS = Object.freeze([
  "module",
  "dependency",
  "status",
  "reason",
  "claim_effect",
  "fallback_evidence",
  "fallback_publishable",
  "observed_at",
  "contract_version",
]);

// A dependency is either unavailable (declared loss) or unknown. `unknown` is
// deliberately NOT sufficient for `degraded`: an unrecognised dependency state is
// exactly the "malformed/unknown contract data" case that must stay `partial`.
export const SCAN_DEGRADATION_STATUSES = Object.freeze({
  UNAVAILABLE: "unavailable",
});

// What the customer may still conclude. Only a bounded-coverage effect can support
// `degraded`; anything that would erase a claim entirely is a `partial` condition.
export const SCAN_DEGRADATION_CLAIM_EFFECTS = Object.freeze({
  COVERAGE_REDUCED: "coverage_reduced",
});

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

// A degradation is VALID only when every field is present, recognised and
// internally consistent. There is no partial credit: one bad field returns null,
// and the caller must then stay `partial`.
export function isValidDegradation(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return false;

  // Exact field set — no missing fields and no undeclared extras. An unexpected
  // field means the producer and this contract disagree, which is precisely the
  // malformed-contract case that must not earn `degraded`.
  const keys = Object.keys(record).sort();
  const want = [...SCAN_DEGRADATION_FIELDS].sort();
  if (keys.length !== want.length) return false;
  for (let i = 0; i < want.length; i += 1) if (keys[i] !== want[i]) return false;

  if (record.contract_version !== SCAN_DEGRADATION_CONTRACT_VERSION) return false;
  if (!nonEmptyString(record.module)) return false;
  if (!nonEmptyString(record.dependency)) return false;
  if (!nonEmptyString(record.reason)) return false;
  if (record.status !== SCAN_DEGRADATION_STATUSES.UNAVAILABLE) return false;
  if (record.claim_effect !== SCAN_DEGRADATION_CLAIM_EFFECTS.COVERAGE_REDUCED) return false;

  // The surviving positive evidence must be real and publishable. "No publishable
  // fallback" is a `partial` condition by FD-006, so it fails closed here.
  if (record.fallback_publishable !== true) return false;
  if (!record.fallback_evidence || typeof record.fallback_evidence !== "object") return false;
  const { source, count } = record.fallback_evidence;
  if (!nonEmptyString(source)) return false;
  if (!Number.isInteger(count) || count <= 0) return false;

  if (!nonEmptyString(record.observed_at) || !ISO_INSTANT.test(record.observed_at)) return false;
  return true;
}

// Build one degradation record. Returns null — never a half-built object — when the
// inputs cannot support a governed `degraded`.
export function buildDegradation({
  module: moduleName,
  dependency,
  reason,
  fallbackSource,
  fallbackCount,
  observedAt,
} = {}) {
  const record = {
    module: moduleName,
    dependency,
    status: SCAN_DEGRADATION_STATUSES.UNAVAILABLE,
    reason,
    claim_effect: SCAN_DEGRADATION_CLAIM_EFFECTS.COVERAGE_REDUCED,
    fallback_evidence: { source: fallbackSource, count: fallbackCount },
    fallback_publishable: true,
    observed_at: observedAt,
    contract_version: SCAN_DEGRADATION_CONTRACT_VERSION,
  };
  return isValidDegradation(record) ? Object.freeze(record) : null;
}

// Collect the valid degradations declared by modules. Invalid records are dropped
// AND reported, so a caller can distinguish "no degradation" from "a degradation we
// refused to honour" — the second must not silently become `degraded`.
export function collectDegradations(modules = {}, observedAt = new Date().toISOString()) {
  const valid = [];
  let rejected = 0;
  for (const value of Object.values(modules || {})) {
    const declared = value?.degradations;
    if (declared === undefined || declared === null) continue;
    if (!Array.isArray(declared)) { rejected += 1; continue; }
    for (const facts of declared) {
      // Modules emit deterministic FACTS; the single observation stamp is applied
      // here so module output stays byte-identical across runs. Anything that does
      // not build into a fully valid record is rejected, never half-honoured.
      const record = (facts && typeof facts === "object" && !Array.isArray(facts))
        ? buildDegradation({
          module: facts.module,
          dependency: facts.dependency,
          reason: facts.reason,
          fallbackSource: facts.fallback_source,
          fallbackCount: facts.fallback_count,
          observedAt,
        })
        : null;
      if (record) valid.push(record);
      else rejected += 1;
    }
  }
  return { degradations: valid, rejected };
}

// THE RE-GRADE PREDICATE. `degraded` is permitted only when every one of these
// holds; otherwise the caller keeps whatever it had (in practice `partial`).
//
//   * the legacy `partial` drivers are absent — any independent incomplete cause
//     dominates and stays `partial`;
//   * at least one VALID structured degradation exists;
//   * no declared degradation was rejected — a malformed record anywhere means the
//     contract is not trustworthy for this scan.
export function mayGradeDegraded({ partialDrivers = 0, degradations = [], rejected = 0 } = {}) {
  if (partialDrivers > 0) return false;
  if (rejected > 0) return false;
  return Array.isArray(degradations) && degradations.length > 0;
}

// Fail-closed equivalence helper. Every gate that is conservative for `partial`
// must use this rather than comparing to the literal `"partial"`, so a future
// status cannot silently escape by not being spelled `partial`.
export const NON_AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["partial", "degraded"]);

// TYPE-STRICT for the same reason as the authoritative predicate, and found by the
// author's own ninth-shape hunt rather than by a reviewer: the surviving
// `String(...)` call here was the LAST coercion on the gate's path, and it is an
// ingress in its own right under the seq-167 law. A hostile `toString`/proxy/getter
// could make it THROW out of moduleCompletionGate rather than return a verdict.
// Its tolerance was conservative-direction (a coerced value merely looked weaker),
// so it was never a verification bypass — but "fails closed by throwing" is not the
// same as "fails closed", and leaving one coercion behind is how this class
// survived three iterations. There is now no coercion anywhere on the gate path.
export function isNonAuthoritativeQuality(status) {
  if (typeof status !== "string") return false;
  return NON_AUTHORITATIVE_SCAN_QUALITIES.includes(status.trim().toLowerCase());
}

// ── The ALLOW-LIST side of the same vocabulary ──────────────────────────────
// `isNonAuthoritativeQuality` answers "is this one of the statuses we know to be
// weak?". That question is deny-by-default in the wrong direction: anything the
// list has not heard of answers `false` and is therefore treated as strong.
//
// A verification decision needs the opposite question — "is this explicitly
// authoritative?" — so an unknown, unrecognised, empty, absent or future status
// fails CLOSED instead of being promoted by silence. Only a completed scan is
// authoritative evidence that a module actually re-ran.
export const AUTHORITATIVE_SCAN_QUALITIES = Object.freeze(["complete"]);

// TYPE ADMISSION BEFORE VALUE NORMALIZATION (Governance seq 167, D1LSV-01).
//
// The previous revision called `String(status ?? "")` FIRST, so anything whose
// coerced representation was "complete" walked straight in: `["complete"]`,
// `{toString:()=>"complete"}` and `new String("complete")` all verified. The
// conversion itself was the ingress.
//
// The ruled law: an authoritative allow-list is a TYPE-AND-VALUE contract.
// Nothing may be stringified, trimmed, case-folded, unboxed or interpolated
// before it has been admitted as a PRIMITIVE STRING. `typeof` is not spoofable —
// a boxed String, an array, a plain object with `toString`/`valueOf`/
// `Symbol.toPrimitive`, and a Symbol all report a non-"string" type and are
// rejected before any conversion can participate.
//
// Trim and case-fold remain legal AFTER admission: the raw type of `" COMPLETE "`
// is already primitive string, so normalizing it is value handling, not type
// coercion. There is deliberately no `String(...)` call left on this path.
export function isAuthoritativeQuality(status) {
  if (typeof status !== "string") return false;
  return AUTHORITATIVE_SCAN_QUALITIES.includes(status.trim().toLowerCase());
}
