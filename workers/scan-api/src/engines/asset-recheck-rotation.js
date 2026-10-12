import { normalizeHostname } from "./hostname-candidates.js";

const DAY_MS = 86_400_000;
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;

// An explicit ISO instant is required; locale dates and numeric coercions are
// not timestamps. No wall clock is read by this module.
function instant(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return null;
  // Date.parse normalizes impossible dates (February 30); reject them first.
  const year = Number(value.slice(0, 4)), month = Number(value.slice(5, 7)), day = Number(value.slice(8, 10));
  const days = new Date(Date.UTC(year < 100 ? year + 400 : year, month, 0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > days || Number(value.slice(11, 13)) > 23) return null;
  return ms;
}

function unavailableCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, 6) : 0;
}

export function selectRecheckHosts(input = {}) {
  const empty = () => ({
    version: "asset-recheck-rotation-v1", selected: [],
    deferred_known_count: 0, deferred_candidate_count: 0, backoff_skipped_count: 0,
  });
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return empty();
    const cap = Number.isSafeInteger(input.cap) && input.cap >= 0 ? input.cap : 50;
    const shareValue = Number.isSafeInteger(input.knownShare) && input.knownShare >= 0 ? input.knownShare : 40;
    const knownShare = Math.min(shareValue, cap);
    const now = instant(input.now);
    const known = new Map();
    for (const row of Array.isArray(input.knownAssets) ? input.knownAssets : []) {
      const hostname = normalizeHostname(row?.hostname);
      if (!hostname) continue;
      let checked = instant(row?.last_rechecked_at);
      // Future timestamps must not hold a name out of rotation indefinitely.
      if (checked !== null && now !== null && checked > now) checked = null;
      const item = { hostname, checked, failures: unavailableCount(row?.consecutive_unavailable) };
      const previous = known.get(hostname);
      // Duplicate rows cannot create slots or hide an older/null check. When
      // timestamps match, the smaller failure count prevents backoff poisoning.
      if (!previous || (item.checked ?? -Infinity) < (previous.checked ?? -Infinity)
        || (item.checked === previous.checked && item.failures < previous.failures)) known.set(hostname, item);
    }
    const eligible = [];
    let backoffSkipped = 0;
    for (const item of known.values()) {
      const backoffDays = item.failures >= 3 ? Math.min(2 ** (item.failures - 3), 7) : 0;
      if (backoffDays && item.checked !== null && now !== null && now - item.checked < backoffDays * DAY_MS) {
        backoffSkipped++;
      } else eligible.push(item);
    }
    eligible.sort((a, b) => {
      if (a.checked !== b.checked) {
        if (a.checked === null) return -1;
        if (b.checked === null) return 1;
        return a.checked - b.checked;
      }
      return compare(a.hostname, b.hostname);
    });
    const fresh = new Map();
    for (const row of Array.isArray(input.candidates) ? input.candidates : []) {
      const hostname = normalizeHostname(row?.hostname);
      if (!hostname || known.has(hostname)) continue;
      if (!fresh.has(hostname)) fresh.set(hostname, new Set());
      for (const source of Array.isArray(row?.sources) ? row.sources : []) {
        if (typeof source === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(source)) fresh.get(hostname).add(source);
      }
    }
    const candidates = [...fresh].map(([hostname, sources]) => ({ hostname, count: sources.size }))
      .sort((a, b) => b.count - a.count || compare(a.hostname, b.hostname));
    let knownCount = Math.min(knownShare, eligible.length);
    let candidateCount = Math.min(cap - knownShare, candidates.length);
    let spare = cap - knownCount - candidateCount;
    const extraKnown = Math.min(spare, eligible.length - knownCount);
    knownCount += extraKnown;
    spare -= extraKnown;
    candidateCount += Math.min(spare, candidates.length - candidateCount);
    return {
      version: "asset-recheck-rotation-v1",
      selected: [
        ...eligible.slice(0, knownCount).map((row) => ({ hostname: row.hostname,
          reason: row.checked === null ? "known_never_checked" : "known_least_recent" })),
        ...candidates.slice(0, candidateCount).map((row) => ({ hostname: row.hostname, reason: "new_candidate" })),
      ],
      // Deferred known includes backoff; backoff_skipped_count is its subset.
      deferred_known_count: known.size - knownCount,
      deferred_candidate_count: candidates.length - candidateCount,
      backoff_skipped_count: backoffSkipped,
    };
  } catch { return empty(); }
}
