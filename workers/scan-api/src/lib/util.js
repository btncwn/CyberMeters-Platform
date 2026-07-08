// ── Shared pure helpers ──────────────────────────────────────────────────────
// Leaf utilities with no app dependencies (ids, validation, pagination,
// response normalisation). Anything here must stay dependency-free.
function createId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function isValidEmail(email) {
  if (typeof email !== "string") return false;
  const value = email.trim();
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function parseBoundedInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function normalizeApiResponseData(data, status) {
  if (!Number.isInteger(status) || status < 400 || !data || typeof data !== "object" || Array.isArray(data)) {
    return data;
  }

  const normalized = { ...data };
  delete normalized.detail;
  delete normalized.stack;

  if (typeof normalized.error !== "string" || !normalized.error.trim()) {
    normalized.error = status >= 500 ? "Request failed. Please try again." : "Request could not be completed.";
  }

  if (!normalized.code) {
    normalized.code = /^[a-z][a-z0-9_]*$/.test(normalized.error)
      ? normalized.error
      : ({ 400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict", 413: "payload_too_large", 414: "uri_too_long", 429: "rate_limit_exceeded" }[status]
        || (status >= 500 ? "server_error" : "request_error"));
  }

  return normalized;
}

// ── List pagination contract ─────────────────────────────────────────────────
// Every list endpoint returns a `pagination` object next to its named array so
// API consumers get one predictable shape. paginationParams parses + clamps
// limit/offset from the query; pageMeta describes the returned page. has_more is
// exact when a total is known, otherwise a full-page heuristic (count >= limit).
function paginationParams(url, { defaultLimit = 50, maxLimit = 100 } = {}) {
  return {
    limit:  parseBoundedInteger(url.searchParams.get("limit"), defaultLimit, 1, maxLimit),
    offset: parseBoundedInteger(url.searchParams.get("offset"), 0, 0, 1_000_000),
  };
}

function pageMeta({ items, limit, offset, total = null }) {
  const count = Array.isArray(items) ? items.length : 0;
  const meta = { limit, offset, count };
  if (total != null) { meta.total = total; meta.has_more = offset + count < total; }
  else { meta.has_more = count >= limit; }
  return meta;
}

export {
  createId,
  isValidEmail,
  normalizeApiResponseData,
  pageMeta,
  paginationParams,
  parseBoundedInteger,
};
