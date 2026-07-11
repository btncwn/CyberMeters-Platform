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

function isValidDomain(domain) {
  if (typeof domain !== "string" || domain.length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2 || !/^[a-zA-Z]{2,63}$/.test(labels.at(-1) || "")) return false;
  return labels.every((label) =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
  );
}

function parseBoundedInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

// Canonical machine `code` per HTTP status — a snake_case token the frontend can
// switch on without parsing prose. Covers every status the API actually returns.
const STATUS_CODE = {
  400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
  405: "method_not_allowed", 409: "conflict", 410: "gone", 413: "payload_too_large",
  414: "uri_too_long", 422: "unprocessable_entity", 429: "rate_limit_exceeded",
  500: "server_error", 502: "bad_gateway", 503: "service_unavailable",
};

// Customer-safe human `message` per status — a sentence a real user can read.
// Never leaks internals; the machine `code` above carries the branching signal.
const STATUS_MESSAGE = {
  400: "The request could not be processed. Please check your input and try again.",
  401: "You're not signed in, or your session has expired. Please sign in and try again.",
  403: "You don't have access to this. Try switching workspace or contact your admin.",
  404: "We couldn't find what you were looking for.",
  405: "That action isn't supported here.",
  409: "This conflicts with the current state. Please refresh and try again.",
  410: "This is no longer available.",
  413: "The request is too large.",
  414: "The request is too long.",
  422: "Some of the information provided couldn't be validated. Please review and try again.",
  429: "Too many requests right now. Please wait a moment and try again.",
};

// normalizeApiResponseData — the single choke point that gives every error
// response (status >= 400) a uniform, leak-free contract: { error, code, message }.
//   - `error`   : preserved verbatim (machine code OR human string the UI reads).
//   - `code`    : snake_case machine token derived from `error` or the status.
//   - `message` : customer-safe human sentence (added only when absent — a
//                 route's own specific message always wins).
// `detail`/`stack` are stripped so an internal trace can never reach a client.
// Called by the `json()` helper, so all 568+ error return sites conform without
// each one repeating the shape. Success bodies (status < 400) pass through untouched.
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
      : (STATUS_CODE[status] || (status >= 500 ? "server_error" : "request_error"));
  }

  if (typeof normalized.message !== "string" || !normalized.message.trim()) {
    normalized.message = STATUS_MESSAGE[status]
      || (status >= 500
        ? "Something went wrong on our end. Please try again in a moment."
        : "The request could not be completed.");
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
  isValidDomain,
  isValidEmail,
  normalizeApiResponseData,
  pageMeta,
  paginationParams,
  parseBoundedInteger,
};
