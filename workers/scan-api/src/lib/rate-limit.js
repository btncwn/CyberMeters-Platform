// ── Canonical D1-backed API / inbound-email rate limiter ─────────────────────
//
// Cycle-safe by design: this module has no imports from the Worker entry point,
// routes, or engines. Both cybermeters-platform and cybermeters-email import
// these exact functions so the routed email Worker cannot silently drift onto
// an unthrottled implementation.

function getRateLimitWindow(windowSeconds = 3600) {
  const now = Date.now();
  const startMs = Math.floor(now / (windowSeconds * 1000)) * windowSeconds * 1000;
  return {
    window_start: new Date(startMs).toISOString(),
    reset_at: new Date(startMs + windowSeconds * 1000).toISOString(),
  };
}

function rateLimitId(scope, scopeId, action, windowStart) {
  const raw = `${scope}:${scopeId}:${action}:${windowStart}`;
  return `rl_${raw.replace(/[^a-zA-Z0-9_-]+/g, "_")}`;
}

function rateLimitExceeded(action, limit, windowSeconds, resetAt) {
  return {
    error: "Rate limit exceeded",
    code: "rate_limit_exceeded",
    action,
    limit,
    window_seconds: windowSeconds,
    reset_at: resetAt,
    upgrade_message: "Upgrade your plan for higher scan limits.",
  };
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value)),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function rateLimitScopeId(prefix, value) {
  const raw = String(value || "unknown");
  try {
    return `${prefix}_${(await sha256Hex(raw)).slice(0, 16)}`;
  } catch {
    return `${prefix}_${raw.replace(/[^a-z0-9]/gi, "_").slice(0, 32)}`;
  }
}

// Rolling window for small limits: `limit` slots per scope, each holding the
// time it was last claimed. A request claims a slot whose claim is older than
// the window, in one conditional UPSERT, so two concurrent requests can never
// claim the same slot. Unlike a fixed window, a burst at the end of one window
// cannot be followed by a second burst at the start of the next. The reset time
// is when the oldest claim leaves the window.
const MAX_ROLLING_SLOTS = 10;

// Internal, request-owned compensation for a confirmed claim. The closure keeps
// the original identity out of HTTP/JSON and consumes its attempt before I/O:
// an uncertain D1 write must never be retried and release someone else's use.
function claimReleaseOnce(env, { id, scope, scopeId, action, windowStart, windowSeconds, revision, expiredAt }) {
  let attempted = false;
  return async () => {
    if (attempted) return false;
    attempted = true;
    try {
      const statement = expiredAt === undefined
        ? env.cybermeters_db.prepare(
          `UPDATE api_rate_limits
           SET request_count = request_count - 1, updated_at = datetime('now')
           WHERE id = ? AND scope = ? AND scope_id = ? AND action = ?
             AND window_start = ? AND window_seconds = ? AND request_count > 0`,
        ).bind(id, scope, scopeId, action, windowStart, windowSeconds)
        : env.cybermeters_db.prepare(
          `UPDATE api_rate_limits
           SET window_start = ?, updated_at = datetime('now')
           WHERE id = ? AND scope = ? AND scope_id = ? AND action = ?
             AND window_start = ? AND window_seconds = ? AND request_count = ?`,
        ).bind(expiredAt, id, scope, scopeId, action, windowStart, windowSeconds, revision);
      const result = await statement.run();
      return result?.meta?.changes === 1;
    } catch {
      // The allowance may remain consumed; never promise a refund or retry an
      // update whose outcome could be unknown. No counter/user identity is logged.
      console.error("[rate-limit] claim release could not be confirmed");
      return false;
    }
  };
}

async function consumeRollingSlots(env, scopes, action, limit, windowSeconds, options) {
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ROLLING_SLOTS) {
    throw new RangeError(`rolling limit must be 1-${MAX_ROLLING_SLOTS}`);
  }
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const cutoff = new Date(nowMs - windowSeconds * 1000).toISOString();
  const slotIds = (scope) => Array.from({ length: limit },
    (_, slot) => rateLimitId(scope.scope, scope.scope_id, action, `slot${slot}`));
  const denied = async (scope) => {
    const ids = slotIds(scope);
    const row = await env.cybermeters_db
      .prepare(`SELECT MIN(window_start) AS oldest FROM api_rate_limits
                WHERE id IN (${ids.map(() => "?").join(", ")}) AND window_start > ?`)
      .bind(...ids, cutoff)
      .first();
    const oldestMs = Date.parse(row?.oldest ?? "");
    const resetAt = new Date((Number.isFinite(oldestMs) ? oldestMs : nowMs) + windowSeconds * 1000).toISOString();
    return { status: 429, body: rateLimitExceeded(action, limit, windowSeconds, resetAt) };
  };

  if (options.peek === true) {
    for (const scope of scopes) {
      const ids = slotIds(scope);
      const row = await env.cybermeters_db
        .prepare(`SELECT COUNT(*) AS active FROM api_rate_limits
                  WHERE id IN (${ids.map(() => "?").join(", ")}) AND window_start > ?`)
        .bind(...ids, cutoff)
        .first();
      if ((row?.active ?? limit) >= limit) return denied(scope);
    }
    return null;
  }

  for (const scope of scopes) {
    let claimed = false;
    for (const id of slotIds(scope)) {
      const row = await env.cybermeters_db
        .prepare(
          `INSERT INTO api_rate_limits
             (id, scope, scope_id, action, window_start, window_seconds,
              request_count, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))
           ON CONFLICT(id) DO UPDATE SET
             window_start = excluded.window_start,
             request_count = api_rate_limits.request_count + 1,
             updated_at = datetime('now')
           WHERE api_rate_limits.window_start <= ?
           RETURNING id, window_start, request_count`,
        )
        .bind(id, scope.scope, scope.scope_id, action, nowIso, windowSeconds, cutoff)
        .first();
      if (row) {
        if (options.onClaim) {
          options.onClaim(claimReleaseOnce(env, {
            id, scope: scope.scope, scopeId: scope.scope_id, action,
            windowStart: row.window_start, windowSeconds,
            // Keep this monotonic revision when releasing a rolling slot; a
            // same-millisecond reuse must not match an older claim.
            revision: row.request_count, expiredAt: cutoff,
          }));
        }
        claimed = true;
        break;
      }
    }
    if (!claimed) return denied(scope);
  }
  return null;
}

export async function consumeApiRateLimit(
  env,
  scopes,
  action,
  limit,
  windowSeconds = 3600,
  options = {},
) {
  // D1-backed rate limiting is adequate for early launch. Existing callers
  // retain the legacy read/update path and fail-open default; expensive actions
  // may explicitly request the atomic UPSERT path and fail-closed behaviour.
  if (!Number.isFinite(limit) || limit >= 999999) return null;
  const activeScopes = scopes.filter((scope) => scope.scope && scope.scope_id);
  if (activeScopes.length === 0) return null;

  const { window_start, reset_at } = getRateLimitWindow(windowSeconds);

  try {
    if (options.rolling === true) {
      return await consumeRollingSlots(env, activeScopes, action, limit, windowSeconds, options);
    }
    if (options.peek === true) {
      // Read-only: is this window already full? Writes nothing, so a caller can
      // refuse before any D1 write and claim later only when work will run.
      for (const scope of activeScopes) {
        const id = rateLimitId(scope.scope, scope.scope_id, action, window_start);
        const row = await env.cybermeters_db
          .prepare("SELECT request_count FROM api_rate_limits WHERE id = ?")
          .bind(id)
          .first();
        if ((row?.request_count ?? 0) >= limit) {
          return { status: 429, body: rateLimitExceeded(action, limit, windowSeconds, reset_at) };
        }
      }
      return null;
    }
    if (options.atomic === true) {
      // Expensive manual security actions need a real concurrency/burst claim,
      // not the legacy read-then-increment approximation. One UPSERT returns the
      // post-increment count atomically for each scope/window.
      for (const scope of activeScopes) {
        const id = rateLimitId(scope.scope, scope.scope_id, action, window_start);
        // Security-sensitive callers can stop at the cap. A denied request
        // must not keep writing the same row indefinitely under a flood.
        const saturating = options.saturating === true;
        const row = await env.cybermeters_db
          .prepare(
            `INSERT INTO api_rate_limits
               (id, scope, scope_id, action, window_start, window_seconds,
                request_count, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))
             ON CONFLICT(id) DO UPDATE SET
               request_count = api_rate_limits.request_count + 1,
               updated_at = datetime('now')
             ${saturating ? 'WHERE api_rate_limits.request_count < ?' : ''}
             RETURNING request_count`,
          )
          .bind(id, scope.scope, scope.scope_id, action, window_start, windowSeconds,
            ...(saturating ? [limit] : []))
          .first();
        // Each post-increment count is returned to exactly one request, so a
        // caller can act once when a count crosses a threshold.
        if (row?.request_count != null) options.onCount?.(row.request_count, scope);
        if ((row?.request_count ?? limit + 1) > limit) {
          return {
            status: 429,
            body: rateLimitExceeded(action, limit, windowSeconds, reset_at),
          };
        }
        options.onClaim?.(claimReleaseOnce(env, {
          id, scope: scope.scope, scopeId: scope.scope_id, action,
          windowStart: window_start, windowSeconds,
        }));
      }
      return null;
    }

    for (const scope of activeScopes) {
      const row = await env.cybermeters_db
        .prepare(
          `SELECT request_count
           FROM api_rate_limits
           WHERE scope = ? AND scope_id = ? AND action = ? AND window_start = ?
           LIMIT 1`,
        )
        .bind(scope.scope, scope.scope_id, action, window_start)
        .first();
      if ((row?.request_count ?? 0) >= limit) {
        return {
          status: 429,
          body: rateLimitExceeded(action, limit, windowSeconds, reset_at),
        };
      }
    }

    for (const scope of activeScopes) {
      const id = rateLimitId(scope.scope, scope.scope_id, action, window_start);
      await env.cybermeters_db
        .prepare(
          `INSERT INTO api_rate_limits
             (id, scope, scope_id, action, window_start, window_seconds, request_count, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
           ON CONFLICT(id) DO NOTHING`,
        )
        .bind(id, scope.scope, scope.scope_id, action, window_start, windowSeconds)
        .run();
      await env.cybermeters_db
        .prepare(
          `UPDATE api_rate_limits
           SET request_count = request_count + 1,
               updated_at = datetime('now')
           WHERE id = ?`,
        )
        .bind(id)
        .run();
    }
    return null;
  } catch (error) {
    console.error(`[rate-limit] ${action} check failed: ${error?.message ?? error}`);
    if (options.failClosed) {
      return {
        status: 503,
        body: {
          error: "Rate limiting is temporarily unavailable. Please try again shortly.",
          code: "rate_limit_unavailable",
        },
      };
    }
    return null; // fail-open for authenticated customer flows to avoid lockout
  }
}
