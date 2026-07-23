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

export async function consumeApiRateLimit(
  env,
  scopes,
  action,
  limit,
  windowSeconds = 3600,
  options = {},
) {
  // D1-backed rate limiting is adequate for early launch and intentionally
  // fails open if the table or query is unavailable. The read/update sequence
  // is not fully atomic under high concurrency; Gate 3B owns atomicity and is
  // deliberately not part of this wiring change.
  if (!Number.isFinite(limit) || limit >= 999999) return null;
  const activeScopes = scopes.filter((scope) => scope.scope && scope.scope_id);
  if (activeScopes.length === 0) return null;

  const { window_start, reset_at } = getRateLimitWindow(windowSeconds);

  try {
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
