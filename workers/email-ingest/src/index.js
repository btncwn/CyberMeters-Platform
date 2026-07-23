// ── cybermeters-email — inbound RUA ingestion worker ─────────────────────────
// Sprint 10 Stage B: the Email Routing target, isolated from the api worker.
// The email handler and its whole service layer are IMPORTED from the shared
// source under ../scan-api/src — one implementation, two deployments — so the
// two workers cannot drift. HTTP surface is health-only by design (§3 of
// docs/SPRINT-10-DESIGN.md: this worker must never serve app routes).
import { handleInboundEmail } from "../../scan-api/src/email/inbound.js";
import {
  consumeApiRateLimit,
  rateLimitScopeId,
} from "../../scan-api/src/lib/rate-limit.js";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (pathname === "/health") {
      return json({
        status: "ok",
        service: "cybermeters-email",
        version: env.APP_VERSION || "dev",
        deployment_id: env.CF_VERSION_METADATA?.id || null,
      });
    }

    if (pathname === "/ready") {
      let d1 = false;
      try {
        await env.cybermeters_db.prepare("SELECT 1").first();
        d1 = true;
      } catch { /* degraded */ }
      return json(
        { status: d1 ? "ready" : "degraded", checks: { d1 }, version: env.APP_VERSION || "dev" },
        d1 ? 200 : 503,
      );
    }

    return json({ error: "Not found" }, 404);
  },

  // Mandatory shared limiter injection. The handler rejects missing wiring
  // before reading a message, so this boundary can never silently fail open.
  email: (message, env, ctx) =>
    handleInboundEmail(message, env, ctx, { consumeApiRateLimit, rateLimitScopeId }),
};
