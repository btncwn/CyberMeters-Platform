// ── Auth routes ──
// Signup, login (brute-force protected, email-verification + MFA gated),
// session me/logout, email verification + resend, Microsoft SSO
// (login/callback/exchange with CSRF state + OTC), forgot/reset password and
// the full MFA lifecycle (status/setup/verify-setup/challenge/recovery-code/
// disable). Extracted near-verbatim from index.js (router split, Phase 2
// PR #20 — the final route group). Receives the per-request routeCtx from
// index.js; returns a Response when a route matches, or null so the main
// router continues.
import { getEffectivePlan } from "../engines/entitlements.js";
import { decryptTotpSecret, encryptTotpSecret, generateEmailVerificationToken, generateMfaChallengeToken, generatePasswordResetToken, generateRecoveryCodes, generateSessionToken, getEmailVerificationTokenStatus, hashToken, isEmailVerificationResendCoolingDown, verifyRecoveryCode } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import { escapeEmailHtml, getEmailFrontendOrigin, sendCustomerEmail, sendLifecycleEmail } from "../lib/lifecycle-email.js";
import { validateMicrosoftIdToken } from "../lib/microsoft-jwt.js";
import { hashPassword, verifyPassword } from "../lib/password.js";
import { generateTotpSecret, verifyTotp } from "../lib/totp.js";
import { createId, isValidEmail } from "../lib/util.js";

export async function authRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, consumeApiRateLimit, rateLimitScopeId } = rctx;

    // ── POST /api/auth/signup ────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/signup") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email    = (body.email    || "").trim().toLowerCase();
      const password = (body.password || "").trim();
      const name     = (body.name     || "").trim();

      if (!isValidEmail(email))        return json({ error: "A valid email address is required" }, 400);
      if (!password)                   return json({ error: "Password cannot be blank" }, 400);
      if (password.length < 12)        return json({ error: "Password must be at least 12 characters" }, 400);
      if (password.length > 128)       return json({ error: "Password is too long" }, 400);

      const signupClientIp = request.headers.get("CF-Connecting-IP") ||
                             request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                             "unknown";
      const signupRateLimit = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("signup", signupClientIp) }],
        "signup",
        5,
        3600,
        // Abuse-critical: if rate limiting is unavailable, refuse rather than
        // allow unmetered account creation.
        { failClosed: true },
      );
      if (signupRateLimit) {
        return json({ error: "Too many signup attempts. Please wait before trying again.", code: "rate_limit_exceeded" }, signupRateLimit.status);
      }

      try {
        // Check for duplicate email. Anti-enumeration: an existing account must
        // NOT be revealed via a distinct 409 — that lets an attacker probe which
        // emails are registered. Instead respond exactly as a fresh signup would
        // (same generic 201 below), create nothing, and send a security notice to
        // the genuine owner so a real person still learns of the attempt.
        const existing = await env.cybermeters_db
          .prepare("SELECT id FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (existing) {
          await createAuditEvent(env, {
            user_id:     existing.id,
            event_type:  "USER_SIGNUP_EXISTING_EMAIL",
            entity_type: "user",
            entity_id:   existing.id,
            description: "Signup attempted for an email that already has an account",
            metadata:    { email },
          }).catch(() => {});
          const notifyBase = env.FRONTEND_URL || "https://app.cybermeters.com";
          await sendCustomerEmail(
            "A sign-up attempt used your CyberMeters email",
            `Hi,\n\nSomeone just tried to create a CyberMeters account with your email address, but you already have an account — so nothing was created or changed.\n\nIf this was you, simply sign in:\n${notifyBase}/login\n\nForgotten your password?\n${notifyBase}/forgot-password\n\nIf this wasn't you, no action is needed.\n\nThe CyberMeters Team`,
            `<!DOCTYPE html><html><body style="font-family:sans-serif;color:#1f2937;max-width:560px;margin:40px auto;padding:0 20px">
              <h2 style="color:#00876A">A sign-up attempt used your email</h2>
              <p>Someone just tried to create a CyberMeters account with your email address, but you already have an account — so nothing was created or changed.</p>
              <p style="margin:28px 0">
                <a href="${notifyBase}/login" style="background:#00876A;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Sign in</a>
              </p>
              <p style="color:#6b7280;font-size:14px">Forgotten your password? <a href="${notifyBase}/forgot-password" style="color:#00876A">Reset it here</a>. If this wasn't you, no action is needed.</p>
            </body></html>`,
            env,
            "HELLO_EMAIL_FROM",
            [email]
          ).catch(() => {});
          return json({ success: true, verification_required: true, email }, 201);
        }

        const userId      = createId("usr");
        const passwordHash = await hashPassword(password);

        // Generate a 24-hour email verification token
        const { raw: verificationToken, hash: verificationTokenHash } = await generateEmailVerificationToken();
        const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO users
               (id, email, name, plan, password_hash, status,
                email_verified, verification_token, verification_token_expires_at,
                created_at)
             VALUES (?, ?, ?, 'free', ?, 'active', 0, ?, ?, datetime('now'))`
          )
          .bind(userId, email, name || null, passwordHash, verificationTokenHash, verificationTokenExpires)
          .run();

        // Audit: account created
        await createAuditEvent(env, {
          user_id:     userId,
          event_type:  "USER_REGISTERED",
          entity_type: "user",
          entity_id:   userId,
          description: `New account created for ${email}`,
          metadata:    { email, name: name || null },
        }).catch(() => {});

        // Send verification email (fire-and-forget — signup succeeds even if email fails)
        const frontendUrl    = env.FRONTEND_URL || "https://app.cybermeters.com";
        const workerBase     = url.origin;
        const verifyLink     = `${workerBase}/api/auth/verify-email?token=${verificationToken}`;
        const displayName    = name || email.split("@")[0];
        const displayNameHtml = escapeEmailHtml(displayName);
        const verificationDelivery = await sendCustomerEmail(
          "Verify your CyberMeters email address",
          `Hi ${displayName},\n\nPlease verify your email address by clicking the link below:\n\n${verifyLink}\n\nThis link expires in 24 hours.\n\nIf you did not create a CyberMeters account, you can safely ignore this email.\n\nThe CyberMeters Team`,
          `<!DOCTYPE html><html><body style="font-family:sans-serif;color:#1f2937;max-width:560px;margin:40px auto;padding:0 20px">
            <h2 style="color:#1d4ed8">Verify your email address</h2>
            <p>Hi ${displayNameHtml},</p>
            <p>Thanks for signing up for CyberMeters. Please verify your email address to activate your account.</p>
            <p style="margin:32px 0">
              <a href="${verifyLink}" style="background:#1d4ed8;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Verify email address</a>
            </p>
            <p style="color:#6b7280;font-size:14px">This link expires in 24 hours. If you did not create a CyberMeters account, you can safely ignore this email.</p>
          </body></html>`,
          env,
          "HELLO_EMAIL_FROM",
          [email]
        );

        await createAuditEvent(env, {
          user_id:     userId,
          event_type:  verificationDelivery.sent ? "USER_EMAIL_VERIFICATION_SENT" : "USER_EMAIL_VERIFICATION_DELIVERY_FAILED",
          entity_type: "user",
          entity_id:   userId,
          description: verificationDelivery.sent
            ? `Verification email sent to ${email}`
            : `Verification email delivery failed for ${email}`,
          metadata:    {
            email,
            delivery_status: verificationDelivery.sent ? "accepted" : "failed",
            delivery_reason: verificationDelivery.reason || null,
            provider_id: verificationDelivery.provider_id || null,
          },
        }).catch(() => {});

        return json({ success: true, verification_required: true, email }, 201);
      } catch (e) {
        return serverError("auth/signup", e, "Signup failed. Please try again.");
      }
    }

    // ── POST /api/auth/login ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email    = (body.email    || "").trim().toLowerCase();
      const password = (body.password || "").trim();

      if (!email || !password) return json({ error: "Email and password are required" }, 400);

      // ── Login brute-force protection ──────────────────────────────────────
      // Rate-limit by hashed client IP: 10 attempts per 15-minute window.
      // Fires before any credential check to prevent timing-assisted enumeration
      // at high attempt counts. Generic 429 message does not reveal account state.
      const _loginClientIp = request.headers.get("CF-Connecting-IP") ||
                             request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                             "unknown";
      const _loginIpHash = await (async () => {
        try {
          const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(_loginClientIp));
          return Array.from(new Uint8Array(buf)).slice(0, 8).map(b => b.toString(16).padStart(2, "0")).join("");
        } catch { return _loginClientIp.replace(/[^a-z0-9]/gi, "_").slice(0, 32); }
      })();
      const _loginRlResult = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: `login_${_loginIpHash}` }],
        "login",
        10,
        900, // 15 minutes
        // Abuse-critical: never allow unmetered credential guessing.
        { failClosed: true },
      );
      if (_loginRlResult) {
        return json({ error: "Too many login attempts. Please wait before trying again.", code: "rate_limit_exceeded" }, 429);
      }
      // ── Per-account brute-force ceiling ───────────────────────────────────
      // The per-IP limit above cannot stop a DISTRIBUTED attack (many IPs, one
      // account). Cap attempts per target account regardless of source IP.
      // Keyed on the (normalised) email so it applies before any credential
      // check and reveals no account state. Fail-CLOSED like the IP limit.
      // Threshold is generous (20 / 15 min) so a real user never trips it; the
      // short window bounds the account-lockout DoS tradeoff inherent to any
      // per-account throttle.
      const _loginAcctRl = await consumeApiRateLimit(
        env,
        [{ scope: "user", scope_id: await rateLimitScopeId("login_acct", email) }],
        "login_account",
        20,
        900, // 15 minutes
        { failClosed: true },
      );
      if (_loginAcctRl) {
        return json({ error: "Too many login attempts. Please wait before trying again.", code: "rate_limit_exceeded" }, 429);
      }
      // ─────────────────────────────────────────────────────────────────────

      try {
        const user = await env.cybermeters_db
          .prepare("SELECT id, email, name, plan, password_hash, status, mfa_enabled, email_verified, auth_provider FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();

        // Always run verifyPassword even if user not found to prevent user-enumeration via timing
        const storedHash  = user?.password_hash ?? "pbkdf2:sha256:100000:0000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000";
        const passwordOk  = await verifyPassword(password, storedHash);

        if (!user || !passwordOk || !user.password_hash) {
          // Audit: failed login — provides brute-force visibility
          if (user?.id) {
            await createAuditEvent(env, {
              user_id:     user.id,
              event_type:  "login_failed",
              entity_type: "user",
              entity_id:   user.id,
              description: `Failed login attempt for ${email}`,
              metadata:    { email, ip_address: request.headers.get("CF-Connecting-IP") || null, user_agent: request.headers.get("User-Agent") || null },
            }).catch(() => {});
          }
          return json({ error: "Invalid email or password" }, 401);
        }
        if (user.status === "suspended") {
          return json({ error: "Account suspended. Contact support." }, 403);
        }

        // ── Email verification gate ───────────────────────────────────────────
        // Local-auth accounts must have a verified email before being granted a session.
        // Microsoft OAuth accounts are auto-verified and skip this check.
        const isLocalAccount = !user.auth_provider || user.auth_provider === "local";
        if (isLocalAccount && !user.email_verified) {
          return json({ error: "email_verification_required", email: user.email }, 403);
        }

        // ── MFA gate ─────────────────────────────────────────────────────────
        // If MFA is enabled, do NOT create a session yet.
        // Issue a short-lived challenge token; client must verify TOTP at
        // POST /api/auth/mfa/challenge to receive the real session token.
        if (user.mfa_enabled) {
          const { raw: challengeRaw, hash: challengeHash } = await generateMfaChallengeToken();
          const challengeId = createId("mfach");
          const challengeExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min
          await env.cybermeters_db
            .prepare(
              `INSERT INTO mfa_challenges (id, user_id, challenge_hash, expires_at)
               VALUES (?, ?, ?, ?)`
            )
            .bind(challengeId, user.id, challengeHash, challengeExpiry)
            .run();
          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "mfa_challenge_issued",
            entity_type: "user",
            entity_id:   user.id,
            description: `MFA challenge issued for ${user.email}`,
            metadata:    { challenge_id: challengeId, ip_address: request.headers.get("CF-Connecting-IP") || null, user_agent: request.headers.get("User-Agent") || null },
          }).catch(() => {});
          return json({ mfa_required: true, challenge_token: challengeRaw });
        }

        // Generate session token — raw sent to client, hash stored in D1
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId  = createId("sess");
        const expiresAt  = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

        const _loginIp = request.headers.get("CF-Connecting-IP") || null;
        const _loginUa = request.headers.get("User-Agent") || null;
        await env.cybermeters_db
          .prepare(
            `INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?, ?)`
          )
          .bind(sessionId, user.id, tokenHash, expiresAt, _loginIp, _loginUa)
          .run();

        // Update last_login_at
        await env.cybermeters_db
          .prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?")
          .bind(user.id)
          .run();

        // Audit: login
        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "login",
          entity_type: "user",
          entity_id:   user.id,
          description: `${user.email} signed in`,
          metadata:    { ip_address: _loginIp, user_agent: _loginUa },
        });

        const plan = await getEffectivePlan(user.id, env);
        return json({
          token,
          user: {
            id:    user.id,
            email: user.email,
            name:  user.name,
            plan,
          },
        });
      } catch (e) {
        return serverError("auth/login", e, "Login failed. Please try again.");
      }
    }

    // ── GET /api/auth/me ─────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const plan = await getEffectivePlan(user.id, env);
      return json({
        id:    user.id,
        email: user.email,
        name:  user.name,
        plan,
      });
    }

    // ── POST /api/auth/logout ────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/logout") {
      const authHeader = request.headers.get("Authorization") || "";
      if (authHeader.startsWith("Bearer ")) {
        const rawToken = authHeader.slice(7).trim();
        if (rawToken) {
          try {
            const tokenHash = await hashToken(rawToken);
            // Resolve user before deleting session so we can audit
            const sessionRow = await env.cybermeters_db
              .prepare("SELECT user_id FROM user_sessions WHERE token_hash = ?")
              .bind(tokenHash)
              .first();
            await env.cybermeters_db
              .prepare("DELETE FROM user_sessions WHERE token_hash = ?")
              .bind(tokenHash)
              .run();
            if (sessionRow?.user_id) {
              await createAuditEvent(env, {
                user_id:     sessionRow.user_id,
                event_type:  "logout",
                entity_type: "user",
                entity_id:   sessionRow.user_id,
                description: "User signed out",
              });
            }
          } catch { /* silent — token may already be expired */ }
        }
      }
      return json({ success: true });
    }

    // ── GET /api/auth/verify-email ───────────────────────────────────────
    // Validates the one-time email verification token sent during signup.
    // On success: marks the account as verified, clears the token, redirects to
    //   ${FRONTEND_URL}/verify-email?success=1
    // On failure: redirects to
    //   ${FRONTEND_URL}/verify-email?error=<reason>
    if (request.method === "GET" && url.pathname === "/api/auth/verify-email") {
      const frontendUrl = env.FRONTEND_URL || "https://app.cybermeters.com";
      const token = url.searchParams.get("token") || "";
      const dest = new URL("/verify-email", frontendUrl);

      if (!token) {
        dest.searchParams.set("error", "Missing verification token");
        return Response.redirect(dest.toString(), 302);
      }

      try {
        const tokenHash = await hashToken(token);
        const userRow = await env.cybermeters_db
          .prepare(
            `SELECT id, email, email_verified, verification_token_expires_at
             FROM users
             WHERE verification_token IN (?, ?)
             LIMIT 1`
          )
          .bind(tokenHash, token)
          .first();

        const tokenStatus = getEmailVerificationTokenStatus(userRow);
        if (tokenStatus === "invalid") {
          dest.searchParams.set("error", "Invalid or already used verification link");
          return Response.redirect(dest.toString(), 302);
        }

        if (tokenStatus === "already_verified") {
          // Already verified — just redirect to success
          dest.searchParams.set("success", "1");
          return Response.redirect(dest.toString(), 302);
        }

        if (tokenStatus === "expired") {
          await createAuditEvent(env, {
            user_id:     userRow.id,
            event_type:  "USER_EMAIL_VERIFICATION_EXPIRED",
            entity_type: "user",
            entity_id:   userRow.id,
            description: `Expired email verification attempted for ${userRow.email}`,
            metadata:    { email: userRow.email },
          }).catch(() => {});
          dest.searchParams.set("error", "Verification link has expired. Please request a new one.");
          return Response.redirect(dest.toString(), 302);
        }

        const verificationUpdate = await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET email_verified = 1,
                 email_verified_at = datetime('now'),
                 verification_token = NULL,
                 verification_token_expires_at = NULL
             WHERE id = ?
               AND email_verified = 0
               AND verification_token IN (?, ?)
               AND verification_token_expires_at IS NOT NULL
               AND unixepoch(verification_token_expires_at) > unixepoch('now')`
          )
          .bind(userRow.id, tokenHash, token)
          .run();

        if ((verificationUpdate.meta?.changes ?? 0) !== 1) {
          dest.searchParams.set("error", "Invalid or already used verification link");
          return Response.redirect(dest.toString(), 302);
        }

        await createAuditEvent(env, {
          user_id:     userRow.id,
          event_type:  "USER_EMAIL_VERIFIED",
          entity_type: "user",
          entity_id:   userRow.id,
          description: `Email verified for ${userRow.email}`,
          metadata:    { email: userRow.email },
        }).catch(() => {});

        // Lifecycle: welcome / getting-started (once per user; verified address).
        await sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: userRow.id, to: userRow.email }).catch(() => {});

        dest.searchParams.set("success", "1");
        return Response.redirect(dest.toString(), 302);
      } catch (e) {
        dest.searchParams.set("error", "Verification failed. Please try again.");
        return Response.redirect(dest.toString(), 302);
      }
    }

    // ── POST /api/auth/resend-verification ───────────────────────────────
    // Generates a fresh verification token and re-sends the email.
    // Always returns success to avoid leaking whether an address is registered.
    if (request.method === "POST" && url.pathname === "/api/auth/resend-verification") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      if (!isValidEmail(email)) return json({ success: true }); // silent — don't leak

      const resendClientIp = request.headers.get("CF-Connecting-IP") ||
                             request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                             "unknown";
      const resendRateLimit = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("resend_verification", resendClientIp) }],
        "resend_verification",
        5,
        900,
        { failClosed: true },
      );
      if (resendRateLimit) {
        return json({
          error: "Too many verification email requests. Please wait before trying again.",
          code: resendRateLimit.body.code,
        }, resendRateLimit.status);
      }

      try {
        const userRow = await env.cybermeters_db
          .prepare(
            `SELECT id, name, email_verified, auth_provider, verification_token_expires_at
             FROM users WHERE email = ? LIMIT 1`
          )
          .bind(email)
          .first();

        // Silently succeed for unknown emails or already-verified accounts
        if (!userRow || userRow.email_verified) return json({ success: true });
        // Microsoft accounts are always verified — should never reach here, but guard anyway
        if (userRow.auth_provider && userRow.auth_provider !== "local") return json({ success: true });

        // 60-second resend cooldown: tokens are always issued with a 24-hour TTL.
        // If the existing expiry is still more than (24h - 60s) in the future, the
        // last token was issued less than 60 seconds ago — return success silently.
        if (isEmailVerificationResendCoolingDown(userRow.verification_token_expires_at)) {
          return json({ success: true }); // account cooldown — do not send
        }

        const { raw: newToken, hash: newTokenHash } = await generateEmailVerificationToken();
        const newExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        const cooldownCutoff = new Date(Date.now() + (24 * 60 * 60 * 1000) - (60 * 1000)).toISOString();

        const tokenUpdate = await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET verification_token = ?,
                 verification_token_expires_at = ?
             WHERE id = ?
               AND email_verified = 0
               AND (verification_token_expires_at IS NULL
                    OR unixepoch(verification_token_expires_at) <= unixepoch(?))`
          )
          .bind(newTokenHash, newExpires, userRow.id, cooldownCutoff)
          .run();

        if ((tokenUpdate.meta?.changes ?? 0) !== 1) return json({ success: true });

        const workerBase  = url.origin;
        const verifyLink  = `${workerBase}/api/auth/verify-email?token=${newToken}`;
        const displayName = userRow.name || email.split("@")[0];
        const displayNameHtml = escapeEmailHtml(displayName);
        const verificationDelivery = await sendCustomerEmail(
          "Verify your CyberMeters email address",
          `Hi ${displayName},\n\nPlease verify your email address by clicking the link below:\n\n${verifyLink}\n\nThis link expires in 24 hours.\n\nIf you did not request this email, you can safely ignore it.\n\nThe CyberMeters Team`,
          `<!DOCTYPE html><html><body style="font-family:sans-serif;color:#1f2937;max-width:560px;margin:40px auto;padding:0 20px">
            <h2 style="color:#1d4ed8">Verify your email address</h2>
            <p>Hi ${displayNameHtml},</p>
            <p>Click below to verify your CyberMeters email address and activate your account.</p>
            <p style="margin:32px 0">
              <a href="${verifyLink}" style="background:#1d4ed8;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Verify email address</a>
            </p>
            <p style="color:#6b7280;font-size:14px">This link expires in 24 hours. If you did not request this, you can safely ignore this email.</p>
          </body></html>`,
          env,
          "HELLO_EMAIL_FROM",
          [email]
        );

        await createAuditEvent(env, {
          user_id:     userRow.id,
          event_type:  verificationDelivery.sent ? "USER_EMAIL_VERIFICATION_RESENT" : "USER_EMAIL_VERIFICATION_DELIVERY_FAILED",
          entity_type: "user",
          entity_id:   userRow.id,
          description: verificationDelivery.sent
            ? `Verification email resent to ${email}`
            : `Verification email delivery failed for ${email}`,
          metadata:    {
            email,
            delivery_status: verificationDelivery.sent ? "accepted" : "failed",
            delivery_reason: verificationDelivery.reason || null,
            provider_id: verificationDelivery.provider_id || null,
          },
        }).catch(() => {});

        return json({ success: true });
      } catch (e) {
        // Swallow errors — never reveal internals
        return json({ success: true });
      }
    }

    // ── GET /api/auth/microsoft/login ────────────────────────────────────
    // Initiates the Microsoft Entra OAuth authorization code flow.
    // Generates a CSRF state token, stores it in oauth_states with a 10-minute
    // TTL, and redirects the browser to Microsoft's authorization endpoint.
    //
    // Env vars required: AZURE_CLIENT_ID, AZURE_TENANT_ID
    // Optional: MICROSOFT_REDIRECT_URI (defaults to same-origin /callback)
    if (request.method === "GET" && url.pathname === "/api/auth/microsoft/login") {
      const clientId  = env.AZURE_CLIENT_ID;
      const tenantId  = env.AZURE_TENANT_ID;

      if (!clientId || !tenantId) {
        return json({ error: "Microsoft login is not configured on this instance" }, 503);
      }

      // Generate a cryptographically random state for CSRF protection
      const stateRaw = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0")).join("");
      const nonceRaw = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      // redirect_uri must match exactly what is registered in Azure App Registration
      const redirectUri = env.MICROSOFT_REDIRECT_URI
        || `${url.origin}/api/auth/microsoft/callback`;

      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min

      await env.cybermeters_db
        .prepare(
          `INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
           VALUES (?, 'microsoft', ?, ?)`
        )
        .bind(stateRaw, JSON.stringify({ redirect_uri: redirectUri, nonce: nonceRaw }), expiresAt)
        .run();

      // Purge expired states while we're here (best-effort, non-fatal)
      env.cybermeters_db
        .prepare("DELETE FROM oauth_states WHERE expires_at < datetime('now')")
        .run()
        .catch(() => {});

      const authorizeUrl = new URL(
        `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`
      );
      authorizeUrl.searchParams.set("client_id",     clientId);
      authorizeUrl.searchParams.set("response_type", "code");
      authorizeUrl.searchParams.set("redirect_uri",  redirectUri);
      authorizeUrl.searchParams.set("response_mode", "query");
      authorizeUrl.searchParams.set("scope",         "openid profile email");
      authorizeUrl.searchParams.set("state",         stateRaw);
      authorizeUrl.searchParams.set("nonce",         nonceRaw);

      return Response.redirect(authorizeUrl.toString(), 302);
    }

    // ── GET /api/auth/microsoft/callback ─────────────────────────────────
    // Handles the OAuth callback from Microsoft.
    //   1. Validates the CSRF state from oauth_states (single-use, TTL-checked)
    //   2. Exchanges the authorization code for tokens at Microsoft's token endpoint
    //   3. Validates the id_token JWT (signature + audience + expiry + oid)
    //   4. Finds an existing user by microsoft_oid, falls back to email match,
    //      or creates a new account
    //   5. Creates a 30-day session (same pattern as POST /api/auth/login)
    //   6. Fires USER_LOGIN_MICROSOFT audit event
    //   7. Redirects to the frontend callback page with token + user params
    //
    // Env vars required: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
    // Optional: FRONTEND_URL (defaults to same origin)
    if (request.method === "GET" && url.pathname === "/api/auth/microsoft/callback") {
      const clientId     = env.AZURE_CLIENT_ID;
      const clientSecret = env.AZURE_CLIENT_SECRET;
      const tenantId     = env.AZURE_TENANT_ID;

      if (!clientId || !clientSecret || !tenantId) {
        return json({ error: "Microsoft login is not configured on this instance" }, 503);
      }

      const code  = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const msErr = url.searchParams.get("error");

      // Microsoft returned an error (e.g. user denied consent)
      if (msErr) {
        const frontendUrl = env.FRONTEND_URL || url.origin;
        const dest = new URL("/login", frontendUrl);
        dest.searchParams.set("ms_error", "Microsoft sign-in was cancelled or failed. Please try again.");
        console.warn("[microsoft/callback] provider returned error", { code: msErr });
        return Response.redirect(dest.toString(), 302);
      }

      if (!code || !state) {
        return json({ error: "Missing code or state parameter" }, 400);
      }

      // ── 1. Validate CSRF state ─────────────────────────────────────────
      const stateRow = await env.cybermeters_db
        .prepare(
          `SELECT state, redirect_uri FROM oauth_states
           WHERE state = ? AND provider = 'microsoft'
             AND expires_at > datetime('now')
           LIMIT 1`
        )
        .bind(state)
        .first();

      if (!stateRow) {
        return json({ error: "Invalid or expired OAuth state. Please try signing in again." }, 400);
      }

      // Delete state immediately — single-use CSRF token
      await env.cybermeters_db
        .prepare("DELETE FROM oauth_states WHERE state = ?")
        .bind(state)
        .run();

      let statePayload = null;
      try { statePayload = JSON.parse(stateRow.redirect_uri); } catch { /* legacy state row */ }
      const redirectUri = statePayload?.redirect_uri
        || stateRow.redirect_uri
        || (env.MICROSOFT_REDIRECT_URI || `${url.origin}/api/auth/microsoft/callback`);
      const expectedNonce = statePayload?.nonce || null;

      // ── 2. Exchange authorization code for tokens ──────────────────────
      const tokenRes = await fetch(
        `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id:     clientId,
            client_secret: clientSecret,
            code,
            redirect_uri:  redirectUri,
            grant_type:    "authorization_code",
            scope:         "openid profile email",
          }).toString(),
        }
      );

      if (!tokenRes.ok) {
        console.error("[microsoft/callback] token exchange failed", { status: tokenRes.status });
        return json({ error: "Failed to exchange authorization code" }, 502);
      }

      const tokenData = await tokenRes.json();
      const idToken   = tokenData.id_token;

      if (!idToken) {
        return json({ error: "Microsoft did not return an id_token" }, 502);
      }

      // ── 3. Validate id_token JWT ───────────────────────────────────────
      let claims;
      try {
        claims = await validateMicrosoftIdToken(idToken, clientId, tenantId, expectedNonce);
      } catch (e) {
        console.error("[microsoft/callback] id_token validation failed:", e.message);
        return json({ error: "Microsoft sign-in could not be validated. Please try again." }, 401);
      }

      const msOid   = claims.oid;
      const msEmail = (claims.email || claims.preferred_username || "").toLowerCase().trim();
      const msName  = claims.name || msEmail.split("@")[0] || "Microsoft User";
      const msTid   = claims.tid;

      if (!msEmail) {
        return json({ error: "Microsoft account did not provide an email address. Ensure the email scope is granted." }, 400);
      }

      // ── 4. Find or create user ─────────────────────────────────────────
      // Priority: (a) match by microsoft_oid, (b) match by email, (c) create new
      let user = await env.cybermeters_db
        .prepare("SELECT id, email, name, plan, status FROM users WHERE microsoft_oid = ? LIMIT 1")
        .bind(msOid)
        .first();

      if (!user) {
        // Try to link to an existing email/password account
        user = await env.cybermeters_db
          .prepare("SELECT id, email, name, plan, status FROM users WHERE email = ? LIMIT 1")
          .bind(msEmail)
          .first();

        if (user) {
          // Link existing account to this Microsoft identity.
          // If the local account is unverified / pending, Microsoft OAuth implicitly
          // verifies the email (same address) and activates the account — the user
          // has just proven control of that inbox via their Microsoft identity provider.
          await env.cybermeters_db
            .prepare(
              `UPDATE users
               SET microsoft_oid    = ?,
                   tenant_id        = ?,
                   auth_provider    = 'microsoft',
                   last_login_at    = datetime('now'),
                   email_verified     = CASE WHEN email_verified = 0 THEN 1 ELSE email_verified END,
                   email_verified_at  = CASE WHEN email_verified = 0 THEN datetime('now') ELSE email_verified_at END,
                   status             = CASE WHEN status = 'pending_verification' THEN 'active' ELSE status END
               WHERE id = ?`
            )
            .bind(msOid, msTid, user.id)
            .run();
          // Refresh user object so status/email_verified reflect post-update state
          const refreshed = await env.cybermeters_db
            .prepare("SELECT id, email, name, plan, status FROM users WHERE id = ? LIMIT 1")
            .bind(user.id)
            .first()
            .catch(() => null);
          if (refreshed) user = refreshed;
        }
      }

      if (!user) {
        // No existing account — create one
        const newUserId    = createId("usr");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO users
               (id, email, name, plan, password_hash, status, auth_provider, microsoft_oid, tenant_id,
                email_verified, email_verified_at, created_at)
             VALUES (?, ?, ?, 'free', NULL, 'active', 'microsoft', ?, ?, 1, datetime('now'), datetime('now'))`
          )
          .bind(newUserId, msEmail, msName, msOid, msTid)
          .run();

        user = { id: newUserId, email: msEmail, name: msName, plan: "free", status: "active" };

        await createAuditEvent(env, {
          user_id:     newUserId,
          event_type:  "signup",
          entity_type: "user",
          entity_id:   newUserId,
          description: `New account created via Microsoft login for ${msEmail}`,
          metadata:    { email: msEmail, name: msName, auth_provider: "microsoft" },
        }).catch(() => {});
      } else {
        // Existing account — update last_login_at and auth fields
        await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET microsoft_oid = ?, tenant_id = ?, auth_provider = 'microsoft',
                 last_login_at = datetime('now')
             WHERE id = ?`
          )
          .bind(msOid, msTid, user.id)
          .run();
      }

      if (user.status === "suspended") {
        const frontendUrl = env.FRONTEND_URL || url.origin;
        const dest = new URL("/login", frontendUrl);
        dest.searchParams.set("ms_error", "Account suspended. Contact support.");
        return Response.redirect(dest.toString(), 302);
      }

      // ── 5. Create session ──────────────────────────────────────────────
      const { raw: token, hash: tokenHash } = await generateSessionToken();
      const sessionId = createId("sess");
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
      const loginIp   = request.headers.get("CF-Connecting-IP") || null;
      const loginUa   = request.headers.get("User-Agent") || null;

      await env.cybermeters_db
        .prepare(
          `INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(sessionId, user.id, tokenHash, expiresAt, loginIp, loginUa)
        .run();

      // ── 6. Audit ──────────────────────────────────────────────────────
      const plan = await getEffectivePlan(user.id, env);

      await createAuditEvent(env, {
        user_id:     user.id,
        event_type:  "USER_LOGIN_MICROSOFT",
        entity_type: "user",
        entity_id:   user.id,
        description: `${user.email} signed in via Microsoft`,
        metadata:    {
          ip_address:    loginIp,
          user_agent:    loginUa,
          microsoft_oid: msOid,
          tenant_id:     msTid,
        },
      }).catch(() => {});

      // ── 7. Issue a short-lived one-time code (OTC) and redirect ──────────
      // The bearer token and user metadata MUST NOT appear in URL parameters —
      // they would be captured by CDN access logs, browser history, and
      // Referrer headers. Instead we generate a 30-second single-use OTC,
      // store it in oauth_states (reusing the existing table with
      // provider = 'ms_exchange'), and redirect with only the OTC in the URL.
      // The frontend immediately POSTs the OTC to /api/auth/exchange, which
      // validates it, deletes it, and returns the session data in a JSON body.
      const otcRaw = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      const otcPayload = JSON.stringify({
        token,
        userId: user.id,
        email:  user.email,
        name:   user.name  || "",
        plan,
      });

      // Store expires_at using SQLite's own datetime() to guarantee format
      // consistency with the datetime('now') comparison in the lookup query.
      // ISO format (JavaScript's toISOString()) cannot be compared correctly
      // against datetime('now') — the 'T' separator makes ISO strings always
      // sort as greater than SQLite datetime strings on the same day.
      // TTL is 5 minutes: long enough for slow edge-cached Pages loads, short
      // enough to limit the replay window if an OTC is somehow observed.
      await env.cybermeters_db
        .prepare(
          `INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
           VALUES (?, 'ms_exchange', ?, datetime('now', '+5 minutes'))`
        )
        .bind(otcRaw, otcPayload)
        .run();

      const frontendUrl = env.FRONTEND_URL || url.origin;
      const dest = new URL("/auth/microsoft/callback", frontendUrl);
      dest.searchParams.set("otc", otcRaw);

      return Response.redirect(dest.toString(), 302);
    }

    // ── POST /api/auth/exchange ──────────────────────────────────────────
    // Exchanges a short-lived one-time code (OTC) issued by the Microsoft
    // OAuth callback for the session bearer token and user metadata.
    //
    // The OTC is stored server-side in oauth_states with provider='ms_exchange'
    // and a 30-second TTL. It is single-use: deleted on first successful exchange.
    // The bearer token is returned in the JSON body — it never appears in any URL.
    //
    // Request:  POST /api/auth/exchange
    //           Content-Type: application/json
    //           Body: { "code": "<otc>" }
    //
    // Response: { "token": "...", "id": "...", "email": "...", "name": "...", "plan": "..." }
    // Errors:   400 { "error": "Missing code" }
    //           401 { "error": "Invalid or expired code. Please sign in again." }
    //           500 { "error": "Exchange failed" }
    if (request.method === "POST" && url.pathname === "/api/auth/exchange") {
      let body;
      try { body = await request.json(); } catch {
        console.error("[auth/exchange] invalid JSON body");
        return json({ error: "Invalid JSON body" }, 400);
      }

      const otc = (body.code || "").trim();
      if (!otc) {
        console.error("[auth/exchange] missing code in request body");
        return json({ error: "Missing code" }, 400);
      }

      // Look up and immediately delete the OTC — single-use enforcement.
      const otcRow = await env.cybermeters_db
        .prepare(
          `SELECT redirect_uri AS payload FROM oauth_states
           WHERE state = ? AND provider = 'ms_exchange'
             AND expires_at > datetime('now')
           LIMIT 1`
        )
        .bind(otc)
        .first();

      if (!otcRow) {
        // Log the OTC prefix (first 8 chars) for correlation — never the full value
        console.error(`[auth/exchange] OTC not found or expired. prefix=${otc.slice(0,8)}`);
        return json({ error: "Invalid or expired code. Please sign in again." }, 401);
      }

      // Delete before responding — prevents replay even under concurrent requests.
      await env.cybermeters_db
        .prepare("DELETE FROM oauth_states WHERE state = ? AND provider = 'ms_exchange'")
        .bind(otc)
        .run();

      let payload;
      try {
        payload = JSON.parse(otcRow.payload);
      } catch (e) {
        console.error("[auth/exchange] payload JSON.parse failed:", e.message);
        return json({ error: "Exchange failed" }, 500);
      }

      if (!payload.token || !payload.userId || !payload.email) {
        console.error("[auth/exchange] payload missing required fields:", Object.keys(payload));
        return json({ error: "Exchange failed" }, 500);
      }

      console.log(`[auth/exchange] success for user ${payload.userId.slice(0,8)}...`);

      return json({
        token: payload.token,
        id:    payload.userId,
        email: payload.email,
        name:  payload.name,
        plan:  payload.plan,
      });
    }

    // ── POST /api/auth/forgot-password ──────────────────────────────────
    // Always returns 200 to prevent user enumeration.
    // Sends a reset link via Resend if the email is registered.
    if (request.method === "POST" && url.pathname === "/api/auth/forgot-password") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      if (!email) return json({ success: true }); // silent — no enumeration

      // Rate limit by source IP — 5 requests per 15-minute window.
      // Prevents email flooding and abuse of the email delivery system.
      // Fails open: if D1 is unavailable, the request proceeds normally.
      const _fpIp = request.headers.get("CF-Connecting-IP") ||
                    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                    "unknown";
      const _fpRl = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("forgot_password", _fpIp) }],
        "forgot_password",
        5,
        900, // 15 minutes
        // Abuse-critical: never allow unmetered reset-email generation.
        { failClosed: true },
      );
      if (_fpRl) return json({ error: "Too many password reset requests. Please wait before trying again.", code: "rate_limit_exceeded" }, _fpRl.status);

      try {
        const user = await env.cybermeters_db
          .prepare("SELECT id, email, name FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();

        if (user) {
          // Invalidate any existing unused tokens for this user (one active reset at a time)
          await env.cybermeters_db
            .prepare(
              `UPDATE password_reset_tokens
               SET used_at = datetime('now')
               WHERE user_id = ? AND used_at IS NULL AND expires_at > datetime('now')`
            )
            .bind(user.id)
            .run();

          const { raw: resetToken, hash: tokenHash } = await generatePasswordResetToken();
          const tokenId  = createId("prt");
          const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

          await env.cybermeters_db
            .prepare(
              `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
               VALUES (?, ?, ?, ?, datetime('now'))`
            )
            .bind(tokenId, user.id, tokenHash, expiresAt)
            .run();

          // Send email (non-fatal — token is in DB regardless)
          const appUrl   = getEmailFrontendOrigin(env) || "https://app.cybermeters.com";
          const resetUrl = `${appUrl}/reset-password?token=${resetToken}`;
          const name     = user.name || user.email;
          const nameHtml = escapeEmailHtml(name);
          const subject  = "Reset your CyberMeters password";
          const text =
            `Hi ${name},\n\n` +
            `You requested a password reset for your CyberMeters account.\n\n` +
            `Reset your password here (link expires in 1 hour):\n${resetUrl}\n\n` +
            `If you didn't request this, you can ignore this email — your password won't change.\n\n` +
            `— The CyberMeters team`;
          const html = `<!DOCTYPE html><html lang="en"><body style="font-family:Arial,sans-serif;color:#111;max-width:560px;margin:40px auto;padding:0 20px">` +
            `<div style="margin-bottom:24px"><span style="font-weight:700;font-size:18px;color:#0a7c5c">CyberMeters</span></div>` +
            `<h2 style="font-size:20px;margin-bottom:8px">Reset your password</h2>` +
            `<p style="color:#555;margin-bottom:24px">Hi ${nameHtml},<br><br>` +
            `You requested a password reset. Click the button below to set a new password.<br>` +
            `This link expires in <strong>1 hour</strong>.</p>` +
            `<a href="${resetUrl}" style="display:inline-block;background:#0a7c5c;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px">Reset password</a>` +
            `<p style="margin-top:32px;font-size:13px;color:#999">Or copy this URL into your browser:<br><span style="color:#0a7c5c">${resetUrl}</span></p>` +
            `<p style="margin-top:40px;font-size:12px;color:#bbb">If you didn't request this, ignore this email — your account is safe.</p>` +
            `</body></html>`;

          const resetDelivery = await sendCustomerEmail(subject, text, html, env, "HELLO_EMAIL_FROM", [user.email]);

          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "password_reset_requested",
            entity_type: "user",
            entity_id:   user.id,
            description: `Password reset requested for ${email}`,
            metadata:    {
              email,
              token_id: tokenId,
              delivery_status: resetDelivery.sent ? "accepted" : "failed",
              delivery_reason: resetDelivery.reason || null,
              provider_id: resetDelivery.provider_id || null,
            },
          }).catch(() => {});
        }

        // Always 200 — caller can't tell if account exists
        return json({ success: true, message: "If an account exists for this email, a reset link has been sent." });
      } catch (e) {
        return serverError("auth/forgot-password", e, "Password reset request failed. Please try again.");
      }
    }

    // ── POST /api/auth/reset-password ───────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/reset-password") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const rawToken   = (body.token    || "").trim();
      const newPassword = (body.password || "").trim();

      if (!rawToken)                    return json({ error: "token is required" }, 400);
      if (!newPassword)                 return json({ error: "Password cannot be blank" }, 400);
      if (newPassword.length < 12)      return json({ error: "Password must be at least 12 characters" }, 400);
      if (newPassword.length > 128)     return json({ error: "Password is too long" }, 400);

      try {
        const tokenHash = await hashToken(rawToken);
        const tokenRow  = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, expires_at, used_at
             FROM password_reset_tokens
             WHERE token_hash = ? LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!tokenRow) {
          createAuditEvent(env, {
            event_type:  "password_reset_failed",
            entity_type: "user",
            description: "Password reset attempt with invalid token",
            metadata:    { reason: "invalid" },
          }).catch(() => {});
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }
        if (tokenRow.used_at) {
          createAuditEvent(env, {
            user_id:     tokenRow.user_id,
            event_type:  "password_reset_failed",
            entity_type: "user",
            entity_id:   tokenRow.user_id,
            description: "Password reset attempt with already-used token",
            metadata:    { reason: "used", token_id: tokenRow.id },
          }).catch(() => {});
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }
        if (new Date(tokenRow.expires_at) <= new Date()) {
          createAuditEvent(env, {
            user_id:     tokenRow.user_id,
            event_type:  "password_reset_failed",
            entity_type: "user",
            entity_id:   tokenRow.user_id,
            description: "Password reset attempt with expired token",
            metadata:    { reason: "expired", token_id: tokenRow.id },
          }).catch(() => {});
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }

        const user = await env.cybermeters_db
          .prepare("SELECT id, email FROM users WHERE id = ? LIMIT 1")
          .bind(tokenRow.user_id)
          .first();
        if (!user) return json({ error: "Account not found" }, 404);

        const newHash = await hashPassword(newPassword);

        // Update password + mark token used in a batch
        await env.cybermeters_db.batch([
          env.cybermeters_db
            .prepare("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(newHash, user.id),
          env.cybermeters_db
            .prepare("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?")
            .bind(tokenRow.id),
          // Invalidate all existing sessions — security best practice after password change
          env.cybermeters_db
            .prepare("DELETE FROM user_sessions WHERE user_id = ?")
            .bind(user.id),
        ]);

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "password_reset_completed",
          entity_type: "user",
          entity_id:   user.id,
          description: `Password reset completed for ${user.email}`,
          metadata:    { email: user.email, token_id: tokenRow.id },
        }).catch(() => {});

        // Security notification — the password just changed and every session
        // was revoked. Sent on every reset (no dedupe: each change matters).
        // The reset itself must succeed even if this email cannot be sent.
        try {
          const origin = getEmailFrontendOrigin(env);
          const resetPath = origin ? `${origin}/forgot-password` : null;
          const text = "Your CyberMeters password was changed\n\n"
            + "Your account password was just changed and all active sessions were signed out.\n\n"
            + "If you made this change, no further action is needed.\n\n"
            + `If you did not make this change, reset your password immediately${resetPath ? ` at ${resetPath}` : ""} and contact CyberMeters support.\n\nCyberMeters`;
          const html = "<p>Your CyberMeters account password was just changed and all active sessions were signed out.</p>"
            + "<p>If you made this change, no further action is needed.</p>"
            + `<p>If you did not make this change, ${resetPath ? `<a href="${resetPath}">reset your password</a>` : "reset your password"} immediately and contact CyberMeters support.</p>`
            + "<p>CyberMeters</p>";
          await sendCustomerEmail("Your CyberMeters password was changed", text, html, env, "ALERT_EMAIL_FROM", [user.email]);
        } catch {
          // Never block a successful reset on email delivery
        }

        return json({ success: true, message: "Password updated. Please sign in with your new password." });
      } catch (e) {
        return serverError("auth/reset-password", e, "Password reset failed. Please try again.");
      }
    }

    // ── GET /api/auth/mfa/status ─────────────────────────────────────────
    // Returns current MFA state for the authenticated user.
    if (request.method === "GET" && url.pathname === "/api/auth/mfa/status") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT mfa_enabled, mfa_enabled_at FROM users WHERE id = ? LIMIT 1")
          .bind(user.id)
          .first();
        return json({
          mfa_enabled:    row?.mfa_enabled === 1 || row?.mfa_enabled === true,
          mfa_enabled_at: row?.mfa_enabled_at ?? null,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/setup ─────────────────────────────────────────
    // Generates a new TOTP secret for the user and returns the otpauth URI.
    // Does NOT enable MFA yet — caller must verify a valid code first via
    // POST /api/auth/mfa/verify-setup.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/setup") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      try {
        // Generate secret and encrypt before storing
        const base32Secret  = generateTotpSecret();
        const encryptedSecret = await encryptTotpSecret(base32Secret, env);

        // Store the secret (not yet enabled — pending verify-setup)
        await env.cybermeters_db
          .prepare("UPDATE users SET totp_secret = ? WHERE id = ?")
          .bind(encryptedSecret, user.id)
          .run();

        const issuer    = "CyberMeters";
        const label     = encodeURIComponent(`${issuer}:${user.email}`);
        const otpauthUri = `otpauth://totp/${label}?secret=${base32Secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "mfa_setup_started",
          entity_type: "user",
          entity_id:   user.id,
          description: `MFA setup started for ${user.email}`,
          // Never log the secret
        }).catch(() => {});

        return json({ otpauth_uri: otpauthUri, secret_base32: base32Secret });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/verify-setup ─────────────────────────────────
    // Verifies the first TOTP code after setup, then enables MFA and
    // returns one-time recovery codes.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/verify-setup") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const code = (body.code || "").trim();
      if (!code) return json({ error: "code is required" }, 400);
      // Fail-closed throttle on the TOTP proof: 10 attempts / 15 min per user.
      const vsRl = await consumeApiRateLimit(env,
        [{ scope: "user", scope_id: await rateLimitScopeId("mfa_verify_setup", user.id) }],
        "mfa_verify_setup", 10, 900, { failClosed: true });
      if (vsRl) return json(vsRl.body, vsRl.status);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT totp_secret, mfa_enabled FROM users WHERE id = ? LIMIT 1")
          .bind(user.id)
          .first();

        if (!row?.totp_secret) return json({ error: "MFA setup not started. Call /api/auth/mfa/setup first." }, 400);
        if (row.mfa_enabled)   return json({ error: "MFA is already enabled" }, 409);

        const base32Secret = await decryptTotpSecret(row.totp_secret, env);
        const valid = await verifyTotp(base32Secret, code);
        if (!valid) {
          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "mfa_setup_failed",
            entity_type: "user",
            entity_id:   user.id,
            description: `Invalid TOTP code during MFA setup for ${user.email}`,
          }).catch(() => {});
          return json({ error: "Invalid or expired verification code" }, 400);
        }

        // Generate recovery codes
        const { codes: rawCodes, hashes } = await generateRecoveryCodes();

        await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET mfa_enabled = 1,
                 mfa_enabled_at = datetime('now'),
                 mfa_last_verified_at = datetime('now'),
                 mfa_recovery_codes_hash_json = ?
             WHERE id = ?`
          )
          .bind(JSON.stringify(hashes), user.id)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "mfa_enabled",
          entity_type: "user",
          entity_id:   user.id,
          description: `MFA enabled for ${user.email}`,
        }).catch(() => {});

        // Recovery codes are returned once — never stored in plaintext
        return json({ success: true, recovery_codes: rawCodes });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/challenge ─────────────────────────────────────
    // Second factor of login. Accepts the challenge_token (from POST /api/auth/login
    // when mfa_required: true) and a 6-digit TOTP code.
    // On success: marks challenge used, creates session, returns token + user.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/challenge") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const rawChallenge = (body.challenge_token || "").trim();
      const code         = (body.code || "").trim();
      if (!rawChallenge) return json({ error: "challenge_token is required" }, 400);
      if (!code)         return json({ error: "code is required" }, 400);
      // Fail-closed IP throttle on the login-MFA proof: 20 attempts / 15 min.
      // Complements the per-challenge single-use guard (used_at set regardless of
      // outcome below) — this bounds cross-challenge grinding from one source.
      const _mfaChIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const chRl = await consumeApiRateLimit(env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("mfa_challenge", _mfaChIp) }],
        "mfa_challenge", 20, 900, { failClosed: true });
      if (chRl) return json(chRl.body, chRl.status);
      try {
        const challengeHash = await hashToken(rawChallenge);
        const challenge = await env.cybermeters_db
          .prepare(
            `SELECT c.id, c.user_id, c.expires_at, c.used_at,
                    u.id AS uid, u.email, u.name, u.plan, u.status,
                    u.totp_secret, u.mfa_enabled
             FROM mfa_challenges c
             JOIN users u ON u.id = c.user_id
             WHERE c.challenge_hash = ? LIMIT 1`
          )
          .bind(challengeHash)
          .first();

        if (!challenge)                                   return json({ error: "Invalid or expired challenge token" }, 401);
        if (challenge.used_at)                            return json({ error: "Challenge token already used" }, 401);
        if (new Date(challenge.expires_at) <= new Date()) return json({ error: "Challenge token expired. Please sign in again." }, 401);
        if (challenge.status === "suspended")             return json({ error: "Account suspended. Contact support." }, 403);
        if (!challenge.mfa_enabled)                       return json({ error: "MFA is not enabled for this account" }, 400);

        const _mfaIp = request.headers.get("CF-Connecting-IP") || null;
        const _mfaUa = request.headers.get("User-Agent") || null;
        const base32Secret = await decryptTotpSecret(challenge.totp_secret, env);
        const valid = await verifyTotp(base32Secret, code);

        // Mark challenge used regardless of outcome (prevent retry attacks)
        await env.cybermeters_db
          .prepare("UPDATE mfa_challenges SET used_at = datetime('now') WHERE id = ?")
          .bind(challenge.id)
          .run();

        if (!valid) {
          await createAuditEvent(env, {
            user_id:     challenge.user_id,
            event_type:  "mfa_challenge_failed",
            entity_type: "user",
            entity_id:   challenge.user_id,
            description: `Failed MFA challenge for ${challenge.email}`,
            metadata:    { challenge_id: challenge.id, ip_address: _mfaIp, user_agent: _mfaUa },
          }).catch(() => {});
          return json({ error: "Invalid verification code" }, 401);
        }

        // TOTP verified — create session
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId = createId("sess");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db.batch([
          env.cybermeters_db
            .prepare(`INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)`)
            .bind(sessionId, challenge.user_id, tokenHash, expiresAt, _mfaIp, _mfaUa),
          env.cybermeters_db
            .prepare("UPDATE users SET last_login_at = datetime('now'), mfa_last_verified_at = datetime('now') WHERE id = ?")
            .bind(challenge.user_id),
        ]);

        await createAuditEvent(env, {
          user_id:     challenge.user_id,
          event_type:  "mfa_challenge_success",
          entity_type: "user",
          entity_id:   challenge.user_id,
          description: `MFA challenge passed — session created for ${challenge.email}`,
          metadata:    { challenge_id: challenge.id, ip_address: _mfaIp, user_agent: _mfaUa },
        }).catch(() => {});

        const plan = await getEffectivePlan(challenge.user_id, env);
        return json({
          token,
          user: {
            id:    challenge.uid,
            email: challenge.email,
            name:  challenge.name,
            plan,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/recovery-code ────────────────────────────────
    // Recovery path: use a backup recovery code instead of TOTP.
    // Each code is single-use — verified hash is removed from the stored array.
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/recovery-code") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const rawChallenge   = (body.challenge_token  || "").trim();
      const submittedCode  = (body.recovery_code    || "").trim();
      if (!rawChallenge)  return json({ error: "challenge_token is required" }, 400);
      if (!submittedCode) return json({ error: "recovery_code is required" }, 400);
      // Fail-closed IP throttle on the recovery-code proof — same guard the TOTP
      // challenge has, so invalid-challenge grinding can't hammer D1 unbounded.
      const _rcIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const rcRl = await consumeApiRateLimit(env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("mfa_recovery", _rcIp) }],
        "mfa_recovery", 20, 900, { failClosed: true });
      if (rcRl) return json(rcRl.body, rcRl.status);
      try {
        const challengeHash = await hashToken(rawChallenge);
        const challenge = await env.cybermeters_db
          .prepare(
            `SELECT c.id, c.user_id, c.expires_at, c.used_at,
                    u.id AS uid, u.email, u.name, u.plan, u.status,
                    u.mfa_enabled, u.mfa_recovery_codes_hash_json
             FROM mfa_challenges c
             JOIN users u ON u.id = c.user_id
             WHERE c.challenge_hash = ? LIMIT 1`
          )
          .bind(challengeHash)
          .first();

        if (!challenge)                                   return json({ error: "Invalid or expired challenge token" }, 401);
        if (challenge.used_at)                            return json({ error: "Challenge token already used" }, 401);
        if (new Date(challenge.expires_at) <= new Date()) return json({ error: "Challenge token expired. Please sign in again." }, 401);
        if (challenge.status === "suspended")             return json({ error: "Account suspended. Contact support." }, 403);
        if (!challenge.mfa_enabled)                       return json({ error: "MFA is not enabled for this account" }, 400);

        const { valid, remainingHashes } = await verifyRecoveryCode(submittedCode, challenge.mfa_recovery_codes_hash_json);

        // Mark challenge used regardless of outcome
        await env.cybermeters_db
          .prepare("UPDATE mfa_challenges SET used_at = datetime('now') WHERE id = ?")
          .bind(challenge.id)
          .run();

        if (!valid) {
          await createAuditEvent(env, {
            user_id:     challenge.user_id,
            event_type:  "mfa_challenge_failed",
            entity_type: "user",
            entity_id:   challenge.user_id,
            description: `Invalid recovery code used for ${challenge.email}`,
            metadata:    { challenge_id: challenge.id, method: "recovery_code" },
          }).catch(() => {});
          return json({ error: "Invalid recovery code" }, 401);
        }

        // Consume the used code — update stored hashes
        await env.cybermeters_db
          .prepare("UPDATE users SET mfa_recovery_codes_hash_json = ?, last_login_at = datetime('now'), mfa_last_verified_at = datetime('now') WHERE id = ?")
          .bind(JSON.stringify(remainingHashes), challenge.user_id)
          .run();

        // Create session
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId = createId("sess");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
        const _rcIp = request.headers.get("CF-Connecting-IP") || null;
        const _rcUa = request.headers.get("User-Agent") || null;
        await env.cybermeters_db
          .prepare(`INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)`)
          .bind(sessionId, challenge.user_id, tokenHash, expiresAt, _rcIp, _rcUa)
          .run();

        await createAuditEvent(env, {
          user_id:     challenge.user_id,
          event_type:  "recovery_code_used",
          entity_type: "user",
          entity_id:   challenge.user_id,
          description: `Recovery code used to sign in — ${remainingHashes.length} codes remaining for ${challenge.email}`,
          metadata:    { challenge_id: challenge.id, remaining_codes: remainingHashes.length, ip_address: _rcIp, user_agent: _rcUa },
        }).catch(() => {});

        const plan = await getEffectivePlan(challenge.user_id, env);
        return json({
          token,
          user:    { id: challenge.uid, email: challenge.email, name: challenge.name, plan },
          warning: remainingHashes.length <= 2
            ? `Only ${remainingHashes.length} recovery code(s) remaining. Disable and re-enable MFA to generate new codes.`
            : null,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/auth/mfa/disable ───────────────────────────────────────
    // Disables MFA for the authenticated user.
    // Requires the current TOTP code OR current password for verification.
    // Note: does NOT disable on password reset (per sprint spec — MFA survives reset).
    if (request.method === "POST" && url.pathname === "/api/auth/mfa/disable") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "MFA management requires session authentication" }, 403);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const code     = (body.code     || "").trim();  // TOTP code
      const password = (body.password || "").trim();  // alternative: current password
      if (!code && !password) return json({ error: "Either a TOTP code or current password is required" }, 400);
      // Fail-closed throttle on the disable proof (TOTP or password): 10 / 15 min
      // per user — an attacker on a hijacked session must not be able to grind
      // the second factor off.
      const disRl = await consumeApiRateLimit(env,
        [{ scope: "user", scope_id: await rateLimitScopeId("mfa_disable", user.id) }],
        "mfa_disable", 10, 900, { failClosed: true });
      if (disRl) return json(disRl.body, disRl.status);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT totp_secret, mfa_enabled, password_hash FROM users WHERE id = ? LIMIT 1")
          .bind(user.id)
          .first();

        if (!row?.mfa_enabled) return json({ error: "MFA is not currently enabled" }, 400);

        let verified = false;
        if (code) {
          const base32Secret = await decryptTotpSecret(row.totp_secret, env);
          verified = await verifyTotp(base32Secret, code);
        } else if (password) {
          verified = await verifyPassword(password, row.password_hash);
        }

        if (!verified) {
          await createAuditEvent(env, {
            user_id:     user.id,
            event_type:  "mfa_disable_failed",
            entity_type: "user",
            entity_id:   user.id,
            description: `Failed attempt to disable MFA for ${user.email}`,
          }).catch(() => {});
          return json({ error: "Verification failed. Provide a valid TOTP code or current password." }, 403);
        }

        // Clear all MFA fields
        await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET mfa_enabled = 0,
                 mfa_enabled_at = NULL,
                 totp_secret = NULL,
                 mfa_recovery_codes_hash_json = NULL,
                 mfa_last_verified_at = NULL
             WHERE id = ?`
          )
          .bind(user.id)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "mfa_disabled",
          entity_type: "user",
          entity_id:   user.id,
          description: `MFA disabled for ${user.email}`,
          metadata:    { method: code ? "totp_code" : "password" },
        }).catch(() => {});

        return json({ success: true, message: "MFA has been disabled." });
      } catch (e) {
        return serverError("api", e);
      }
    }


  return null;
}
