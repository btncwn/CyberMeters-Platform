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
import { isSingleTenantConfig, validateMicrosoftIdToken } from "../lib/microsoft-jwt.js";
import { hashPassword, verifyPassword } from "../lib/password.js";
import { newPasswordRejection } from "../lib/common-passwords.js";
import { browserBindingChallenges, isBrowserBindingChallenge } from "../lib/oauth-browser-binding.js";
import { generateTotpSecret, verifyTotp } from "../lib/totp.js";
import { createId, isValidEmail } from "../lib/util.js";
import { revokeMcpOAuthUserGrantsForPurge } from "./mcp-oauth-purge.js";

export async function authRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, consumeApiRateLimit, rateLimitScopeId } = rctx;

  // Mark an MFA challenge used if — and only if — it is still unused and in
  // date. True only for the single request whose UPDATE changed the row.
  const claimMfaChallenge = async (challengeId) => {
    const result = await env.cybermeters_db
      .prepare(
        `UPDATE mfa_challenges SET used_at = datetime('now')
         WHERE id = ? AND used_at IS NULL AND expires_at > ?`
      )
      .bind(challengeId, new Date().toISOString())
      .run();
    return result?.meta?.changes === 1;
  };

  // Spend one recovery code. Returns the remaining hashes once this request's
  // compare-and-swap has removed the code, or null when the code is not (or no
  // longer) in the stored list. The matching hash is found once; a lost race
  // re-checks that exact hash against the fresh list, so no extra hashing.
  const consumeRecoveryCode = async (userId, submittedCode, storedJson) => {
    const first = await verifyRecoveryCode(submittedCode, storedJson);
    if (!first.valid) return null;
    let stored = storedJson;
    let hashes = JSON.parse(storedJson);
    const matched = hashes.find((hash) => !first.remainingHashes.includes(hash));
    if (!matched) return null;
    for (let attempt = 0; attempt < 5; attempt++) {
      const index = hashes.indexOf(matched);
      if (index === -1) return null;
      const remaining = hashes.filter((_, i) => i !== index);
      const swap = await env.cybermeters_db
        .prepare(
          `UPDATE users
           SET mfa_recovery_codes_hash_json = ?, last_login_at = datetime('now'), mfa_last_verified_at = datetime('now')
           WHERE id = ? AND mfa_enabled = 1 AND mfa_recovery_codes_hash_json = ?`
        )
        .bind(JSON.stringify(remaining), userId, stored)
        .run();
      if (swap?.meta?.changes === 1) return remaining;
      const fresh = await env.cybermeters_db
        .prepare("SELECT mfa_recovery_codes_hash_json, mfa_enabled FROM users WHERE id = ? LIMIT 1")
        .bind(userId)
        .first();
      if (!fresh?.mfa_enabled || !fresh.mfa_recovery_codes_hash_json) return null;
      stored = fresh.mfa_recovery_codes_hash_json;
      try { hashes = JSON.parse(stored); } catch { return null; }
      if (!Array.isArray(hashes)) return null;
    }
    return null;
  };

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
        // Check before account lookup so the response cannot reveal an existing email.
        const passwordRejection = await newPasswordRejection(password);
        if (passwordRejection) return json(passwordRejection.body, passwordRejection.status);

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
        { failClosed: true, atomic: true },
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
        { failClosed: true, atomic: true },
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

    // ── POST /api/auth/microsoft/start ───────────────────────────────────
    // Starts the Microsoft Entra authorization code flow for the app's own
    // sign-in page. Body: { "binding": "<SHA-256 challenge>" } — the challenge
    // of a verifier the starting browser keeps; the sign-in result is released
    // only to that verifier (POST /api/auth/exchange). Returns the Microsoft
    // authorize URL as JSON for the page to navigate to.
    //
    // A JSON POST (CORS-limited to the app origin) rather than a link: another
    // site cannot start a sign-in with a challenge of its choosing and route the
    // visitor through Microsoft, and the challenge never appears in a URL.
    //
    // Env vars required: AZURE_CLIENT_ID, AZURE_TENANT_ID
    // Optional: MICROSOFT_REDIRECT_URI (defaults to same-origin /callback)
    if (request.method === "POST" && url.pathname === "/api/auth/microsoft/start") {
      const clientId  = env.AZURE_CLIENT_ID;
      const tenantId  = env.AZURE_TENANT_ID;

      if (!clientId || !tenantId) {
        return json({ error: "Microsoft login is not configured on this instance" }, 503);
      }
      if (!/^application\/json\b/i.test(request.headers.get("Content-Type") || "")) {
        return json({ error: "Expected a JSON request" }, 415);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
      const binding = body?.binding;
      if (!isBrowserBindingChallenge(binding)) {
        return json({ error: "Please start Microsoft sign-in again from the sign-in page." }, 400);
      }

      // Generate a cryptographically random state for CSRF protection
      const stateRaw = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0")).join("");
      const nonceRaw = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      // redirect_uri must match exactly what is registered in Azure App Registration
      const redirectUri = env.MICROSOFT_REDIRECT_URI
        || `${url.origin}/api/auth/microsoft/callback`;

      // SQLite datetime() format, so the expiry compares correctly against
      // datetime('now') in the callback lookup.
      await env.cybermeters_db
        .prepare(
          `INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
           VALUES (?, 'microsoft', ?, datetime('now', '+10 minutes'))`
        )
        .bind(stateRaw, JSON.stringify({ redirect_uri: redirectUri, nonce: nonceRaw, binding }))
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

      return json({ authorize_url: authorizeUrl.toString() });
    }

    // ── GET /api/auth/microsoft/login ────────────────────────────────────
    // The old link-based start. A link can be followed from any site, so it no
    // longer starts a sign-in; it sends the visitor to the sign-in page, which
    // starts one with POST /api/auth/microsoft/start.
    if (request.method === "GET" && url.pathname === "/api/auth/microsoft/login") {
      const dest = new URL("/login", env.FRONTEND_URL || url.origin);
      dest.searchParams.set("ms_error", "start_again");
      return Response.redirect(dest.toString(), 302);
    }

    // ── GET /api/auth/microsoft/callback ─────────────────────────────────
    // Handles the OAuth callback from Microsoft.
    //   1. Validates the CSRF state from oauth_states (single-use, TTL-checked)
    //   2. Exchanges the authorization code for tokens at Microsoft's token endpoint
    //   3. Validates the id_token JWT (signature + audience + expiry + oid)
    //   4. Finds an existing user by microsoft_oid, falls back to email match,
    //      or creates a new account
    //   5. Stores a short-lived one-time result bound to the starting browser
    //   6. Redirects to the frontend callback page with only that one-time code
    // No session or MFA challenge exists until POST /api/auth/exchange proves
    // the browser holds the verifier for the challenge the sign-in started with.
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

      // ── 1. Validate and consume the CSRF state in one statement ────────
      // Single-use: only the request whose DELETE removes the row continues.
      const stateRow = await env.cybermeters_db
        .prepare(
          `DELETE FROM oauth_states
           WHERE state = ? AND provider = 'microsoft'
             AND expires_at > datetime('now')
           RETURNING redirect_uri`
        )
        .bind(state)
        .first();

      if (!stateRow) {
        return json({ error: "Invalid or expired OAuth state. Please try signing in again." }, 400);
      }

      let statePayload = null;
      try { statePayload = JSON.parse(stateRow.redirect_uri); } catch { /* legacy state row */ }
      // A sign-in started before browser binding existed has no challenge. It
      // is refused rather than completed without the check.
      const binding = statePayload?.binding;
      if (!isBrowserBindingChallenge(binding)) {
        const dest = new URL("/login", env.FRONTEND_URL || url.origin);
        dest.searchParams.set("ms_error", "Sign-in expired. Please try again.");
        return Response.redirect(dest.toString(), 302);
      }
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
        .prepare("SELECT id, email, name, plan, status, mfa_enabled FROM users WHERE microsoft_oid = ? LIMIT 1")
        .bind(msOid)
        .first();

      // nOAuth guard: auto-linking an incoming Microsoft identity to an existing
      // local account by EMAIL (and auto-verifying it) is only safe when the
      // email claim is trustworthy — i.e. a single-tenant app, where only the
      // configured org's users can obtain a token and the tid is enforced. In a
      // multi-tenant config any tenant's token is accepted and its email claim is
      // attacker-controllable, so email-based auto-linking would be account
      // takeover. When not trusted we skip the link entirely (a Microsoft
      // identity then only ever creates/uses its own oid-keyed account).
      const tenantTrusted = isSingleTenantConfig(tenantId);

      if (!user && tenantTrusted) {
        // Try to link to an existing email/password account
        user = await env.cybermeters_db
          .prepare("SELECT id, email, name, plan, status, mfa_enabled FROM users WHERE email = ? LIMIT 1")
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
            .prepare("SELECT id, email, name, plan, status, mfa_enabled FROM users WHERE id = ? LIMIT 1")
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

        user = { id: newUserId, email: msEmail, name: msName, plan: "free", status: "active", mfa_enabled: 0 };

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

      // ── 5. Issue a one-time result bound to the starting browser ────────
      // The result names the user only; no session token or MFA challenge
      // exists yet. POST /api/auth/exchange releases it to the browser that
      // presents the verifier for `binding`, and only then mints the session
      // (or, for an MFA account, the second-factor challenge). A callback link
      // opened in another browser therefore cannot sign that browser in.
      //
      // Only the one-time code appears in the redirect URL. TTL is 5 minutes:
      // long enough for a slow page load, short enough to limit replay. SQLite
      // datetime() keeps the expiry comparable with datetime('now').
      const otcRaw = Array.from(crypto.getRandomValues(new Uint8Array(32)))
        .map(b => b.toString(16).padStart(2, "0")).join("");
      await env.cybermeters_db
        .prepare(
          `INSERT INTO oauth_states (state, provider, redirect_uri, expires_at)
           VALUES (?, 'ms_exchange', ?, datetime('now', '+5 minutes'))`
        )
        .bind(otcRaw, JSON.stringify({
          binding,
          user_id:       user.id,
          microsoft_oid: msOid,
          tenant_id:     msTid,
        }))
        .run();

      const frontendUrl = env.FRONTEND_URL || url.origin;
      const dest = new URL("/auth/microsoft/callback", frontendUrl);
      dest.searchParams.set("otc", otcRaw);

      return Response.redirect(dest.toString(), 302);
    }

    // ── POST /api/auth/exchange ──────────────────────────────────────────
    // Releases the result of a Microsoft sign-in to the browser that started
    // it. The one-time code (OTC) from the callback redirect is consumed in the
    // same statement that checks the browser binding, so it is single-use even
    // under concurrent requests, and a request without the matching verifier
    // neither consumes nor receives it.
    //
    // Request:  POST /api/auth/exchange
    //           Body: { "code": "<otc>", "verifiers": ["<verifier>", ...] }
    //
    // Response: { "token", "id", "email", "name", "plan", "binding" } — a new
    //           session; or { "mfa_required": true, "challenge_token", "binding" }
    //           for an MFA account. `binding` is the matched challenge.
    // Errors:   400 missing code; 401 unknown, expired, replayed or unbound
    //           code (one message, so a caller learns nothing about which);
    //           403 suspended account.
    if (request.method === "POST" && url.pathname === "/api/auth/exchange") {
      let body;
      try { body = await request.json(); } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const otc = typeof body?.code === "string" ? body.code.trim() : "";
      if (!otc) {
        return json({ error: "Missing code" }, 400);
      }

      const rejected = () => json({ error: "Sign-in could not be completed in this browser. Please sign in again." }, 401);
      const challenges = await browserBindingChallenges(body?.verifiers);
      if (challenges.length === 0) return rejected();

      // Consume the OTC only when one of the presented verifiers matches its
      // binding. A non-matching request leaves it for the starting browser.
      const placeholders = challenges.map(() => "?").join(", ");
      const otcRow = await env.cybermeters_db
        .prepare(
          `DELETE FROM oauth_states
           WHERE state = ? AND provider = 'ms_exchange'
             AND expires_at > datetime('now')
             AND (CASE WHEN json_valid(redirect_uri)
                       THEN json_extract(redirect_uri, '$.binding') END) IN (${placeholders})
           RETURNING redirect_uri AS payload`
        )
        .bind(otc, ...challenges)
        .first();
      if (!otcRow) return rejected();

      let payload = null;
      try { payload = JSON.parse(otcRow.payload); } catch { /* handled below */ }
      if (typeof payload?.user_id !== "string" || !payload.user_id) return rejected();

      try {
        const user = await env.cybermeters_db
          .prepare("SELECT id, email, name, status, mfa_enabled FROM users WHERE id = ? LIMIT 1")
          .bind(payload.user_id)
          .first();
        if (!user) return rejected();
        if (user.status === "suspended") return json({ error: "Account suspended. Contact support." }, 403);

        const loginIp = request.headers.get("CF-Connecting-IP") || null;
        const loginUa = request.headers.get("User-Agent") || null;

        // MFA gate: an MFA account receives a second-factor challenge, never a
        // session. It completes at POST /api/auth/mfa/challenge (or the
        // recovery-code path) exactly like password sign-in.
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
            description: `MFA challenge issued for ${user.email} (Microsoft SSO)`,
            metadata:    { challenge_id: challengeId, auth_provider: "microsoft", ip_address: loginIp, user_agent: loginUa },
          }).catch(() => {});
          return json({ mfa_required: true, challenge_token: challengeRaw, binding: payload.binding });
        }

        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId = createId("sess");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days
        await env.cybermeters_db
          .prepare(
            `INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?, ?)`
          )
          .bind(sessionId, user.id, tokenHash, expiresAt, loginIp, loginUa)
          .run();

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
            microsoft_oid: payload.microsoft_oid || null,
            tenant_id:     payload.tenant_id || null,
          },
        }).catch(() => {});

        return json({
          token,
          id:      user.id,
          email:   user.email,
          name:    user.name || "",
          plan,
          // The challenge this sign-in was bound to (not secret), so the page
          // forgets only that verifier and keeps other tabs' sign-ins.
          binding: payload.binding,
        });
      } catch (e) {
        return serverError("api", e);
      }
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

        const passwordRateLimit = await consumeApiRateLimit(
          env, [{ scope: "user", scope_id: user.id }], "new_password_check", 10, 900,
          { atomic: true, failClosed: true },
        );
        if (passwordRateLimit) return json({ error: "Please wait before trying again." }, passwordRateLimit.status);
        const passwordRejection = await newPasswordRejection(newPassword);
        if (passwordRejection) return json(passwordRejection.body, passwordRejection.status);

        const newHash = await hashPassword(newPassword);

        // Recheck token eligibility in the same atomic batch as every change,
        // then consume it last. Concurrent resets cannot reuse the token or sign
        // out a newly recovered session.
        const checkedAt = new Date().toISOString();
        const eligible = `EXISTS (SELECT 1 FROM password_reset_tokens
          WHERE id = ? AND user_id = ? AND used_at IS NULL
          AND julianday(expires_at) > julianday(?))`;
        const guard = [tokenRow.id, user.id, checkedAt];
        const mcpConnectionsExist = Boolean(await env.cybermeters_db.prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mcp_oauth_connections' LIMIT 1",
        ).first());
        const resetStatements = [
          env.cybermeters_db
            .prepare(`UPDATE users SET password_hash = ? WHERE id = ? AND ${eligible}`)
            .bind(newHash, user.id, ...guard),
          // Invalidate all existing sessions — security best practice after password change
          env.cybermeters_db
            .prepare(`DELETE FROM user_sessions WHERE user_id = ? AND ${eligible}`)
            .bind(user.id, ...guard),
          // Revoke all active API tokens too. Password reset is the primary account-
          // recovery action after a suspected compromise; leaving long-lived `cm_`
          // bearer tokens valid would let an attacker who minted one retain access
          // through the exact flow meant to cut them off. Append-only status flip
          // (mirrors DELETE /api/account/api-tokens/:id) — history is preserved.
          env.cybermeters_db
            .prepare(`UPDATE api_tokens SET status = 'revoked' WHERE user_id = ? AND status = 'active' AND ${eligible}`)
            .bind(user.id, ...guard),
          ...(mcpConnectionsExist ? [env.cybermeters_db
            .prepare(`UPDATE mcp_oauth_connections SET status = 'revoked',
                revoked_at = COALESCE(revoked_at, datetime('now'))
              WHERE user_id = ? AND status = 'active' AND ${eligible}`)
            .bind(user.id, ...guard)] : []),
          env.cybermeters_db
            .prepare(`UPDATE password_reset_tokens SET used_at = ?
              WHERE id = ? AND user_id = ? AND used_at IS NULL AND julianday(expires_at) > julianday(?)`)
            .bind(checkedAt, ...guard),
        ];
        const resetResults = await env.cybermeters_db.batch(resetStatements);
        if (resetResults.at(-1)?.meta?.changes !== 1) {
          return json({ error: "Reset link is invalid, expired, or has already been used." }, 400);
        }
        if (mcpConnectionsExist && env.OAUTH_KV) {
          // D1 admission is already fenced by the atomic reset batch. KV
          // cleanup removes provider refresh grants as well.
          await revokeMcpOAuthUserGrantsForPurge(env, user.id).catch(() => {
            console.error("mcp_oauth_password_reset_kv_revoke_unavailable");
          });
        }

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

        // Enrollment must never replace an enabled factor. Keep the condition
        // in the write so a concurrent verify-setup cannot be overwritten.
        const enrollment = await env.cybermeters_db
          .prepare("UPDATE users SET totp_secret = ? WHERE id = ? AND mfa_enabled = 0")
          .bind(encryptedSecret, user.id)
          .run();
        if (enrollment.meta?.changes !== 1) {
          return json({ error: "MFA is already enabled or the account is unavailable" }, 409);
        }

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

        // Enable only the exact pending secret that this code proved. A setup
        // rotation or another successful verification makes this proof stale.
        const enrollment = await env.cybermeters_db
          .prepare(
            `UPDATE users
             SET mfa_enabled = 1,
                 mfa_enabled_at = datetime('now'),
                 mfa_last_verified_at = datetime('now'),
                 mfa_recovery_codes_hash_json = ?
             WHERE id = ? AND mfa_enabled = 0 AND totp_secret = ?`
          )
          .bind(JSON.stringify(hashes), user.id, row.totp_secret)
          .run();
        if (enrollment.meta?.changes !== 1) {
          return json({ error: "MFA setup changed or is already enabled. Please check its status and try again." }, 409);
        }

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

        // Claim the challenge before checking the code, whatever the outcome
        // (prevents retries). Only the request whose conditional UPDATE changes
        // the row continues, so concurrent submissions cannot both sign in.
        if (!(await claimMfaChallenge(challenge.id))) {
          return json({ error: "Challenge token already used" }, 401);
        }

        const base32Secret = await decryptTotpSecret(challenge.totp_secret, env);
        const valid = await verifyTotp(base32Secret, code);

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

        // Claim the challenge first, whatever the outcome (single use).
        if (!(await claimMfaChallenge(challenge.id))) {
          return json({ error: "Challenge token already used" }, 401);
        }

        // Consume the code with a compare-and-swap on the stored list: the
        // UPDATE applies only if the list is still exactly the one this request
        // read. A request that loses a race re-reads the list; its code counts
        // only if that exact hash is still there, so two requests can never
        // both spend one code, and one request can never restore a code another
        // has spent. No session exists until a swap has changed the row.
        const remainingHashes = await consumeRecoveryCode(challenge.user_id, submittedCode, challenge.mfa_recovery_codes_hash_json);
        const valid = Array.isArray(remainingHashes);

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

        // Clear MFA and fence all MCP connections atomically in D1.
        const mcpConnectionsExist = Boolean(await env.cybermeters_db.prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mcp_oauth_connections' LIMIT 1",
        ).first());
        const disableMfa = env.cybermeters_db.prepare(
            `UPDATE users
             SET mfa_enabled = 0,
                 mfa_enabled_at = NULL,
                 totp_secret = NULL,
                 mfa_recovery_codes_hash_json = NULL,
                 mfa_last_verified_at = NULL
             WHERE id = ?`
          ).bind(user.id);
        const disableStatements = [disableMfa];
        if (mcpConnectionsExist) disableStatements.push(env.cybermeters_db.prepare(
          `UPDATE mcp_oauth_connections SET status = 'revoked',
             revoked_at = COALESCE(revoked_at, datetime('now'))
           WHERE user_id = ? AND status = 'active'`,
        ).bind(user.id));
        await env.cybermeters_db.batch(disableStatements);
        if (mcpConnectionsExist && env.OAUTH_KV) {
          await revokeMcpOAuthUserGrantsForPurge(env, user.id).catch(() => {
            console.error("mcp_oauth_mfa_disable_kv_revoke_unavailable");
          });
        }

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
