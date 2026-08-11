// ── Brand HTTP/TLS live enrichment ────────────────────────────────────────────
// PR-C of the Brand Protection blocker-remediation sprint. The final signal layer:
// for lookalike candidates that DNS has already confirmed live (dns_resolves = 1),
// this probes the live web surface to set two evidence signals the earlier stages
// could only guess at from the NAME:
//   - https_available  — the host actually serves HTTPS (a TLS handshake completed
//                        and an HTTP response came back).
//   - looks_like_login — the live page contains a password/login form (real
//                        credential-harvesting surface), not merely a login-ish word
//                        in the hostname.
//
// SECURITY (load-bearing): a brand candidate is an ATTACKER-INFLUENCED host — a
// lookalike domain the attacker controls could point DNS at an internal/reserved
// IP. Every probe therefore goes through the CANONICAL SSRF-safe fetcher
// (makeReservedProbeFetch → makeSsrfSafeProbeFetch), which re-resolves and rejects
// private/reserved hops. This module NEVER calls fetch() directly.
//
// Honesty (identical tri-state discipline to brand-dns-enrichment):
//   https_available NULL = not yet probed   0 = probed, no HTTPS   1 = serving HTTPS
// A transient failure (timeout, budget throw, blocked target) is NEVER coerced to
// 0 — the row is left untouched so the next batch retries it. CyberMeters imports
// no external verdict; every persisted state is its own observation.

import { createId } from "../lib/util.js";
import { makeReservedProbeFetch } from "./reserved-probe.js";

export const BRAND_HTTP_BATCH_SIZE = 8;                 // candidates per workspace per invocation
export const BRAND_HTTP_WORKSPACES_PER_TICK = 3;        // workspaces per daily run
export const BRAND_HTTP_TIMEOUT_MS = 8_000;
export const BRAND_HTTP_RECHECK_AFTER_MS = 7 * 24 * 60 * 60 * 1000; // re-probe weekly
export const BRAND_HTTP_MAX_BODY_BYTES = 64 * 1024;     // bounded read for login-form detection

const CLOSED_CLASSIFICATIONS = "('owned','ignored','false_positive')";

// A password field or an explicit login form is the honest signal for a live
// credential-harvesting surface. Bounded, deterministic, case-insensitive.
const PASSWORD_INPUT_RE = /<input\b[^>]*\btype\s*=\s*["']?password\b/i;
const PASSWORD_NAME_RE  = /<input\b[^>]*\bname\s*=\s*["']?(?:pass(?:word|wd)?|otp|mfa|totp)\b/i;

/** Detect a login/password surface in a bounded slice of HTML. Pure. */
export function detectLoginSurface(html) {
  const s = String(html || "");
  return PASSWORD_INPUT_RE.test(s) || PASSWORD_NAME_RE.test(s);
}

/**
 * Probe ONE candidate's live HTTPS surface via an SSRF-safe fetcher. Returns one
 * conclusive-or-transient outcome:
 *   { outcome: 'served', https_available: 1, looks_like_login }  — HTTPS responded
 *   { outcome: 'no_https', https_available: 0 }                  — resolver ok, no HTTPS response
 *   { outcome: 'transient' }                                      — timeout/blocked/budget → DO NOT persist
 * `probeFetch(url)` must return a Response or null (blocked target); it must apply
 * the SSRF guards itself. Injected so tests can pin behaviour without network.
 */
export async function probeCandidateHttp(candidateDomain, probeFetch, opts = {}) {
  const maxBytes = opts.maxBodyBytes || BRAND_HTTP_MAX_BODY_BYTES;
  let res;
  try {
    res = await probeFetch(`https://${candidateDomain}/`);
  } catch {
    return { outcome: "transient" };                 // timeout / subrequest budget → inconclusive
  }
  if (res === null) return { outcome: "transient" }; // SSRF-blocked target — never a positive OR negative fact
  if (!res || typeof res.status !== "number") return { outcome: "transient" };
  // Any HTTP response over HTTPS proves the host serves HTTPS (even a 4xx/5xx is
  // a served response). Only detect a login surface on a successful body.
  let looksLikeLogin = false;
  if (res.status >= 200 && res.status < 400) {
    try {
      const body = typeof res.text === "function" ? await res.text() : "";
      looksLikeLogin = detectLoginSurface(String(body).slice(0, maxBytes));
    } catch { /* body read failed — HTTPS still served; login unknown */ }
  }
  return { outcome: "served", https_available: 1, looks_like_login: looksLikeLogin };
}

/** Map a probe outcome to persisted fields, or null when nothing may be persisted. */
export function httpOutcomeToPersistence(outcome) {
  if (outcome?.outcome === "served") {
    return { https_available: 1, looks_like_login: outcome.looks_like_login === true };
  }
  if (outcome?.outcome === "no_https") return { https_available: 0, looks_like_login: false };
  return null; // transient — leave the row for retry
}

/**
 * Selection: DNS-CONFIRMED-LIVE candidates only (dns_resolves = 1) whose HTTPS
 * state is unknown or stale. Probing a host that does not resolve would be wasted
 * work and could hit a parked/for-sale page — the DNS gate keeps the probe honest
 * and bounded. Deterministic order; risk then domain tie-break.
 */
export function selectBrandHttpCandidatesSql() {
  // Positional binds: workspace_id, staleBefore, batchSize.
  return `SELECT id, candidate_domain, https_available, evidence_json, last_checked_at
          FROM workspace_brand_assets a
          WHERE workspace_id = ?
            AND dns_resolves = 1
            AND (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
            AND (https_available IS NULL OR last_checked_at IS NULL OR last_checked_at < ?)
            AND EXISTS (
                  SELECT 1
                    FROM workspaces w
                    JOIN workspace_domains wd ON wd.workspace_id = w.id
                    JOIN domains d ON d.id = wd.domain_id
                   WHERE w.id = a.workspace_id
                     AND w.deleted_at IS NULL
                     AND lower(d.domain) = lower(a.domain)
                )
          ORDER BY (https_available IS NOT NULL) ASC,
                   CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC,
                   candidate_domain ASC
          LIMIT ?`;
}

function parseJsonArray(text) {
  if (!text) return [];
  try { const v = JSON.parse(text); return Array.isArray(v) ? v : []; } catch { return []; }
}

/**
 * Merge the live https/login signals into a candidate's evidence_json without
 * dropping any existing signal. Pure. A live login detection is recorded as
 * looks_like_login (the same canonical signal the serializer reads), plus an
 * https_active signal when HTTPS served.
 */
export function mergeHttpEvidence(existingJson, persist) {
  const evidence = parseJsonArray(existingJson).filter((e) => e && typeof e.signal === "string");
  const setSignal = (signal, value) => {
    const i = evidence.findIndex((e) => e.signal === signal);
    if (i >= 0) evidence[i] = { signal, value };
    else evidence.push({ signal, value });
  };
  if (persist.https_available === 1) setSignal("https_active", true);
  if (persist.looks_like_login === true) setSignal("looks_like_login", true);
  return evidence;
}

function runChanges(result) {
  const value = result?.meta?.changes ?? result?.changes;
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}

/**
 * Enrich a bounded batch of ONE workspace's DNS-live brand candidates with a live
 * HTTPS/login probe. Idempotent, tenant-scoped (every read and write filtered by
 * workspace_id), retry-safe (transient failures leave the row eligible).
 */
export async function enrichBrandCandidatesHttp(env, workspaceId, opts = {}) {
  const {
    batchSize = BRAND_HTTP_BATCH_SIZE,
    now = new Date().toISOString(),
    recheckAfterMs = BRAND_HTTP_RECHECK_AFTER_MS,
    timeoutMs = BRAND_HTTP_TIMEOUT_MS,
  } = opts;
  // SSRF-safe fetcher — private/reserved hops are rejected. Injected in tests.
  const probeFetch = opts.probeFetch || makeReservedProbeFetch({ timeoutMs });
  const staleBefore = new Date(Date.now() - recheckAfterMs).toISOString();
  const stats = { selected: 0, served: 0, no_https: 0, transient: 0, login_surfaces: 0, checked: 0 };

  let rows;
  try {
    rows = await env.cybermeters_db
      .prepare(selectBrandHttpCandidatesSql())
      .bind(workspaceId, staleBefore, Math.max(1, batchSize))
      .all();
  } catch {
    return stats;
  }
  const candidates = rows?.results || [];
  stats.selected = candidates.length;

  for (const row of candidates) {
    const probe = await probeCandidateHttp(row.candidate_domain, probeFetch, opts);
    stats[probe.outcome] = (stats[probe.outcome] || 0) + 1;
    const persist = httpOutcomeToPersistence(probe);
    if (!persist) continue; // transient — untouched, retried next batch
    if (persist.looks_like_login) stats.login_surfaces++;
    const evidence = mergeHttpEvidence(row.evidence_json, persist);
    try {
      const result = await env.cybermeters_db.prepare(
        `UPDATE workspace_brand_assets
            SET https_available = ?, evidence_json = ?, last_checked_at = ?, updated_at = ?
          WHERE id = ? AND workspace_id = ?
            AND EXISTS (
                  SELECT 1
                    FROM workspaces w
                    JOIN workspace_domains wd ON wd.workspace_id = w.id
                    JOIN domains d ON d.id = wd.domain_id
                   WHERE w.id = workspace_brand_assets.workspace_id
                     AND w.deleted_at IS NULL
                     AND lower(d.domain) = lower(workspace_brand_assets.domain)
                )`
      ).bind(persist.https_available, JSON.stringify(evidence), now, now, row.id, workspaceId).run();
      if (runChanges(result) !== 1) continue;
      stats.checked++;
    } catch { /* isolated — the batch continues */ }
  }
  return stats;
}

/**
 * Daily bounded HTTP-enrichment sweep. Selects workspaces that have DNS-live,
 * not-yet-HTTP-probed candidates (most-pending first) and probes a bounded batch
 * of each. Bounded, self-limiting, and logs the eligible-workspace count so the
 * per-run cap is never silent.
 */
export async function runBrandHttpEnrichmentSweep(env, opts = {}) {
  const perTick = Math.max(1, opts.workspacesPerTick || BRAND_HTTP_WORKSPACES_PER_TICK);
  let rows;
  try {
    rows = await env.cybermeters_db.prepare(
      `SELECT a.workspace_id, COUNT(*) AS pending
         FROM workspace_brand_assets a
         JOIN workspaces w
           ON w.id = a.workspace_id AND w.deleted_at IS NULL
         JOIN workspace_domains wd ON wd.workspace_id = w.id
         JOIN domains d
           ON d.id = wd.domain_id AND lower(d.domain) = lower(a.domain)
        WHERE a.dns_resolves = 1
          AND a.https_available IS NULL
          AND (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
        GROUP BY a.workspace_id
        ORDER BY pending DESC, a.workspace_id ASC`
    ).all();
  } catch {
    return { workspaces: 0, checked: 0, login_surfaces: 0, skipped_workspaces: 0 };
  }
  const all = rows?.results || [];
  const selected = all.slice(0, perTick);
  const skipped = Math.max(0, all.length - selected.length);

  let checked = 0, loginSurfaces = 0;
  for (const w of selected) {
    const s = await enrichBrandCandidatesHttp(env, w.workspace_id, opts);
    checked += s.checked;
    loginSurfaces += s.login_surfaces;
  }
  return { workspaces: selected.length, checked, login_surfaces: loginSurfaces, skipped_workspaces: skipped };
}
