// ── Shadow IT & Unmanaged Technology — approved inventory ───────────────────
// Turns externally-observed technology (vendors/SaaS/providers) into a canonical,
// workspace-scoped APPROVED INVENTORY with classification, ownership and a managed
// lifecycle. It CORRELATES the raw observation evidence (workspace_vendors, plus
// ephemeral saas_exposure portal URLs) into one canonical item per product, and
// is the source of truth for CLASSIFICATION / OWNERSHIP / LIFECYCLE only — the raw
// observation stays in workspace_vendors (referenced, never duplicated).
//
// Honest scope (permanent): items are EXTERNALLY OBSERVED. Classification is a
// CUSTOMER decision, separate from observation. `approved` != secure; `rejected`
// != removed; disappearance != verified removal. No internal-network / endpoint /
// CASB / EDR claim, and nothing is called "unauthorised" until the customer (or a
// policy) classifies it that way. Follow-up uses the Universal Managed-Case Model
// (shadow_it_case → shadow_it.saas.review remediation).

import { emitLifecycleAlert, describeRecurrenceEvent, recommendationForRecurrence } from "./alert-consumers.js";
import { resolveRemediation } from "./remediation-registry.js";
import { buildMonitoringTransitionDetail, isMonitoringTransition } from "./alert-occurrence.js";
import { createManagedCase, canTransitionCase, canonicalPhaseFor } from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";

function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 12).padEnd(12, "0")}`;
}
function parseJson(v, fallback = null) { try { return v ? JSON.parse(v) : fallback; } catch { return fallback; } }
function safeJson(v, fallback = null) { try { return v == null ? fallback : JSON.stringify(v); } catch { return fallback; } }

// ── Canonical identity ──────────────────────────────────────────────────────
// PRODUCT-level slug of the observed technology name. Deterministic and stable;
// NEVER a mutable display value. Distinct products of one provider keep distinct
// keys ("Google Workspace" → google_workspace, "Google Cloud" → google_cloud) so
// unrelated products are never merged.
// Explicit, deterministic alias layer — a SMALL set of known naming variants that
// resolve to one stable key. NOT fuzzy matching. Different products of one
// provider are deliberately NOT aliased together (microsoft_365 vs
// microsoft_entra_id stay separate; google_workspace vs google_cloud stay
// separate). Keyed by the normalized (lowercased, single-spaced) product name AND
// by its slug so either form resolves.
export const TECHNOLOGY_ALIASES = Object.freeze({
  "microsoft office 365": "microsoft_365", "office 365": "microsoft_365",
  "m365": "microsoft_365", "o365": "microsoft_365", "microsoft 365": "microsoft_365",
  "g suite": "google_workspace", "gsuite": "google_workspace", "google workspace": "google_workspace",
  "azure ad": "microsoft_entra_id", "azure active directory": "microsoft_entra_id",
  "microsoft entra id": "microsoft_entra_id", "entra id": "microsoft_entra_id",
  "amazon s3": "aws_s3", "aws s3": "aws_s3", "s3": "aws_s3",
  "azure blob storage": "azure_blob", "azure blob": "azure_blob",
  "google cloud storage": "google_cloud_storage", "gcs": "google_cloud_storage",
});
export function canonicalTechnologyKey(name) {
  const norm = String(name || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (TECHNOLOGY_ALIASES[norm]) return TECHNOLOGY_ALIASES[norm];
  const slug = norm.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80);
  return TECHNOLOGY_ALIASES[slug] || slug || "unknown";
}

// Cloud-provider tokens (workspace_assets.cloud_provider) → display + category.
// Object storage is a real customer resource; CDN/edge is generic infrastructure
// (kept honest — never treated as approved SaaS; classification stays customer-led).
const CLOUD_PROVIDER_META = {
  aws_s3: { display: "Amazon S3", category: "cloud_storage" },
  azure_blob: { display: "Azure Blob Storage", category: "cloud_storage" },
  gcs: { display: "Google Cloud Storage", category: "cloud_storage" },
  cloudflare: { display: "Cloudflare", category: "cdn" },
  fastly: { display: "Fastly", category: "cdn" },
  akamai: { display: "Akamai", category: "cdn" },
};
function cloudProviderMeta(token) {
  const t = String(token || "").trim().toLowerCase();
  if (CLOUD_PROVIDER_META[t]) return CLOUD_PROVIDER_META[t];
  return { display: t.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()), category: "hosting" };
}

// Gather externally-observed technology from every persisted, safely-joinable
// source. Each observation carries a structured evidence reference:
//   { source_table, source_record_id, source_type, observed_identifier,
//     first_seen_at, last_seen_at, confidence, name, category, hostnames[] }
// Reuses the raw stores (workspace_vendors / workspace_assets / identity_assets /
// email_sender_sources) — no duplicate authoritative observation store.
async function gatherShadowItObservations(env, workspaceId, saasExposure) {
  const q = (sql, ...b) => env.cybermeters_db.prepare(sql).bind(...b).all().catch(() => ({ results: [] }));
  const obs = [];

  // 1. workspace_vendors — SaaS/vendor/provider signals.
  for (const r of (await q(`SELECT id, vendor_name, category, evidence, confidence, first_seen, last_seen FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'`, workspaceId)).results || []) {
    const hosts = [];
    for (const e of (parseJson(r.evidence, []) || [])) if (e?.detail) hosts.push(String(e.detail).slice(0, 200));
    obs.push({ source_table: "workspace_vendors", source_record_id: r.id, source_type: "vendor", observed_identifier: r.vendor_name, name: r.vendor_name, category: r.category || "other", first_seen_at: r.first_seen, last_seen_at: r.last_seen, confidence: r.confidence || "low", hostnames: hosts });
  }
  // 2. workspace_assets.cloud_provider — cloud/CDN/hosting infrastructure. Kept
  //    honest (category cloud_storage/cdn/hosting), never auto-treated as SaaS.
  for (const r of (await q(`SELECT id, hostname, cloud_provider, first_seen, last_seen FROM workspace_assets WHERE workspace_id = ? AND status = 'active' AND cloud_provider IS NOT NULL AND cloud_provider != ''`, workspaceId)).results || []) {
    const meta = cloudProviderMeta(r.cloud_provider);
    obs.push({ source_table: "workspace_assets", source_record_id: r.id, source_type: "cloud_asset", observed_identifier: r.cloud_provider, name: meta.display, category: meta.category, first_seen_at: r.first_seen, last_seen_at: r.last_seen, confidence: "medium", hostnames: r.hostname ? [r.hostname] : [] });
  }
  // 3. identity_assets — externally observed identity providers.
  for (const r of (await q(`SELECT id, hostname, provider, risk_score, first_seen, last_seen FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND provider IS NOT NULL AND provider != ''`, workspaceId)).results || []) {
    obs.push({ source_table: "identity_assets", source_record_id: r.id, source_type: "identity_provider", observed_identifier: r.provider, name: r.provider, category: "identity_provider", first_seen_at: r.first_seen, last_seen_at: r.last_seen, confidence: (r.risk_score || 0) >= 20 ? "high" : "medium", hostnames: r.hostname ? [r.hostname] : [] });
  }
  // 4. email_sender_sources — email/ESP providers seen in DMARC reports.
  for (const r of (await q(`SELECT id, provider_guess, provider_confidence, header_from, first_seen, last_seen FROM email_sender_sources WHERE workspace_id = ? AND provider_guess IS NOT NULL AND provider_guess != ''`, workspaceId)).results || []) {
    obs.push({ source_table: "email_sender_sources", source_record_id: r.id, source_type: "email_sender", observed_identifier: r.provider_guess, name: r.provider_guess, category: "email_provider", first_seen_at: r.first_seen, last_seen_at: r.last_seen, confidence: r.provider_confidence || "low", hostnames: r.header_from ? [r.header_from] : [] });
  }
  // 5. saas_exposure (ephemeral, this scan only) — portal/tenant URLs. No durable
  //    record id, so it enriches hostnames but is a distinct evidence source_type.
  for (const ex of (Array.isArray(saasExposure?.exposures) ? saasExposure.exposures : [])) {
    const name = ex.name || ex.provider || ex.product;
    if (!name) continue;
    obs.push({ source_table: "saas_exposure", source_record_id: null, source_type: "saas_portal", observed_identifier: name, name, category: "saas", first_seen_at: null, last_seen_at: null, confidence: "low", hostnames: [ex.tenant_url, ex.portal_url, ex.admin_url].filter(Boolean) });
  }
  return obs;
}

// Non-destructive evidence UNION: every prior reference is preserved; new ones are
// appended. Deduped by (source_table, source_record_id | observed_identifier,
// source_type) so re-correlation never loses a source contribution nor grows
// unboundedly.
export function unionEvidence(existing = [], incoming = []) {
  const seen = new Map();
  const keyOf = (e) => `${e.source_table}:${e.source_record_id ?? e.observed_identifier ?? ""}:${e.source_type}`;
  for (const e of [...(existing || []), ...(incoming || [])]) {
    if (!e || typeof e !== "object") continue;
    const k = keyOf(e);
    // Prefer the freshest last_seen_at when the same reference recurs.
    const prev = seen.get(k);
    if (!prev || (e.last_seen_at && (!prev.last_seen_at || e.last_seen_at > prev.last_seen_at))) seen.set(k, { ...prev, ...e });
  }
  return [...seen.values()];
}

// Derive ownership status from the assigned owners — this is SERVER-derived and
// SEPARATE from the customer classification.
export function deriveOwnershipStatus(business_owner, technical_owner) {
  const b = String(business_owner || "").trim();
  const t = String(technical_owner || "").trim();
  if (b && t) return "known";
  if (b || t) return "partial";
  return "missing";
}

const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 };
function strongerConfidence(a, b) {
  return (CONFIDENCE_RANK[a] || 0) >= (CONFIDENCE_RANK[b] || 0) ? (a || b || "low") : (b || "low");
}

// ── Classification model ────────────────────────────────────────────────────
// Customer classification (a decision), SEPARATE from the server-derived
// ownership_status (known|partial|missing).
export const SHADOW_IT_CLASSIFICATIONS = Object.freeze([
  "unreviewed", "approved", "rejected", "exception", "retired",
]);
export const SHADOW_IT_OWNERSHIP_STATUSES = Object.freeze(["known", "partial", "missing"]);
export const SHADOW_IT_EVENT_TYPES = Object.freeze([
  "observed", "material_change", "monitoring_changed", "classified",
  "owner_assigned", "owner_missing", "purpose_set", "onboarding_changed",
  "removal_changed", "removal_contradicted", "retired", "reopened", "case_linked",
  // "we touched the already-open case for the same recurrence again". Its own type
  // BECAUSE it is not a monitoring change: it records no transition and carries no
  // to_recurrence_type. It used to be written as `monitoring_changed`, which put one
  // row per evaluation pass into the namespace the occurrence resolver searches —
  // measured at 148 rows for a single item, of which 4 were real occurrences.
  "case_recurrence_noted",
]);
// Customer classification actions and the classification they set.
export const SHADOW_IT_ACTIONS = Object.freeze({
  approve:        { classification: "approved" },
  reject:         { classification: "rejected" },
  mark_exception: { classification: "exception", requiresReason: true, requiresExpiry: true },
  retire:         { classification: "retired", requiresReason: true },
  reopen_review:  { classification: "unreviewed" },
});

async function appendEvent(env, item, { actor_type = "system", actor_id = null, event_type, detail = null }) {
  await env.cybermeters_db
    .prepare(`INSERT INTO shadow_it_inventory_events
      (id, item_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newId("sie"), item.id, item.workspace_id, actor_type, actor_id, event_type, safeJson(detail))
    .run();
}

// ── Correlation / upsert ────────────────────────────────────────────────────
// Read the workspace's active vendor observations, group by canonical technology
// key, and upsert one inventory item per product. Observation fields refresh;
// classification/ownership persist. Detects material change + disappearance/
// reappearance. Soft-deleted workspaces are skipped (no new observations).
export async function correlateShadowItInventory(env, workspaceId, { saasExposure = null, now = new Date().toISOString() } = {}) {
  // Soft-delete gate — a deleted workspace never receives new observations.
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(workspaceId).first().catch(() => null);
  if (!ws) return { correlated: 0, created: 0, changed: 0, skipped: "workspace_inactive" };

  // Gather observations from EVERY persisted, safely-joinable source. Each
  // contribution retains a structured evidence reference.
  const observations = await gatherShadowItObservations(env, workspaceId, saasExposure);

  // Group observations by canonical technology key (alias-resolved). Unrelated
  // products of one provider stay in separate groups.
  const groups = new Map();
  for (const o of observations) {
    if (!o.name) continue;
    const key = canonicalTechnologyKey(o.name);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(o);
  }

  let created = 0, changed = 0;
  const seenKeys = new Set();
  for (const [key, obs] of groups) {
    seenKeys.add(key);
    // Prefer a vendor-typed name for the display; category = most specific.
    const primary = obs.find((o) => o.source_type === "vendor") || obs[0];
    const display_name = primary.name;
    const category = obs.map((o) => o.category).find(Boolean) || "other";
    let confidence = "low";
    let firstSeen = null, lastSeen = null;
    const hostnames = new Set();
    const sourceTypes = new Set();
    const evidenceRefs = [];
    for (const o of obs) {
      confidence = strongerConfidence(confidence, o.confidence);
      if (o.first_seen_at && (!firstSeen || o.first_seen_at < firstSeen)) firstSeen = o.first_seen_at;
      if (o.last_seen_at && (!lastSeen || o.last_seen_at > lastSeen)) lastSeen = o.last_seen_at;
      sourceTypes.add(o.source_type);
      for (const h of (o.hostnames || [])) if (h) hostnames.add(String(h).slice(0, 300));
      evidenceRefs.push({
        source_table: o.source_table, source_record_id: o.source_record_id,
        source_type: o.source_type, observed_identifier: o.observed_identifier,
        first_seen_at: o.first_seen_at || null, last_seen_at: o.last_seen_at || null, confidence: o.confidence || "low",
      });
    }
    const snapshot = {
      display_name, provider: display_name, category,
      source_type: [...sourceTypes].join(","),
      observed_hostnames: [...hostnames], observed_identifiers: evidenceRefs.map((e) => e.observed_identifier).filter(Boolean),
      confidence, first_seen: firstSeen || lastSeen || now, last_seen: lastSeen || firstSeen || now,
      source_evidence: evidenceRefs,
    };

    const existing = await env.cybermeters_db
      .prepare(`SELECT * FROM shadow_it_inventory WHERE workspace_id = ? AND canonical_technology_key = ?`)
      .bind(workspaceId, key).first().catch(() => null);

    if (!existing) {
      const id = newId("sii");
      const item = { id, workspace_id: workspaceId };
      await env.cybermeters_db
        .prepare(`INSERT INTO shadow_it_inventory
          (id, workspace_id, canonical_technology_key, display_name, provider, category, source_type,
           observed_identifiers_json, observed_hostnames_json, observed_domains_json,
           first_seen_at, last_seen_at, confidence, classification, ownership_status, monitoring_status, source_evidence_json,
           created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unreviewed', 'missing', 'observed', ?, ?, ?)`)
        .bind(id, workspaceId, key, snapshot.display_name, snapshot.provider, snapshot.category, snapshot.source_type,
          safeJson(snapshot.observed_identifiers, "[]"), safeJson(snapshot.observed_hostnames, "[]"), safeJson([], "[]"),
          snapshot.first_seen, snapshot.last_seen, snapshot.confidence, safeJson(snapshot.source_evidence, "[]"), now, now)
        .run();
      await appendEvent(env, item, { event_type: "observed", detail: { created: true, category, confidence, source_types: [...sourceTypes] } });
      created++;
      continue;
    }

    // NON-DESTRUCTIVE evidence union: prior references are preserved, new ones
    // appended (dedup by source_table + source_record_id).
    const unionedEvidence = unionEvidence(parseJson(existing.source_evidence_json, []) || [], evidenceRefs);
    const prevHosts = new Set(parseJson(existing.observed_hostnames_json, []) || []);
    const newHost = [...hostnames].some((h) => !prevHosts.has(h));
    const unionedHosts = [...new Set([...prevHosts, ...hostnames])];
    // Material change: provider/category changed OR a new hostname appeared.
    const material = existing.category !== category || existing.provider !== snapshot.provider || newHost;
    const reappeared = existing.monitoring_status === "no_longer_observed";
    const monitoring = reappeared ? "reappeared" : "observed";
    const unionedSourceTypes = [...new Set([...(existing.source_type ? existing.source_type.split(",") : []), ...sourceTypes])].filter(Boolean).join(",");

    await env.cybermeters_db
      .prepare(`UPDATE shadow_it_inventory SET
          display_name = ?, provider = ?, category = ?, source_type = ?,
          observed_identifiers_json = ?, observed_hostnames_json = ?,
          last_seen_at = ?, confidence = ?, monitoring_status = ?, source_evidence_json = ?,
          last_changed_at = CASE WHEN ? THEN ? ELSE last_changed_at END,
          updated_at = ?
        WHERE id = ? AND workspace_id = ?`)
      .bind(snapshot.display_name, snapshot.provider, category, unionedSourceTypes,
        safeJson(snapshot.observed_identifiers, "[]"), safeJson(unionedHosts, "[]"),
        snapshot.last_seen, snapshot.confidence, monitoring, safeJson(unionedEvidence, "[]"),
        material ? 1 : 0, now, now, existing.id, workspaceId)
      .run();
    if (material) { await appendEvent(env, existing, { event_type: "material_change", detail: { category, provider: snapshot.provider, new_host: newHost } }); changed++; }
    if (reappeared) await appendEvent(env, existing, { event_type: "monitoring_changed", detail: { to: "reappeared" } });
  }

  // Run the deterministic monitoring evaluator (disappearance, recurrence,
  // ownership, staleness, removal contradiction, + case follow-up).
  const monitoring = await evaluateShadowItMonitoring(env, workspaceId, { seenKeys, now });
  return { correlated: groups.size, created, changed, monitoring };
}

// ── Monitoring evaluator ────────────────────────────────────────────────────
// ONE deterministic pass over the workspace's inventory. Explicit thresholds;
// disappearance is never verified removal; an approved technology disappearing is
// a monitoring observation, not an issue. Persists the evaluator snapshot and,
// where follow-up is due, opens or REOPENS the existing Universal Managed Case.
export const STALE_EVIDENCE_DAYS = 45;      // evidence older than this = stale
export const MATERIAL_CHANGE_WINDOW_DAYS = 30; // a change within this window is "recent"

function daysBetween(from, to) {
  const d = (Date.parse(to) - Date.parse(from)) / 86400000;
  return Number.isFinite(d) ? Math.max(0, Math.floor(d)) : null;
}

// ── Alert evidence + monitored domain (alert-truth episode, July 2026) ───────

// Customer-facing labels for HOW an observation was made. Keys are the vendor
// evidence `source` vocabulary (vendor-signatures.js / vendor-risk.js) plus the
// inventory-level source_type fallbacks. Internal table/module names must never
// reach the customer; an unknown source gets the honest generic label.
const EVIDENCE_SOURCE_LABELS = Object.freeze({
  "csp:script-src": "Content-Security-Policy (script-src)",
  "csp:connect-src": "Content-Security-Policy (connect-src)",
  csp: "Content-Security-Policy",
  script: "page script reference",
  cname: "DNS CNAME record",
  spf: "SPF DNS record",
  dkim: "DKIM DNS record",
  mx: "MX DNS record",
  ns: "NS DNS record",
  server: "HTTP server header",
  headers: "HTTP response headers",
  header: "HTTP response headers",
  tech: "technology fingerprint",
});
const SOURCE_TYPE_LABELS = Object.freeze({
  vendor: "external website analysis",
  cloud_asset: "cloud infrastructure observation",
  identity_provider: "identity-surface observation",
  email_sender: "email sender analysis",
  saas_portal: "SaaS portal discovery",
});

// Bounded, structured evidence summary for ONE inventory item: the strongest
// specific signal we hold (a workspace_vendors evidence entry, e.g. a CSP source
// naming https://js.stripe.com), falling back to the item's own source-type +
// observed hostname. One tenant-scoped read at most, only at alert time — never
// per evaluation row. Returns { label, detail, last_seen_at } or null: missing
// evidence yields NO statement, never a confident invented one.
export async function summarizeShadowItEvidence(env, item) {
  try {
    const refs = parseJson(item.source_evidence_json, []) || [];
    const vendorRef = refs.find((r) => r?.source_table === "workspace_vendors" && r?.source_record_id);
    if (vendorRef) {
      const row = await env.cybermeters_db
        .prepare(`SELECT evidence, last_seen FROM workspace_vendors WHERE id = ? AND workspace_id = ?`)
        .bind(vendorRef.source_record_id, item.workspace_id).first().catch(() => null);
      const entries = parseJson(row?.evidence, []) || [];
      const e = entries.find((x) => x?.source && x?.detail);
      if (e) {
        return {
          label: EVIDENCE_SOURCE_LABELS[String(e.source)] || SOURCE_TYPE_LABELS.vendor,
          detail: String(e.detail).slice(0, 200),
          last_seen_at: row?.last_seen || item.last_seen_at || null,
        };
      }
    }
    const firstType = String(item.source_type || "").split(",")[0].trim();
    const label = SOURCE_TYPE_LABELS[firstType] || (firstType ? "external observation" : null);
    const hosts = parseJson(item.observed_hostnames_json, []) || [];
    const detail = hosts.length ? String(hosts[0]).slice(0, 200) : null;
    if (!label && !detail) return null;
    return { label: label || "external observation", detail, last_seen_at: item.last_seen_at || null };
  } catch {
    return null;
  }
}

// The workspace's monitored domain, shown in the alert ONLY when it is
// unambiguous: exactly one linked domain. With several domains the observation
// cannot be attributed to one of them from the inventory row, and guessing would
// present an attribution the evidence does not support. Same join as
// brand-protection.js; tenant-scoped by workspace_id.
async function workspaceMonitoredDomain(env, workspaceId) {
  try {
    const rows = (await env.cybermeters_db
      .prepare(`SELECT d.domain FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
                WHERE wd.workspace_id = ? LIMIT 2`)
      .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
    return rows.length === 1 ? String(rows[0].domain) : null;
  } catch {
    return null;
  }
}

export async function evaluateShadowItMonitoring(env, workspaceId, { seenKeys = null, now = new Date().toISOString() } = {}) {
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`).bind(workspaceId).first().catch(() => null);
  if (!ws) return { evaluated: 0, skipped: "workspace_inactive" };

  const items = (await env.cybermeters_db
    .prepare(`SELECT * FROM shadow_it_inventory WHERE workspace_id = ?`).bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  let disappeared = 0, contradictions = 0, cases = 0, ownerMissingEvents = 0;
  // One bounded read per evaluation pass, not per item.
  const monitoredDomain = await workspaceMonitoredDomain(env, workspaceId);

  for (const it of items) {
    let monitoring_status = it.monitoring_status;
    // Disappearance — key no longer observed this correlation. Never verified removal.
    if (seenKeys && !seenKeys.has(it.canonical_technology_key) && monitoring_status !== "no_longer_observed") {
      monitoring_status = "no_longer_observed";
      await appendEvent(env, it, { event_type: "monitoring_changed", detail: { to: "no_longer_observed", note: "not_verified_removed" } });
      disappeared++;
    }
    const stillObserved = monitoring_status === "observed" || monitoring_status === "reappeared";
    const evidence_age_days = daysBetween(it.last_seen_at, now);
    const material_change = it.last_changed_at ? (daysBetween(it.last_changed_at, now) <= MATERIAL_CHANGE_WINDOW_DAYS ? 1 : 0) : 0;
    const stale = evidence_age_days != null && evidence_age_days > STALE_EVIDENCE_DAYS;
    const ownership_status = deriveOwnershipStatus(it.business_owner, it.technical_owner);

    // Removal verification: a customer "removed" that is still observed is
    // CONTRADICTED (assertion preserved, never overwritten).
    //
    // A customer "removed" that is NO LONGER OBSERVED stays UNVERIFIED. This used to
    // resolve to "verified", which laundered two different facts into one word: the
    // customer's assertion, and our failure to see the thing. Disappearance is absence of
    // evidence — the technology may have moved, been renamed, stopped serving a public
    // signal, or simply not been re-observed this pass. This file's own header states the
    // rule ("disappearance != verified removal"), the disappearance event above records
    // `note: "not_verified_removed"`, and migration 084 calls removal_status "customer-
    // asserted, NOT verified-gone" — the engine was the only thing that disagreed.
    //
    // "verified" is therefore unreachable here BY DESIGN and that is correct, not a hole:
    // Shadow IT is external-observation-only, its canonical remediation is
    // `manual_attestation` (remediation-registry.js), and nothing external can prove an
    // internal removal. Asymmetry is intended — we CAN externally disprove ("contradicted"
    // is a real observation of the thing still being there); we cannot externally confirm.
    // The column keeps the value in its domain for a future verification-grade signal.
    let removal_verified = it.removal_verified || null;
    if (it.removal_status === "removed") removal_verified = stillObserved ? "contradicted" : "unverified";
    else if (it.removal_status === "in_progress" && stillObserved) removal_verified = "unverified";

    // Deterministic priority: contradictions/recurrence first, then owner/stale/change.
    let recurrence_type = null, monitoring_reason = null, required_case_action = "none";
    if (it.removal_status === "removed" && stillObserved) { recurrence_type = "removal_contradicted"; monitoring_reason = "marked_removed_but_still_observed"; required_case_action = "open_or_reopen"; }
    else if (it.removal_status === "in_progress" && stillObserved) { recurrence_type = "removal_incomplete"; monitoring_reason = "removal_in_progress_still_observed"; required_case_action = "open_or_reopen"; }
    else if (it.classification === "rejected" && stillObserved) { recurrence_type = "rejected_reappeared"; monitoring_reason = "rejected_still_observed"; required_case_action = "open_or_reopen"; }
    else if (it.classification === "retired" && monitoring_status === "reappeared") { recurrence_type = "retired_reappeared"; monitoring_reason = "retired_reappeared"; required_case_action = "open_or_reopen"; }
    else if (it.classification === "exception" && it.exception_until && it.exception_until < now) { recurrence_type = "exception_expired"; monitoring_reason = "exception_expired"; required_case_action = "open_or_reopen"; }
    else if (ownership_status === "missing" && (it.classification === "approved" || it.classification === "exception")) { recurrence_type = "owner_missing"; monitoring_reason = "owner_missing"; required_case_action = "assign_owner"; }
    else if (it.classification === "approved" && monitoring_status === "no_longer_observed") { recurrence_type = "approved_disappeared"; monitoring_reason = "approved_no_longer_observed"; required_case_action = "none"; }
    else if (stale && stillObserved) { recurrence_type = "evidence_stale"; monitoring_reason = "evidence_stale"; required_case_action = "none"; }
    else if (material_change) { recurrence_type = "material_change"; monitoring_reason = "material_change_within_window"; required_case_action = "none"; }

    // Transition events on becoming missing / contradicted.
    if (ownership_status === "missing" && it.ownership_status !== "missing" && it.ownership_status != null) {
      await appendEvent(env, it, { event_type: "owner_missing", detail: { classification: it.classification } });
      ownerMissingEvents++;
    }
    if (removal_verified === "contradicted" && it.removal_verified !== "contradicted") {
      await appendEvent(env, it, { event_type: "removal_contradicted", detail: { note: "customer_marked_removed_but_still_observed", last_seen_at: it.last_seen_at } });
      contradictions++;
    }

    // ── Monitoring transition (append-only) ──────────────────────────────────
    // The canonical occurrence record: findConditionOccurrence reads this event's
    // created_at as the condition-start and its id as the occurrence identity.
    // Without it the consumer resolves nothing and every condition here is treated
    // as pre-existing — i.e. this domain would be silently unable to alert.
    //
    // The OTHER monitoring_changed sites in this file ("reappeared",
    // "no_longer_observed", case-linkage) are different facts and carry different
    // payloads; only this one records a recurrence transition, so only this one
    // carries to_recurrence_type.
    //
    // Only a real CHANGE is appended: re-observing the same condition next hour is
    // not a new occurrence, and appending one would mint a fresh occurrence id and
    // re-alert the same unchanged item every hour.
    const nextShadowMonitoring = { monitoring_status, recurrence_type: recurrence_type === "none" ? null : recurrence_type };
    if (isMonitoringTransition({ monitoring_status: it.monitoring_status, recurrence_type: it.recurrence_type }, nextShadowMonitoring)) {
      await appendEvent(env, it, {
        event_type: "monitoring_changed",
        detail: buildMonitoringTransitionDetail({
          from_monitoring_status: it.monitoring_status ?? null,
          to_monitoring_status: nextShadowMonitoring.monitoring_status ?? null,
          from_recurrence_type: it.recurrence_type ?? null,
          to_recurrence_type: nextShadowMonitoring.recurrence_type,
          required_case_action, reason: monitoring_reason,
          // The stable technology identity, not the row surrogate: the dedupe and
        // cooldown keys are built from this.
        entity: it.canonical_technology_key,
        }),
      }).catch(() => { /* history is best-effort; it must not break the evaluator */ });
    }

    await env.cybermeters_db
      .prepare(`UPDATE shadow_it_inventory SET monitoring_status = ?, monitoring_reason = ?, evidence_age_days = ?,
                  material_change = ?, recurrence_type = ?, required_case_action = ?, ownership_status = ?,
                  removal_verified = ?, evaluated_at = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
      .bind(monitoring_status, monitoring_reason, evidence_age_days, material_change, recurrence_type, required_case_action,
        ownership_status, removal_verified, now, now, it.id, workspaceId)
      .run();

    if (required_case_action === "open_or_reopen" || required_case_action === "assign_owner") {
      const acted = await openOrReopenShadowItCase(env, { ...it, monitoring_status, ownership_status }, { reason: recurrence_type, now });
      // Tell the customer — through the ONE canonical pipeline, from the same
      // deterministic decision that just opened/reopened the case. Detection is not
      // repeated here. The condition-start and occurrence identity come from the
      // append-only monitoring_changed event, so hourly re-evaluation of the same
      // occurrence dedupes and pre-existing state stays silent. Never sends directly.
      await emitLifecycleAlert(env, {
        workspace_id: workspaceId, domain_key: "shadow_it_unmanaged_technology",
        record_id: it.id, entity: it.canonical_technology_key,
        hostname: it.primary_hostname || null,
        recurrence: recurrence_type,
        // Same finding type the linked case is opened under (linkShadowItCase),
        // so the alert and the case resolve to the SAME canonical remediation.
        finding_type: "saas_exposure",
        case_id: it.linked_case_id || null,
        // The observed entity is a SERVICE, not a domain: label it as one, with
        // its customer-facing display name, the workspace's monitored domain
        // shown separately, and a bounded structured evidence summary.
        entity_type: "service",
        entity_display: it.display_name || it.canonical_technology_key,
        monitored_domain: monitoredDomain,
        evidence_source: await summarizeShadowItEvidence(env, it),
      }).catch(() => { /* alerting must never break the evaluator */ });
      if (acted?.ok) cases++;
    }
  }
  return { evaluated: items.length, disappeared, contradictions, cases, owner_missing: ownerMissingEvents };
}

// Open a new shadow_it_case OR reopen/update the EXISTING linked case through the
// universal transition validator (never a separate case table, never a bare dedup
// return). A resolved/monitoring case is reopened via canTransitionCase; an active
// case receives an appended recurrence event.
async function openOrReopenShadowItCase(env, item, { reason, now = new Date().toISOString() } = {}) {
  if (!item.linked_case_id) {
    return linkShadowItCase(env, item, {
      actor: { actor_type: "system", actor_id: null },
      title: `Review ${item.display_name} (${String(reason || "review").replace(/_/g, " ")})`,
      summary: `Externally observed technology "${item.display_name}" needs review: ${String(reason || "review").replace(/_/g, " ")}.`,
    });
  }
  const kase = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ?`).bind(item.linked_case_id, item.workspace_id).first().catch(() => null);
  if (!kase) {
    await env.cybermeters_db.prepare(`UPDATE shadow_it_inventory SET linked_case_id = NULL WHERE id = ? AND workspace_id = ?`).bind(item.id, item.workspace_id).run();
    return linkShadowItCase(env, item, { actor: { actor_type: "system", actor_id: null }, title: `Review ${item.display_name}`, summary: `Recurrence: ${reason}.` });
  }
  const phase = canonicalPhaseFor(kase.case_type, kase.status);
  if (phase === "verified" || phase === "monitoring") {
    const decision = canTransitionCase({ case: kase, target_status: "reopened", actor: { actor_type: "system", actor_id: null }, reason, now });
    if (decision.ok) {
      const n = decision.case;
      await env.cybermeters_db
        .prepare(`UPDATE managed_cases SET status = ?, reopened_at = ?, reopened_count = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
        .bind(n.status, n.reopened_at || now, Number(n.reopened_count || 0), n.updated_at, kase.id, kase.workspace_id).run();
      await env.cybermeters_db
        .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                  VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
        .bind(newCaseEventId(), kase.id, kase.workspace_id, kase.status, n.status, decision.event.action, safeJson({ reason, inventory_item: item.id })).run();
      await appendEvent(env, item, { event_type: "reopened", detail: { case_id: kase.id, reason } });
      return { ok: true, reopened: true };
    }
  }
  // Active case → append a recurrence event (update, not a bare dedup return).
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, 'shadow_it_recurrence', ?, datetime('now'))`)
    .bind(newCaseEventId(), kase.id, kase.workspace_id, kase.status, kase.status, safeJson({ reason, inventory_item: item.id })).run();
  // NOT `monitoring_changed`: nothing about the monitoring state changed here. This says
  // "the already-open case was touched again for the same recurrence", which is a
  // case-linkage fact, and it is appended on EVERY evaluation pass for as long as the
  // condition persists. Typing it as `monitoring_changed` put an ever-growing pile of
  // rows into the namespace findConditionOccurrence searches — one per hour, per item,
  // forever — and pushed the real occurrence out of its (then bounded) window at pass 26.
  //
  // The resolver no longer depends on a window, so this is NOT what makes it correct, and
  // it does not make the resolver faster either: the only index here is
  // (item_id, created_at) (083:75-76), so `event_type` is a residual filter applied to
  // each visited row and the walk still steps over every event for this item. An earlier
  // version of this comment claimed the retype shortened that walk. It does not — the row
  // is merely rejected on a string compare instead of after a JSON parse. If walk length
  // ever matters, the answer is an index on (item_id, event_type, created_at), not this.
  //
  // What it IS for: the log should not call a case touch a monitoring change, and the
  // occurrence namespace should mean one thing, so a future reader counting
  // `monitoring_changed` gets real transitions rather than an hourly heartbeat.
  //
  // The growth itself is NOT fixed here — this row, and the managed_case_events row
  // above it, are still written once per pass and still record no new fact. That is a
  // storage/history concern with its own semantics (does a still-open case want an
  // hourly heartbeat at all?) and it is recorded as outstanding rather than decided as a
  // side effect of an alerting fix.
  await appendEvent(env, item, { event_type: "case_recurrence_noted", detail: { case_id: kase.id, recurrence: reason, updated_case: true } });
  return { ok: true, updated: true };
}
export { openOrReopenShadowItCase };

// Create a shadow_it_case via the universal factory and link it to the item.
async function linkShadowItCase(env, item, { actor, title, summary } = {}) {
  const result = await createManagedCase(env, {
    workspace_id: item.workspace_id,
    domain_key: "shadow_it_unmanaged_technology",
    case_type: "shadow_it_case",
    source_finding_type: "saas_exposure", // → canonical remediation shadow_it.saas.review
    source_finding_id: `shadow_it:${item.canonical_technology_key}`,
    title: title || `Review ${item.display_name}`,
    summary: summary || null,
    severity: "low",
    actor: actor || { actor_type: "system", actor_id: null },
  });
  if (!result.ok) return result;
  await env.cybermeters_db
    .prepare(`UPDATE shadow_it_inventory SET linked_case_id = ?, updated_at = datetime('now') WHERE id = ? AND workspace_id = ?`)
    .bind(result.case.id, item.id, item.workspace_id).run();
  await appendEvent(env, item, { actor_type: actor?.actor_type || "system", actor_id: actor?.actor_id || null, event_type: "case_linked", detail: { case_id: result.case.id, remediation_id: result.case.remediation_id } });
  return { ok: true, case: result.case };
}
export { linkShadowItCase };

// ── Classification / workflow service ───────────────────────────────────────
// The customer actions. Every action is workspace-scoped and audit-logged
// (append-only event). Classification is a customer decision — approved is NOT a
// security claim, rejected is NOT removal, and marking removed is a customer
// assertion, not product-verified removal.
export const SHADOW_IT_WORKFLOW_ACTIONS = Object.freeze([
  "approve", "reject", "mark_exception", "assign_business_owner", "assign_technical_owner",
  "set_business_purpose", "begin_onboarding", "mark_onboarded", "begin_removal",
  "mark_removed", "retire", "reopen_review",
]);

async function loadItem(env, workspaceId, itemId) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM shadow_it_inventory WHERE id = ? AND workspace_id = ?`)
    .bind(itemId, workspaceId).first().catch(() => null);
}

export async function classifyShadowItItem(env, workspaceId, itemId, action, opts = {}) {
  if (!SHADOW_IT_WORKFLOW_ACTIONS.includes(action)) return { ok: false, code: "invalid_action" };
  const item = await loadItem(env, workspaceId, itemId);
  if (!item) return { ok: false, code: "not_found" }; // same for foreign + nonexistent
  const actor = { actor_type: "customer", actor_id: opts.actor_id || null };
  const now = new Date().toISOString();
  const set = { updated_at: now };
  let eventType = "classified", detail = { action };
  let openCase = false;

  switch (action) {
    case "approve":
      set.classification = "approved"; set.approved_at = now; set.approved_by = actor.actor_id;
      set.classification_reason = opts.reason || null; detail.classification = "approved";
      break;
    case "reject":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      set.classification = "rejected"; set.rejected_at = now; set.rejected_by = actor.actor_id;
      set.classification_reason = opts.reason; detail.classification = "rejected";
      openCase = item.monitoring_status !== "no_longer_observed"; // rejected-still-observed
      break;
    case "mark_exception":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      if (!opts.exception_until || !Number.isFinite(Date.parse(opts.exception_until))) return { ok: false, code: "expiry_required" };
      set.classification = "exception"; set.exception_until = opts.exception_until; set.exception_reason = opts.reason;
      set.classification_reason = opts.reason; detail.classification = "exception";
      break;
    case "retire":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      set.classification = "retired"; set.classification_reason = opts.reason; detail.classification = "retired";
      eventType = "retired";
      break;
    case "reopen_review":
      set.classification = "unreviewed"; set.classification_reason = opts.reason || null;
      eventType = "reopened"; detail.classification = "unreviewed";
      break;
    case "assign_business_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.business_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveOwnershipStatus(set.business_owner, item.technical_owner);
      eventType = "owner_assigned"; detail = { role: "business", owner: set.business_owner, ownership_status: set.ownership_status };
      break;
    case "assign_technical_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.technical_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveOwnershipStatus(item.business_owner, set.technical_owner);
      eventType = "owner_assigned"; detail = { role: "technical", owner: set.technical_owner, ownership_status: set.ownership_status };
      break;
    case "set_business_purpose":
      set.business_purpose = String(opts.business_purpose || "").slice(0, 1000); eventType = "purpose_set"; detail = { business_purpose: set.business_purpose };
      break;
    case "begin_onboarding":
      set.onboarding_status = "in_progress"; eventType = "onboarding_changed"; detail = { onboarding_status: "in_progress" };
      break;
    case "mark_onboarded":
      set.onboarding_status = "onboarded"; eventType = "onboarding_changed"; detail = { onboarding_status: "onboarded" };
      break;
    case "begin_removal":
      set.removal_status = "in_progress"; eventType = "removal_changed"; detail = { removal_status: "in_progress" };
      break;
    case "mark_removed":
      // Customer assertion — NOT product-verified removal.
      set.removal_status = "removed"; eventType = "removal_changed"; detail = { removal_status: "removed", note: "customer_asserted_not_verified" };
      break;
    default:
      return { ok: false, code: "invalid_action" };
  }

  const cols = Object.keys(set);
  await env.cybermeters_db
    .prepare(`UPDATE shadow_it_inventory SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE id = ? AND workspace_id = ?`)
    .bind(...cols.map((c) => set[c]), itemId, workspaceId).run();
  const updated = { ...item, ...set };
  await appendEvent(env, updated, { actor_type: "customer", actor_id: actor.actor_id, event_type: eventType, detail });

  if (openCase) {
    // Open OR reopen the existing linked case (never a bare dedup return).
    await openOrReopenShadowItCase(env, updated, { reason: "rejected_still_observed" });
  }
  const fresh = await loadItem(env, workspaceId, itemId);
  return { ok: true, item: shadowItItemToApi(fresh) };
}

// The canonical registry action for the finding type Shadow IT cases open under —
// the same fallback the alert consumer uses, so UI and email cannot disagree.
// Resolved lazily (and gated on status) so an unmapped registry never yields an
// invented action.
function registryActionForShadowIt() {
  const r = resolveRemediation({ finding_type: "saas_exposure" });
  return r?.status === "resolved" ? (r.recommended_action || null) : null;
}

// ── API serializer ──────────────────────────────────────────────────────────
export function shadowItItemToApi(row) {
  return {
    inventory_item_id: row.id,
    workspace_id: row.workspace_id,
    canonical_technology_key: row.canonical_technology_key,
    display_name: row.display_name,
    provider: row.provider,
    category: row.category,
    source_type: row.source_type,
    observed_hostnames: parseJson(row.observed_hostnames_json, []) || [],
    observed_identifiers: parseJson(row.observed_identifiers_json, []) || [],
    first_seen_at: row.first_seen_at,
    last_seen_at: row.last_seen_at,
    last_changed_at: row.last_changed_at || null,
    confidence: row.confidence,
    classification: row.classification,
    classification_reason: row.classification_reason || null,
    ownership_status: row.ownership_status || deriveOwnershipStatus(row.business_owner, row.technical_owner),
    business_purpose: row.business_purpose || null,
    business_owner: row.business_owner || null,
    technical_owner: row.technical_owner || null,
    exception_until: row.exception_until || null,
    exception_reason: row.exception_reason || null,
    onboarding_status: row.onboarding_status || null,
    removal_status: row.removal_status || null,
    removal_verified: row.removal_verified || null,
    monitoring_status: row.monitoring_status,
    monitoring_reason: row.monitoring_reason || null,
    evidence_age_days: row.evidence_age_days ?? null,
    material_change: Boolean(row.material_change),
    recurrence_type: row.recurrence_type || null,
    // Parity fields (PR-2): the SAME copy the alert email and in-app card carry,
    // computed by the same functions — the UI never re-derives or re-words the
    // recurrence meaning. Null when there is no active recurrence.
    recurrence_summary: row.recurrence_type
      ? describeRecurrenceEvent("shadow_it_unmanaged_technology", row.recurrence_type, row.display_name || row.canonical_technology_key)
      : null,
    recommended_next_action: row.recurrence_type
      ? recommendationForRecurrence("shadow_it_unmanaged_technology", row.recurrence_type,
          row.display_name || row.canonical_technology_key, registryActionForShadowIt())
      : null,
    required_case_action: row.required_case_action || null,
    evaluated_at: row.evaluated_at || null,
    source_evidence: parseJson(row.source_evidence_json, []) || [],
    linked_case_id: row.linked_case_id || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    // Honest-scope reminder carried to the client.
    scope_note: "Externally observed only. Classification is your decision; approved is not a security guarantee and rejected is not removal.",
  };
}

export async function listShadowItInventory(env, workspaceId, { classification = null, monitoring_status = null, ownership_status = null, limit = 100 } = {}) {
  const where = ["workspace_id = ?"]; const binds = [workspaceId];
  if (classification) { where.push("classification = ?"); binds.push(classification); }
  if (monitoring_status) { where.push("monitoring_status = ?"); binds.push(monitoring_status); }
  if (ownership_status) { where.push("ownership_status = ?"); binds.push(ownership_status); }
  const rows = (await env.cybermeters_db
    .prepare(`SELECT * FROM shadow_it_inventory WHERE ${where.join(" AND ")} ORDER BY last_seen_at DESC LIMIT ?`)
    .bind(...binds, Math.max(1, Math.min(500, Number(limit) || 100))).all().catch(() => ({ results: [] }))).results || [];
  return rows.map(shadowItItemToApi);
}
export async function getShadowItItem(env, workspaceId, itemId) {
  const row = await loadItem(env, workspaceId, itemId);
  return row ? shadowItItemToApi(row) : null;
}
export async function listShadowItItemEvents(env, workspaceId, itemId) {
  return (await env.cybermeters_db
    .prepare(`SELECT id, actor_type, actor_id, event_type, detail_json, created_at
              FROM shadow_it_inventory_events WHERE workspace_id = ? AND item_id = ? ORDER BY created_at ASC`)
    .bind(workspaceId, itemId).all().catch(() => ({ results: [] }))).results || [];
}
export async function countShadowItByClassification(env, workspaceId) {
  const rows = (await env.cybermeters_db
    .prepare(`SELECT classification, COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id = ? GROUP BY classification`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  const counts = Object.fromEntries(SHADOW_IT_CLASSIFICATIONS.map((c) => [c, 0]));
  for (const r of rows) counts[r.classification] = r.n;
  return counts;
}
