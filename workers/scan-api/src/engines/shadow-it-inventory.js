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

import { createManagedCase } from "./managed-case-model.js";

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
export function canonicalTechnologyKey(name) {
  const slug = String(name || "").trim().toLowerCase()
    .replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80);
  return slug || "unknown";
}

const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 };
function strongerConfidence(a, b) {
  return (CONFIDENCE_RANK[a] || 0) >= (CONFIDENCE_RANK[b] || 0) ? (a || b || "low") : (b || "low");
}

// ── Classification model ────────────────────────────────────────────────────
export const SHADOW_IT_CLASSIFICATIONS = Object.freeze([
  "unreviewed", "approved", "rejected", "exception", "unknown_owner", "retired",
]);
export const SHADOW_IT_EVENT_TYPES = Object.freeze([
  "observed", "material_change", "monitoring_changed", "classified",
  "owner_assigned", "purpose_set", "onboarding_changed", "removal_changed",
  "retired", "reopened", "case_linked",
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

  const vendorRows = (await env.cybermeters_db
    .prepare(`SELECT id, vendor_name, category, source, evidence, confidence, first_seen, last_seen
              FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];

  // Portal/tenant hostnames from the ephemeral saas_exposure module, keyed by name.
  const exposureByKey = new Map();
  for (const ex of (Array.isArray(saasExposure?.exposures) ? saasExposure.exposures : [])) {
    const k = canonicalTechnologyKey(ex.name || ex.provider || ex.product);
    const hosts = [ex.tenant_url, ex.portal_url, ex.admin_url].filter(Boolean);
    if (!exposureByKey.has(k)) exposureByKey.set(k, []);
    exposureByKey.get(k).push(...hosts);
  }

  // Group vendor rows by canonical technology key.
  const groups = new Map();
  for (const r of vendorRows) {
    const key = canonicalTechnologyKey(r.vendor_name);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }

  let created = 0, changed = 0;
  const seenKeys = new Set();
  for (const [key, rows] of groups) {
    seenKeys.add(key);
    // Aggregate the correlated observation.
    const display_name = rows[0].vendor_name;
    const category = rows.map((r) => r.category).find(Boolean) || "other";
    let confidence = "low";
    let firstSeen = now, lastSeen = "0";
    const hostnames = new Set(exposureByKey.get(key) || []);
    const identifiers = new Set();
    const sources = new Set();
    const evidenceRefs = [];
    for (const r of rows) {
      confidence = strongerConfidence(confidence, r.confidence);
      if (r.first_seen && r.first_seen < firstSeen) firstSeen = r.first_seen;
      if (r.last_seen && r.last_seen > lastSeen) lastSeen = r.last_seen;
      if (r.source) sources.add(r.source);
      for (const e of (parseJson(r.evidence, []) || [])) {
        if (e?.detail) identifiers.add(String(e.detail).slice(0, 200));
        if (e?.source) sources.add(e.source);
      }
      evidenceRefs.push({ vendor_id: r.id, category: r.category, source: r.source });
    }
    const snapshot = {
      display_name, provider: display_name, category,
      source_type: [...sources].join(","),
      observed_hostnames: [...hostnames], observed_identifiers: [...identifiers],
      confidence, first_seen: firstSeen === now ? lastSeen : firstSeen, last_seen: lastSeen || now,
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
           first_seen_at, last_seen_at, confidence, classification, monitoring_status, source_evidence_json,
           created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unreviewed', 'observed', ?, ?, ?)`)
        .bind(id, workspaceId, key, snapshot.display_name, snapshot.provider, snapshot.category, snapshot.source_type,
          safeJson(snapshot.observed_identifiers, "[]"), safeJson(snapshot.observed_hostnames, "[]"), safeJson([], "[]"),
          snapshot.first_seen, snapshot.last_seen, snapshot.confidence, safeJson(snapshot.source_evidence, "[]"), now, now)
        .run();
      await appendEvent(env, item, { event_type: "observed", detail: { created: true, category, confidence } });
      created++;
      continue;
    }

    // Material change: provider/category changed OR a new hostname appeared.
    const prevHosts = new Set(parseJson(existing.observed_hostnames_json, []) || []);
    const newHost = [...hostnames].some((h) => !prevHosts.has(h));
    const material = existing.category !== category || existing.provider !== snapshot.provider || newHost;
    // Reappearance after being no-longer-observed.
    const reappeared = existing.monitoring_status === "no_longer_observed";
    const monitoring = reappeared ? "reappeared" : "observed";

    await env.cybermeters_db
      .prepare(`UPDATE shadow_it_inventory SET
          display_name = ?, provider = ?, category = ?, source_type = ?,
          observed_identifiers_json = ?, observed_hostnames_json = ?,
          last_seen_at = ?, confidence = ?, monitoring_status = ?, source_evidence_json = ?,
          last_changed_at = CASE WHEN ? THEN ? ELSE last_changed_at END,
          updated_at = ?
        WHERE id = ? AND workspace_id = ?`)
      .bind(snapshot.display_name, snapshot.provider, category, snapshot.source_type,
        safeJson(snapshot.observed_identifiers, "[]"), safeJson([...new Set([...prevHosts, ...hostnames])], "[]"),
        snapshot.last_seen, snapshot.confidence, monitoring, safeJson(snapshot.source_evidence, "[]"),
        material ? 1 : 0, now, now, existing.id, workspaceId)
      .run();
    if (material) { await appendEvent(env, existing, { event_type: "material_change", detail: { category, provider: snapshot.provider, new_host: newHost } }); changed++; }
    if (reappeared) await appendEvent(env, existing, { event_type: "monitoring_changed", detail: { to: "reappeared" } });
  }

  // Disappearance: items whose key is no longer in the active vendor set are
  // marked no_longer_observed — NEVER auto-marked removed/verified-gone.
  const invItems = (await env.cybermeters_db
    .prepare(`SELECT id, workspace_id, canonical_technology_key, monitoring_status FROM shadow_it_inventory
              WHERE workspace_id = ? AND monitoring_status != 'no_longer_observed'`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  for (const it of invItems) {
    if (!seenKeys.has(it.canonical_technology_key)) {
      await env.cybermeters_db
        .prepare(`UPDATE shadow_it_inventory SET monitoring_status = 'no_longer_observed', updated_at = ? WHERE id = ? AND workspace_id = ?`)
        .bind(now, it.id, workspaceId).run();
      await appendEvent(env, it, { event_type: "monitoring_changed", detail: { to: "no_longer_observed", note: "no_longer_externally_observed_not_verified_removed" } });
    }
  }

  // Open managed-case follow-ups where the state demands it.
  const followups = await evaluateShadowItRecurrence(env, workspaceId, { now });
  return { correlated: groups.size, created, changed, followups };
}

// ── Recurrence / follow-up → Universal Managed Cases ────────────────────────
// Opens (or links) a shadow_it_case via the universal factory when: a rejected
// technology is still/again observed; a retired technology reappears; an
// exception has expired. Deduplicated by the inventory item (createManagedCase
// dedups on source_finding_id). Honest scope preserved via shadow_it.saas.review.
export async function evaluateShadowItRecurrence(env, workspaceId, { now = new Date().toISOString() } = {}) {
  const rows = (await env.cybermeters_db
    .prepare(`SELECT * FROM shadow_it_inventory WHERE workspace_id = ? AND linked_case_id IS NULL`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  let opened = 0;
  for (const it of rows) {
    let reason = null;
    if (it.classification === "rejected" && it.monitoring_status !== "no_longer_observed") reason = "rejected_still_observed";
    else if (it.classification === "retired" && it.monitoring_status === "reappeared") reason = "retired_reappeared";
    else if (it.classification === "exception" && it.exception_until && it.exception_until < now) reason = "exception_expired";
    if (!reason) continue;
    const linked = await linkShadowItCase(env, it, {
      actor: { actor_type: "system", actor_id: null },
      title: `Review ${it.display_name} (${reason.replace(/_/g, " ")})`,
      summary: `Externally observed technology "${it.display_name}" needs review: ${reason.replace(/_/g, " ")}.`,
    });
    if (linked?.ok) opened++;
  }
  return { opened };
}

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
      set.business_owner = String(opts.owner).slice(0, 255); eventType = "owner_assigned"; detail = { role: "business", owner: set.business_owner };
      break;
    case "assign_technical_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.technical_owner = String(opts.owner).slice(0, 255); eventType = "owner_assigned"; detail = { role: "technical", owner: set.technical_owner };
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

  if (openCase && !item.linked_case_id) {
    await linkShadowItCase(env, updated, {
      actor: { actor_type: "system", actor_id: null },
      title: `Rejected technology still observed: ${item.display_name}`,
      summary: `"${item.display_name}" was rejected but is still externally observed. Confirm removal or record an exception.`,
    });
  }
  const fresh = await loadItem(env, workspaceId, itemId);
  return { ok: true, item: shadowItItemToApi(fresh) };
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
    business_purpose: row.business_purpose || null,
    business_owner: row.business_owner || null,
    technical_owner: row.technical_owner || null,
    exception_until: row.exception_until || null,
    exception_reason: row.exception_reason || null,
    onboarding_status: row.onboarding_status || null,
    removal_status: row.removal_status || null,
    monitoring_status: row.monitoring_status,
    linked_case_id: row.linked_case_id || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    // Honest-scope reminder carried to the client.
    scope_note: "Externally observed only. Classification is your decision; approved is not a security guarantee and rejected is not removal.",
  };
}

export async function listShadowItInventory(env, workspaceId, { classification = null, monitoring_status = null, limit = 100 } = {}) {
  const where = ["workspace_id = ?"]; const binds = [workspaceId];
  if (classification) { where.push("classification = ?"); binds.push(classification); }
  if (monitoring_status) { where.push("monitoring_status = ?"); binds.push(monitoring_status); }
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
