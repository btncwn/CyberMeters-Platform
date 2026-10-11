// ── Website Security: important-page inventory persistence + reads ───────────
//
// Persists engines/page-discovery.js results into migration 115's tables for
// each workspace that owns the scanned domain AND has it verified. Honesty
// rules (mirrors the migration header):
//   • only an OBSERVED page can create a row (we never record a page we have
//     not actually seen);
//   • `not_found` only when the page was requested in this scan and answered
//     404/410; `unconfirmed` when it was requested but the answer could not
//     establish it; pages not requested in this scan are left untouched;
//   • observation JSON is an allow-listed projection — never cookie values,
//     never raw HTML, never the requested query string.
// One D1 batch per (workspace, scan); deterministic ids make a retry a no-op.

const PAGE_STATUS = Object.freeze({ OBSERVED: "observed", NOT_FOUND: "not_found", UNCONFIRMED: "unconfirmed" });
const MAX_PAGES_PER_RUN = 25;
const MAX_LIST_ROWS_PER_DOMAIN = 60;

async function sha(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function websitePageId(workspaceId, domainId, path) {
  return `wsp-${(await sha(`${workspaceId}|${domainId}|${path}`)).slice(0, 24)}`;
}

function statusFor(outcome) {
  if (outcome === "observed") return PAGE_STATUS.OBSERVED;
  if (outcome === "not_found") return PAGE_STATUS.NOT_FOUND;
  return PAGE_STATUS.UNCONFIRMED;
}

const strList = (v, max) => (Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, max) : []);

/** Allow-listed observation projection (defence in depth over the engine). */
export function projectObservation(page) {
  if (!page || page.outcome !== "observed") return null;
  return {
    https: page.https === true,
    redirected: page.redirected === true,
    security_headers: {
      present: strList(page.security_headers?.present, 10),
      missing: strList(page.security_headers?.missing, 10),
    },
    cookies: (Array.isArray(page.cookies) ? page.cookies : []).slice(0, 20).map((c) => ({
      name: String(c?.name ?? "").slice(0, 80),
      secure: c?.secure === true,
      httponly: c?.httponly === true,
      samesite: typeof c?.samesite === "string" ? c.samesite.slice(0, 10) : null,
    })),
    forms: (Array.isArray(page.forms) ? page.forms : []).slice(0, 10).map((f) => ({
      method: f?.method === "post" ? "post" : "get",
      action_kind: ["same_origin", "other_origin", "unparseable"].includes(f?.action_kind) ? f.action_kind : "same_origin",
      action_scheme: f?.action_scheme === "http" || f?.action_scheme === "https" ? f.action_scheme : null,
      action_host: typeof f?.action_host === "string" ? f.action_host.slice(0, 253) : null,
      has_password: f?.has_password === true,
    })),
    password_field: page.password_field === true,
    mixed_content: {
      count: Number.isFinite(page.mixed_content?.count) ? page.mixed_content.count : 0,
      hosts: strList(page.mixed_content?.hosts, 10),
    },
    third_party_scripts: strList(page.third_party_scripts, 20),
    sensitive_basis: page.sensitive_basis === "password_field" || page.sensitive_basis === "path" ? page.sensitive_basis : null,
  };
}

function finalUrlOf(page) {
  if (typeof page?.final_url !== "string") return null;
  try { const u = new URL(page.final_url); return `${u.protocol}//${u.host}${u.pathname}`.slice(0, 500); } catch { return null; }
}

/**
 * persistWebsitePagesForScan(env, { workspace_id, domain_id, domain, scan_id, discovery, now })
 * Returns { skipped } or { run, created, updated, events }.
 */
export async function persistWebsitePagesForScan(env, { workspace_id, domain_id, domain, scan_id, discovery, now = new Date().toISOString() }) {
  if (!discovery || typeof discovery !== "object" || discovery.source !== "page_discovery") return { skipped: "no_result" };
  const db = env.cybermeters_db;
  const eligible = await db
    .prepare(`SELECT 1 AS ok FROM workspaces w
                JOIN workspace_domains wd ON wd.workspace_id = w.id
               WHERE w.id = ? AND w.deleted_at IS NULL
                 AND wd.domain_id = ? AND wd.verification_status = 'verified'
               LIMIT 1`)
    .bind(workspace_id, domain_id).first();
  if (!eligible) return { skipped: "workspace_or_domain_not_eligible" };

  const stmts = [];
  const coverage = ["complete", "partial", "not_run"].includes(discovery.coverage) ? discovery.coverage : "not_run";
  stmts.push(db.prepare(
    `INSERT OR IGNORE INTO website_page_discovery_runs
       (id, workspace_id, domain_id, scan_id, coverage, partial_reasons_json, counts_json, module_version, observed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    `wspr-${(await sha(`${scan_id}|${workspace_id}|${domain_id}`)).slice(0, 24)}`,
    workspace_id, domain_id, scan_id, coverage,
    JSON.stringify(strList(discovery.partial_reasons, 10)),
    JSON.stringify({
      fetched: Number(discovery.counts?.fetched) || 0,
      observed: Number(discovery.counts?.observed) || 0,
      not_found: Number(discovery.counts?.not_found) || 0,
      sensitive: Number(discovery.counts?.sensitive) || 0,
      max_pages: Number(discovery.limits?.max_pages) || null,
    }),
    typeof discovery.version === "string" ? discovery.version : null,
    now,
  ));

  // Dedupe by path; bounded.
  const byPath = new Map();
  for (const p of Array.isArray(discovery.pages) ? discovery.pages : []) {
    if (typeof p?.path !== "string" || !p.path.startsWith("/") || p.path.length > 300) continue;
    if (!byPath.has(p.path)) byPath.set(p.path, p);
    if (byPath.size >= MAX_PAGES_PER_RUN) break;
  }
  const paths = [...byPath.keys()];
  const existing = new Map();
  if (paths.length) {
    const rows = await db
      .prepare(`SELECT id, path, monitoring_status, first_seen_at FROM website_pages
                 WHERE workspace_id = ? AND domain_id = ? AND path IN (${paths.map(() => "?").join(",")})`)
      .bind(workspace_id, domain_id, ...paths).all();
    for (const r of rows?.results || []) existing.set(r.path, r);
  }

  let created = 0, updated = 0, events = 0;
  const event = async (pageId, path, type, detail) => {
    events++;
    stmts.push(db.prepare(
      `INSERT OR IGNORE INTO website_page_events
         (id, workspace_id, domain_id, page_id, path, scan_id, event_type, detail_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(`wspe-${(await sha(`${scan_id}|${pageId}|${type}`)).slice(0, 24)}`,
      workspace_id, domain_id, pageId, path, scan_id, type, JSON.stringify(detail || {}), now));
  };

  for (const [path, page] of byPath) {
    const status = statusFor(page.outcome);
    const prior = existing.get(path);
    const kind = ["login", "admin", "account", "checkout"].includes(page.sensitive_kind) ? page.sensitive_kind : null;
    const obs = projectObservation(page);
    const statusCode = Number.isInteger(page.status_code) ? page.status_code : null;
    const source = ["homepage", "homepage_link", "sitemap", "well_known"].includes(page.source) ? page.source : null;
    const outcome = String(page.outcome || "unavailable").slice(0, 40);

    if (!prior) {
      if (status !== PAGE_STATUS.OBSERVED) continue; // never record a page we have not seen
      const id = await websitePageId(workspace_id, domain_id, path);
      stmts.push(db.prepare(
        `INSERT INTO website_pages
           (id, workspace_id, domain_id, domain, path, monitoring_status, sensitive_kind, discovery_source,
            last_outcome, last_status_code, last_final_url, last_observation_json,
            first_seen_at, last_seen_at, last_checked_at, last_scan_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'observed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (workspace_id, domain_id, path) DO NOTHING`,
      ).bind(id, workspace_id, domain_id, String(domain || "").slice(0, 253), path, kind, source,
        outcome, statusCode, finalUrlOf(page), JSON.stringify(obs), now, now, now, scan_id, now, now));
      created++;
      // Guarded so two concurrent scans cannot both record a first sighting.
      events++;
      stmts.push(db.prepare(
        `INSERT OR IGNORE INTO website_page_events
           (id, workspace_id, domain_id, page_id, path, scan_id, event_type, detail_json, created_at)
         SELECT ?, ?, ?, ?, ?, ?, 'page_first_seen', ?, ?
          WHERE NOT EXISTS (SELECT 1 FROM website_page_events e
                             WHERE e.workspace_id = ? AND e.page_id = ? AND e.event_type = 'page_first_seen')`,
      ).bind(`wspe-${(await sha(`${scan_id}|${id}|page_first_seen`)).slice(0, 24)}`,
        workspace_id, domain_id, id, path, scan_id, JSON.stringify({ sensitive_kind: kind, source }), now, workspace_id, id));
      continue;
    }

    if (status === PAGE_STATUS.OBSERVED) {
      stmts.push(db.prepare(
        `UPDATE website_pages SET monitoring_status = 'observed', sensitive_kind = ?,
                last_outcome = ?, last_status_code = ?, last_final_url = ?, last_observation_json = ?,
                first_seen_at = COALESCE(first_seen_at, ?), last_seen_at = ?, last_checked_at = ?,
                last_scan_id = ?, updated_at = ?
          WHERE id = ? AND workspace_id = ?`,
      ).bind(kind, outcome, statusCode, finalUrlOf(page), JSON.stringify(obs), now, now, now, scan_id, now, prior.id, workspace_id));
      if (prior.monitoring_status === PAGE_STATUS.NOT_FOUND) await event(prior.id, path, "page_reappeared", { status_code: statusCode });
    } else {
      // Requested but not observed: keep last_seen and the last good observation.
      stmts.push(db.prepare(
        `UPDATE website_pages SET monitoring_status = ?, last_outcome = ?, last_status_code = ?,
                last_checked_at = ?, last_scan_id = ?, updated_at = ?
          WHERE id = ? AND workspace_id = ?`,
      ).bind(status, outcome, statusCode, now, scan_id, now, prior.id, workspace_id));
      if (status === PAGE_STATUS.NOT_FOUND && prior.monitoring_status !== PAGE_STATUS.NOT_FOUND) {
        await event(prior.id, path, "page_not_found", { status_code: statusCode });
      }
    }
    updated++;
  }

  await db.batch(stmts);
  return { run: coverage, created, updated, events };
}

/** Read surface: pages + latest run per domain linked to the workspace (bounded per domain). */
export async function listWebsitePages(env, workspaceId, { domainId = null } = {}) {
  const db = env.cybermeters_db;
  const domainRows = (await db
    .prepare(`SELECT d.id AS domain_id, d.domain AS domain FROM workspace_domains wd
                JOIN domains d ON d.id = wd.domain_id
               WHERE wd.workspace_id = ? ${domainId ? "AND d.id = ?" : ""}
               ORDER BY d.domain`)
    .bind(...(domainId ? [workspaceId, domainId] : [workspaceId])).all())?.results || [];
  if (!domainRows.length) return [];
  // Bound by subquery, not by binding every domain id: D1 allows at most 100
  // parameters per query and a workspace may hold more domains than that.
  const DOMAINS = domainId
    ? "(SELECT ?)"
    : "(SELECT wd.domain_id FROM workspace_domains wd WHERE wd.workspace_id = ?)";
  const domainArg = domainId || workspaceId;
  const [pages, runs] = await Promise.all([
    db.prepare(`SELECT * FROM (
                  SELECT id, domain_id, path, monitoring_status, sensitive_kind, discovery_source, last_outcome,
                         last_status_code, last_final_url, last_observation_json, first_seen_at, last_seen_at,
                         last_checked_at,
                         ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY (sensitive_kind IS NULL), path) AS rn,
                         COUNT(*) OVER (PARTITION BY domain_id) AS domain_total
                    FROM website_pages WHERE workspace_id = ? AND domain_id IN ${DOMAINS})
                 WHERE rn <= ${MAX_LIST_ROWS_PER_DOMAIN}
                 ORDER BY domain_id, rn`)
      .bind(workspaceId, domainArg).all(),
    db.prepare(`SELECT r.domain_id, r.scan_id, r.coverage, r.partial_reasons_json, r.counts_json, r.observed_at
                  FROM website_page_discovery_runs r
                 WHERE r.workspace_id = ? AND r.domain_id IN ${DOMAINS}
                   AND r.observed_at = (SELECT MAX(r2.observed_at) FROM website_page_discovery_runs r2
                                         WHERE r2.workspace_id = r.workspace_id AND r2.domain_id = r.domain_id)`)
      .bind(workspaceId, domainArg).all(),
  ]);
  const parse = (s, d) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
  const runByDomain = new Map((runs?.results || []).map((r) => [r.domain_id, {
    scan_id: r.scan_id, coverage: r.coverage, partial_reasons: parse(r.partial_reasons_json, []),
    counts: parse(r.counts_json, {}), observed_at: r.observed_at,
  }]));
  const pagesByDomain = new Map();
  const totals = new Map();
  for (const p of pages?.results || []) {
    totals.set(p.domain_id, Number(p.domain_total) || 0);
    const list = pagesByDomain.get(p.domain_id) || [];
    list.push({
      id: p.id, path: p.path, monitoring_status: p.monitoring_status, sensitive_kind: p.sensitive_kind,
      discovery_source: p.discovery_source, last_outcome: p.last_outcome, last_status_code: p.last_status_code,
      last_final_url: p.last_final_url, observation: parse(p.last_observation_json, null),
      first_seen_at: p.first_seen_at, last_seen_at: p.last_seen_at, last_checked_at: p.last_checked_at,
    });
    pagesByDomain.set(p.domain_id, list);
  }
  return domainRows.map((d) => ({
    domain_id: d.domain_id, domain: d.domain,
    latest_run: runByDomain.get(d.domain_id) || null,
    pages: pagesByDomain.get(d.domain_id) || [],
    total_pages: totals.get(d.domain_id) || 0,
    truncated: (totals.get(d.domain_id) || 0) > (pagesByDomain.get(d.domain_id) || []).length,
  }));
}
