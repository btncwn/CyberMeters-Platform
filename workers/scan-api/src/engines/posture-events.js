// ── Posture diff event engine ──
// Cross-scan Exposure Timeline events for email-auth posture and internet-exposed
// services. Reads the previous completed scan report from R2, compares it with
// the current in-memory modules, and writes asset_events. All failures are
// non-fatal so scan completion never depends on timeline event generation.
import { createId } from "../lib/util.js";
import { loadTimelineComparisonContext } from "./timeline-trust.js";

function normalizeValue(value) {
  return String(value ?? "").trim();
}

function boolState(value) {
  return typeof value === "boolean" ? value : null;
}

function policyValue(emailMod) {
  const policy = normalizeValue(emailMod?.dmarc?.policy).toLowerCase();
  if (policy) return policy;
  const present = boolState(emailMod?.dmarc?.present);
  if (present === false) return "absent";
  return "";
}

function dmarcSeverity(oldPolicy, newPolicy) {
  const strong = new Set(["reject", "quarantine"]);
  if ((strong.has(oldPolicy) && newPolicy === "none") || newPolicy === "absent") return "high";
  if (oldPolicy === "none" && strong.has(newPolicy)) return "low";
  return "medium";
}

function serviceKey(service) {
  const hostname = normalizeValue(service?.hostname).toLowerCase();
  const product = normalizeValue(service?.product).toLowerCase();
  if (!hostname || !product) return "";
  return `${hostname}::${product}`;
}

function serviceMap(adminModule) {
  const map = new Map();
  for (const service of adminModule?.services || []) {
    const key = serviceKey(service);
    if (key && !map.has(key)) map.set(key, service);
  }
  return map;
}

function pushEvent(events, { event_type, hostname, severity, description }) {
  events.push({ event_type, hostname, severity, description });
}

function buildPostureDiffEvents(domain, prevModules, currentModules) {
  const events = [];
  const previousEmail = prevModules?.email_security || {};
  const currentEmail = currentModules?.email_security || {};

  const prevSpfPresent = boolState(previousEmail?.spf?.present);
  const currSpfPresent = boolState(currentEmail?.spf?.present);
  const prevSpfRecord = normalizeValue(previousEmail?.spf?.record);
  const currSpfRecord = normalizeValue(currentEmail?.spf?.record);
  if (prevSpfPresent !== null && currSpfPresent !== null && prevSpfPresent !== currSpfPresent) {
    pushEvent(events, {
      event_type: "email_spf_changed",
      hostname: domain,
      severity: prevSpfPresent && !currSpfPresent ? "high" : "low",
      description: `SPF record changed for ${domain}`,
    });
  } else if (prevSpfRecord && currSpfRecord && prevSpfRecord !== currSpfRecord) {
    pushEvent(events, {
      event_type: "email_spf_changed",
      hostname: domain,
      severity: "medium",
      description: `SPF record changed for ${domain}`,
    });
  }

  const prevPolicy = policyValue(previousEmail);
  const currPolicy = policyValue(currentEmail);
  if (prevPolicy && currPolicy && prevPolicy !== currPolicy) {
    pushEvent(events, {
      event_type: "email_dmarc_policy_changed",
      hostname: domain,
      severity: dmarcSeverity(prevPolicy, currPolicy),
      description: `DMARC policy changed: ${prevPolicy} → ${currPolicy}`,
    });
  }

  const prevDkimPresent = boolState(previousEmail?.dkim?.present);
  const currDkimPresent = boolState(currentEmail?.dkim?.present);
  if (prevDkimPresent !== null && currDkimPresent !== null && prevDkimPresent !== currDkimPresent) {
    pushEvent(events, {
      event_type: "email_dkim_changed",
      hostname: domain,
      severity: prevDkimPresent && !currDkimPresent ? "medium" : "low",
      description: `DKIM status changed for ${domain}`,
    });
  }

  const previousServices = serviceMap(prevModules?.admin_surface_detection);
  const currentServices = serviceMap(currentModules?.admin_surface_detection);
  for (const [key, service] of currentServices) {
    if (previousServices.has(key)) continue;
    pushEvent(events, {
      event_type: "exposed_service_detected",
      hostname: normalizeValue(service.hostname),
      severity: service.severity ?? service.risk_level ?? "high",
      description: `New internet-exposed service detected: ${service.product} on ${service.hostname}`,
    });
  }
  for (const [key, service] of previousServices) {
    if (currentServices.has(key)) continue;
    pushEvent(events, {
      event_type: "exposed_service_resolved",
      hostname: normalizeValue(service.hostname),
      severity: "low",
      description: `Exposed service no longer detected: ${service.product} on ${service.hostname}`,
    });
  }

  return events;
}

export async function recordPostureEvents(scanId, domainId, domain, modules, env, opts = {}) {
  try {
    const comparison = await loadTimelineComparisonContext(env, {
      scanId,
      domainId,
      currentReport: opts.currentReport,
    });
    if (!comparison.comparable || !comparison.previousReport?.modules) return;

    const events = buildPostureDiffEvents(domain, comparison.previousReport.modules, modules);
    if (events.length === 0) return;

    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    const wsRows = r.results || [];
    if (wsRows.length === 0) return;

    const now = new Date().toISOString();
    for (const { workspace_id } of wsRows) {
      const recent = await env.cybermeters_db
        .prepare(
          `SELECT event_type, hostname FROM asset_events
           WHERE workspace_id = ? AND domain_id = ?
             AND created_at >= datetime('now', '-24 hours')`
        )
        .bind(workspace_id, domainId)
        .all();
      const recentEvtSet = new Set(
        (recent.results || []).map((row) => `${row.event_type}:${row.hostname}`)
      );

      for (const event of events) {
        const dedupeKey = `${event.event_type}:${event.hostname}`;
        if (recentEvtSet.has(dedupeKey)) continue;
        recentEvtSet.add(dedupeKey);

        let assetId = null;
        if (event.event_type.startsWith("exposed_service_")) {
          try {
            const assetRow = await env.cybermeters_db
              .prepare("SELECT id FROM workspace_assets WHERE workspace_id = ? AND hostname = ?")
              .bind(workspace_id, event.hostname)
              .first();
            assetId = assetRow?.id ?? null;
          } catch { /* asset link is best-effort */ }
        }

        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, asset_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            createId("evt"),
            workspace_id,
            domainId,
            assetId,
            scanId,
            event.event_type,
            event.hostname,
            event.severity,
            event.description,
            now
          )
          .run();
      }
    }
  } catch { /* non-fatal — posture events catch up on a later scan */ }
}
